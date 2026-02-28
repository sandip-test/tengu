"""Unit tests for ScoutSuite cloud security scanner helpers."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from tengu.tools.cloud.scoutsuite import _VALID_PROVIDERS, _parse_scoutsuite_report

# ---------------------------------------------------------------------------
# TestValidProviders
# ---------------------------------------------------------------------------


class TestValidProviders:
    def test_aws_present(self):
        assert "aws" in _VALID_PROVIDERS

    def test_azure_present(self):
        assert "azure" in _VALID_PROVIDERS

    def test_gcp_present(self):
        assert "gcp" in _VALID_PROVIDERS

    def test_all_lowercase(self):
        for p in _VALID_PROVIDERS:
            assert p == p.lower()

    def test_at_least_three_providers(self):
        assert len(_VALID_PROVIDERS) >= 3


# ---------------------------------------------------------------------------
# TestParseScoutsuiteReport
# ---------------------------------------------------------------------------


def _write_results(tmp_dir: str, data: dict) -> None:
    """Write a fake scoutsuite_results.json to the expected path."""
    report_dir = Path(tmp_dir) / "scoutsuite-report"
    report_dir.mkdir(parents=True, exist_ok=True)
    results_path = report_dir / "scoutsuite_results.json"
    results_path.write_text(json.dumps(data))


class TestParseScoutsuiteReport:
    def test_missing_report_dir_returns_not_parsed(self):
        result = _parse_scoutsuite_report("/nonexistent/path/that/does/not/exist")
        assert result["parsed"] is False
        assert "error" in result

    def test_invalid_json_returns_not_parsed(self):
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = Path(tmp) / "scoutsuite-report"
            report_dir.mkdir(parents=True)
            (report_dir / "scoutsuite_results.json").write_text("not json {{{")
            result = _parse_scoutsuite_report(tmp)
        assert result["parsed"] is False
        assert "error" in result

    def test_empty_services_parsed_successfully(self):
        with tempfile.TemporaryDirectory() as tmp:
            _write_results(tmp, {"services": {}})
            result = _parse_scoutsuite_report(tmp)
        assert result["parsed"] is True
        assert result["total_flagged_items"] == 0
        assert result["top_findings"] == []

    def test_service_with_flagged_finding(self):
        data = {
            "services": {
                "s3": {
                    "findings": {
                        "s3-bucket-public": {
                            "flagged_items": 3,
                            "level": "danger",
                            "description": "S3 bucket publicly accessible",
                        }
                    }
                }
            }
        }
        with tempfile.TemporaryDirectory() as tmp:
            _write_results(tmp, data)
            result = _parse_scoutsuite_report(tmp)
        assert result["parsed"] is True
        assert result["total_flagged_items"] == 3
        assert len(result["top_findings"]) == 1
        assert result["top_findings"][0]["severity"] == "high"

    def test_warning_level_mapped_to_medium(self):
        data = {
            "services": {
                "iam": {
                    "findings": {
                        "iam-no-mfa": {
                            "flagged_items": 2,
                            "level": "warning",
                            "description": "MFA not enabled",
                        }
                    }
                }
            }
        }
        with tempfile.TemporaryDirectory() as tmp:
            _write_results(tmp, data)
            result = _parse_scoutsuite_report(tmp)
        assert result["top_findings"][0]["severity"] == "medium"

    def test_zero_flagged_items_not_included(self):
        data = {
            "services": {
                "ec2": {
                    "findings": {
                        "ec2-clean": {
                            "flagged_items": 0,
                            "level": "danger",
                            "description": "No issues",
                        }
                    }
                }
            }
        }
        with tempfile.TemporaryDirectory() as tmp:
            _write_results(tmp, data)
            result = _parse_scoutsuite_report(tmp)
        assert result["total_flagged_items"] == 0
        assert result["top_findings"] == []

    def test_top_findings_sorted_by_flagged_items(self):
        data = {
            "services": {
                "s3": {
                    "findings": {
                        "small-issue": {
                            "flagged_items": 1,
                            "level": "danger",
                            "description": "Small",
                        },
                        "big-issue": {
                            "flagged_items": 10,
                            "level": "danger",
                            "description": "Big",
                        },
                    }
                }
            }
        }
        with tempfile.TemporaryDirectory() as tmp:
            _write_results(tmp, data)
            result = _parse_scoutsuite_report(tmp)
        assert result["top_findings"][0]["flagged_items"] == 10

    def test_multiple_services_total_flagged_summed(self):
        data = {
            "services": {
                "s3": {
                    "findings": {
                        "f1": {"flagged_items": 5, "level": "danger", "description": "A"}
                    }
                },
                "iam": {
                    "findings": {
                        "f2": {"flagged_items": 3, "level": "warning", "description": "B"}
                    }
                },
            }
        }
        with tempfile.TemporaryDirectory() as tmp:
            _write_results(tmp, data)
            result = _parse_scoutsuite_report(tmp)
        assert result["total_flagged_items"] == 8

    def test_top_findings_capped_at_20(self):
        findings = {
            f"finding-{i}": {
                "flagged_items": i + 1,
                "level": "danger",
                "description": f"Issue {i}",
            }
            for i in range(30)
        }
        data = {"services": {"s3": {"findings": findings}}}
        with tempfile.TemporaryDirectory() as tmp:
            _write_results(tmp, data)
            result = _parse_scoutsuite_report(tmp)
        assert len(result["top_findings"]) <= 20

    def test_services_summary_includes_service_name(self):
        data = {
            "services": {
                "rds": {
                    "findings": {
                        "rds-public": {
                            "flagged_items": 2,
                            "level": "danger",
                            "description": "RDS public",
                        }
                    }
                }
            }
        }
        with tempfile.TemporaryDirectory() as tmp:
            _write_results(tmp, data)
            result = _parse_scoutsuite_report(tmp)
        assert "rds" in result["services"]
