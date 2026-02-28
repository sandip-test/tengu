"""Unit tests for secrets scanning parsers: trufflehog and gitleaks."""

from __future__ import annotations

import json

from tengu.tools.secrets.gitleaks import (
    _VALID_REPORT_FORMATS,
    _parse_gitleaks_output,
)
from tengu.tools.secrets.gitleaks import (
    _VALID_SCAN_TYPES as GITLEAKS_SCAN_TYPES,
)
from tengu.tools.secrets.gitleaks import (
    _redact_secret as gitleaks_redact,
)
from tengu.tools.secrets.trufflehog import (
    _VALID_SCAN_TYPES as TRUFFLEHOG_SCAN_TYPES,
)
from tengu.tools.secrets.trufflehog import (
    _parse_trufflehog_output,
)
from tengu.tools.secrets.trufflehog import (
    _redact_secret as trufflehog_redact,
)

# ---------------------------------------------------------------------------
# TestRedactSecretTrufflehog
# ---------------------------------------------------------------------------


class TestRedactSecretTrufflehog:
    def test_short_value_all_stars(self):
        # len <= 6*2=12 → all stars
        assert trufflehog_redact("hello") == "*****"

    def test_short_boundary_all_stars(self):
        assert trufflehog_redact("a" * 12) == "*" * 12

    def test_long_value_shows_prefix_and_suffix(self):
        result = trufflehog_redact("ABCDEF_secret_content_GHIJKL")
        assert result.startswith("ABCDEF")
        assert result.endswith("GHIJKL")
        assert "*" in result

    def test_empty_string(self):
        assert trufflehog_redact("") == ""

    def test_masked_section_capped_at_20_stars(self):
        # For very long secrets, masked section is at most 20 stars
        very_long = "A" * 6 + "secret_that_is_very_very_long_indeed" + "B" * 6
        result = trufflehog_redact(very_long)
        star_section = result[6:-6]
        assert len(star_section) <= 20


# ---------------------------------------------------------------------------
# TestParseTrufflehogOutput
# ---------------------------------------------------------------------------


def _make_trufflehog_line(
    detector: str = "AWS",
    verified: bool = False,
    raw: str = "AKIAIOSFODNN7EXAMPLE",
) -> str:
    return json.dumps({
        "DetectorName": detector,
        "Verified": verified,
        "Raw": raw,
        "SourceMetadata": {
            "Data": {
                "Git": {
                    "commit": "abc123",
                    "file": "config.py",
                    "line": 42,
                }
            }
        },
    })


class TestParseTrufflehogOutput:
    def test_empty_returns_empty(self):
        assert _parse_trufflehog_output("") == []

    def test_whitespace_returns_empty(self):
        assert _parse_trufflehog_output("  \n\n  ") == []

    def test_invalid_json_skipped(self):
        assert _parse_trufflehog_output("not json\n{broken") == []

    def test_single_finding_parsed(self):
        line = _make_trufflehog_line(detector="AWS", verified=True)
        findings = _parse_trufflehog_output(line)
        assert len(findings) == 1
        assert findings[0]["detector"] == "AWS"

    def test_verified_finding_is_high_severity(self):
        line = _make_trufflehog_line(verified=True)
        findings = _parse_trufflehog_output(line)
        assert findings[0]["verified"] is True
        assert findings[0]["severity"] == "high"

    def test_unverified_finding_is_info_severity(self):
        line = _make_trufflehog_line(verified=False)
        findings = _parse_trufflehog_output(line)
        assert findings[0]["verified"] is False
        assert findings[0]["severity"] == "info"

    def test_secret_is_redacted(self):
        line = _make_trufflehog_line(raw="ABCDEF_very_long_secret_value_XYZ")
        findings = _parse_trufflehog_output(line)
        assert "ABCDEF_very_long_secret_value_XYZ" not in findings[0]["secret_redacted"]
        assert "*" in findings[0]["secret_redacted"]

    def test_camelcase_field_names(self):
        # CamelCase keys (trufflehog v3 output)
        line = json.dumps({
            "DetectorName": "GitHub",
            "Verified": True,
            "Raw": "ghp_" + "x" * 36,
            "SourceMetadata": {"Data": {}},
        })
        findings = _parse_trufflehog_output(line)
        assert findings[0]["detector"] == "GitHub"

    def test_lowercase_field_names(self):
        # Lowercase keys (alternate output format)
        line = json.dumps({
            "detectorName": "Slack",
            "verified": False,
            "raw": "xoxb-slack-token",
            "sourceMetadata": {"data": {}},
        })
        findings = _parse_trufflehog_output(line)
        assert findings[0]["detector"] == "Slack"

    def test_multiple_findings(self):
        lines = "\n".join([_make_trufflehog_line(detector=f"Detector{i}") for i in range(4)])
        findings = _parse_trufflehog_output(lines)
        assert len(findings) == 4

    def test_mixed_valid_and_invalid_lines(self):
        valid_line = _make_trufflehog_line()
        output = f"invalid json\n{valid_line}\n{{broken"
        findings = _parse_trufflehog_output(output)
        assert len(findings) == 1


# ---------------------------------------------------------------------------
# TestRedactSecretGitleaks
# ---------------------------------------------------------------------------


class TestRedactSecretGitleaks:
    def test_short_value_all_stars(self):
        # visible_chars=4, len <= 4*2=8 → all stars
        assert gitleaks_redact("short") == "*****"

    def test_short_boundary_all_stars(self):
        assert gitleaks_redact("a" * 8) == "*" * 8

    def test_long_value_shows_prefix_and_suffix(self):
        result = gitleaks_redact("ABCD_very_secret_value_WXYZ")
        assert result.startswith("ABCD")
        assert result.endswith("WXYZ")

    def test_masked_section_capped_at_16_stars(self):
        very_long = "A" * 4 + "s" * 40 + "B" * 4
        result = gitleaks_redact(very_long)
        star_section = result[4:-4]
        assert len(star_section) <= 16


# ---------------------------------------------------------------------------
# TestParseGitleaksOutput
# ---------------------------------------------------------------------------


def _make_gitleaks_item(
    rule_id: str = "aws-access-token",
    secret: str = "AKIAIOSFODNN7EXAMPLE",
    file_path: str = "config.py",
) -> dict:
    return {
        "RuleID": rule_id,
        "Description": "AWS Access Token",
        "File": file_path,
        "StartLine": 10,
        "Commit": "abc123def456",
        "Author": "dev@example.com",
        "Date": "2024-01-01",
        "Match": f"key={secret}",
        "Secret": secret,
    }


class TestParseGitleaksOutput:
    def test_empty_returns_empty(self):
        assert _parse_gitleaks_output("", "json") == []

    def test_whitespace_returns_empty(self):
        assert _parse_gitleaks_output("   ", "json") == []

    def test_invalid_json_returns_empty(self):
        assert _parse_gitleaks_output("not json", "json") == []

    def test_non_list_json_returns_empty(self):
        assert _parse_gitleaks_output('{"key": "value"}', "json") == []

    def test_valid_finding_parsed(self):
        item = _make_gitleaks_item()
        findings = _parse_gitleaks_output(json.dumps([item]), "json")
        assert len(findings) == 1
        assert findings[0]["rule"] == "aws-access-token"

    def test_secret_is_redacted(self):
        item = _make_gitleaks_item(secret="AKIAIOSFODNN7EXAMPLE_LONG")
        findings = _parse_gitleaks_output(json.dumps([item]), "json")
        assert "AKIAIOSFODNN7EXAMPLE_LONG" not in findings[0]["secret_redacted"]

    def test_severity_always_high(self):
        item = _make_gitleaks_item()
        findings = _parse_gitleaks_output(json.dumps([item]), "json")
        assert findings[0]["severity"] == "high"

    def test_multiple_findings(self):
        items = [_make_gitleaks_item(rule_id=f"rule-{i}") for i in range(3)]
        findings = _parse_gitleaks_output(json.dumps(items), "json")
        assert len(findings) == 3

    def test_lowercase_field_names(self):
        # Alternate lowercase field format
        item = {
            "ruleID": "github-pat",
            "description": "GitHub PAT",
            "file": "app.py",
            "startLine": 5,
            "commit": "deadbeef",
            "secret": "ghp_xxxxxx",
        }
        findings = _parse_gitleaks_output(json.dumps([item]), "json")
        assert len(findings) == 1
        assert findings[0]["rule"] == "github-pat"

    def test_non_dict_items_skipped(self):
        # Array with mix of dict and non-dict items
        output = json.dumps([_make_gitleaks_item(), "invalid", 42])
        findings = _parse_gitleaks_output(output, "json")
        assert len(findings) == 1


# ---------------------------------------------------------------------------
# TestValidScanTypes
# ---------------------------------------------------------------------------


class TestValidScanTypes:
    def test_gitleaks_has_detect(self):
        assert "detect" in GITLEAKS_SCAN_TYPES

    def test_gitleaks_has_dir(self):
        assert "dir" in GITLEAKS_SCAN_TYPES

    def test_trufflehog_has_git(self):
        assert "git" in TRUFFLEHOG_SCAN_TYPES

    def test_trufflehog_has_filesystem(self):
        assert "filesystem" in TRUFFLEHOG_SCAN_TYPES

    def test_gitleaks_report_formats(self):
        assert "json" in _VALID_REPORT_FORMATS
        assert "csv" in _VALID_REPORT_FORMATS
