"""Unit tests for Trivy container scanner helpers."""

from __future__ import annotations

import json

import pytest

from tengu.exceptions import InvalidInputError
from tengu.tools.container.trivy import (
    _VALID_SCAN_TYPES,
    _VALID_SEVERITIES,
    _parse_trivy_output,
    _sanitize_docker_image,
)

# ---------------------------------------------------------------------------
# TestSanitizeDockerImage
# ---------------------------------------------------------------------------


class TestSanitizeDockerImage:
    def test_valid_image_name(self):
        assert _sanitize_docker_image("nginx:latest") == "nginx:latest"

    def test_image_with_registry(self):
        assert _sanitize_docker_image("registry.example.com/myapp:1.0") == "registry.example.com/myapp:1.0"

    def test_image_with_digest(self):
        sha = "sha256:" + "a" * 64
        result = _sanitize_docker_image(f"nginx@{sha}")
        assert "nginx" in result

    def test_empty_raises(self):
        with pytest.raises(InvalidInputError):
            _sanitize_docker_image("")

    def test_spaces_raise(self):
        with pytest.raises(InvalidInputError):
            _sanitize_docker_image("nginx latest")

    def test_semicolon_raises(self):
        with pytest.raises(InvalidInputError):
            _sanitize_docker_image("nginx;rm -rf /")

    def test_strips_whitespace(self):
        result = _sanitize_docker_image("  nginx:latest  ")
        assert result == "nginx:latest"


# ---------------------------------------------------------------------------
# TestValidScanTypes
# ---------------------------------------------------------------------------


class TestValidScanTypes:
    def test_image_present(self):
        assert "image" in _VALID_SCAN_TYPES

    def test_fs_present(self):
        assert "fs" in _VALID_SCAN_TYPES

    def test_repo_present(self):
        assert "repo" in _VALID_SCAN_TYPES

    def test_all_entries_are_strings(self):
        for scan_type in _VALID_SCAN_TYPES:
            assert isinstance(scan_type, str)


# ---------------------------------------------------------------------------
# TestValidSeverities
# ---------------------------------------------------------------------------


class TestValidSeverities:
    def test_critical_present(self):
        assert "CRITICAL" in _VALID_SEVERITIES

    def test_high_present(self):
        assert "HIGH" in _VALID_SEVERITIES

    def test_all_uppercase(self):
        for sev in _VALID_SEVERITIES:
            assert sev == sev.upper()


# ---------------------------------------------------------------------------
# TestParseTrivyOutput
# ---------------------------------------------------------------------------


def _make_trivy_output(results: list | None = None) -> str:
    return json.dumps({
        "SchemaVersion": 2,
        "Results": results or [],
    })


def _make_vuln(
    vuln_id: str = "CVE-2023-0001",
    pkg: str = "libssl",
    installed: str = "1.1.1",
    fixed: str = "1.1.2",
    severity: str = "HIGH",
    cvss: float | None = 7.5,
) -> dict:
    vuln: dict = {
        "VulnerabilityID": vuln_id,
        "PkgName": pkg,
        "InstalledVersion": installed,
        "FixedVersion": fixed,
        "Severity": severity,
        "Description": "Test vulnerability description",
    }
    if cvss is not None:
        vuln["CVSS"] = {"nvd": {"V3Score": cvss}}
    return vuln


def _make_result_entry(
    target: str = "nginx:latest (debian 11.6)",
    vuln_class: str = "os-pkgs",
    vulns: list | None = None,
) -> dict:
    return {
        "Target": target,
        "Class": vuln_class,
        "Type": "debian",
        "Vulnerabilities": vulns or [],
    }


class TestParseTrivyOutput:
    def test_empty_string_returns_defaults(self):
        result = _parse_trivy_output("")
        assert result["total"] == 0
        assert result["results"] == []

    def test_invalid_json_returns_defaults(self):
        result = _parse_trivy_output("not json {{{")
        assert result["total"] == 0

    def test_single_vulnerability(self):
        vuln = _make_vuln()
        entry = _make_result_entry(vulns=[vuln])
        output = _make_trivy_output([entry])
        result = _parse_trivy_output(output)
        assert result["total"] == 1
        assert result["severity_counts"]["HIGH"] == 1

    def test_critical_vulnerability_counted(self):
        vuln = _make_vuln(severity="CRITICAL", cvss=9.8)
        entry = _make_result_entry(vulns=[vuln])
        output = _make_trivy_output([entry])
        result = _parse_trivy_output(output)
        assert result["severity_counts"]["CRITICAL"] == 1

    def test_multiple_vulns_total(self):
        vulns = [_make_vuln(vuln_id=f"CVE-{i}") for i in range(5)]
        entry = _make_result_entry(vulns=vulns)
        output = _make_trivy_output([entry])
        result = _parse_trivy_output(output)
        assert result["total"] == 5

    def test_cvss_score_extracted(self):
        vuln = _make_vuln(cvss=8.1)
        entry = _make_result_entry(vulns=[vuln])
        output = _make_trivy_output([entry])
        result = _parse_trivy_output(output)
        assert result["top_vulns"][0]["cvss_score"] == 8.1

    def test_top_vulns_sorted_by_severity(self):
        low_vuln = _make_vuln(severity="LOW", cvss=2.0)
        critical_vuln = _make_vuln(vuln_id="CVE-CRITICAL", severity="CRITICAL", cvss=9.8)
        entry = _make_result_entry(vulns=[low_vuln, critical_vuln])
        output = _make_trivy_output([entry])
        result = _parse_trivy_output(output)
        # CRITICAL should come first
        assert result["top_vulns"][0]["severity"] == "CRITICAL"

    def test_top_vulns_capped_at_20(self):
        vulns = [_make_vuln(vuln_id=f"CVE-{i}") for i in range(30)]
        entry = _make_result_entry(vulns=vulns)
        output = _make_trivy_output([entry])
        result = _parse_trivy_output(output)
        assert len(result["top_vulns"]) <= 20

    def test_empty_results_array(self):
        output = _make_trivy_output([])
        result = _parse_trivy_output(output)
        assert result["total"] == 0

    def test_unknown_severity_mapped_to_unknown(self):
        vuln = _make_vuln(severity="MADEUP", cvss=None)
        entry = _make_result_entry(vulns=[vuln])
        output = _make_trivy_output([entry])
        result = _parse_trivy_output(output)
        assert result["severity_counts"]["UNKNOWN"] >= 1
