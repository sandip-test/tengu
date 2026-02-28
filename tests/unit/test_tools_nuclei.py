"""Unit tests for Nuclei output parser."""

from __future__ import annotations

import json

from tengu.tools.web.nuclei import _parse_nuclei_output

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_nuclei_line(
    template_id: str = "cve-2021-44228",
    name: str = "Log4Shell",
    severity: str = "critical",
    matched_at: str = "https://app.com/",
    cve_ids: list | None = None,
    cvss_score: float | None = 9.0,
    tags: list | None = None,
) -> str:
    return json.dumps({
        "template-id": template_id,
        "info": {
            "name": name,
            "severity": severity,
            "description": "Remote code execution via Log4j",
            "classification": {
                "cve-id": cve_ids or ["CVE-2021-44228"],
                "cwe-id": ["CWE-502"],
                "cvss-score": cvss_score,
            },
            "tags": tags or ["cve", "rce", "log4j"],
            "reference": ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
        },
        "matched-at": matched_at,
        "type": "http",
        "extracted-results": [],
        "curl-command": "",
        "timestamp": "2024-01-01T00:00:00Z",
    })


# ---------------------------------------------------------------------------
# TestParseNucleiOutput
# ---------------------------------------------------------------------------


class TestParseNucleiOutput:
    def test_empty_string_returns_empty(self):
        assert _parse_nuclei_output("") == []

    def test_whitespace_only_returns_empty(self):
        assert _parse_nuclei_output("   \n  ") == []

    def test_single_valid_line(self):
        line = _make_nuclei_line()
        findings = _parse_nuclei_output(line)
        assert len(findings) == 1

    def test_template_id_extracted(self):
        line = _make_nuclei_line(template_id="sqli-error-based")
        findings = _parse_nuclei_output(line)
        assert findings[0]["template_id"] == "sqli-error-based"

    def test_template_name_extracted(self):
        line = _make_nuclei_line(name="XSS Reflected")
        findings = _parse_nuclei_output(line)
        assert findings[0]["template_name"] == "XSS Reflected"

    def test_severity_extracted(self):
        line = _make_nuclei_line(severity="high")
        findings = _parse_nuclei_output(line)
        assert findings[0]["severity"] == "high"

    def test_matched_url_extracted(self):
        line = _make_nuclei_line(matched_at="https://target.com/path")
        findings = _parse_nuclei_output(line)
        assert findings[0]["matched_url"] == "https://target.com/path"

    def test_cve_ids_extracted(self):
        line = _make_nuclei_line(cve_ids=["CVE-2021-44228", "CVE-2022-0001"])
        findings = _parse_nuclei_output(line)
        assert "CVE-2021-44228" in findings[0]["cve_ids"]

    def test_cvss_score_extracted(self):
        line = _make_nuclei_line(cvss_score=9.8)
        findings = _parse_nuclei_output(line)
        assert findings[0]["cvss_score"] == 9.8

    def test_tags_extracted(self):
        line = _make_nuclei_line(tags=["sqli", "owasp"])
        findings = _parse_nuclei_output(line)
        assert "sqli" in findings[0]["tags"]

    def test_invalid_json_line_skipped(self):
        lines = "not json\n" + _make_nuclei_line() + "\n{broken"
        findings = _parse_nuclei_output(lines)
        assert len(findings) == 1

    def test_multiple_findings(self):
        lines = "\n".join([
            _make_nuclei_line(template_id=f"tmpl-{i}") for i in range(5)
        ])
        findings = _parse_nuclei_output(lines)
        assert len(findings) == 5

    def test_missing_info_block_defaults(self):
        minimal = json.dumps({"template-id": "minimal", "matched-at": "https://x.com"})
        findings = _parse_nuclei_output(minimal)
        assert len(findings) == 1
        assert findings[0]["severity"] == "unknown"

    def test_timestamp_extracted(self):
        line = _make_nuclei_line()
        findings = _parse_nuclei_output(line)
        assert findings[0]["timestamp"] == "2024-01-01T00:00:00Z"
