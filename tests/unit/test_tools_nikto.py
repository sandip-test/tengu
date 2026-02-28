"""Unit tests for Nikto web scanner output parser."""

from __future__ import annotations

import json

from tengu.tools.web.nikto import _parse_nikto_output

# ---------------------------------------------------------------------------
# TestParseNiktoOutput
# ---------------------------------------------------------------------------


def _make_nikto_json(vulnerabilities: list | None = None) -> str:
    return json.dumps({"vulnerabilities": vulnerabilities or []})


def _make_vuln(
    vuln_id: str = "700001",
    osvdb: str = "OSVDB-0",
    method: str = "GET",
    url: str = "/test",
    msg: str = "Server leaks information",
) -> dict:
    return {
        "id": vuln_id,
        "OSVDB": osvdb,
        "method": method,
        "url": url,
        "msg": msg,
        "references": {"url": []},
    }


class TestParseNiktoOutput:
    def test_empty_string_returns_empty(self):
        assert _parse_nikto_output("") == []

    def test_single_json_vulnerability(self):
        output = _make_nikto_json([_make_vuln()])
        result = _parse_nikto_output(output)
        assert len(result) == 1
        assert result[0]["id"] == "700001"

    def test_message_extracted(self):
        output = _make_nikto_json([_make_vuln(msg="Apache version disclosure")])
        result = _parse_nikto_output(output)
        assert result[0]["message"] == "Apache version disclosure"

    def test_url_extracted(self):
        output = _make_nikto_json([_make_vuln(url="/admin/config.php")])
        result = _parse_nikto_output(output)
        assert result[0]["url"] == "/admin/config.php"

    def test_method_extracted(self):
        output = _make_nikto_json([_make_vuln(method="POST")])
        result = _parse_nikto_output(output)
        assert result[0]["method"] == "POST"

    def test_osvdb_extracted(self):
        output = _make_nikto_json([_make_vuln(osvdb="OSVDB-3268")])
        result = _parse_nikto_output(output)
        assert result[0]["osvdb"] == "OSVDB-3268"

    def test_multiple_vulnerabilities(self):
        vulns = [_make_vuln(vuln_id=str(i)) for i in range(5)]
        output = _make_nikto_json(vulns)
        result = _parse_nikto_output(output)
        assert len(result) == 5

    def test_empty_vulnerabilities_list(self):
        output = _make_nikto_json([])
        assert _parse_nikto_output(output) == []

    def test_text_fallback_plus_prefix(self):
        text = "+ Apache/2.4.49 appears to be outdated\n+ Allowed HTTP Methods: GET, POST"
        result = _parse_nikto_output(text)
        assert len(result) == 2
        assert "Apache" in result[0]["message"]

    def test_text_fallback_skips_non_plus_lines(self):
        text = "- Nikto v2.1.6\n+ Server: Apache/2.4.49\n[INFO] scan complete"
        result = _parse_nikto_output(text)
        # Only lines starting with "+ " are captured
        assert len(result) == 1
        assert "Apache" in result[0]["message"]

    def test_invalid_json_uses_text_fallback(self):
        text = "not json\n+ XSS vulnerability found"
        result = _parse_nikto_output(text)
        assert len(result) == 1

    def test_text_fallback_message_strips_prefix(self):
        text = "+ Outdated jQuery detected"
        result = _parse_nikto_output(text)
        assert result[0]["message"] == "Outdated jQuery detected"
