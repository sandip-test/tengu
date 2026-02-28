"""Unit tests for XSS scanner (dalfox) output parser."""

from __future__ import annotations

import json

from tengu.tools.injection.xss import _parse_dalfox_output

# ---------------------------------------------------------------------------
# TestParseDalfoxOutput
# ---------------------------------------------------------------------------


def _make_dalfox_finding(
    finding_type: str = "Reflected",
    param: str = "q",
    payload: str = "<script>alert(1)</script>",
    evidence: str = "Response contains payload",
    poc: str = "https://example.com/search?q=<script>alert(1)</script>",
) -> dict:
    return {
        "type": finding_type,
        "param": param,
        "payload": payload,
        "evidence": evidence,
        "poc": poc,
    }


class TestParseDalfoxOutput:
    def test_empty_string_returns_empty(self):
        assert _parse_dalfox_output("") == []

    def test_single_json_list_finding(self):
        findings_data = [_make_dalfox_finding()]
        result = _parse_dalfox_output(json.dumps(findings_data))
        assert len(result) == 1
        assert result[0]["type"] == "Reflected"
        assert result[0]["parameter"] == "q"

    def test_payload_extracted(self):
        findings_data = [_make_dalfox_finding(payload="<img src=x onerror=alert(1)>")]
        result = _parse_dalfox_output(json.dumps(findings_data))
        assert "<img" in result[0]["payload"]

    def test_poc_extracted(self):
        poc = "https://example.com/?xss=1"
        findings_data = [_make_dalfox_finding(poc=poc)]
        result = _parse_dalfox_output(json.dumps(findings_data))
        assert result[0]["poc"] == poc

    def test_multiple_findings(self):
        findings_data = [_make_dalfox_finding(param=f"param{i}") for i in range(4)]
        result = _parse_dalfox_output(json.dumps(findings_data))
        assert len(result) == 4

    def test_dict_json_wrapped_as_finding(self):
        data = {"type": "DOM", "param": "search", "payload": "xss", "evidence": "", "poc": ""}
        result = _parse_dalfox_output(json.dumps(data))
        assert len(result) == 1
        assert result[0]["type"] == "DOM"

    def test_invalid_json_fallback_v_marker(self):
        text = "[V] XSS detected in param 'q' with payload <script>alert(1)</script>"
        result = _parse_dalfox_output(text)
        assert len(result) == 1
        assert result[0]["type"] == "xss"
        assert "[V]" in result[0]["message"]

    def test_invalid_json_fallback_poc_marker(self):
        text = "POC: https://evil.com/?xss=<script>alert(1)</script>"
        result = _parse_dalfox_output(text)
        assert len(result) == 1

    def test_non_matching_lines_ignored_in_fallback(self):
        text = "Running scan...\n[INFO] testing parameter q\nScan complete."
        result = _parse_dalfox_output(text)
        assert result == []

    def test_empty_json_list_returns_empty(self):
        assert _parse_dalfox_output("[]") == []
