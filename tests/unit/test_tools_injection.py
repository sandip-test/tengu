"""Unit tests for injection tool parsers: sqlmap."""

from __future__ import annotations

from tengu.tools.injection.sqlmap import _parse_sqlmap_output

# ---------------------------------------------------------------------------
# TestParseSqlmapOutput
# ---------------------------------------------------------------------------


class TestParseSqlmapOutput:
    def test_empty_output_returns_defaults(self):
        result = _parse_sqlmap_output("")
        assert result["vulnerable_params"] == []
        assert result["dbms"] is None
        assert result["injection_types"] == []

    def test_vulnerable_param_detected(self):
        output = "parameter 'id' is vulnerable. Do you want to keep testing the others?"
        result = _parse_sqlmap_output(output)
        assert "id" in result["vulnerable_params"]

    def test_multiple_params_detected(self):
        output = (
            "parameter 'id' is vulnerable.\n"
            "parameter 'username' is vulnerable.\n"
        )
        result = _parse_sqlmap_output(output)
        assert "id" in result["vulnerable_params"]
        assert "username" in result["vulnerable_params"]
        assert len(result["vulnerable_params"]) == 2

    def test_duplicate_params_not_repeated(self):
        output = (
            "parameter 'id' is vulnerable.\n"
            "parameter 'id' is vulnerable.\n"
        )
        result = _parse_sqlmap_output(output)
        assert result["vulnerable_params"].count("id") == 1

    def test_dbms_detected(self):
        output = "back-end DBMS: MySQL >= 5.0.12"
        result = _parse_sqlmap_output(output)
        assert result["dbms"] == "MySQL >= 5.0.12"

    def test_injection_type_detected(self):
        output = "Type: boolean-based blind"
        result = _parse_sqlmap_output(output)
        assert "boolean-based blind" in result["injection_types"]

    def test_multiple_injection_types(self):
        output = "Type: boolean-based blind\nType: time-based blind"
        result = _parse_sqlmap_output(output)
        assert len(result["injection_types"]) == 2

    def test_duplicate_injection_types_not_repeated(self):
        output = "Type: error-based\nType: error-based"
        result = _parse_sqlmap_output(output)
        assert result["injection_types"].count("error-based") == 1

    def test_case_insensitive_matching(self):
        output = "PARAMETER 'id' IS VULNERABLE"
        result = _parse_sqlmap_output(output)
        assert "id" in result["vulnerable_params"]

    def test_no_match_lines_ignored(self):
        output = "testing connection to the target URL\nsome random output\ngot a 301 redirect"
        result = _parse_sqlmap_output(output)
        assert result["vulnerable_params"] == []
        assert result["dbms"] is None
