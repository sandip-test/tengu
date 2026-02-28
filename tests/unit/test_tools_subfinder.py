"""Unit tests for subfinder output parser."""

from __future__ import annotations

import json

from tengu.tools.recon.subfinder import _parse_subfinder_output

# ---------------------------------------------------------------------------
# TestParseSubfinderOutput
# ---------------------------------------------------------------------------


class TestParseSubfinderOutput:
    def test_empty_string_returns_empty(self):
        assert _parse_subfinder_output("") == []

    def test_whitespace_returns_empty(self):
        assert _parse_subfinder_output("   \n\n  ") == []

    def test_plain_text_subdomain(self):
        result = _parse_subfinder_output("api.example.com\nwww.example.com")
        assert "api.example.com" in result
        assert "www.example.com" in result

    def test_json_format_extracts_host(self):
        line = json.dumps({"host": "mail.example.com", "source": "crtsh"})
        result = _parse_subfinder_output(line)
        assert "mail.example.com" in result

    def test_comment_lines_skipped(self):
        result = _parse_subfinder_output("# comment\napi.example.com")
        assert "api.example.com" in result
        assert "# comment" not in result

    def test_duplicates_deduplicated(self):
        result = _parse_subfinder_output("api.example.com\napi.example.com\napi.example.com")
        assert result.count("api.example.com") == 1

    def test_output_is_sorted(self):
        raw = "z.example.com\na.example.com\nm.example.com"
        result = _parse_subfinder_output(raw)
        assert result == sorted(result)

    def test_plain_hostname_without_dot_skipped(self):
        result = _parse_subfinder_output("localhostname")
        assert "localhostname" not in result

    def test_mixed_json_and_plain(self):
        json_line = json.dumps({"host": "api.example.com"})
        raw = f"{json_line}\nwww.example.com"
        result = _parse_subfinder_output(raw)
        assert "api.example.com" in result
        assert "www.example.com" in result

    def test_json_without_host_key_falls_back_to_plain_if_dot(self):
        # JSON line without "host" key shouldn't add anything
        line = json.dumps({"source": "crtsh", "other": "data"})
        result = _parse_subfinder_output(line)
        # The line is parsed as JSON with empty host → skipped
        assert result == []
