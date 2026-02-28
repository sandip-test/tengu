"""Unit tests for FFUF output parser."""

from __future__ import annotations

import json

from tengu.tools.web.ffuf import _parse_ffuf_output

# ---------------------------------------------------------------------------
# TestParseFfufOutput
# ---------------------------------------------------------------------------


def _make_ffuf_output(results: list[dict] | None = None) -> str:
    return json.dumps({
        "commandline": "ffuf -u https://example.com/FUZZ -w wordlist.txt",
        "time": "2024-01-01T00:00:00Z",
        "results": results or [],
    })


def _make_result_entry(
    url: str = "https://example.com/admin",
    status: int = 200,
    length: int = 1024,
    words: int = 50,
    lines: int = 30,
    redirect: str = "",
    fuzz_word: str = "admin",
) -> dict:
    return {
        "url": url,
        "status": status,
        "length": length,
        "words": words,
        "lines": lines,
        "redirectlocation": redirect,
        "input": {"FUZZ": fuzz_word},
    }


class TestParseFfufOutput:
    def test_empty_string_returns_empty(self):
        assert _parse_ffuf_output("") == []

    def test_invalid_json_returns_empty(self):
        assert _parse_ffuf_output("not json {{{") == []

    def test_valid_single_result(self):
        entry = _make_result_entry(url="https://example.com/admin", status=200)
        output = _make_ffuf_output([entry])
        results = _parse_ffuf_output(output)
        assert len(results) == 1
        assert results[0]["url"] == "https://example.com/admin"
        assert results[0]["status"] == 200

    def test_length_extracted(self):
        entry = _make_result_entry(length=2048)
        output = _make_ffuf_output([entry])
        results = _parse_ffuf_output(output)
        assert results[0]["length"] == 2048

    def test_redirect_location_extracted(self):
        entry = _make_result_entry(redirect="https://example.com/admin/")
        output = _make_ffuf_output([entry])
        results = _parse_ffuf_output(output)
        assert results[0]["redirect_location"] == "https://example.com/admin/"

    def test_fuzz_word_extracted(self):
        entry = _make_result_entry(fuzz_word="robots.txt")
        output = _make_ffuf_output([entry])
        results = _parse_ffuf_output(output)
        assert results[0]["input"] == "robots.txt"

    def test_multiple_results(self):
        entries = [
            _make_result_entry(url=f"https://example.com/path{i}") for i in range(5)
        ]
        output = _make_ffuf_output(entries)
        results = _parse_ffuf_output(output)
        assert len(results) == 5

    def test_empty_results_list(self):
        output = _make_ffuf_output([])
        results = _parse_ffuf_output(output)
        assert results == []

    def test_words_and_lines_extracted(self):
        entry = _make_result_entry(words=100, lines=50)
        output = _make_ffuf_output([entry])
        results = _parse_ffuf_output(output)
        assert results[0]["words"] == 100
        assert results[0]["lines"] == 50
