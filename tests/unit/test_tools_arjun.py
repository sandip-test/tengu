"""Unit tests for Arjun parameter discovery parser."""

from __future__ import annotations

import json

from tengu.tools.api.arjun import _VALID_METHODS, _parse_arjun_output

# ---------------------------------------------------------------------------
# TestValidMethods
# ---------------------------------------------------------------------------


class TestValidMethods:
    def test_get_present(self):
        assert "GET" in _VALID_METHODS

    def test_post_present(self):
        assert "POST" in _VALID_METHODS

    def test_json_present(self):
        assert "JSON" in _VALID_METHODS

    def test_all_uppercase(self):
        for method in _VALID_METHODS:
            assert method == method.upper()


# ---------------------------------------------------------------------------
# TestParseArjunOutput
# ---------------------------------------------------------------------------


class TestParseArjunOutput:
    def test_empty_returns_empty(self):
        assert _parse_arjun_output("") == []

    def test_whitespace_returns_empty(self):
        assert _parse_arjun_output("   ") == []

    def test_arjun_key_format(self):
        data = {"arjun": ["id", "username", "page"]}
        result = _parse_arjun_output(json.dumps(data))
        assert "id" in result
        assert "username" in result
        assert "page" in result

    def test_nested_params_format(self):
        data = {"https://example.com": {"params": ["token", "csrf"]}}
        result = _parse_arjun_output(json.dumps(data))
        assert "token" in result
        assert "csrf" in result

    def test_list_format(self):
        data = ["q", "search", "page"]
        result = _parse_arjun_output(json.dumps(data))
        assert "q" in result
        assert "search" in result

    def test_deduplication_preserving_order(self):
        data = {"arjun": ["id", "id", "name", "id"]}
        result = _parse_arjun_output(json.dumps(data))
        assert result.count("id") == 1

    def test_invalid_json_fallback(self):
        # Fallback: line-by-line regex search
        text = '  "token": "abc123",\n  "page": 1,'
        result = _parse_arjun_output(text)
        assert "token" in result
        assert "page" in result

    def test_fallback_skips_arjun_url_method_keys(self):
        text = '  "arjun": "v2",\n  "url": "...",\n  "method": "GET",\n  "debug": true'
        result = _parse_arjun_output(text)
        # arjun/url/method should be excluded by the fallback filter
        assert "arjun" not in result
        assert "url" not in result
        assert "method" not in result
        assert "debug" in result

    def test_nested_dict_in_value(self):
        data = {"mysite": {"parameters": ["search", "filter"]}}
        result = _parse_arjun_output(json.dumps(data))
        assert "search" in result
        assert "filter" in result
