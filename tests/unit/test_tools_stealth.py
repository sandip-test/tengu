"""Unit tests for stealth tool constants."""

from __future__ import annotations

from tengu.tools.stealth.proxy_check import _ALLOWED_SCHEMES

# ---------------------------------------------------------------------------
# TestAllowedSchemes
# ---------------------------------------------------------------------------


class TestAllowedSchemes:
    def test_socks5_present(self):
        assert "socks5://" in _ALLOWED_SCHEMES

    def test_socks4_present(self):
        assert "socks4://" in _ALLOWED_SCHEMES

    def test_http_present(self):
        assert "http://" in _ALLOWED_SCHEMES

    def test_https_present(self):
        assert "https://" in _ALLOWED_SCHEMES

    def test_is_tuple_or_list(self):
        assert isinstance(_ALLOWED_SCHEMES, (tuple, list, frozenset, set))

    def test_at_least_four_schemes(self):
        assert len(_ALLOWED_SCHEMES) >= 4

    def test_all_end_with_double_slash(self):
        for scheme in _ALLOWED_SCHEMES:
            assert scheme.endswith("://"), f"{scheme!r} does not end with ://"

    def test_invalid_scheme_not_present(self):
        assert "ftp://" not in _ALLOWED_SCHEMES
