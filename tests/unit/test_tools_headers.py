"""Unit tests for HTTP security headers analysis helpers."""

from __future__ import annotations

from tengu.tools.web.headers import (
    _INFORMATION_DISCLOSURE_HEADERS,
    _SECURITY_HEADERS,
    _score_to_grade,
)

# ---------------------------------------------------------------------------
# TestScoreToGrade
# ---------------------------------------------------------------------------


class TestScoreToGrade:
    def test_90_or_above_is_a_plus(self):
        assert _score_to_grade(90) == "A+"
        assert _score_to_grade(100) == "A+"

    def test_80_to_89_is_a(self):
        assert _score_to_grade(80) == "A"
        assert _score_to_grade(89) == "A"

    def test_70_to_79_is_b(self):
        assert _score_to_grade(70) == "B"
        assert _score_to_grade(79) == "B"

    def test_60_to_69_is_c(self):
        assert _score_to_grade(60) == "C"
        assert _score_to_grade(69) == "C"

    def test_50_to_59_is_d(self):
        assert _score_to_grade(50) == "D"
        assert _score_to_grade(59) == "D"

    def test_below_50_is_f(self):
        assert _score_to_grade(49) == "F"
        assert _score_to_grade(0) == "F"


# ---------------------------------------------------------------------------
# TestSecurityHeadersConfig
# ---------------------------------------------------------------------------


class TestSecurityHeadersConfig:
    def test_at_least_eight_headers_defined(self):
        assert len(_SECURITY_HEADERS) >= 8

    def test_each_header_has_name(self):
        for hdr in _SECURITY_HEADERS:
            assert "name" in hdr
            assert isinstance(hdr["name"], str)
            assert hdr["name"]

    def test_each_header_has_required_flag(self):
        for hdr in _SECURITY_HEADERS:
            assert "required" in hdr
            assert isinstance(hdr["required"], bool)

    def test_each_header_has_recommendation(self):
        for hdr in _SECURITY_HEADERS:
            assert "recommendation" in hdr
            assert hdr["recommendation"]

    def test_hsts_is_required(self):
        hsts = next((h for h in _SECURITY_HEADERS if h["name"] == "Strict-Transport-Security"), None)
        assert hsts is not None
        assert hsts["required"] is True

    def test_csp_is_required(self):
        csp = next((h for h in _SECURITY_HEADERS if h["name"] == "Content-Security-Policy"), None)
        assert csp is not None
        assert csp["required"] is True

    def test_required_headers_count(self):
        required = [h for h in _SECURITY_HEADERS if h["required"]]
        # There should be at least 6 required headers
        assert len(required) >= 6


# ---------------------------------------------------------------------------
# TestInformationDisclosureHeaders
# ---------------------------------------------------------------------------


class TestInformationDisclosureHeaders:
    def test_server_header_in_list(self):
        assert "Server" in _INFORMATION_DISCLOSURE_HEADERS

    def test_x_powered_by_in_list(self):
        assert "X-Powered-By" in _INFORMATION_DISCLOSURE_HEADERS

    def test_at_least_four_entries(self):
        assert len(_INFORMATION_DISCLOSURE_HEADERS) >= 4

    def test_all_entries_are_strings(self):
        for header in _INFORMATION_DISCLOSURE_HEADERS:
            assert isinstance(header, str)
            assert header
