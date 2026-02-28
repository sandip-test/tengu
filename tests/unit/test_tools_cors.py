"""Unit tests for CORS severity helper and test origins config."""

from __future__ import annotations

from tengu.tools.web.cors import _TEST_ORIGINS, _assess_severity

# ---------------------------------------------------------------------------
# TestAssessSeverity
# ---------------------------------------------------------------------------


class TestAssessSeverity:
    def test_no_issues_returns_none(self):
        assert _assess_severity([], False) == "none"

    def test_issues_without_credentials_is_high(self):
        assert _assess_severity(["Origin reflected"], False) == "high"

    def test_issues_with_credentials_is_critical(self):
        assert _assess_severity(["Origin reflected"], True) == "critical"

    def test_credentials_without_issues_is_none(self):
        # No issues → "none" even if credentials=True (unreachable in practice,
        # but tests the function branch)
        assert _assess_severity([], True) == "none"


# ---------------------------------------------------------------------------
# TestTestOriginsConfig
# ---------------------------------------------------------------------------


class TestTestOriginsConfig:
    def test_evil_com_present(self):
        assert "https://evil.com" in _TEST_ORIGINS

    def test_null_origin_present(self):
        assert "null" in _TEST_ORIGINS

    def test_at_least_three_test_origins(self):
        assert len(_TEST_ORIGINS) >= 3

    def test_all_entries_are_strings(self):
        for origin in _TEST_ORIGINS:
            assert isinstance(origin, str)
            assert origin
