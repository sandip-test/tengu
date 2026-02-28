"""Unit tests for report generation pure helpers."""

from __future__ import annotations

from tengu.tools.reporting.generate import (
    _SEVERITY_WEIGHTS,
    _build_risk_matrix,
    _score_to_rating,
)
from tengu.types import Finding

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


_FINDING_COUNTER = 0


def _make_finding(severity: str = "high", title: str = "Test Finding") -> Finding:
    global _FINDING_COUNTER
    _FINDING_COUNTER += 1
    return Finding(
        id=f"TENGU-2026-{_FINDING_COUNTER:03d}",
        title=title,
        severity=severity,
        description="Test description",
        affected_asset="https://example.com",
        tool="nmap",
    )


# ---------------------------------------------------------------------------
# TestScoreToRating
# ---------------------------------------------------------------------------


class TestScoreToRating:
    def test_zero_is_informational(self):
        assert _score_to_rating(0.0) == "INFORMATIONAL"

    def test_one_is_low(self):
        assert _score_to_rating(1.0) == "LOW"

    def test_four_is_medium(self):
        assert _score_to_rating(4.0) == "MEDIUM"

    def test_seven_is_high(self):
        assert _score_to_rating(7.0) == "HIGH"

    def test_nine_is_critical(self):
        assert _score_to_rating(9.0) == "CRITICAL"

    def test_ten_is_critical(self):
        assert _score_to_rating(10.0) == "CRITICAL"


# ---------------------------------------------------------------------------
# TestBuildRiskMatrix
# ---------------------------------------------------------------------------


class TestBuildRiskMatrix:
    def test_empty_findings(self):
        matrix = _build_risk_matrix([])
        assert matrix.critical_count == 0
        assert matrix.high_count == 0
        assert matrix.total == 0
        assert matrix.risk_score == 0.0

    def test_counts_by_severity(self):
        findings = [
            _make_finding("critical"),
            _make_finding("critical"),
            _make_finding("high"),
            _make_finding("medium"),
            _make_finding("low"),
            _make_finding("info"),
        ]
        matrix = _build_risk_matrix(findings)
        assert matrix.critical_count == 2
        assert matrix.high_count == 1
        assert matrix.medium_count == 1
        assert matrix.low_count == 1
        assert matrix.info_count == 1
        assert matrix.total == 6

    def test_risk_score_positive_with_findings(self):
        findings = [_make_finding("critical")]
        matrix = _build_risk_matrix(findings)
        assert matrix.risk_score > 0

    def test_critical_gives_higher_score_than_info(self):
        critical_matrix = _build_risk_matrix([_make_finding("critical")])
        info_matrix = _build_risk_matrix([_make_finding("info")])
        assert critical_matrix.risk_score > info_matrix.risk_score

    def test_score_capped_at_ten(self):
        findings = [_make_finding("critical") for _ in range(20)]
        matrix = _build_risk_matrix(findings)
        assert matrix.risk_score <= 10.0

    def test_total_matches_finding_count(self):
        findings = [_make_finding() for _ in range(7)]
        matrix = _build_risk_matrix(findings)
        assert matrix.total == 7


# ---------------------------------------------------------------------------
# TestSeverityWeights
# ---------------------------------------------------------------------------


class TestSeverityWeights:
    def test_critical_highest_weight(self):
        assert _SEVERITY_WEIGHTS["critical"] > _SEVERITY_WEIGHTS["high"]

    def test_info_lowest_weight(self):
        assert _SEVERITY_WEIGHTS["info"] < _SEVERITY_WEIGHTS["low"]

    def test_all_severities_present(self):
        for sev in ("critical", "high", "medium", "low", "info"):
            assert sev in _SEVERITY_WEIGHTS
