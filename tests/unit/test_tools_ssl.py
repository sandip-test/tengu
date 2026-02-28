"""Unit tests for SSL/TLS helper functions."""

from __future__ import annotations

from tengu.tools.web.ssl_tls import (
    _WEAK_CIPHERS_PATTERNS,
    _WEAK_PROTOCOLS,
    _generate_recommendations,
)
from tengu.types import SSLResult

# ---------------------------------------------------------------------------
# TestWeakProtocols
# ---------------------------------------------------------------------------


class TestWeakProtocols:
    def test_sslv2_in_weak(self):
        assert "SSLv2" in _WEAK_PROTOCOLS

    def test_sslv3_in_weak(self):
        assert "SSLv3" in _WEAK_PROTOCOLS

    def test_tls10_in_weak(self):
        assert "TLSv1.0" in _WEAK_PROTOCOLS

    def test_tls11_in_weak(self):
        assert "TLSv1.1" in _WEAK_PROTOCOLS

    def test_tls12_not_in_weak(self):
        assert "TLSv1.2" not in _WEAK_PROTOCOLS

    def test_tls13_not_in_weak(self):
        assert "TLSv1.3" not in _WEAK_PROTOCOLS


# ---------------------------------------------------------------------------
# TestWeakCiphersPatterns
# ---------------------------------------------------------------------------


class TestWeakCiphersPatterns:
    def test_rc4_in_patterns(self):
        assert "RC4" in _WEAK_CIPHERS_PATTERNS

    def test_des_in_patterns(self):
        assert "DES" in _WEAK_CIPHERS_PATTERNS

    def test_null_in_patterns(self):
        assert "NULL" in _WEAK_CIPHERS_PATTERNS

    def test_at_least_five_patterns(self):
        assert len(_WEAK_CIPHERS_PATTERNS) >= 5


# ---------------------------------------------------------------------------
# TestGenerateRecommendations
# ---------------------------------------------------------------------------


class TestGenerateRecommendations:
    def test_clean_result_no_recommendations(self):
        result = SSLResult(host="example.com", port=443)
        result.protocols = ["TLSv1.2", "TLSv1.3"]
        result.certificate_valid = True
        recs = _generate_recommendations(result)
        assert recs == []

    def test_weak_protocol_triggers_recommendation(self):
        result = SSLResult(host="example.com", port=443)
        result.weak_protocols = ["TLSv1.0"]
        result.certificate_valid = True
        result.protocols = ["TLSv1.0", "TLSv1.2", "TLSv1.3"]
        recs = _generate_recommendations(result)
        assert any("deprecated protocols" in r.lower() for r in recs)

    def test_heartbleed_triggers_recommendation(self):
        result = SSLResult(host="example.com", port=443)
        result.vulnerabilities = ["Heartbleed (CVE-2014-0160)"]
        result.protocols = ["TLSv1.2", "TLSv1.3"]
        result.certificate_valid = True
        recs = _generate_recommendations(result)
        assert any("Heartbleed" in r for r in recs)

    def test_invalid_certificate_triggers_recommendation(self):
        result = SSLResult(host="example.com", port=443)
        result.certificate_valid = False
        result.protocols = ["TLSv1.2", "TLSv1.3"]
        recs = _generate_recommendations(result)
        assert any("certificate" in r.lower() for r in recs)

    def test_no_tls13_triggers_recommendation(self):
        result = SSLResult(host="example.com", port=443)
        result.protocols = ["TLSv1.2"]  # No TLSv1.3
        result.certificate_valid = True
        recs = _generate_recommendations(result)
        assert any("TLS 1.3" in r for r in recs)

    def test_multiple_issues_multiple_recommendations(self):
        result = SSLResult(host="example.com", port=443)
        result.weak_protocols = ["SSLv3"]
        result.vulnerabilities = ["Heartbleed (CVE-2014-0160)"]
        result.certificate_valid = False
        result.protocols = ["SSLv3", "TLSv1.2"]
        recs = _generate_recommendations(result)
        assert len(recs) >= 3
