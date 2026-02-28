"""Unit tests for DNS tool constants."""

from __future__ import annotations

from tengu.tools.recon.dns import _ALL_RECORD_TYPES

# ---------------------------------------------------------------------------
# TestAllRecordTypes
# ---------------------------------------------------------------------------


class TestAllRecordTypes:
    def test_a_record_present(self):
        assert "A" in _ALL_RECORD_TYPES

    def test_mx_record_present(self):
        assert "MX" in _ALL_RECORD_TYPES

    def test_ns_record_present(self):
        assert "NS" in _ALL_RECORD_TYPES

    def test_txt_record_present(self):
        assert "TXT" in _ALL_RECORD_TYPES

    def test_aaaa_record_present(self):
        assert "AAAA" in _ALL_RECORD_TYPES

    def test_cname_record_present(self):
        assert "CNAME" in _ALL_RECORD_TYPES

    def test_all_types_are_uppercase_strings(self):
        for rtype in _ALL_RECORD_TYPES:
            assert isinstance(rtype, str)
            assert rtype == rtype.upper()

    def test_at_least_eight_types(self):
        assert len(_ALL_RECORD_TYPES) >= 8

    def test_no_duplicates(self):
        assert len(_ALL_RECORD_TYPES) == len(set(_ALL_RECORD_TYPES))
