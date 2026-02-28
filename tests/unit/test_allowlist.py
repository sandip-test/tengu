"""Unit tests for the target allowlist."""

from __future__ import annotations

import pytest

from tengu.exceptions import TargetNotAllowedError
from tengu.security.allowlist import TargetAllowlist


class TestTargetAllowlist:
    def test_empty_allowlist_permits_all(self):
        """Empty allowlist warns but allows (for development use)."""
        al = TargetAllowlist(allowed_hosts=[], blocked_hosts=[])
        # Should not raise
        al.check("192.168.1.1")

    def test_blocklist_always_wins(self):
        al = TargetAllowlist(
            allowed_hosts=["192.168.1.0/24"],
            blocked_hosts=["192.168.1.1"],
        )
        with pytest.raises(TargetNotAllowedError):
            al.check("192.168.1.1")

    def test_allowlist_passes_matching_host(self):
        al = TargetAllowlist(
            allowed_hosts=["example.com"],
            blocked_hosts=[],
        )
        al.check("example.com")  # Should not raise

    def test_allowlist_blocks_non_matching_host(self):
        al = TargetAllowlist(
            allowed_hosts=["example.com"],
            blocked_hosts=[],
        )
        with pytest.raises(TargetNotAllowedError):
            al.check("evil.com")

    def test_cidr_allowlist(self):
        al = TargetAllowlist(
            allowed_hosts=["192.168.1.0/24"],
            blocked_hosts=[],
        )
        al.check("192.168.1.50")  # In range — should pass

    def test_cidr_allowlist_outside_range(self):
        al = TargetAllowlist(
            allowed_hosts=["192.168.1.0/24"],
            blocked_hosts=[],
        )
        with pytest.raises(TargetNotAllowedError):
            al.check("10.0.0.1")  # Outside range

    def test_wildcard_allowlist(self):
        al = TargetAllowlist(
            allowed_hosts=["*.example.com"],
            blocked_hosts=[],
        )
        al.check("sub.example.com")  # Should pass

    def test_wildcard_allowlist_blocks_other_domain(self):
        al = TargetAllowlist(
            allowed_hosts=["*.example.com"],
            blocked_hosts=[],
        )
        with pytest.raises(TargetNotAllowedError):
            al.check("sub.evil.com")

    def test_url_target_extracts_host(self):
        al = TargetAllowlist(
            allowed_hosts=["example.com"],
            blocked_hosts=[],
        )
        al.check("https://example.com/path?q=test")  # Host should match

    def test_default_blocked_hosts(self):
        """Localhost and government sites should be blocked by default."""
        al = TargetAllowlist(
            allowed_hosts=["localhost"],  # Even if listed, blocked wins
            blocked_hosts=["localhost", "127.0.0.1"],
        )
        with pytest.raises(TargetNotAllowedError):
            al.check("127.0.0.1")

    def test_is_allowed_returns_bool(self):
        al = TargetAllowlist(
            allowed_hosts=["example.com"],
            blocked_hosts=["evil.com"],
        )
        assert al.is_allowed("example.com") is True
        assert al.is_allowed("evil.com") is False
        assert al.is_allowed("other.com") is False
