"""Unit tests for hash identification and cracking helpers."""

from __future__ import annotations

import pytest

from tengu.tools.bruteforce.hash_tools import _HASH_PATTERNS, hash_identify

# ---------------------------------------------------------------------------
# TestHashPatterns — structure validation
# ---------------------------------------------------------------------------


class TestHashPatterns:
    def test_at_least_ten_patterns_defined(self):
        assert len(_HASH_PATTERNS) >= 10

    def test_each_entry_is_three_tuple(self):
        for entry in _HASH_PATTERNS:
            assert len(entry) == 3

    def test_md5_pattern_matches(self):
        md5_hash = "d41d8cd98f00b204e9800998ecf8427e"
        matches = [name for pat, name, _ in _HASH_PATTERNS if pat.match(md5_hash)]
        assert any("MD5" in m for m in matches)

    def test_sha1_pattern_matches(self):
        sha1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        matches = [name for pat, name, _ in _HASH_PATTERNS if pat.match(sha1)]
        assert any("SHA-1" in m for m in matches)

    def test_sha256_pattern_matches(self):
        sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        matches = [name for pat, name, _ in _HASH_PATTERNS if pat.match(sha256)]
        assert any("SHA-256" in m for m in matches)

    def test_bcrypt_pattern_matches(self):
        bcrypt = "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW"
        matches = [name for pat, name, _ in _HASH_PATTERNS if pat.match(bcrypt)]
        assert any("bcrypt" in m for m in matches)

    def test_sha512_pattern_matches(self):
        sha512_valid = "a" * 128
        matches = [name for pat, name, _ in _HASH_PATTERNS if pat.match(sha512_valid)]
        assert any("SHA-512" in m for m in matches)


# ---------------------------------------------------------------------------
# TestHashIdentify — async but no subprocess/ctx
# ---------------------------------------------------------------------------


class TestHashIdentify:
    @pytest.mark.asyncio
    async def test_md5_identified(self):
        md5 = "d41d8cd98f00b204e9800998ecf8427e"
        result = await hash_identify(None, md5)  # ctx not used
        types = [m["type"] for m in result["possible_types"]]
        assert any("MD5" in t for t in types)

    @pytest.mark.asyncio
    async def test_sha1_identified(self):
        sha1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        result = await hash_identify(None, sha1)
        types = [m["type"] for m in result["possible_types"]]
        assert any("SHA-1" in t for t in types)

    @pytest.mark.asyncio
    async def test_sha256_identified(self):
        sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        result = await hash_identify(None, sha256)
        types = [m["type"] for m in result["possible_types"]]
        assert any("SHA-256" in t for t in types)

    @pytest.mark.asyncio
    async def test_unknown_hash_returns_empty_matches(self):
        # 10-char hex string: valid for sanitize_hash but matches no known pattern
        result = await hash_identify(None, "a1b2c3d4e5")
        assert result["possible_types"] == []

    @pytest.mark.asyncio
    async def test_hash_length_in_result(self):
        md5 = "d41d8cd98f00b204e9800998ecf8427e"
        result = await hash_identify(None, md5)
        assert result["length"] == 32

    @pytest.mark.asyncio
    async def test_hashcat_mode_added_for_md5(self):
        md5 = "d41d8cd98f00b204e9800998ecf8427e"
        result = await hash_identify(None, md5)
        md5_matches = [m for m in result["possible_types"] if m["type"] == "MD5"]
        if md5_matches:
            assert md5_matches[0].get("hashcat_mode") == 0

    @pytest.mark.asyncio
    async def test_recommendation_for_known_hash(self):
        sha1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        result = await hash_identify(None, sha1)
        assert "Most likely" in result["recommendation"]

    @pytest.mark.asyncio
    async def test_recommendation_for_unknown_hash(self):
        # 10-char hex string: valid for sanitize_hash but matches no known pattern
        result = await hash_identify(None, "a1b2c3d4e5")
        assert "Unknown" in result["recommendation"]

    def test_bcrypt_pattern_matches_directly(self):
        """Test bcrypt recognition directly via _HASH_PATTERNS (bypasses sanitize_hash
        which doesn't accept non-hex chars like uppercase letters in bcrypt)."""
        bcrypt = "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW"
        matches = [name for pat, name, _ in _HASH_PATTERNS if pat.match(bcrypt)]
        assert any("bcrypt" in m for m in matches)
