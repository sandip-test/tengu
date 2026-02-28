"""Unit tests for AD tools: nxc/crackmapexec parser and impacket kerberoast parser."""

from __future__ import annotations

from tengu.tools.ad.crackmapexec import (
    _MODULE_NAME_PATTERN,
    _SUPPORTED_PROTOCOLS,
    _parse_nxc_output,
)
from tengu.tools.ad.impacket import (
    _TGS_HASH_PATTERN,
    _parse_kerberoast_output,
)

# ---------------------------------------------------------------------------
# TestSupportedProtocols
# ---------------------------------------------------------------------------


class TestSupportedProtocols:
    def test_smb_present(self):
        assert "smb" in _SUPPORTED_PROTOCOLS

    def test_ldap_present(self):
        assert "ldap" in _SUPPORTED_PROTOCOLS

    def test_ssh_present(self):
        assert "ssh" in _SUPPORTED_PROTOCOLS

    def test_at_least_six_protocols(self):
        assert len(_SUPPORTED_PROTOCOLS) >= 6

    def test_all_lowercase(self):
        for proto in _SUPPORTED_PROTOCOLS:
            assert proto == proto.lower()


# ---------------------------------------------------------------------------
# TestModuleNamePattern
# ---------------------------------------------------------------------------


class TestModuleNamePattern:
    def test_valid_module_name(self):
        assert _MODULE_NAME_PATTERN.match("spider_plus")

    def test_hyphenated_module_name(self):
        assert _MODULE_NAME_PATTERN.match("enum-av")

    def test_alphanumeric_module(self):
        assert _MODULE_NAME_PATTERN.match("smb2")

    def test_space_rejected(self):
        assert not _MODULE_NAME_PATTERN.match("invalid module")

    def test_semicolon_rejected(self):
        assert not _MODULE_NAME_PATTERN.match("mod;rm -rf /")


# ---------------------------------------------------------------------------
# TestParseNxcOutput
# ---------------------------------------------------------------------------


class TestParseNxcOutput:
    def test_empty_returns_defaults(self):
        result = _parse_nxc_output("")
        assert result["auth_status"] == "unknown"
        assert result["hosts"] == []
        assert result["shares"] == []
        assert result["users"] == []

    def test_success_line_detected(self):
        output = "[+] 192.168.1.1:445 WORKGROUP\\admin:password (Pwn3d!)"
        result = _parse_nxc_output(output)
        assert len(result["success_lines"]) == 1
        assert result["auth_status"] == "admin_access"

    def test_authentication_success(self):
        output = "[+] 192.168.1.1:445 CORP\\user:pass"
        result = _parse_nxc_output(output)
        assert result["auth_status"] == "authenticated"

    def test_authentication_failed(self):
        output = "[-] 192.168.1.1:445 CORP\\user:wrongpass STATUS_LOGON_FAILURE"
        result = _parse_nxc_output(output)
        assert result["auth_status"] == "authentication_failed"

    def test_info_line_captured(self):
        output = "[*] 192.168.1.1 SMB signing disabled"
        result = _parse_nxc_output(output)
        assert len(result["info_lines"]) == 1

    def test_ip_extraction(self):
        output = "[*] 10.0.0.5 Windows Server 2019"
        result = _parse_nxc_output(output)
        assert "10.0.0.5" in result["hosts"]

    def test_share_extraction(self):
        output = "SHARE  IPC$  READ"
        result = _parse_nxc_output(output)
        assert len(result["shares"]) == 1
        assert result["shares"][0]["name"] == "IPC$"
        assert result["shares"][0]["access"] == "READ"

    def test_user_extraction(self):
        output = "User: Administrator"
        result = _parse_nxc_output(output)
        assert "Administrator" in result["users"]

    def test_duplicate_ips_not_repeated(self):
        output = "[*] 10.0.0.1 info\n[*] 10.0.0.1 more info"
        result = _parse_nxc_output(output)
        assert result["hosts"].count("10.0.0.1") == 1

    def test_duplicate_users_not_repeated(self):
        output = "User: admin\nUser: admin"
        result = _parse_nxc_output(output)
        assert result["users"].count("admin") == 1

    def test_pwned_detection(self):
        output = "[+] 192.168.1.1 pwned Pwn3d!"
        result = _parse_nxc_output(output)
        assert result["auth_status"] == "admin_access"

    def test_multiple_shares(self):
        output = "SHARE  C$  READ\nSHARE  ADMIN$  NO ACCESS"
        result = _parse_nxc_output(output)
        assert len(result["shares"]) == 2


# ---------------------------------------------------------------------------
# TestTgsHashPattern
# ---------------------------------------------------------------------------


class TestTgsHashPattern:
    def test_valid_tgs_hash_matched(self):
        # Synthetic TGS hash (hashcat format)
        tgs = "$krb5tgs$23$*SVC_SQL$CORP.LOCAL$HTTP/sqlserver.corp.local*$" + "a" * 32 + "$" + "b" * 32
        assert _TGS_HASH_PATTERN.search(tgs)

    def test_non_hash_not_matched(self):
        assert not _TGS_HASH_PATTERN.search("just a normal line of text")

    def test_partial_hash_not_matched(self):
        assert not _TGS_HASH_PATTERN.search("$krb5tgs$incomplete")


# ---------------------------------------------------------------------------
# TestParseKerberoastOutput
# ---------------------------------------------------------------------------


class TestParseKerberoastOutput:
    def test_empty_returns_empty(self):
        result = _parse_kerberoast_output("")
        assert result["accounts"] == []
        assert result["tgs_hashes"] == []

    def test_tgs_hash_extracted(self):
        tgs = "$krb5tgs$23$*SVC$CORP$HTTP/srv*$" + "a" * 32 + "$" + "b" * 32
        result = _parse_kerberoast_output(tgs)
        assert len(result["tgs_hashes"]) == 1
        assert result["tgs_hashes"][0] == tgs

    def test_hash_only_creates_unknown_account(self):
        tgs = "$krb5tgs$23$*SVC$CORP$HTTP/srv*$" + "a" * 32 + "$" + "b" * 32
        result = _parse_kerberoast_output(tgs)
        # When hashes found but no structured account info
        assert len(result["accounts"]) >= 1
        assert result["accounts"][0]["spn"].startswith("unknown-spn-")

    def test_structured_output_parsed(self):
        output = (
            "ServicePrincipalName     Name     MemberOf     PasswordLastSet     LastLogon\n"
            "HTTP/sqlserver.corp.local  svc_sql  Domain Users  2024-01-01         N/A\n"
        )
        result = _parse_kerberoast_output(output)
        if result["accounts"]:
            assert result["accounts"][0]["spn"] == "HTTP/sqlserver.corp.local"
            assert result["accounts"][0]["account"] == "svc_sql"

    def test_header_line_skipped(self):
        output = "ServicePrincipalName  Name  MemberOf  PasswordLastSet  LastLogon\n"
        result = _parse_kerberoast_output(output)
        # Header line should be skipped (spn == "ServicePrincipalName")
        assert all(a.get("spn") != "ServicePrincipalName" for a in result["accounts"])

    def test_multiple_hashes(self):
        hashes = "\n".join(
            f"$krb5tgs$23$*SVC{i}$CORP$HTTP/srv{i}*$" + "a" * 32 + "$" + "b" * 32
            for i in range(3)
        )
        result = _parse_kerberoast_output(hashes)
        assert len(result["tgs_hashes"]) == 3
