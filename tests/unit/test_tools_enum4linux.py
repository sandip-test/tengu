"""Unit tests for enum4linux AD enumeration output parsers."""

from __future__ import annotations

import json

from tengu.tools.ad.enum4linux import _parse_enum4linux_output, _parse_enum4linux_text

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_enum4linux_json(
    users: dict | list | None = None,
    groups: dict | None = None,
    shares: dict | None = None,
    password_policy: dict | None = None,
    smb_info: dict | None = None,
) -> str:
    data: dict = {}
    if users is not None:
        data["users"] = users
    if groups is not None:
        data["groups"] = groups
    if shares is not None:
        data["shares"] = shares
    if password_policy is not None:
        data["password_policy"] = password_policy
    if smb_info is not None:
        data["smb_info"] = smb_info
    return json.dumps(data)


# ---------------------------------------------------------------------------
# TestParseEnum4linuxOutput
# ---------------------------------------------------------------------------


class TestParseEnum4linuxOutput:
    def test_empty_returns_defaults(self):
        result = _parse_enum4linux_output("")
        assert result["users"] == []
        assert result["shares"] == []
        assert result["groups"] == []

    def test_invalid_json_falls_back_to_text_parser(self):
        # Non-JSON triggers _parse_enum4linux_text fallback
        result = _parse_enum4linux_output("user:[admin] rid:[500]")
        assert len(result["users"]) == 1
        assert result["users"][0]["username"] == "admin"

    def test_json_users_dict_format(self):
        users = {
            "1000": {"username": "bob", "fullname": "Bob Smith", "description": "Staff"},
        }
        output = _make_enum4linux_json(users=users)
        result = _parse_enum4linux_output(output)
        assert len(result["users"]) == 1
        assert result["users"][0]["username"] == "bob"
        assert result["users"][0]["full_name"] == "Bob Smith"

    def test_json_users_list_format(self):
        users = [{"username": "alice", "rid": "1001"}]
        output = _make_enum4linux_json(users=users)
        result = _parse_enum4linux_output(output)
        assert len(result["users"]) == 1
        assert result["users"][0]["username"] == "alice"

    def test_json_groups_parsed(self):
        groups = {
            "512": {"groupname": "Domain Admins", "members": ["Administrator"]}
        }
        output = _make_enum4linux_json(groups=groups)
        result = _parse_enum4linux_output(output)
        assert len(result["groups"]) == 1
        assert result["groups"][0]["name"] == "Domain Admins"

    def test_json_shares_parsed(self):
        shares = {
            "ADMIN$": {"type": "Disk", "comment": "Remote Admin", "access": "NO ACCESS"},
            "C$": {"type": "Disk", "comment": "Default share", "access": "READ"},
        }
        output = _make_enum4linux_json(shares=shares)
        result = _parse_enum4linux_output(output)
        assert len(result["shares"]) == 2
        names = [s["name"] for s in result["shares"]]
        assert "ADMIN$" in names

    def test_json_password_policy_parsed(self):
        policy = {
            "min_password_length": 8,
            "account_lockout_threshold": 5,
        }
        output = _make_enum4linux_json(password_policy=policy)
        result = _parse_enum4linux_output(output)
        assert result["password_policy"]["min_length"] == 8
        assert result["password_policy"]["lockout_threshold"] == 5

    def test_json_smb_info_parsed(self):
        smb = {"os": "Windows Server 2019", "domain": "CORP"}
        output = _make_enum4linux_json(smb_info=smb)
        result = _parse_enum4linux_output(output)
        assert result["os_info"]["os"] == "Windows Server 2019"

    def test_json_empty_data_returns_defaults(self):
        output = json.dumps({})
        result = _parse_enum4linux_output(output)
        assert result["users"] == []
        assert result["shares"] == []


# ---------------------------------------------------------------------------
# TestParseEnum4linuxText
# ---------------------------------------------------------------------------


class TestParseEnum4linuxText:
    def test_empty_returns_defaults(self):
        result = _parse_enum4linux_text("")
        assert result["users"] == []
        assert result["shares"] == []
        assert result["groups"] == []

    def test_user_rid_extracted(self):
        text = "user:[Administrator] rid:[0x1f4]"
        result = _parse_enum4linux_text(text)
        assert len(result["users"]) == 1
        assert result["users"][0]["username"] == "Administrator"
        assert result["users"][0]["rid"] == "0x1f4"

    def test_multiple_users(self):
        text = (
            "user:[admin] rid:[500]\n"
            "user:[guest] rid:[501]\n"
            "user:[bob] rid:[1001]\n"
        )
        result = _parse_enum4linux_text(text)
        assert len(result["users"]) == 3

    def test_share_disk_extracted(self):
        text = "    ADMIN$    Disk    Remote Admin"
        result = _parse_enum4linux_text(text)
        assert len(result["shares"]) == 1
        assert result["shares"][0]["name"] == "ADMIN$"
        assert result["shares"][0]["type"] == "Disk"

    def test_share_ipc_extracted(self):
        text = "    IPC$    IPC    Remote IPC"
        result = _parse_enum4linux_text(text)
        assert len(result["shares"]) == 1
        assert result["shares"][0]["type"] == "IPC"

    def test_group_extracted(self):
        text = "group:[Domain Admins] rid:[0x200]"
        result = _parse_enum4linux_text(text)
        assert len(result["groups"]) == 1
        assert result["groups"][0]["name"] == "Domain Admins"

    def test_non_matching_lines_ignored(self):
        text = "[+] Getting domain SID...\n[*] Connecting to target...\n"
        result = _parse_enum4linux_text(text)
        assert result["users"] == []
        assert result["shares"] == []

    def test_mixed_output(self):
        text = (
            "user:[svc_sql] rid:[1105]\n"
            "    C$    Disk    Default Share\n"
            "group:[IT Staff] rid:[0x210]\n"
        )
        result = _parse_enum4linux_text(text)
        assert len(result["users"]) == 1
        assert len(result["shares"]) == 1
        assert len(result["groups"]) == 1
