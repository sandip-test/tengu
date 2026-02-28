"""Unit tests for Hydra brute-force tool: parser and constants."""

from __future__ import annotations

from tengu.tools.bruteforce.hydra import _SUPPORTED_SERVICES, _parse_hydra_output

# ---------------------------------------------------------------------------
# TestSupportedServices
# ---------------------------------------------------------------------------


class TestSupportedServices:
    def test_ssh_present(self):
        assert "ssh" in _SUPPORTED_SERVICES

    def test_ftp_present(self):
        assert "ftp" in _SUPPORTED_SERVICES

    def test_smb_present(self):
        assert "smb" in _SUPPORTED_SERVICES

    def test_rdp_present(self):
        assert "rdp" in _SUPPORTED_SERVICES

    def test_mysql_present(self):
        assert "mysql" in _SUPPORTED_SERVICES

    def test_http_get_present(self):
        assert "http-get" in _SUPPORTED_SERVICES

    def test_http_post_form_present(self):
        assert "http-post-form" in _SUPPORTED_SERVICES

    def test_all_lowercase(self):
        for svc in _SUPPORTED_SERVICES:
            assert svc == svc.lower()

    def test_at_least_ten_services(self):
        assert len(_SUPPORTED_SERVICES) >= 10

    def test_is_set_or_frozenset(self):
        assert isinstance(_SUPPORTED_SERVICES, (set, frozenset))


# ---------------------------------------------------------------------------
# TestParseHydraOutput
# ---------------------------------------------------------------------------


class TestParseHydraOutput:
    def test_empty_string_returns_empty(self):
        assert _parse_hydra_output("") == []

    def test_no_match_returns_empty(self):
        output = "[INFO] Attacking ssh\n[STATUS] 10 of 100 done\n"
        assert _parse_hydra_output(output) == []

    def test_single_credential_extracted(self):
        output = "[ssh][192.168.1.1:22] login: admin password: secret123"
        result = _parse_hydra_output(output)
        assert len(result) == 1
        assert result[0]["username"] == "admin"
        assert result[0]["password"] == "secret123"

    def test_raw_line_preserved(self):
        line = "[ftp][10.0.0.5:21] login: ftpuser password: p@ss"
        result = _parse_hydra_output(line)
        assert result[0]["raw_line"] == line

    def test_multiple_credentials(self):
        output = (
            "[ssh][10.0.0.1:22] login: user1 password: pass1\n"
            "[rdp][10.0.0.2:3389] login: user2 password: pass2\n"
        )
        result = _parse_hydra_output(output)
        assert len(result) == 2
        assert result[0]["username"] == "user1"
        assert result[1]["username"] == "user2"

    def test_case_insensitive_pattern(self):
        output = "[HTTP][192.168.0.1:80] Login: webadmin Password: hunter2"
        result = _parse_hydra_output(output)
        assert len(result) == 1
        assert result[0]["username"] == "webadmin"

    def test_non_matching_lines_skipped(self):
        output = "[INFO] Starting attack\n[ERROR] Connection refused\n"
        assert _parse_hydra_output(output) == []

    def test_mixed_lines_only_matches_extracted(self):
        output = (
            "Hydra v9.4 starting...\n"
            "[ssh][10.0.0.1:22] login: root password: toor\n"
            "[STATUS] Attack finished.\n"
        )
        result = _parse_hydra_output(output)
        assert len(result) == 1
        assert result[0]["username"] == "root"
        assert result[0]["password"] == "toor"
