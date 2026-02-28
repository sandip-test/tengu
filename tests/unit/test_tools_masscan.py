"""Unit tests for masscan output parser."""

from __future__ import annotations

import json

from tengu.tools.recon.masscan import _parse_masscan_json

# ---------------------------------------------------------------------------
# TestParseMasscanJson
# ---------------------------------------------------------------------------


class TestParseMasscanJson:
    def test_empty_string_returns_empty(self):
        assert _parse_masscan_json("") == []

    def test_whitespace_only_returns_empty(self):
        assert _parse_masscan_json("   ") == []

    def test_valid_json_single_host_single_port(self):
        data = [{"ip": "10.0.0.1", "ports": [{"port": 80, "proto": "tcp", "status": "open"}]}]
        result = _parse_masscan_json(json.dumps(data))
        assert len(result) == 1
        assert result[0]["ip"] == "10.0.0.1"
        assert result[0]["port"] == 80
        assert result[0]["protocol"] == "tcp"
        assert result[0]["status"] == "open"

    def test_multiple_ports_per_host(self):
        data = [
            {
                "ip": "192.168.1.1",
                "ports": [
                    {"port": 22, "proto": "tcp", "status": "open"},
                    {"port": 443, "proto": "tcp", "status": "open"},
                ],
            }
        ]
        result = _parse_masscan_json(json.dumps(data))
        assert len(result) == 2
        ports = {r["port"] for r in result}
        assert ports == {22, 443}

    def test_multiple_hosts(self):
        data = [
            {"ip": "10.0.0.1", "ports": [{"port": 80, "proto": "tcp", "status": "open"}]},
            {"ip": "10.0.0.2", "ports": [{"port": 22, "proto": "tcp", "status": "open"}]},
        ]
        result = _parse_masscan_json(json.dumps(data))
        assert len(result) == 2
        ips = {r["ip"] for r in result}
        assert ips == {"10.0.0.1", "10.0.0.2"}

    def test_trailing_comma_fixed(self):
        # Masscan sometimes emits JSON with trailing comma before closing bracket
        raw = '[{"ip": "1.2.3.4", "ports": [{"port": 80, "proto": "tcp", "status": "open"}]},'
        result = _parse_masscan_json(raw)
        assert len(result) == 1
        assert result[0]["port"] == 80

    def test_text_fallback_parses_discovered_port(self):
        text = "Discovered open port 22/tcp on 192.168.1.10"
        result = _parse_masscan_json(text)
        assert len(result) == 1
        assert result[0]["port"] == 22
        assert result[0]["protocol"] == "tcp"
        assert result[0]["ip"] == "192.168.1.10"
        assert result[0]["status"] == "open"

    def test_text_fallback_multiple_lines(self):
        text = (
            "Discovered open port 80/tcp on 10.0.0.1\n"
            "Discovered open port 443/tcp on 10.0.0.2\n"
            "some other line that doesn't match\n"
        )
        result = _parse_masscan_json(text)
        assert len(result) == 2

    def test_default_proto_is_tcp(self):
        data = [{"ip": "10.0.0.1", "ports": [{"port": 80, "status": "open"}]}]
        result = _parse_masscan_json(json.dumps(data))
        assert result[0]["protocol"] == "tcp"

    def test_empty_ports_list(self):
        data = [{"ip": "10.0.0.1", "ports": []}]
        result = _parse_masscan_json(json.dumps(data))
        assert result == []
