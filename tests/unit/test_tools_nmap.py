"""Unit tests for nmap parsing helpers and configuration constants."""

from __future__ import annotations

from tengu.tools.recon.nmap import (
    _SCAN_TYPE_FLAGS,
    _parse_nmap_xml,
    _summarize_ports,
)
from tengu.types import Host, Port

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _minimal_xml(hosts_xml: str = "") -> str:
    return f'<?xml version="1.0"?><nmaprun>{hosts_xml}</nmaprun>'


def _host_xml(
    addr: str = "192.168.1.1",
    status: str = "up",
    hostname: str = "",
    ports_xml: str = "",
    os_xml: str = "",
) -> str:
    hn = f'<hostnames><hostname name="{hostname}"/></hostnames>' if hostname else "<hostnames/>"
    os_block = f"<os>{os_xml}</os>" if os_xml else ""
    return (
        f'<host>'
        f'<status state="{status}"/>'
        f'<address addr="{addr}" addrtype="ipv4"/>'
        f"{hn}"
        f"<ports>{ports_xml}</ports>"
        f"{os_block}"
        f"</host>"
    )


def _port_xml(
    portid: int = 80,
    protocol: str = "tcp",
    state: str = "open",
    service: str = "http",
    product: str = "",
    version: str = "",
) -> str:
    svc = f'<service name="{service}" product="{product}" version="{version}"/>'
    return (
        f'<port protocol="{protocol}" portid="{portid}">'
        f'<state state="{state}"/>'
        f"{svc}"
        f"</port>"
    )


# ---------------------------------------------------------------------------
# TestParseNmapXml
# ---------------------------------------------------------------------------


class TestParseNmapXml:
    def test_empty_string_returns_empty_list(self):
        assert _parse_nmap_xml("") == []

    def test_whitespace_returns_empty_list(self):
        assert _parse_nmap_xml("   ") == []

    def test_invalid_xml_returns_empty_list(self):
        assert _parse_nmap_xml("not valid xml <<<<") == []

    def test_no_hosts_returns_empty_list(self):
        xml = _minimal_xml()
        assert _parse_nmap_xml(xml) == []

    def test_single_host_with_open_port(self):
        port_xml = _port_xml(portid=80, state="open", service="http")
        xml = _minimal_xml(_host_xml(addr="10.0.0.1", ports_xml=port_xml))
        hosts = _parse_nmap_xml(xml)
        assert len(hosts) == 1
        assert hosts[0].address == "10.0.0.1"
        assert len(hosts[0].ports) == 1
        assert hosts[0].ports[0].number == 80

    def test_closed_ports_not_included(self):
        open_port = _port_xml(portid=80, state="open")
        closed_port = _port_xml(portid=443, state="closed")
        xml = _minimal_xml(_host_xml(ports_xml=open_port + closed_port))
        hosts = _parse_nmap_xml(xml)
        assert len(hosts[0].ports) == 1
        assert hosts[0].ports[0].number == 80

    def test_hostname_parsed(self):
        xml = _minimal_xml(_host_xml(hostname="example.com"))
        hosts = _parse_nmap_xml(xml)
        assert hosts[0].hostname == "example.com"

    def test_service_version_combined(self):
        port_xml = _port_xml(portid=22, state="open", service="ssh", product="OpenSSH", version="8.9")
        xml = _minimal_xml(_host_xml(ports_xml=port_xml))
        hosts = _parse_nmap_xml(xml)
        assert "OpenSSH" in hosts[0].ports[0].version
        assert "8.9" in hosts[0].ports[0].version

    def test_os_detection_parsed(self):
        os_xml = '<osmatch name="Linux 4.15"/>'
        xml = _minimal_xml(_host_xml(os_xml=os_xml))
        hosts = _parse_nmap_xml(xml)
        assert hosts[0].os == "Linux 4.15"

    def test_multiple_hosts(self):
        h1 = _host_xml(addr="192.168.1.1")
        h2 = _host_xml(addr="192.168.1.2")
        xml = _minimal_xml(h1 + h2)
        hosts = _parse_nmap_xml(xml)
        assert len(hosts) == 2
        addrs = {h.address for h in hosts}
        assert "192.168.1.1" in addrs
        assert "192.168.1.2" in addrs

    def test_host_without_address_skipped(self):
        # ipv6 address type — the parser only accepts ipv4/ipv6
        # Use a host with only MAC address → skipped
        xml = _minimal_xml(
            '<host><address addr="00:11:22:33:44:55" addrtype="mac"/></host>'
        )
        hosts = _parse_nmap_xml(xml)
        assert hosts == []

    def test_host_status_is_up(self):
        xml = _minimal_xml(_host_xml(addr="1.2.3.4", status="up"))
        hosts = _parse_nmap_xml(xml)
        assert hosts[0].status == "up"


# ---------------------------------------------------------------------------
# TestSummarizePorts
# ---------------------------------------------------------------------------


class TestSummarizePorts:
    def test_empty_hosts_returns_empty(self):
        assert _summarize_ports([]) == []

    def test_host_with_no_ports(self):
        host = Host(address="10.0.0.1", ports=[], status="up")
        assert _summarize_ports([host]) == []

    def test_open_port_appears_in_summary(self):
        port = Port(number=80, protocol="tcp", state="open", service="http")
        host = Host(address="10.0.0.1", ports=[port], status="up")
        summary = _summarize_ports([host])
        assert len(summary) == 1
        assert summary[0]["port"] == 80
        assert summary[0]["host"] == "10.0.0.1"

    def test_multiple_ports_from_multiple_hosts(self):
        p1 = Port(number=80, protocol="tcp", state="open", service="http")
        p2 = Port(number=443, protocol="tcp", state="open", service="https")
        h1 = Host(address="10.0.0.1", ports=[p1], status="up")
        h2 = Host(address="10.0.0.2", ports=[p2], status="up")
        summary = _summarize_ports([h1, h2])
        assert len(summary) == 2


# ---------------------------------------------------------------------------
# TestScanTypeFlags
# ---------------------------------------------------------------------------


class TestScanTypeFlags:
    def test_connect_scan_uses_st_flag(self):
        assert "-sT" in _SCAN_TYPE_FLAGS["connect"]

    def test_syn_scan_uses_ss_flag(self):
        assert "-sS" in _SCAN_TYPE_FLAGS["syn"]

    def test_all_scan_types_present(self):
        for scan_type in ("syn", "connect", "udp", "version", "ping", "fast"):
            assert scan_type in _SCAN_TYPE_FLAGS
