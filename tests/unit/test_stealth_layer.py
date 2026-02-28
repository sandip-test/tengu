"""Unit tests for StealthLayer orchestrator."""

from __future__ import annotations

import pytest

from tengu.stealth.config import (
    ProxyConfig,
    StealthConfig,
    TimingConfig,
    UserAgentConfig,
)
from tengu.stealth.layer import StealthLayer, reset_stealth_layer

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _disabled_config() -> StealthConfig:
    return StealthConfig(enabled=False)


def _proxy_config(host: str = "127.0.0.1", port: int = 9050) -> StealthConfig:
    return StealthConfig(
        enabled=True,
        proxy=ProxyConfig(enabled=True, type="socks5", host=host, port=port),
    )


def _ua_config() -> StealthConfig:
    return StealthConfig(
        enabled=True,
        user_agent=UserAgentConfig(enabled=True, browser_type="chrome", rotate_every=5),
    )


def _timing_config(min_ms: int = 0, max_ms: int = 1) -> StealthConfig:
    return StealthConfig(
        enabled=True,
        timing=TimingConfig(enabled=True, min_delay_ms=min_ms, max_delay_ms=max_ms, jitter_percent=0),
    )


# ---------------------------------------------------------------------------
# TestStealthLayerEnabled
# ---------------------------------------------------------------------------


class TestStealthLayerEnabled:
    def test_disabled_by_default(self):
        layer = StealthLayer(_disabled_config())
        assert layer.enabled is False

    def test_enabled_when_config_enabled(self):
        layer = StealthLayer(_proxy_config())
        assert layer.enabled is True

    def test_config_property_returns_config(self):
        cfg = _disabled_config()
        layer = StealthLayer(cfg)
        assert layer.config is cfg


# ---------------------------------------------------------------------------
# TestStealthLayerProxy
# ---------------------------------------------------------------------------


class TestStealthLayerProxy:
    def test_proxy_url_none_when_disabled(self):
        layer = StealthLayer(_disabled_config())
        assert layer.proxy_url is None

    def test_proxy_url_returned_when_enabled(self):
        layer = StealthLayer(_proxy_config(host="127.0.0.1", port=9050))
        assert layer.proxy_url == "socks5://127.0.0.1:9050"

    def test_proxy_url_none_if_stealth_disabled(self):
        cfg = StealthConfig(enabled=False, proxy=ProxyConfig(enabled=True))
        layer = StealthLayer(cfg)
        assert layer.proxy_url is None

    def test_get_proxy_env_empty_when_no_proxy(self):
        layer = StealthLayer(_disabled_config())
        assert layer.get_proxy_env() == {}

    def test_get_proxy_env_returns_all_keys(self):
        layer = StealthLayer(_proxy_config())
        env = layer.get_proxy_env()
        assert "http_proxy" in env
        assert "https_proxy" in env
        assert "HTTP_PROXY" in env
        assert "HTTPS_PROXY" in env
        assert "ALL_PROXY" in env

    def test_get_proxy_env_values_match_proxy_url(self):
        layer = StealthLayer(_proxy_config(host="10.0.0.5", port=8080))
        env = layer.get_proxy_env()
        assert env["http_proxy"] == "socks5://10.0.0.5:8080"


# ---------------------------------------------------------------------------
# TestInjectProxyFlags
# ---------------------------------------------------------------------------


class TestInjectProxyFlags:
    def test_no_injection_when_no_proxy(self):
        layer = StealthLayer(_disabled_config())
        args = ["nmap", "-p", "80", "10.0.0.1"]
        assert layer.inject_proxy_flags("nmap", args) == args

    def test_nmap_proxy_injected(self):
        layer = StealthLayer(_proxy_config())
        args = ["nmap", "-p", "80", "10.0.0.1"]
        result = layer.inject_proxy_flags("nmap", args)
        assert "--proxies" in result
        assert "socks5://127.0.0.1:9050" in result

    def test_nuclei_proxy_injected(self):
        layer = StealthLayer(_proxy_config())
        args = ["nuclei", "-u", "https://target.com"]
        result = layer.inject_proxy_flags("nuclei", args)
        assert "-proxy" in result

    def test_ffuf_proxy_injected(self):
        layer = StealthLayer(_proxy_config())
        args = ["ffuf", "-u", "https://target.com/FUZZ"]
        result = layer.inject_proxy_flags("ffuf", args)
        assert "-x" in result

    def test_unknown_tool_no_injection(self):
        layer = StealthLayer(_proxy_config())
        args = ["unknown_tool", "--arg"]
        result = layer.inject_proxy_flags("unknown_tool", args)
        assert result == args

    def test_first_element_preserved(self):
        layer = StealthLayer(_proxy_config())
        args = ["nmap", "-sV", "192.168.1.1"]
        result = layer.inject_proxy_flags("nmap", args)
        assert result[0] == "nmap"

    def test_original_args_preserved(self):
        layer = StealthLayer(_proxy_config())
        args = ["nmap", "-p", "443", "10.0.0.1"]
        result = layer.inject_proxy_flags("nmap", args)
        assert "-p" in result
        assert "443" in result
        assert "10.0.0.1" in result


# ---------------------------------------------------------------------------
# TestUserAgent
# ---------------------------------------------------------------------------


class TestUserAgent:
    def test_no_ua_when_disabled(self):
        layer = StealthLayer(_disabled_config())
        assert layer.get_user_agent() is None

    def test_ua_returned_when_enabled(self):
        layer = StealthLayer(_ua_config())
        ua = layer.get_user_agent()
        assert isinstance(ua, str)
        assert "Mozilla" in ua


# ---------------------------------------------------------------------------
# TestWaitIfEnabled
# ---------------------------------------------------------------------------


class TestWaitIfEnabled:
    @pytest.mark.asyncio
    async def test_wait_completes_when_disabled(self):
        layer = StealthLayer(_disabled_config())
        await layer.wait_if_enabled()

    @pytest.mark.asyncio
    async def test_wait_completes_with_minimal_delay(self):
        layer = StealthLayer(_timing_config(min_ms=0, max_ms=1))
        await layer.wait_if_enabled()


# ---------------------------------------------------------------------------
# TestResetStealthLayer
# ---------------------------------------------------------------------------


class TestResetStealthLayer:
    def test_reset_clears_singleton(self):
        reset_stealth_layer()
        from tengu.stealth.layer import _stealth_layer
        assert _stealth_layer is None
