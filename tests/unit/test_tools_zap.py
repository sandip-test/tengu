"""Unit tests for OWASP ZAP proxy tool helpers."""

from __future__ import annotations

from tengu.tools.proxy.zap import _get_zap_config


class TestGetZapConfig:
    def test_defaults_when_no_env(self, monkeypatch):
        monkeypatch.delenv("ZAP_BASE_URL", raising=False)
        monkeypatch.delenv("ZAP_API_KEY", raising=False)
        base_url, api_key = _get_zap_config()
        assert base_url == "http://localhost:8080"
        assert api_key == ""

    def test_custom_base_url_from_env(self, monkeypatch):
        monkeypatch.setenv("ZAP_BASE_URL", "http://zap.corp.com:8090")
        monkeypatch.delenv("ZAP_API_KEY", raising=False)
        base_url, api_key = _get_zap_config()
        assert base_url == "http://zap.corp.com:8090"

    def test_api_key_from_env(self, monkeypatch):
        monkeypatch.delenv("ZAP_BASE_URL", raising=False)
        monkeypatch.setenv("ZAP_API_KEY", "my-secret-key")
        _, api_key = _get_zap_config()
        assert api_key == "my-secret-key"

    def test_returns_tuple_of_two_strings(self, monkeypatch):
        monkeypatch.delenv("ZAP_BASE_URL", raising=False)
        monkeypatch.delenv("ZAP_API_KEY", raising=False)
        result = _get_zap_config()
        assert isinstance(result, tuple)
        assert len(result) == 2
        assert all(isinstance(v, str) for v in result)

    def test_both_env_vars_used(self, monkeypatch):
        monkeypatch.setenv("ZAP_BASE_URL", "http://10.0.0.5:8080")
        monkeypatch.setenv("ZAP_API_KEY", "abc123")
        base_url, api_key = _get_zap_config()
        assert base_url == "http://10.0.0.5:8080"
        assert api_key == "abc123"
