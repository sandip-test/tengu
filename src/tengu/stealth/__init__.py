"""Stealth/OPSEC layer for Tengu — Tor, proxychains, UA rotation, timing jitter, DNS privacy."""

from __future__ import annotations

from tengu.stealth.layer import StealthLayer, get_stealth_layer

__all__ = ["StealthLayer", "get_stealth_layer"]
