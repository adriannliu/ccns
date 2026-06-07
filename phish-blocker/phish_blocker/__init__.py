"""Phish-Blocker — AI call screener for inbound phone calls."""

from phish_blocker.ssl_certs import ensure as _ensure_ssl_certs

_ensure_ssl_certs()

__version__ = "0.1.0"
