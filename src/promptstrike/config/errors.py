"""Typed exceptions for the config layer."""

from __future__ import annotations


class ConfigError(Exception):
    """Raised when a run config is missing, malformed, or has unresolved refs."""
