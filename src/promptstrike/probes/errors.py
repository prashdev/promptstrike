"""Typed exceptions for probe loading."""

from __future__ import annotations


class ProbeLoadError(Exception):
    """Raised when a probe directory or YAML file cannot be loaded/validated."""
