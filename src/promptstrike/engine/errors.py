"""Typed exceptions for the engine layer."""

from __future__ import annotations


class ResultsError(Exception):
    """Raised when a saved scan-results JSON file cannot be read or parsed."""
