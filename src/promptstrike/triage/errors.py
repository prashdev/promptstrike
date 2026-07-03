"""Typed exceptions for the triage layer."""

from __future__ import annotations


class TriageError(Exception):
    """Raised when the severity rubric cannot be loaded or is invalid."""
