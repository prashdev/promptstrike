"""Typed exceptions for the provider layer.

Kept in one place so callers can catch provider problems distinctly from bugs
elsewhere, and so error handling stays consistent across adapters.
"""

from __future__ import annotations


class ProviderError(Exception):
    """Base class for all provider-layer failures."""


class ProviderConfigError(ProviderError):
    """Raised when provider config is missing, malformed, or unresolved."""


class ProviderResponseError(ProviderError):
    """Raised when a target endpoint errors out or returns an unusable body."""
