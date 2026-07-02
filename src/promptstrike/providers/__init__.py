"""Provider layer: the model-agnostic seam of the scanner.

Public surface:

* ``LLMProvider`` — the abstract interface everything downstream depends on.
* ``create_provider(config)`` — build a provider from a plain config dict.
* ``provider_from_yaml(path, key=...)`` — load that dict from a YAML file.

Keeping the factory here (rather than making callers import concrete classes)
means the *only* thing the rest of the package names is ``LLMProvider`` plus a
string in config. Swap ``provider: openai`` for ``provider: ollama`` and nothing
else changes — that is what keeps the scanner model-agnostic.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from promptstrike.providers.base import LLMProvider, Message
from promptstrike.providers.errors import (
    ProviderConfigError,
    ProviderError,
    ProviderResponseError,
)
from promptstrike.providers.registry import PROVIDERS

__all__ = [
    "LLMProvider",
    "Message",
    "ProviderError",
    "ProviderConfigError",
    "ProviderResponseError",
    "create_provider",
    "provider_from_yaml",
]


def create_provider(config: dict[str, Any]) -> LLMProvider:
    """Build a concrete provider from an already-resolved config dict.

    The dict must contain ``provider`` (the adapter name); the remaining keys are
    forwarded to that adapter's constructor as-is, and the adapter decides which
    are required (most need ``model``; wrappers may take ``backend`` instead).

    Env-var resolution is intentionally *not* done here:
    ``promptstrike.config.loader`` is the single owner of ``${ENV}`` resolution
    and resolves the whole run config before it reaches this factory, so this
    function must receive a plain, already-resolved dict.

    Args:
        config: The resolved provider configuration.

    Returns:
        A ready-to-use ``LLMProvider``.

    Raises:
        ProviderConfigError: On unknown provider name or missing required keys.
    """
    if "provider" not in config:
        raise ProviderConfigError("provider config missing required key 'provider'")

    kwargs = {k: v for k, v in config.items() if k != "provider"}
    name = config["provider"]

    provider_cls = PROVIDERS.get(name)
    if provider_cls is None:
        known = ", ".join(sorted(PROVIDERS))
        raise ProviderConfigError(f"unknown provider {name!r}; known: {known}")

    # Each adapter declares its own required kwargs (e.g. ``model``,
    # ``api_key``), so a missing one raises TypeError below -> ProviderConfigError.
    # This also lets wrappers like ``vulnerable_chatbot`` (which take ``backend``
    # instead of ``model``) be built from config without a bespoke guard.
    try:
        return provider_cls(**kwargs)
    except TypeError as exc:  # unexpected/invalid kwargs for this adapter
        raise ProviderConfigError(
            f"invalid config for provider {name!r}: {exc}"
        ) from exc


def provider_from_yaml(path: str | Path, key: str | None = None) -> LLMProvider:
    """Load a provider config from a YAML file and build the provider.

    Loading and ``${ENV}`` resolution are delegated to
    ``promptstrike.config.loader`` (the single owner of resolution); this helper
    only selects the relevant section and hands the resolved dict to the factory.

    The file may be a flat provider config, or a larger run config from which a
    sub-block is selected via ``key`` (e.g. ``key="target"`` or ``key="judge"``
    against ``configs/example.yaml``).

    Args:
        path: Path to the YAML file.
        key: Optional top-level key whose value is the provider config.

    Returns:
        A ready-to-use ``LLMProvider``.

    Raises:
        ProviderConfigError: If the selected section is missing or not a mapping.
    """
    # Imported locally so the providers package has no import-time dependency on
    # the config package; resolution still lives entirely in config.loader.
    from promptstrike.config.loader import load_config_dict

    doc = load_config_dict(path)
    section = doc.get(key) if key is not None else doc
    if not isinstance(section, dict):
        where = f"section {key!r}" if key else "top level"
        raise ProviderConfigError(f"expected a mapping at {where} of {path}")
    return create_provider(section)
