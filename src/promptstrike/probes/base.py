"""The ``Probe`` ABC and probe registration.

A probe produces attack attempts against a target via a ``Provider``. Every
probe declares its OWASP LLM id and MITRE ATLAS technique so findings can't
drift from their mappings, and registers itself so the engine can discover it.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from promptstrike.models.probe import AttackResult
from promptstrike.providers.base import Provider

_REGISTRY: dict[str, type[Probe]] = {}


def register(cls: type[Probe]) -> type[Probe]:
    """Class decorator that registers a probe by its ``name``."""
    _REGISTRY[cls.name] = cls
    return cls


class Probe(ABC):
    """Abstract attack module for one OWASP LLM category.

    Subclasses must set ``name``, ``owasp_id``, and ``atlas_id`` and implement
    :meth:`run`.
    """

    #: Unique probe key, e.g. ``"llm01_prompt_injection"``.
    name: str
    #: OWASP LLM id, e.g. ``"LLM01:2025"``.
    owasp_id: str
    #: MITRE ATLAS technique, e.g. ``"AML.T0051"``.
    atlas_id: str

    @abstractmethod
    async def run(self, target: Provider) -> list[AttackResult]:
        """Execute the probe's attacks against ``target``.

        Args:
            target: The provider under test.

        Returns:
            Raw attack results for the judge to score.
        """
        raise NotImplementedError
