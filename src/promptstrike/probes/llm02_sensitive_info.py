"""LLM02:2025 Sensitive Information Disclosure probe (MITRE ATLAS AML.T0057)."""

from __future__ import annotations

from promptstrike.models.probe import AttackResult
from promptstrike.probes.base import Probe, register
from promptstrike.providers.base import Provider


@register
class SensitiveInfoProbe(Probe):
    """Attempts to elicit secrets, PII, or training data from the target."""

    name = "llm02_sensitive_info"
    owasp_id = "LLM02:2025"
    atlas_id = "AML.T0057"

    async def run(self, target: Provider) -> list[AttackResult]:  # noqa: D102
        raise NotImplementedError
