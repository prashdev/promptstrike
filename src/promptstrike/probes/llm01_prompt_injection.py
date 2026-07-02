"""LLM01:2025 Prompt Injection probe (MITRE ATLAS AML.T0051)."""

from __future__ import annotations

from promptstrike.models.probe import AttackResult
from promptstrike.probes.base import Probe, register
from promptstrike.providers.base import Provider


@register
class PromptInjectionProbe(Probe):
    """Attempts to override system instructions via injected user input."""

    name = "llm01_prompt_injection"
    owasp_id = "LLM01:2025"
    atlas_id = "AML.T0051"

    async def run(self, target: Provider) -> list[AttackResult]:  # noqa: D102
        raise NotImplementedError
