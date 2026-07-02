"""LLM07:2025 System Prompt Leakage probe (MITRE ATLAS AML.T0056)."""

from __future__ import annotations

from promptstrike.models.probe import AttackResult
from promptstrike.probes.base import Probe, register
from promptstrike.providers.base import Provider


@register
class SystemPromptLeakProbe(Probe):
    """Attempts to make the target reveal its hidden system prompt."""

    name = "llm07_system_prompt_leak"
    owasp_id = "LLM07:2025"
    atlas_id = "AML.T0056"

    async def run(self, target: Provider) -> list[AttackResult]:  # noqa: D102
        raise NotImplementedError
