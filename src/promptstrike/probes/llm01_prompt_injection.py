"""LLM01:2025 Prompt Injection probe (MITRE ATLAS AML.T0051 LLM Prompt Injection)."""

from __future__ import annotations

from promptstrike.mappings.mitre_atlas import T0051_LLM_PROMPT_INJECTION
from promptstrike.mappings.owasp_llm_2025 import LLM01_PROMPT_INJECTION
from promptstrike.models.probe import AttackResult
from promptstrike.probes.base import Probe, register
from promptstrike.providers.base import Provider


@register
class PromptInjectionProbe(Probe):
    """Attempts to override system instructions via injected user input."""

    name = "llm01_prompt_injection"
    owasp_id = LLM01_PROMPT_INJECTION
    atlas_id = T0051_LLM_PROMPT_INJECTION

    async def run(self, target: Provider) -> list[AttackResult]:  # noqa: D102
        raise NotImplementedError
