"""LLM07:2025 System Prompt Leakage probe (MITRE ATLAS AML.T0056).

ATLAS names this technique "Extract LLM System Prompt"; OWASP frames the same
weakness as "System Prompt Leakage".
"""

from __future__ import annotations

from promptstrike.mappings.mitre_atlas import T0056_EXTRACT_LLM_SYSTEM_PROMPT
from promptstrike.mappings.owasp_llm_2025 import LLM07_SYSTEM_PROMPT_LEAKAGE
from promptstrike.models.probe import AttackResult
from promptstrike.probes.base import Probe, register
from promptstrike.providers.base import Provider


@register
class SystemPromptLeakProbe(Probe):
    """Attempts to make the target reveal its hidden system prompt."""

    name = "llm07_system_prompt_leak"
    owasp_id = LLM07_SYSTEM_PROMPT_LEAKAGE
    atlas_id = T0056_EXTRACT_LLM_SYSTEM_PROMPT

    async def run(self, target: Provider) -> list[AttackResult]:  # noqa: D102
        raise NotImplementedError
