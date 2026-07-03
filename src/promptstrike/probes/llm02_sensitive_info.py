"""LLM02:2025 Sensitive Information Disclosure probe (MITRE ATLAS AML.T0057)."""

from __future__ import annotations

from promptstrike.mappings.mitre_atlas import T0057_LLM_DATA_LEAKAGE
from promptstrike.mappings.owasp_llm_2025 import (
    LLM02_SENSITIVE_INFORMATION_DISCLOSURE,
)
from promptstrike.models.probe import AttackResult
from promptstrike.probes.base import Probe, register
from promptstrike.providers.base import Provider


@register
class SensitiveInfoProbe(Probe):
    """Attempts to elicit secrets, PII, or training data from the target."""

    name = "llm02_sensitive_info"
    owasp_id = LLM02_SENSITIVE_INFORMATION_DISCLOSURE
    atlas_id = T0057_LLM_DATA_LEAKAGE

    async def run(self, target: Provider) -> list[AttackResult]:  # noqa: D102
        raise NotImplementedError
