"""LLM06:2025 Excessive Agency probe (MITRE ATLAS AML.T0053)."""

from __future__ import annotations

from promptstrike.models.probe import AttackResult
from promptstrike.probes.base import Probe, register
from promptstrike.providers.base import Provider


@register
class ExcessiveAgencyProbe(Probe):
    """Attempts to trigger unauthorised tool use or actions beyond scope."""

    name = "llm06_excessive_agency"
    owasp_id = "LLM06:2025"
    atlas_id = "AML.T0053"

    async def run(self, target: Provider) -> list[AttackResult]:  # noqa: D102
        raise NotImplementedError
