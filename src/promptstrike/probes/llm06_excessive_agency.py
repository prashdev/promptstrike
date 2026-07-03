"""LLM06:2025 Excessive Agency probe (no direct 1:1 MITRE ATLAS technique).

OWASP LLM06 is a *design weakness* (an LLM system granted excessive functionality,
permissions, or autonomy). ATLAS instead catalogues concrete adversary techniques,
so there is no clean 1:1 match. The closest techniques are the AI-agent-tool
family — AML.T0053 (AI Agent Tool Invocation), AML.T0086 (Exfiltration via AI
Agent Tool Invocation), AML.T0101 (Data Destruction via AI Agent Tool Invocation)
— which are exploitation *of* excessive agency, not the weakness itself. Per the
mappings policy we record ``NO_DIRECT_ATLAS_MAPPING`` rather than force one of them.
"""

from __future__ import annotations

from promptstrike.mappings.mitre_atlas import NO_DIRECT_ATLAS_MAPPING
from promptstrike.mappings.owasp_llm_2025 import LLM06_EXCESSIVE_AGENCY
from promptstrike.models.probe import AttackResult
from promptstrike.probes.base import Probe, register
from promptstrike.providers.base import Provider


@register
class ExcessiveAgencyProbe(Probe):
    """Attempts to trigger unauthorised tool use or actions beyond scope."""

    name = "llm06_excessive_agency"
    owasp_id = LLM06_EXCESSIVE_AGENCY
    atlas_id = NO_DIRECT_ATLAS_MAPPING

    async def run(self, target: Provider) -> list[AttackResult]:  # noqa: D102
        raise NotImplementedError
