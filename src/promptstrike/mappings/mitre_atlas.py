"""Static catalogue of MITRE ATLAS techniques referenced by PromptStrike.

Single source of truth for ATLAS technique ids and names. Reference the ``T*``
id constants below (and ``MITRE_ATLAS`` for id -> name) instead of retyping
literal strings elsewhere.

Names verified verbatim against the official MITRE ATLAS data,
``dist/ATLAS.yaml`` at https://github.com/mitre-atlas/atlas-data (version 5.6.0).
Do not add an id here without confirming it against that catalogue.

Not every OWASP LLM category has a clean 1:1 ATLAS technique. Where it does not,
use ``NO_DIRECT_ATLAS_MAPPING`` rather than forcing an approximate id — an honest
"no mapping" is more useful than a wrong one.
"""

from __future__ import annotations

#: Version of the MITRE ATLAS catalogue these names were verified against.
ATLAS_VERSION = "5.6.0"

#: Valid, explicit value for "this category has no clean 1:1 ATLAS technique".
NO_DIRECT_ATLAS_MAPPING = "no direct ATLAS mapping"

# Stable id constants — use these instead of hard-coding the literal strings.
T0051_LLM_PROMPT_INJECTION = "AML.T0051"
T0051_000_DIRECT = "AML.T0051.000"
T0051_001_INDIRECT = "AML.T0051.001"
T0053_AI_AGENT_TOOL_INVOCATION = "AML.T0053"
T0056_EXTRACT_LLM_SYSTEM_PROMPT = "AML.T0056"
T0057_LLM_DATA_LEAKAGE = "AML.T0057"
T0086_EXFILTRATION_VIA_AI_AGENT_TOOL_INVOCATION = "AML.T0086"
T0101_DATA_DESTRUCTION_VIA_AI_AGENT_TOOL_INVOCATION = "AML.T0101"

#: Maps ATLAS technique id -> official name (verbatim from ATLAS 5.6.0).
#: Sub-technique names are shown with their parent for readability.
MITRE_ATLAS: dict[str, str] = {
    T0051_LLM_PROMPT_INJECTION: "LLM Prompt Injection",
    T0051_000_DIRECT: "LLM Prompt Injection: Direct",
    T0051_001_INDIRECT: "LLM Prompt Injection: Indirect",
    T0053_AI_AGENT_TOOL_INVOCATION: "AI Agent Tool Invocation",
    T0056_EXTRACT_LLM_SYSTEM_PROMPT: "Extract LLM System Prompt",
    T0057_LLM_DATA_LEAKAGE: "LLM Data Leakage",
    T0086_EXFILTRATION_VIA_AI_AGENT_TOOL_INVOCATION: (
        "Exfiltration via AI Agent Tool Invocation"
    ),
    T0101_DATA_DESTRUCTION_VIA_AI_AGENT_TOOL_INVOCATION: (
        "Data Destruction via AI Agent Tool Invocation"
    ),
}


def atlas_name(atlas_id: str) -> str:
    """Return the official ATLAS name for a technique id (or the sentinel).

    Args:
        atlas_id: An id such as ``"AML.T0051"``, or ``NO_DIRECT_ATLAS_MAPPING``.

    Returns:
        The catalogue name, or the sentinel string unchanged.

    Raises:
        KeyError: If the id is neither in the catalogue nor the sentinel.
    """
    if atlas_id == NO_DIRECT_ATLAS_MAPPING:
        return NO_DIRECT_ATLAS_MAPPING
    return MITRE_ATLAS[atlas_id]
