"""Static catalogue of the OWASP Top 10 for LLM Applications (2025).

Single source of truth for OWASP LLM ids and titles. Reference the ``LLM*``
id constants below (and ``OWASP_LLM_2025`` for id -> title) instead of retyping
literal strings elsewhere, so ids and titles can never drift.

Titles verified against the official list at
https://genai.owasp.org/llm-top-10/ (OWASP Top 10 for LLM Applications, 2025).
"""

from __future__ import annotations

# Stable id constants — use these instead of hard-coding the literal strings.
LLM01_PROMPT_INJECTION = "LLM01:2025"
LLM02_SENSITIVE_INFORMATION_DISCLOSURE = "LLM02:2025"
LLM03_SUPPLY_CHAIN = "LLM03:2025"
LLM04_DATA_AND_MODEL_POISONING = "LLM04:2025"
LLM05_IMPROPER_OUTPUT_HANDLING = "LLM05:2025"
LLM06_EXCESSIVE_AGENCY = "LLM06:2025"
LLM07_SYSTEM_PROMPT_LEAKAGE = "LLM07:2025"
LLM08_VECTOR_AND_EMBEDDING_WEAKNESSES = "LLM08:2025"
LLM09_MISINFORMATION = "LLM09:2025"
LLM10_UNBOUNDED_CONSUMPTION = "LLM10:2025"

#: Maps OWASP LLM id -> official 2025 title.
OWASP_LLM_2025: dict[str, str] = {
    LLM01_PROMPT_INJECTION: "Prompt Injection",
    LLM02_SENSITIVE_INFORMATION_DISCLOSURE: "Sensitive Information Disclosure",
    LLM03_SUPPLY_CHAIN: "Supply Chain",
    LLM04_DATA_AND_MODEL_POISONING: "Data and Model Poisoning",
    LLM05_IMPROPER_OUTPUT_HANDLING: "Improper Output Handling",
    LLM06_EXCESSIVE_AGENCY: "Excessive Agency",
    LLM07_SYSTEM_PROMPT_LEAKAGE: "System Prompt Leakage",
    LLM08_VECTOR_AND_EMBEDDING_WEAKNESSES: "Vector and Embedding Weaknesses",
    LLM09_MISINFORMATION: "Misinformation",
    LLM10_UNBOUNDED_CONSUMPTION: "Unbounded Consumption",
}


def owasp_title(owasp_id: str) -> str:
    """Return the official title for an OWASP LLM id.

    Args:
        owasp_id: An id such as ``"LLM01:2025"``.

    Returns:
        The catalogue title.

    Raises:
        KeyError: If the id is not in the 2025 catalogue.
    """
    return OWASP_LLM_2025[owasp_id]
