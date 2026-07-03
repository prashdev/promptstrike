"""Per-category enrichment: plain-English impact + OWASP mitigation advice.

Static reference data (kept in ``mappings/`` alongside the id catalogues) used by
the triage module to enrich a finding with a human-readable impact statement and
remediation guidance. The remediation bullets summarise the mitigation advice
from the OWASP Top 10 for LLM Applications (2025) for each category.
"""

from __future__ import annotations

from dataclasses import dataclass

from promptstrike.mappings.owasp_llm_2025 import (
    LLM01_PROMPT_INJECTION,
    LLM02_SENSITIVE_INFORMATION_DISCLOSURE,
    LLM05_IMPROPER_OUTPUT_HANDLING,
    LLM06_EXCESSIVE_AGENCY,
    LLM07_SYSTEM_PROMPT_LEAKAGE,
    LLM09_MISINFORMATION,
)


@dataclass(frozen=True)
class CategoryGuidance:
    """Impact prose and remediation bullets for one OWASP LLM category."""

    impact: str
    remediation: tuple[str, ...]


OWASP_GUIDANCE: dict[str, CategoryGuidance] = {
    LLM01_PROMPT_INJECTION: CategoryGuidance(
        impact=(
            "Attacker-controlled input overrode the application's intended "
            "instructions, letting the attacker redirect the model, extract its "
            "context, or drive unintended downstream behaviour."
        ),
        remediation=(
            "Treat all model output as untrusted; never let it act with implicit "
            "authority.",
            "Constrain behaviour with a tightly scoped system prompt and refuse "
            "out-of-scope requests.",
            "Segregate and clearly label external/untrusted content passed into "
            "the prompt.",
            "Require human approval for high-impact actions the model can trigger.",
            "Adversarially test (red-team) the application before and after "
            "deployment.",
        ),
    ),
    LLM02_SENSITIVE_INFORMATION_DISCLOSURE: CategoryGuidance(
        impact=(
            "The model disclosed sensitive information — credentials, API keys, "
            "internal configuration, or personal data — that should never reach "
            "an end user."
        ),
        remediation=(
            "Minimise and sanitise data: keep secrets and PII out of prompts, "
            "context, and training data.",
            "Enforce least-privilege access controls on the data the model can reach.",
            "Apply output filtering / DLP to redact secrets before they are returned.",
            "Govern data handling and educate users on what not to submit.",
        ),
    ),
    LLM05_IMPROPER_OUTPUT_HANDLING: CategoryGuidance(
        impact=(
            "The model emitted unsanitised, active content that a downstream "
            "consumer could execute or render — enabling XSS, SQL injection, "
            "SSRF, or remote code execution if passed on without validation."
        ),
        remediation=(
            "Treat model output as untrusted user input at every downstream sink.",
            "Apply context-aware encoding/escaping (HTML, SQL, shell) before use.",
            "Use parameterised queries and avoid passing output to interpreters.",
            "Apply least privilege to any system that consumes the output.",
        ),
    ),
    LLM06_EXCESSIVE_AGENCY: CategoryGuidance(
        impact=(
            "The system was willing to take (or claimed to take) a consequential, "
            "state-changing action beyond its intended advisory scope, driven by "
            "excessive functionality, permissions, or autonomy."
        ),
        remediation=(
            "Minimise tools, functions, and permissions to only what the task "
            "requires; avoid open-ended capabilities.",
            "Require human-in-the-loop approval for consequential or irreversible "
            "actions.",
            "Enforce authorisation in the downstream systems themselves — do not "
            "rely on the model to self-restrict.",
            "Rate-limit and log all actions the model can initiate.",
        ),
    ),
    LLM07_SYSTEM_PROMPT_LEAKAGE: CategoryGuidance(
        impact=(
            "The model revealed its system prompt / developer instructions, "
            "exposing hidden rules, embedded secrets, and design details that aid "
            "further attacks."
        ),
        remediation=(
            "Never place secrets or credentials in the system prompt.",
            "Do not rely on the system prompt as a security control; enforce "
            "guardrails independently of it.",
            "Keep sensitive logic and authorisation server-side, outside the "
            "model's context.",
        ),
    ),
    LLM09_MISINFORMATION: CategoryGuidance(
        impact=(
            "The model asserted fabricated or false information as fact, which a "
            "user could trust and act on."
        ),
        remediation=(
            "Ground responses in verified sources (e.g. RAG) and require citations.",
            "Add human oversight / fact-checking for high-stakes outputs.",
            "Communicate model uncertainty and limitations to users.",
        ),
    ),
}


def guidance_for(owasp_id: str) -> CategoryGuidance:
    """Return enrichment guidance for an OWASP LLM id.

    Args:
        owasp_id: An id such as ``"LLM01:2025"``.

    Returns:
        The category's impact prose and remediation bullets.

    Raises:
        KeyError: If no guidance is defined for the id.
    """
    return OWASP_GUIDANCE[owasp_id]
