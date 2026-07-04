"""GRC cross-references: OWASP LLM category → NIST AI RMF / ISO 42001 / EU AI Act.

Static reference data used by the report's governance/risk/compliance appendix.
The mappings are **indicative** — they point a compliance team at the controls
and obligations most relevant to each weakness class; they are not a certified
crosswalk and should be validated against an organisation's own control set.

Sources: NIST AI RMF 1.0 (AI 100-1) core subcategories, ISO/IEC 42001:2023
Annex A control groups, and the EU AI Act (Regulation (EU) 2024/1689) articles.
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

#: Shown beneath the GRC table so the mappings are not over-read.
GRC_CAVEAT = (
    "GRC mappings are indicative, not a certified crosswalk. They flag the "
    "controls and obligations most relevant to each weakness class and should be "
    "validated against your own control framework and legal advice."
)


@dataclass(frozen=True)
class GrcMapping:
    """Cross-framework references for one OWASP LLM category."""

    nist_ai_rmf: tuple[str, ...]
    iso_42001: tuple[str, ...]
    eu_ai_act: tuple[str, ...]


GRC_MAPPINGS: dict[str, GrcMapping] = {
    LLM01_PROMPT_INJECTION: GrcMapping(
        nist_ai_rmf=(
            "MEASURE 2.7 (Security & resilience)",
            "MANAGE 4.1 (Post-deployment monitoring)",
        ),
        iso_42001=("A.6.2 (AI system life cycle)",),
        eu_ai_act=(
            "Art. 15 (Accuracy, robustness & cybersecurity)",
            "Art. 9 (Risk management system)",
        ),
    ),
    LLM02_SENSITIVE_INFORMATION_DISCLOSURE: GrcMapping(
        nist_ai_rmf=(
            "MEASURE 2.10 (Privacy risk)",
            "MEASURE 2.7 (Security & resilience)",
        ),
        iso_42001=(
            "A.7 (Data for AI systems)",
            "A.5.2 (AI system impact assessment)",
        ),
        eu_ai_act=(
            "Art. 10 (Data & data governance)",
            "Art. 15 (Cybersecurity)",
        ),
    ),
    LLM05_IMPROPER_OUTPUT_HANDLING: GrcMapping(
        nist_ai_rmf=("MEASURE 2.7 (Security & resilience)",),
        iso_42001=("A.6.2 (AI system life cycle — verification & validation)",),
        eu_ai_act=("Art. 15 (Accuracy, robustness & cybersecurity)",),
    ),
    LLM06_EXCESSIVE_AGENCY: GrcMapping(
        nist_ai_rmf=(
            "MEASURE 2.7 (Security & resilience)",
            "MANAGE 4.1 (Post-deployment monitoring)",
        ),
        iso_42001=(
            "A.9 (Responsible use of AI systems)",
            "A.6.2 (AI system life cycle)",
        ),
        eu_ai_act=(
            "Art. 14 (Human oversight)",
            "Art. 15 (Robustness)",
        ),
    ),
    LLM07_SYSTEM_PROMPT_LEAKAGE: GrcMapping(
        nist_ai_rmf=("MEASURE 2.7 (Security & resilience)",),
        iso_42001=("A.6.2 (AI system life cycle)",),
        eu_ai_act=("Art. 15 (Cybersecurity)",),
    ),
    LLM09_MISINFORMATION: GrcMapping(
        nist_ai_rmf=(
            "MEASURE 2.3 (Validity & reliability)",
            "MEASURE 2.9 (Model explainability)",
        ),
        iso_42001=(
            "A.6.2 (AI system life cycle — verification & validation)",
            "A.8 (Information for interested parties)",
        ),
        eu_ai_act=(
            "Art. 50 (Transparency of AI-generated content)",
            "Art. 13 (Transparency to deployers)",
        ),
    ),
}


def grc_for(owasp_id: str) -> GrcMapping | None:
    """Return the GRC mapping for an OWASP LLM id, or None if unmapped."""
    return GRC_MAPPINGS.get(owasp_id)
