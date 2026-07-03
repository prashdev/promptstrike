"""Domain models for triaged findings.

A ``TriagedFinding`` is a confirmed weakness after false-positive filtering,
de-duplication, severity scoring, and enrichment. It is the fully self-describing
unit the reporter renders: taxonomy ids + names, a documented severity (with a
CVSS-style vector and justification), impact, reproduction steps, remediation,
and the raw transcript for provenance.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field

from promptstrike.models.finding import Transcript


class Severity(StrEnum):
    """Ordinal severity levels, highest to lowest."""

    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


class TriagedFinding(BaseModel):
    """A confirmed, scored, enriched finding ready for reporting."""

    # -- identity / taxonomy --
    probe_id: str
    owasp_id: str
    owasp_title: str
    atlas_technique: str
    atlas_name: str
    category_name: str

    # -- judge verdict carried forward --
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: str

    # -- severity (documented, auditable) --
    severity: Severity
    severity_vector: str = Field(
        description="CVSS-style vector string capturing the scoring inputs."
    )
    severity_justification: str = Field(
        description="One-line explanation of how the severity was derived."
    )

    # -- enrichment --
    impact: str
    reproduction: list[str]
    remediation: list[str]

    # -- provenance / dedup --
    transcript: Transcript
    duplicate_count: int = Field(
        default=1,
        ge=1,
        description="How many near-identical raw findings this represents.",
    )
