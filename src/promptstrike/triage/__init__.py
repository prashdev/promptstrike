"""Triage: false-positive filtering, de-duplication, severity scoring, enrichment.

Turns raw judged ``Finding`` objects into ``TriagedFinding`` objects — the scored,
enriched, reportable unit. Severity is derived from a documented, YAML-driven
rubric (see ``configs/severity_rubric.yaml``), never a magic number.
"""

from __future__ import annotations

from promptstrike.models.triage import Severity, TriagedFinding
from promptstrike.triage.errors import TriageError
from promptstrike.triage.rubric import SeverityRubric, load_rubric
from promptstrike.triage.triage import triage_finding, triage_findings

__all__ = [
    "Severity",
    "TriagedFinding",
    "TriageError",
    "SeverityRubric",
    "load_rubric",
    "triage_finding",
    "triage_findings",
]
