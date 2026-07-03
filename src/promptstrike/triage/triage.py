"""Triage: turn raw judged Findings into scored, enriched TriagedFindings.

Pipeline (each stage is small and testable):
  1. False-positive filter — drop non-successful, unparseable, and low-confidence
     findings (``judge.false_positive``).
  2. De-duplicate — collapse near-identical findings (same category + evidence).
  3. Score — assign a documented severity via the rubric.
  4. Enrich — attach OWASP/ATLAS ids and names (verified mapping modules), a
     plain-English impact, reproduction steps, and OWASP remediation guidance.
Results are returned most-severe first.
"""

from __future__ import annotations

from promptstrike.judge.false_positive import filter_false_positives
from promptstrike.mappings.mitre_atlas import atlas_name
from promptstrike.mappings.owasp_guidance import guidance_for
from promptstrike.mappings.owasp_llm_2025 import owasp_title
from promptstrike.models.finding import Finding
from promptstrike.models.triage import Severity, TriagedFinding
from promptstrike.triage.rubric import SeverityRubric, load_rubric

# Sort order for "most severe first" output.
_SEVERITY_ORDER = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFO: 0,
}


def _signature(finding: Finding) -> tuple[str, str]:
    """A dedup key: same OWASP category + same normalised leaked evidence."""
    evidence = " ".join((finding.verdict.evidence or "").lower().split())
    if not evidence:
        evidence = " ".join((finding.transcript.response or "").lower().split())[:200]
    return (finding.owasp_id, evidence)


def deduplicate(findings: list[Finding]) -> list[tuple[Finding, int]]:
    """Collapse near-identical findings, keeping the highest-confidence one.

    Args:
        findings: Confirmed findings.

    Returns:
        ``(representative_finding, duplicate_count)`` pairs, first-seen order.
    """
    best: dict[tuple[str, str], tuple[Finding, int]] = {}
    order: list[tuple[str, str]] = []
    for finding in findings:
        sig = _signature(finding)
        if sig not in best:
            best[sig] = (finding, 1)
            order.append(sig)
            continue
        rep, count = best[sig]
        if finding.verdict.confidence > rep.verdict.confidence:
            rep = finding
        best[sig] = (rep, count + 1)
    return [best[sig] for sig in order]


def _reproduction(finding: Finding) -> list[str]:
    """Exact-payload reproduction steps, including how to re-run the scan."""
    return [
        "Send this as a single user message to the target (no other setup required):",
        f"    {finding.transcript.payload}",
        "Or re-run automatically: `promptstrike scan -c <config>` with probe "
        f"`{finding.probe_id}` enabled.",
    ]


def _impact(finding: Finding) -> str:
    """Category impact prose plus what was actually observed this run."""
    prose = guidance_for(finding.owasp_id).impact
    observed = (finding.verdict.evidence or "").strip()
    if observed:
        return f"{prose} In this scan the target exposed: “{observed[:200]}”."
    return f"{prose} The target's response met the attack's success criteria."


def triage_finding(
    finding: Finding,
    rubric: SeverityRubric,
    *,
    agentic: bool,
    duplicate_count: int = 1,
) -> TriagedFinding:
    """Score and enrich a single confirmed finding."""
    severity, vector, justification = rubric.score(
        owasp_id=finding.owasp_id,
        confidence=finding.verdict.confidence,
        agentic=agentic,
    )
    return TriagedFinding(
        probe_id=finding.probe_id,
        owasp_id=finding.owasp_id,
        owasp_title=owasp_title(finding.owasp_id),
        atlas_technique=finding.atlas_technique,
        atlas_name=atlas_name(finding.atlas_technique),
        category_name=finding.category_name,
        confidence=finding.verdict.confidence,
        evidence=finding.verdict.evidence,
        severity=severity,
        severity_vector=vector,
        severity_justification=justification,
        impact=_impact(finding),
        reproduction=_reproduction(finding),
        remediation=list(guidance_for(finding.owasp_id).remediation),
        transcript=finding.transcript,
        duplicate_count=duplicate_count,
    )


def triage_findings(
    findings: list[Finding],
    *,
    agentic: bool = False,
    rubric: SeverityRubric | None = None,
) -> list[TriagedFinding]:
    """Filter, de-duplicate, score, and enrich raw findings.

    Args:
        findings: Raw judged findings from a scan.
        agentic: Whether the target can take actions (drives escalation).
        rubric: Severity rubric; loaded from the default path when omitted.

    Returns:
        Triaged findings, most severe first (ties broken by confidence).
    """
    rubric = rubric or load_rubric()
    confirmed = filter_false_positives(findings, rubric.fp_confidence_threshold)
    deduped = deduplicate(confirmed)
    triaged = [
        triage_finding(f, rubric, agentic=agentic, duplicate_count=count)
        for f, count in deduped
    ]
    return sorted(
        triaged,
        key=lambda t: (_SEVERITY_ORDER[t.severity], t.confidence),
        reverse=True,
    )
