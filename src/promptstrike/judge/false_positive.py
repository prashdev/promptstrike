"""Post-verdict false-positive filtering.

Drops findings that should not survive into triage: non-successful verdicts,
fail-safe parse errors, and low-confidence verdicts below a configurable
threshold. A distinct, testable stage so the final verdict is never a raw string
match.
"""

from __future__ import annotations

from promptstrike.models.finding import Finding


def is_false_positive(finding: Finding, confidence_threshold: float) -> bool:
    """Decide whether a finding is a false positive and should be dropped.

    Args:
        finding: A judged finding.
        confidence_threshold: Minimum judge confidence to keep a finding.

    Returns:
        True if the finding should be discarded (not a confirmed weakness,
        an unparseable judge response, or below the confidence threshold).
    """
    verdict = finding.verdict
    return (
        not verdict.success
        or verdict.parse_error
        or verdict.confidence < confidence_threshold
    )


def filter_false_positives(
    findings: list[Finding], confidence_threshold: float
) -> list[Finding]:
    """Return only the findings that survive false-positive filtering.

    Args:
        findings: Raw judged findings.
        confidence_threshold: Minimum judge confidence to keep a finding.

    Returns:
        The confirmed findings, in input order.
    """
    return [f for f in findings if not is_false_positive(f, confidence_threshold)]
