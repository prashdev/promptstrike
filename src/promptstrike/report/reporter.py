"""Build report context from triaged findings and render via Jinja2.

Produces a single self-contained HTML report (inline CSS, no external assets,
dark theme) and a GitHub-flavoured Markdown report. All presentation lives in the
templates; this module computes the context — severity counts, the SVG severity
bar, the CISO risk narrative, the coverage matrix, redacted evidence, and the GRC
appendix — so the templates stay dumb.

Redaction note: the HTML template autoescapes, so an attacker-controlled response
(which may contain ``<script>``) cannot inject into the report. On top of that we
best-effort redact secrets (API keys, emails, labelled credentials) from the
evidence shown.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from promptstrike import __version__
from promptstrike.mappings.grc import GRC_CAVEAT, grc_for
from promptstrike.mappings.owasp_llm_2025 import OWASP_LLM_2025
from promptstrike.models.probe import Probe
from promptstrike.models.triage import Severity, TriagedFinding
from promptstrike.probes.loader import load_probes

_TEMPLATES = Path(__file__).resolve().parent / "templates"

_SEVERITY_ORDER = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
]
#: Dark-theme palette (bright hues that read on a dark background).
_SEVERITY_COLOR = {
    Severity.CRITICAL: "#f2495c",
    Severity.HIGH: "#ff7a45",
    Severity.MEDIUM: "#f5b301",
    Severity.LOW: "#4cc4e8",
    Severity.INFO: "#8b949e",
}

_RESPONSE_EXCERPT_CHARS = 700

# --- redaction ---------------------------------------------------------------
_API_KEY_RE = re.compile(r"\bsk-[A-Za-z0-9_-]{6,}\b")
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_LABELLED_RE = re.compile(
    r"(?i)\b(password|passcode|passwd|secret|api[ _-]?key|token|credential)\b"
    r"(\s*(?:is|:|=)\s*)([^\s,\";”“]+)"
)
_JSON_SECRET_RE = re.compile(
    r'(?i)("(?:[^"]*'
    r"(?:password|passcode|secret|api[_-]?key|token|credential|override)"
    r'[^"]*)"\s*:\s*")([^"]*)(")'
)
_REDACTED = "«redacted»"


def _mask_email(match: re.Match[str]) -> str:
    """Mask an email's local part: ``jane.roe@example.com`` → ``j…@example.com``."""
    local, _, domain = match.group().partition("@")
    return f"{local[:1]}…@{domain}"


def redact(text: str) -> str:
    """Best-effort redaction of secrets from evidence shown in the report."""
    text = _API_KEY_RE.sub(_REDACTED, text)
    text = _JSON_SECRET_RE.sub(rf"\1{_REDACTED}\3", text)
    text = _LABELLED_RE.sub(rf"\1\2{_REDACTED}", text)
    text = _EMAIL_RE.sub(_mask_email, text)
    return text


def _severity_bar_svg(counts: dict[Severity, int]) -> str:
    """A stacked horizontal SVG bar of the severity distribution."""
    total = sum(counts.values())
    if total == 0:
        return (
            '<svg viewBox="0 0 100 8" width="100%" height="14" '
            'preserveAspectRatio="none" role="img" aria-label="no findings">'
            '<rect x="0" y="0" width="100" height="8" fill="#30363d"/></svg>'
        )
    segments: list[str] = []
    x = 0.0
    for sev in _SEVERITY_ORDER:
        n = counts[sev]
        if not n:
            continue
        w = n / total * 100
        segments.append(
            f'<rect x="{x:.3f}" y="0" width="{w:.3f}" height="8" '
            f'fill="{_SEVERITY_COLOR[sev]}"><title>{sev.value}: {n}</title></rect>'
        )
        x += w
    return (
        '<svg viewBox="0 0 100 8" width="100%" height="14" '
        'preserveAspectRatio="none" role="img" '
        f'aria-label="severity distribution of {total} findings">'
        f"{''.join(segments)}</svg>"
    )


def _risk_narrative(
    target: str, findings: list[TriagedFinding], counts: dict[Severity, int]
) -> str:
    """A 3-sentence, CISO-ready risk narrative derived from the findings."""
    total = len(findings)
    if total == 0:
        return (
            f"PromptStrike assessed {target} against the OWASP LLM Top 10 (2025) "
            "and confirmed no findings in the tested categories. This indicates "
            "the tested attack classes did not succeed under the current "
            "configuration. Re-test after any change to the model, system prompt, "
            "or tool surface, and keep the out-of-scope categories in mind for a "
            "fuller assessment."
        )
    categories = sorted({f.category_name for f in findings})
    crit, high = counts[Severity.CRITICAL], counts[Severity.HIGH]
    top = findings[0]
    cat_list = ", ".join(categories[:3])
    s1 = (
        f"PromptStrike assessed {target} against the OWASP LLM Top 10 (2025) and "
        f"confirmed {total} finding{'s' if total != 1 else ''} across "
        f"{len(categories)} categor{'ies' if len(categories) != 1 else 'y'}, "
        f"including {crit} Critical and {high} High-severity issue"
        f"{'s' if high != 1 else ''}."
    )
    s2 = (
        f"The highest-rated weakness is a {top.severity.value} "
        f"{top.category_name} issue ({top.owasp_id}); across the confirmed "
        f"findings ({cat_list}) an unauthorised user can extract secrets, "
        "override the assistant's instructions, or drive unintended behaviour."
    )
    s3 = (
        f"Remediation of the {crit} Critical and {high} High finding"
        f"{'s' if (crit + high) != 1 else ''} should be prioritised before "
        "production exposure; per-finding guidance and control mappings (NIST AI "
        "RMF, ISO/IEC 42001, EU AI Act) are provided below."
    )
    return f"{s1} {s2} {s3}"


def _coverage_matrix(
    probes: list[Probe], findings: list[TriagedFinding]
) -> list[dict[str, object]]:
    """All 10 OWASP LLM categories with tested/out-of-scope status + counts."""
    by_id = {p.owasp_id: p for p in probes}
    finding_counts: dict[str, int] = {}
    for f in findings:
        finding_counts[f.owasp_id] = finding_counts.get(f.owasp_id, 0) + 1

    rows: list[dict[str, object]] = []
    for owasp_id, title in OWASP_LLM_2025.items():
        probe = by_id.get(owasp_id)
        if probe is None:
            status, note = "Not covered", ""
        elif probe.out_of_scope:
            status, note = "Out of scope", probe.out_of_scope_reason or ""
        else:
            status, note = "Tested", ""
        rows.append(
            {
                "owasp_id": owasp_id,
                "title": title,
                "status": status,
                "note": note.strip(),
                "findings": finding_counts.get(owasp_id, 0),
            }
        )
    return rows


def _response_excerpt(response: str) -> str:
    """A redacted, length-capped excerpt of the target response."""
    excerpt = response.strip()
    if len(excerpt) > _RESPONSE_EXCERPT_CHARS:
        excerpt = excerpt[:_RESPONSE_EXCERPT_CHARS].rstrip() + " …"
    return redact(excerpt)


def _finding_view(index: int, f: TriagedFinding) -> dict[str, object]:
    """Presentation-ready, redacted view of one triaged finding."""
    return {
        "index": index,
        "title": f"{f.owasp_id} — {f.category_name}",
        "severity": f.severity.value,
        "severity_color": _SEVERITY_COLOR[f.severity],
        "vector": f.severity_vector,
        "justification": f.severity_justification,
        "owasp_id": f.owasp_id,
        "owasp_title": f.owasp_title,
        "atlas_technique": f.atlas_technique,
        "atlas_name": f.atlas_name,
        "confidence": f"{f.confidence:.2f}",
        "duplicate_count": f.duplicate_count,
        "impact": redact(f.impact),
        "reproduction": [redact(step) for step in f.reproduction],
        "request": redact(f.transcript.payload),
        "response_excerpt": _response_excerpt(f.transcript.response),
        "evidence": redact(f.evidence),
        "remediation": list(f.remediation),
    }


def _grc_rows(findings: list[TriagedFinding]) -> list[dict[str, object]]:
    """One GRC row per distinct OWASP category present, in finding order."""
    seen: set[str] = set()
    rows: list[dict[str, object]] = []
    for f in findings:
        if f.owasp_id in seen:
            continue
        seen.add(f.owasp_id)
        mapping = grc_for(f.owasp_id)
        rows.append(
            {
                "owasp_id": f.owasp_id,
                "title": f.category_name,
                "nist": list(mapping.nist_ai_rmf) if mapping else [],
                "iso": list(mapping.iso_42001) if mapping else [],
                "eu": list(mapping.eu_ai_act) if mapping else [],
            }
        )
    return rows


def build_context(
    findings: list[TriagedFinding],
    *,
    target: str,
    probes: list[Probe],
    scanned_at: datetime,
) -> dict[str, object]:
    """Assemble the full template context from triaged findings + scan metadata."""
    counts = dict.fromkeys(_SEVERITY_ORDER, 0)
    for f in findings:
        counts[f.severity] += 1

    coverage = _coverage_matrix(probes, findings)
    tested = sum(1 for row in coverage if row["status"] == "Tested")
    out_of_scope = sum(1 for row in coverage if row["status"] == "Out of scope")

    return {
        "target": target,
        "scanned_at": scanned_at.strftime("%Y-%m-%d"),
        "generated_at": scanned_at.strftime("%Y-%m-%d %H:%M UTC"),
        "tool": "PromptStrike",
        "version": __version__,
        "total_findings": len(findings),
        "severity_counts": [
            (sev.value, counts[sev], _SEVERITY_COLOR[sev]) for sev in _SEVERITY_ORDER
        ],
        "severity_bar_svg": _severity_bar_svg(counts),
        "narrative": _risk_narrative(target, findings, counts),
        "coverage": coverage,
        "tested_count": tested,
        "out_of_scope_count": out_of_scope,
        "findings": [_finding_view(i + 1, f) for i, f in enumerate(findings)],
        "grc_rows": _grc_rows(findings),
        "grc_caveat": GRC_CAVEAT,
    }


def render_report(
    findings: list[TriagedFinding],
    *,
    target: str,
    probes: list[Probe] | None = None,
    scanned_at: datetime | None = None,
    fmt: str = "html",
) -> str:
    """Render a triaged findings list into an HTML or Markdown report.

    Args:
        findings: Triaged findings (already scored/enriched), most severe first.
        target: Human-readable target label for the report header.
        probes: The probe library for the coverage matrix (defaults to the
            full shipped library).
        scanned_at: Timestamp for the report (defaults to now, UTC).
        fmt: ``"html"`` or ``"md"``.

    Returns:
        The rendered report as a string.

    Raises:
        ValueError: If ``fmt`` is not ``"html"`` or ``"md"``.
    """
    if fmt not in ("html", "md"):
        raise ValueError(f"unknown report format {fmt!r}; expected 'html' or 'md'")
    probes = probes if probes is not None else load_probes()
    scanned_at = scanned_at or datetime.now(UTC)

    env = Environment(
        loader=FileSystemLoader(_TEMPLATES),
        autoescape=lambda name: bool(name) and name.endswith(".html.j2"),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    context = build_context(
        findings, target=target, probes=probes, scanned_at=scanned_at
    )
    template = "report.html.j2" if fmt == "html" else "report.md.j2"
    return env.get_template(template).render(**context)
