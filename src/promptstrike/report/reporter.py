"""Build report context from findings and render via jinja2 templates.

Pure presentation: consumes ``Finding`` models and produces a rendered report.
Adding an output format is a new template plus a branch here — no logic changes
elsewhere.
"""

from __future__ import annotations

from promptstrike.models.finding import Finding


def render_report(findings: list[Finding], fmt: str = "md") -> str:
    """Render findings into a report string.

    Args:
        findings: The findings to report.
        fmt: Output format key (``"md"`` or ``"html"``).

    Returns:
        The rendered report text.
    """
    raise NotImplementedError
