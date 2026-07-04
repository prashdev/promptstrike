"""The ``ScanRun`` model: raw scan output persisted between scan and report.

A scan produces raw (pre-triage) findings plus the metadata needed to triage and
report later — the target label, whether the target is agentic, and when it ran.
Persisting this as JSON makes a scan and a re-report fully separable: run the scan
once (which needs network access to the target and judge), then re-render the
report offline as often as you like, with different thresholds or filters.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field

from promptstrike import __version__
from promptstrike.models.finding import Finding


class ScanRun(BaseModel):
    """Raw results of one scan, serialisable to/from JSON."""

    tool: str = "PromptStrike"
    version: str = __version__
    target: str = Field(description="Human-readable target label.")
    agentic: bool = Field(
        default=False,
        description="Whether the target can take actions (drives triage).",
    )
    scanned_at: datetime
    config_path: str | None = None
    findings: list[Finding] = Field(
        description="Raw, pre-triage judged findings (one per payload sent)."
    )
