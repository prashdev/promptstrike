"""Scan orchestration: load probes, run them, collect findings.

The scanner wires providers, probes, judge, and FP filter together and produces
``Finding`` objects for the reporter. It holds orchestration only — no attack or
scoring logic.
"""

from __future__ import annotations

from promptstrike.config.schema import RunConfig
from promptstrike.models.finding import Finding


async def run_scan(config: RunConfig) -> list[Finding]:
    """Execute a full scan described by ``config``.

    Args:
        config: The validated run config.

    Returns:
        The collected findings.
    """
    raise NotImplementedError
