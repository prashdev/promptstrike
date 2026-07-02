"""Pydantic models describing a PromptStrike run config (the YAML schema).

These models define the shape of a run: the target endpoint, which probe suites
to run, judge settings, and report output. Validation lives here; loading and
``${ENV}`` resolution live in ``config.loader``.
"""

from __future__ import annotations

from pydantic import BaseModel


class RunConfig(BaseModel):
    """Top-level config for a single scan run.

    TODO: define fields (target, credentials refs, probe selection, judge
    settings, report format).
    """
