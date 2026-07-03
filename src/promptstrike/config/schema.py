"""Pydantic models describing a PromptStrike run config (the YAML schema).

These models define the shape of a run: the target endpoint, judge settings,
which probes to run, and report output. Validation lives here; loading and
``${ENV}`` resolution live in ``config.loader``.

``target`` and ``judge`` are left as free-form mappings because their keys vary
per provider; they are validated when handed to ``providers.create_provider``.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class RunConfig(BaseModel):
    """Top-level config for a single scan run."""

    model_config = ConfigDict(extra="forbid")

    target: dict[str, Any] = Field(
        description="Provider config for the target under test (see create_provider)."
    )
    judge: dict[str, Any] = Field(
        description="Provider config for the separate judge model."
    )
    probes: list[str] | None = Field(
        default=None,
        description="Optional probe ids to run; None runs the whole library.",
    )
    probe_dir: str | None = Field(
        default=None,
        description="Optional override for the probe YAML directory.",
    )
    report: dict[str, Any] | None = Field(
        default=None,
        description="Optional report settings (format, output path).",
    )
