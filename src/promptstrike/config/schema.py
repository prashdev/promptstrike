"""Pydantic models describing a PromptStrike run config (the YAML schema).

These models define the shape of a run: the target endpoint, judge settings,
which probes to run, and report output. Validation lives here; loading and
``${ENV}`` resolution live in ``config.loader``.

``target`` and ``judge`` are left as free-form mappings because their keys vary
per provider; they are validated when handed to ``providers.create_provider``.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator


class RunConfig(BaseModel):
    """Top-level config for a single scan run."""

    model_config = ConfigDict(extra="forbid")

    target: dict[str, Any] = Field(
        description="Provider config for the target under test (see create_provider)."
    )
    judge: dict[str, Any] = Field(
        description="Provider config for the separate judge model."
    )
    agentic: bool = Field(
        default=False,
        description=(
            "Whether the target can take actions (tools/plugins/autonomy). "
            "Set in YAML as target.agentic; it is lifted out of the target block "
            "so the provider factory never sees it. Drives triage severity "
            "escalation for action-oriented categories."
        ),
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

    @model_validator(mode="before")
    @classmethod
    def _lift_agentic_from_target(cls, data: Any) -> Any:
        """Move ``target.agentic`` up to the top-level ``agentic`` field.

        Users declare the flag under ``target`` in YAML (it is a property of the
        target), but the provider factory must not receive it as a constructor
        kwarg — so we lift it out before validation.
        """
        if isinstance(data, dict) and isinstance(data.get("target"), dict):
            target = data["target"]
            if "agentic" in target:
                target = dict(target)
                data = dict(data)
                data["agentic"] = target.pop("agentic")
                data["target"] = target
        return data
