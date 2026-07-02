"""LLM-as-judge: scores whether an attack attempt succeeded.

Runs a judge model against an ``AttackResult`` using a structured rubric and
returns a verdict plus score. The judge is a separate stage from probes so the
judging strategy or model can change without touching attack logic.
"""

from __future__ import annotations

from promptstrike.models.probe import AttackResult
from promptstrike.providers.base import Provider


async def score_attack(judge: Provider, result: AttackResult) -> object:
    """Score one attack attempt with the judge model.

    Args:
        judge: Provider wrapping the judge model.
        result: The attack attempt to evaluate.

    Returns:
        A verdict object (score + rationale). TODO: define verdict model.
    """
    raise NotImplementedError
