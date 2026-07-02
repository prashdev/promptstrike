"""Domain models describing probe metadata and attack results.

``AttackResult`` captures a single attack attempt (the prompt sent and the
target's response) before it is scored by the judge.
"""

from __future__ import annotations

from pydantic import BaseModel


class AttackResult(BaseModel):
    """The raw outcome of one attack attempt, pre-judging. TODO: define fields."""
