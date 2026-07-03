"""LLM-as-judge: score whether one attack attempt succeeded.

Sends the payload, the probe's success criteria, and the target response to a
*separate* judge model under a strict JSON rubric, parses the JSON defensively,
and retries once if the first output is unparseable. If it still can't be
parsed, returns a fail-safe verdict (``success=False``, ``parse_error=True``)
rather than raising — a broken judge response must never be read as a pass.
"""

from __future__ import annotations

import json
import re

from pydantic import ValidationError

from promptstrike.judge.rubric import (
    JUDGE_RETRY_SUFFIX,
    JUDGE_SYSTEM_PROMPT,
    build_judge_user_prompt,
)
from promptstrike.models.finding import JudgeVerdict
from promptstrike.providers.base import LLMProvider

# Matches a ```json ... ``` or ``` ... ``` fenced block; we take the inner text.
_FENCE_RE = re.compile(r"```(?:json)?\s*(.*?)\s*```", re.DOTALL | re.IGNORECASE)


def _extract_json_object(text: str) -> dict | None:
    """Best-effort extraction of a single JSON object from model output.

    Tries, in order: the whole string, the contents of a markdown fence, and the
    substring from the first ``{`` to the last ``}``. Returns the parsed dict, or
    ``None`` if nothing parses to an object.
    """
    candidates: list[str] = [text]
    fence = _FENCE_RE.search(text)
    if fence:
        candidates.append(fence.group(1))
    first, last = text.find("{"), text.rfind("}")
    if first != -1 and last > first:
        candidates.append(text[first : last + 1])

    for candidate in candidates:
        try:
            parsed = json.loads(candidate)
        except (json.JSONDecodeError, ValueError):
            continue
        if isinstance(parsed, dict):
            return parsed
    return None


def _verdict_from_text(text: str) -> JudgeVerdict | None:
    """Parse judge output into a ``JudgeVerdict``, or ``None`` on failure."""
    obj = _extract_json_object(text)
    if obj is None:
        return None
    try:
        return JudgeVerdict.model_validate(obj)
    except ValidationError:
        return None


async def judge_attack(
    judge: LLMProvider,
    *,
    payload: str,
    success_criteria: str,
    response: str,
) -> JudgeVerdict:
    """Judge a single attack attempt and return a structured verdict.

    Calls the judge model, parses its JSON defensively, and retries exactly once
    with a reinforced format instruction if the first output is unparseable.

    Args:
        judge: The (separate) judge provider.
        payload: The adversarial prompt sent to the target.
        success_criteria: The probe's success criteria.
        response: The target's response text.

    Returns:
        The parsed verdict, or a fail-safe ``parse_error`` verdict if the judge
        never returned valid JSON.
    """
    user_prompt = build_judge_user_prompt(
        payload=payload,
        success_criteria=success_criteria,
        response=response,
    )

    # Attempt 1, then a single retry with a stronger format nudge.
    for prompt in (user_prompt, user_prompt + JUDGE_RETRY_SUFFIX):
        raw = await judge.chat(
            [{"role": "user", "content": prompt}],
            system=JUDGE_SYSTEM_PROMPT,
        )
        verdict = _verdict_from_text(raw)
        if verdict is not None:
            return verdict

    return JudgeVerdict(
        success=False,
        confidence=0.0,
        evidence="",
        reasoning="Judge output could not be parsed as JSON after one retry.",
        parse_error=True,
    )
