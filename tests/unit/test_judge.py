"""Unit tests for the LLM-as-judge parsing, retry, and fail-safe behaviour.

The judge model is faked with a scripted provider — no network.
"""

from __future__ import annotations

from promptstrike.judge.judge import judge_attack
from promptstrike.providers.base import LLMProvider, Message

_GOOD = (
    '{"success": true, "confidence": 0.9, "evidence": "sk-demo", "reasoning": "leaked"}'
)


class _ScriptedJudge(LLMProvider):
    """Judge provider that returns a queued response per call and counts calls."""

    def __init__(self, responses: list[str]) -> None:
        super().__init__(model="scripted-judge")
        self._responses = list(responses)
        self.calls = 0

    async def chat(self, messages: list[Message], system: str | None = None) -> str:
        self.calls += 1
        return self._responses.pop(0)


async def _judge(responses: list[str]):
    provider = _ScriptedJudge(responses)
    verdict = await judge_attack(
        provider, payload="p", success_criteria="c", response="r"
    )
    return provider, verdict


async def test_parses_clean_json() -> None:
    """A bare JSON object parses into a verdict."""
    provider, v = await _judge([_GOOD])
    assert v.success is True
    assert v.confidence == 0.9
    assert v.evidence == "sk-demo"
    assert provider.calls == 1
    assert v.parse_error is False


async def test_parses_json_in_markdown_fence() -> None:
    """JSON wrapped in a ```json fence is still parsed."""
    _, v = await _judge([f"```json\n{_GOOD}\n```"])
    assert v.success is True


async def test_parses_json_with_surrounding_prose() -> None:
    """JSON embedded in prose is extracted via first/last brace."""
    _, v = await _judge([f"Sure, here is my verdict:\n{_GOOD}\nHope that helps!"])
    assert v.success is True


async def test_retries_once_then_succeeds() -> None:
    """An unparseable first response triggers exactly one retry."""
    provider, v = await _judge(["not json at all", _GOOD])
    assert provider.calls == 2
    assert v.success is True
    assert v.parse_error is False


async def test_failsafe_verdict_when_never_parseable() -> None:
    """Two bad responses yield a fail-safe non-success verdict, not an error."""
    provider, v = await _judge(["nope", "still nope"])
    assert provider.calls == 2
    assert v.success is False
    assert v.parse_error is True
    assert v.confidence == 0.0


async def test_out_of_range_confidence_is_rejected_then_retried() -> None:
    """Schema-invalid JSON (confidence > 1) is treated as a parse failure."""
    bad = '{"success": true, "confidence": 5, "evidence": "", "reasoning": "x"}'
    provider, v = await _judge([bad, _GOOD])
    assert provider.calls == 2
    assert v.confidence == 0.9
