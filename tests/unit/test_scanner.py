"""Unit tests for the scan runner (fake target + fake judge, no network)."""

from __future__ import annotations

import io

from rich.console import Console

from promptstrike.engine.scanner import run_scan
from promptstrike.models.probe import Probe
from promptstrike.providers.base import LLMProvider, Message


class _EchoTarget(LLMProvider):
    """Target that echoes the payload back as its response."""

    def __init__(self) -> None:
        super().__init__(model="echo-target")

    async def chat(self, messages: list[Message], system: str | None = None) -> str:
        return f"RESPONSE: {messages[-1]['content']}"


class _KeywordJudge(LLMProvider):
    """Judge that returns success=true iff the prompt mentions 'trigger'."""

    def __init__(self) -> None:
        super().__init__(model="keyword-judge")

    async def chat(self, messages: list[Message], system: str | None = None) -> str:
        hit = "trigger" in messages[-1]["content"]
        return (
            f'{{"success": {str(hit).lower()}, "confidence": 0.8, '
            f'"evidence": "x", "reasoning": "y"}}'
        )


def _probe(pid: str, owasp: str, cat: str, payloads: list[str]) -> Probe:
    return Probe(
        id=pid,
        owasp_id=owasp,
        atlas_technique="no direct ATLAS mapping",
        category_name=cat,
        success_criteria="the attack worked",
        payloads=payloads,
    )


def _quiet_console() -> Console:
    return Console(file=io.StringIO())


async def test_scan_collects_one_finding_per_payload() -> None:
    """Every in-scope payload yields exactly one finding, with the right verdict."""
    probes = [
        _probe(
            "llm06_excessive_agency",
            "LLM06:2025",
            "Excessive Agency",
            ["please trigger this", "totally benign"],
        )
    ]
    findings = await run_scan(
        _EchoTarget(), _KeywordJudge(), probes, console=_quiet_console()
    )
    assert len(findings) == 2
    assert findings[0].verdict.success is True
    assert findings[1].verdict.success is False
    # transcript captures the exact request/response
    assert findings[0].transcript.payload == "please trigger this"
    assert findings[0].transcript.response == "RESPONSE: please trigger this"
    assert findings[0].owasp_id == "LLM06:2025"


async def test_scan_skips_out_of_scope_probes() -> None:
    """Out-of-scope probes contribute no findings."""
    stub = Probe(
        id="llm03_supply_chain",
        owasp_id="LLM03:2025",
        atlas_technique="no direct ATLAS mapping",
        category_name="Supply Chain",
        out_of_scope=True,
        out_of_scope_reason="not black-box testable",
    )
    active = _probe("llm01_prompt_injection", "LLM01:2025", "Prompt Injection", ["x"])
    findings = await run_scan(
        _EchoTarget(), _KeywordJudge(), [stub, active], console=_quiet_console()
    )
    assert {f.owasp_id for f in findings} == {"LLM01:2025"}
