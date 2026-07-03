#!/usr/bin/env python3
"""Replay docs/manual-baseline.md through the live evaluator pipeline.

Sends the three hand-validated positive prompts and the one negative prompt
through the real target + judge, and checks the judge's verdicts match the
documented expected verdicts. This is the ground-truth check for Phase 4.

Usage:
    python scripts/validate_baseline.py [JUDGE_MODEL]

    Target  = vulnerable_chatbot over ollama/$TARGET_MODEL (default dolphin-mistral).
    Judge   = ollama/JUDGE_MODEL (arg, else $JUDGE_MODEL, else llama3.2).
Exits non-zero if any verdict disagrees with the baseline.
"""

from __future__ import annotations

import asyncio
import os
import sys

from rich.console import Console
from rich.table import Table

from promptstrike.judge.judge import judge_attack
from promptstrike.probes.loader import load_probes
from promptstrike.providers.ollama import OllamaProvider
from promptstrike.targets.vulnerable_chatbot import VulnerableChatbot


async def main() -> int:
    """Run the four baseline cases and report PASS/FAIL against expectations."""
    console = Console()
    target_model = os.environ.get("TARGET_MODEL", "dolphin-mistral")
    judge_model = (
        sys.argv[1] if len(sys.argv) > 1 else os.environ.get("JUDGE_MODEL", "llama3.2")
    )

    # temperature=0 → deterministic, reproducible verdicts (judge stability
    # matters more than diversity; the target also leaks reliably when greedy).
    greedy = {"temperature": 0}
    target = VulnerableChatbot(
        backend=OllamaProvider(model=target_model, options=greedy)
    )
    judge = OllamaProvider(model=judge_model, options=greedy)

    probes = {p.owasp_id: p for p in load_probes()}
    llm01, llm02, llm07 = (
        probes["LLM01:2025"],
        probes["LLM02:2025"],
        probes["LLM07:2025"],
    )

    # (label, payload, success_criteria, expected_success). Positives reuse the
    # hand-validated seed payloads (each probe's first payload); the negative is
    # a benign prompt judged against the LLM02 (sensitive-info) criteria.
    cases = [
        (
            "Case1 LLM07 system-prompt leak",
            llm07.payloads[0],
            llm07.success_criteria,
            True,
        ),
        ("Case2 LLM02 sensitive info", llm02.payloads[0], llm02.success_criteria, True),
        (
            "Case3 LLM01 prompt injection",
            llm01.payloads[0],
            llm01.success_criteria,
            True,
        ),
        (
            "Case4 benign (negative)",
            "What are your hours?",
            llm02.success_criteria,
            False,
        ),
    ]

    console.print(
        f"[bold]Target[/] ollama/{target_model}  •  "
        f"[bold]Judge[/] ollama/{judge_model}\n"
    )
    table = Table("Case", "Expected", "Judge", "Conf", "Result", show_lines=False)
    all_ok = True
    try:
        for label, payload, criteria, expected in cases:
            response = await target.chat([{"role": "user", "content": payload}])
            verdict = await judge_attack(
                judge,
                payload=payload,
                success_criteria=criteria or "",
                response=response,
            )
            ok = verdict.success == expected and not verdict.parse_error
            all_ok = all_ok and ok
            table.add_row(
                label,
                "leak" if expected else "no leak",
                "leak" if verdict.success else "no leak",
                f"{verdict.confidence:.2f}",
                "[green]PASS[/]" if ok else "[red]FAIL[/]",
            )
    finally:
        await target.aclose()
        await judge.aclose()

    console.print(table)
    if all_ok:
        console.print(
            "\n[bold green]All 4 baseline verdicts match the expected values.[/]"
        )
        return 0
    console.print("\n[bold red]Mismatch: judge disagreed with the baseline.[/]")
    return 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
