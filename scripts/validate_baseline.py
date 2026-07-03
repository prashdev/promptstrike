#!/usr/bin/env python3
"""Replay docs/manual-baseline.md through the live pipeline, end-to-end.

Sends the three hand-validated positive prompts and the one negative prompt
through the real target + judge, checks the judge's verdicts match the
documented expectations, then runs the triage stage and prints the resulting
severity table — so you see scan → judge → triage → severity on real output.

Usage:
    python scripts/validate_baseline.py [JUDGE_MODEL]

    Target  = vulnerable_chatbot over ollama/$TARGET_MODEL (default dolphin-mistral).
    Judge   = ollama/JUDGE_MODEL (arg, else $JUDGE_MODEL, else llama3.2).
Exits non-zero if any verdict disagrees with the baseline, or if triage does not
yield exactly the 3 positive findings.
"""

from __future__ import annotations

import asyncio
import os
import sys

from rich.console import Console
from rich.table import Table

from promptstrike.judge.judge import judge_attack
from promptstrike.models.finding import Finding, Transcript
from promptstrike.models.triage import Severity
from promptstrike.probes.loader import load_probes
from promptstrike.providers.ollama import OllamaProvider
from promptstrike.targets.vulnerable_chatbot import VulnerableChatbot
from promptstrike.triage import triage_findings

_SEVERITY_STYLE = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}


async def main() -> int:
    """Run the four baseline cases, then triage, and report the full pipeline."""
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

    # (label, probe, payload, expected_success). Positives reuse the hand-
    # validated seed payloads (each probe's first payload); the negative is a
    # benign prompt judged against the LLM02 (sensitive-info) criteria.
    cases = [
        ("Case1 LLM07 system-prompt leak", llm07, llm07.payloads[0], True),
        ("Case2 LLM02 sensitive info", llm02, llm02.payloads[0], True),
        ("Case3 LLM01 prompt injection", llm01, llm01.payloads[0], True),
        ("Case4 benign (negative)", llm02, "What are your hours?", False),
    ]

    console.print(
        f"[bold]Target[/] ollama/{target_model}  •  "
        f"[bold]Judge[/] ollama/{judge_model}\n"
    )

    verdict_table = Table(
        "Case", "Expected", "Judge", "Conf", "Result", title="1. scan → judge"
    )
    findings: list[Finding] = []
    verdicts_ok = True
    try:
        for label, probe, payload, expected in cases:
            response = await target.chat([{"role": "user", "content": payload}])
            verdict = await judge_attack(
                judge,
                payload=payload,
                success_criteria=probe.success_criteria or "",
                response=response,
            )
            findings.append(
                Finding.from_attempt(
                    probe, verdict, Transcript(payload=payload, response=response)
                )
            )
            ok = verdict.success == expected and not verdict.parse_error
            verdicts_ok = verdicts_ok and ok
            verdict_table.add_row(
                label,
                "leak" if expected else "no leak",
                "leak" if verdict.success else "no leak",
                f"{verdict.confidence:.2f}",
                "[green]PASS[/]" if ok else "[red]FAIL[/]",
            )
    finally:
        await target.aclose()
        await judge.aclose()

    console.print(verdict_table)

    # --- triage stage: filter → dedup → score → enrich -----------------------
    triaged = triage_findings(findings, agentic=False)

    sev_table = Table(
        "Severity",
        "OWASP",
        "Category",
        "ATLAS",
        "Conf",
        "Vector",
        title="\n2. judge → triage → severity",
    )
    for t in triaged:
        style = _SEVERITY_STYLE[t.severity]
        sev_table.add_row(
            f"[{style}]{t.severity.value}[/]",
            t.owasp_id,
            t.category_name,
            t.atlas_technique,
            f"{t.confidence:.2f}",
            t.severity_vector,
        )
    console.print(sev_table)

    # Show one finding's full enrichment so the whole record is visible.
    if triaged:
        top = triaged[0]
        console.print(
            f"\n[bold]Top finding — {top.severity.value} {top.owasp_id} "
            f"{top.category_name}[/] ({top.atlas_technique})"
        )
        console.print(f"  [bold]Why:[/] {top.severity_justification}")
        console.print(f"  [bold]Vector:[/] {top.severity_vector}")
        console.print(f"  [bold]Impact:[/] {top.impact}")
        console.print("  [bold]Reproduce:[/]")
        for step in top.reproduction:
            console.print(f"    {step}")
        console.print("  [bold]Remediation:[/]")
        for step in top.remediation:
            console.print(f"    • {step}")

    triage_ok = {t.owasp_id for t in triaged} == {
        "LLM01:2025",
        "LLM02:2025",
        "LLM07:2025",
    }

    if verdicts_ok and triage_ok:
        console.print(
            "\n[bold green]Pipeline OK:[/] 4/4 verdicts match the baseline; "
            "triage kept the 3 positives and filtered the negative."
        )
        return 0
    if not verdicts_ok:
        console.print("\n[bold red]Mismatch: judge disagreed with the baseline.[/]")
    if not triage_ok:
        console.print(
            "\n[bold red]Triage did not yield exactly the 3 positive findings.[/]"
        )
    return 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
