"""Scan orchestration: run in-scope probes against a target and collect findings.

Wires the target provider, the probe library, and the LLM-as-judge together:
for each payload of each in-scope probe it sends the attack, captures the
response, asks the judge for a verdict, and assembles a ``Finding``. A live
``rich`` progress display shows scan progress. Orchestration only — the attack
payloads live in the probe YAMLs and the scoring lives in ``judge``.
"""

from __future__ import annotations

from rich.console import Console
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)

from promptstrike.judge.judge import judge_attack
from promptstrike.models.finding import Finding, Transcript
from promptstrike.models.probe import Probe
from promptstrike.providers.base import LLMProvider


async def run_scan(
    target: LLMProvider,
    judge: LLMProvider,
    probes: list[Probe],
    *,
    console: Console | None = None,
) -> list[Finding]:
    """Run every in-scope probe against ``target`` and judge each response.

    Args:
        target: The provider under test.
        judge: A *separate* provider used to score attack success.
        probes: The probe library (out-of-scope probes are skipped).
        console: Optional ``rich`` console (defaults to a fresh one).

    Returns:
        One ``Finding`` per payload sent, in probe order.
    """
    console = console or Console()
    in_scope = [p for p in probes if not p.out_of_scope]
    total_payloads = sum(len(p.payloads) for p in in_scope)
    findings: list[Finding] = []

    progress = Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        console=console,
        transient=False,
    )
    with progress:
        task = progress.add_task("Scanning", total=total_payloads)
        for probe in in_scope:
            progress.update(task, description=f"{probe.owasp_id} {probe.category_name}")
            for payload in probe.payloads:
                response = await target.chat([{"role": "user", "content": payload}])
                verdict = await judge_attack(
                    judge,
                    payload=payload,
                    success_criteria=probe.success_criteria or "",
                    response=response,
                )
                findings.append(
                    Finding.from_attempt(
                        probe,
                        verdict,
                        Transcript(payload=payload, response=response),
                    )
                )
                progress.advance(task)

    hits = sum(1 for f in findings if f.verdict.success)
    console.print(
        f"[bold]Scan complete:[/] {hits} finding(s) across "
        f"{total_payloads} attempt(s) in {len(in_scope)} in-scope categories."
    )
    return findings
