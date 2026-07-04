"""Scan orchestration: run in-scope probes against a target and collect findings.

Wires the target provider, the probe library, and the LLM-as-judge together:
for each payload of each in-scope probe it sends the attack, captures the
response, asks the judge for a verdict, and assembles a ``Finding``. A live
``rich`` progress display shows scan progress. Orchestration only — the attack
payloads live in the probe YAMLs and the scoring lives in ``judge``.
"""

from __future__ import annotations

from datetime import UTC, datetime

from rich.console import Console
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)

from promptstrike.config.errors import ConfigError
from promptstrike.config.loader import load_config
from promptstrike.config.schema import RunConfig
from promptstrike.judge.judge import judge_attack
from promptstrike.models.finding import Finding, Transcript
from promptstrike.models.probe import Probe
from promptstrike.models.scan import ScanRun
from promptstrike.probes.loader import load_probes
from promptstrike.providers import create_provider
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


def _select_probes(probes: list[Probe], wanted: list[str] | None) -> list[Probe]:
    """Filter the probe library to the ids in ``wanted`` (or all if None)."""
    if wanted is None:
        return probes
    by_id = {p.id: p for p in probes}
    missing = [pid for pid in wanted if pid not in by_id]
    if missing:
        raise ConfigError(f"config selects unknown probe id(s): {', '.join(missing)}")
    return [by_id[pid] for pid in wanted]


def _target_label(config: RunConfig) -> str:
    """A short human label for the target, e.g. ``ollama/dolphin-mistral``."""
    target = config.target
    provider = str(target.get("provider", "?"))
    backend = target.get("backend")
    model = target.get("model")
    if not model and isinstance(backend, dict):
        model = backend.get("model")
    return f"{provider}/{model}" if model else provider


async def run_scan_with_config(
    config: RunConfig,
    *,
    config_path: str | None = None,
    only: set[str] | None = None,
    console: Console | None = None,
) -> ScanRun:
    """Run a scan described by an already-loaded ``RunConfig``.

    Builds the target and judge providers, selects the probes (``config.probes``,
    optionally narrowed to the OWASP ids in ``only``), runs the scan, and returns
    the **raw** findings wrapped in a ``ScanRun`` (with the target label, the
    ``agentic`` flag, and the timestamp). Triage is intentionally *not* done here
    so scan and report stay separable. Providers it constructs are closed.

    Args:
        config: The validated run config.
        config_path: Optional path, recorded in the ScanRun for provenance.
        only: Optional set of OWASP ids (e.g. ``{"LLM01:2025"}``) to restrict to.
        console: Optional ``rich`` console.

    Returns:
        A ``ScanRun`` holding the raw judged findings.
    """
    target = create_provider(config.target)
    judge = create_provider(config.judge)
    probes = _select_probes(load_probes(config.probe_dir), config.probes)
    if only:
        probes = [p for p in probes if p.owasp_id in only]
        if not probes:
            raise ConfigError(f"no probes match the requested categories: {only}")
    try:
        findings = await run_scan(target, judge, probes, console=console)
    finally:
        await target.aclose()
        await judge.aclose()
    return ScanRun(
        target=_target_label(config),
        agentic=config.agentic,
        scanned_at=datetime.now(UTC),
        config_path=config_path,
        findings=findings,
    )


async def run_scan_from_config(
    config_path: str,
    *,
    only: set[str] | None = None,
    console: Console | None = None,
) -> ScanRun:
    """Load a YAML run config and run the scan it describes.

    Thin wrapper over :func:`run_scan_with_config` that resolves ``${ENV}`` refs
    and validates the config first. Returns the raw ``ScanRun`` (untriaged) so a
    scan and a later re-report are separable.
    """
    config = load_config(config_path)
    return await run_scan_with_config(
        config, config_path=str(config_path), only=only, console=console
    )
