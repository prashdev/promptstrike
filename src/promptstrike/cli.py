"""PromptStrike command-line interface (Typer).

Commands
--------
* ``ping``         — check the target and judge endpoints are reachable.
* ``list-probes``  — show the probe library (categories, scope, payload counts).
* ``scan``         — run the full pipeline (scan → judge → triage → report) and
                     persist the raw findings to timestamped JSON.
* ``report``       — re-render a report from a saved results JSON, offline.

The scanner core lives in ``engine``/``triage``/``report``; this module only
wires them to the CLI and owns the authorised-use notice.
"""

from __future__ import annotations

import asyncio
import time
from datetime import datetime
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from promptstrike import __version__
from promptstrike.config.errors import ConfigError
from promptstrike.config.loader import load_config
from promptstrike.config.schema import RunConfig
from promptstrike.engine.errors import ResultsError
from promptstrike.engine.results import load_scan_run, save_scan_run, timestamped_path
from promptstrike.engine.scanner import run_scan_with_config
from promptstrike.mappings.owasp_llm_2025 import OWASP_LLM_2025
from promptstrike.models.scan import ScanRun
from promptstrike.models.triage import Severity, TriagedFinding
from promptstrike.probes.errors import ProbeLoadError
from promptstrike.probes.loader import load_probes
from promptstrike.providers import create_provider
from promptstrike.providers.errors import ProviderError
from promptstrike.report.reporter import render_report
from promptstrike.triage import TriageError, load_rubric, triage_findings

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    rich_markup_mode="rich",
    help=(
        "PromptStrike — black-box LLM red-teaming scanner for the OWASP LLM "
        "Top 10 (2025).\n\n"
        "[bold]Authorised use only.[/] Run it only against endpoints you own or "
        "have explicit written permission to test."
    ),
)

console = Console()
err = Console(stderr=True)

_SCAN_ERRORS = (ConfigError, ProbeLoadError, ProviderError, TriageError, ResultsError)
_SEVERITY_STYLE = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}

_AUTH_NOTICE = (
    "[bold]Authorised use only.[/] PromptStrike is a security-testing tool. Run "
    "it only against endpoints you own or have explicit written permission to test."
)


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _die(message: str) -> None:
    """Print an error to stderr and exit non-zero."""
    err.print(f"[red]Error:[/] {message}")
    raise typer.Exit(1)


def _override_provider(block: dict, spec: str) -> dict:
    """Apply a ``--target``/``--judge`` override to a provider config block.

    ``spec`` is ``provider:model`` (replaces the block) or a bare ``model``
    (overrides only the model on the existing block).
    """
    if ":" in spec:
        provider, model = spec.split(":", 1)
        return {"provider": provider.strip(), "model": model.strip()}
    return {**block, "model": spec.strip()}


def _normalise_only(text: str) -> set[str]:
    """Parse ``--only LLM01,LLM07`` into validated OWASP ids (``LLM01:2025``)."""
    ids: set[str] = set()
    for raw in text.split(","):
        token = raw.strip().upper()
        if not token:
            continue
        owasp_id = token if token.endswith(":2025") else f"{token}:2025"
        if owasp_id not in OWASP_LLM_2025:
            _die(f"unknown OWASP category in --only: {raw.strip()!r}")
        ids.add(owasp_id)
    if not ids:
        _die("--only was given but no valid categories were parsed")
    return ids


def _triage_run(
    run: ScanRun, *, min_confidence: float | None, only: set[str] | None
) -> list[TriagedFinding]:
    """Triage a ScanRun's raw findings, applying CLI overrides."""
    findings = run.findings
    if only:
        findings = [f for f in findings if f.owasp_id in only]
    rubric = load_rubric()
    if min_confidence is not None:
        rubric = rubric.model_copy(update={"fp_confidence_threshold": min_confidence})
    return triage_findings(findings, agentic=run.agentic, rubric=rubric)


def _report_format(path: Path) -> str:
    """Infer the report format from a path's extension (default HTML)."""
    return "md" if path.suffix.lower() in (".md", ".markdown") else "html"


def _write_report(
    triaged: list[TriagedFinding], *, target: str, scanned_at: datetime, path: Path
) -> str:
    """Render and write a report; return the format used."""
    fmt = _report_format(path)
    text = render_report(triaged, target=target, scanned_at=scanned_at, fmt=fmt)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return fmt


def _print_findings(triaged: list[TriagedFinding]) -> None:
    """Print a severity-ranked summary table of triaged findings."""
    if not triaged:
        console.print("[green]No confirmed findings.[/]")
        return
    table = Table("Severity", "OWASP", "Category", "Conf", title="Confirmed findings")
    for f in triaged:
        style = _SEVERITY_STYLE.get(f.severity, "white")
        table.add_row(
            f"[{style}]{f.severity.value}[/]",
            f.owasp_id,
            f.category_name,
            f"{f.confidence:.2f}",
        )
    console.print(table)


# --------------------------------------------------------------------------- #
# Commands
# --------------------------------------------------------------------------- #
@app.command()
def ping(
    config: Annotated[
        Path,
        typer.Option(
            "--config",
            "-c",
            exists=True,
            dir_okay=False,
            help="YAML run config whose target and judge endpoints are pinged.",
        ),
    ],
) -> None:
    """Check that the target and judge endpoints are reachable and respond.

    Sends one trivial prompt to each provider named in the config and reports the
    round-trip latency — a fast pre-flight check before a full scan.
    """

    async def _run() -> int:
        cfg = load_config(config)
        ok = True
        table = Table("Role", "Provider", "Latency", "Reply", title="ping")
        for role, block in (("target", cfg.target), ("judge", cfg.judge)):
            provider = create_provider(block)
            try:
                t0 = time.perf_counter()
                reply = await provider.chat(
                    [{"role": "user", "content": "Reply with the single word: pong"}]
                )
                dt = (time.perf_counter() - t0) * 1000
                table.add_row(role, provider.model, f"{dt:.0f} ms", reply.strip()[:40])
            except ProviderError as exc:
                ok = False
                table.add_row(role, provider.model, "[red]FAIL[/]", str(exc)[:40])
            finally:
                await provider.aclose()
        console.print(table)
        return 0 if ok else 1

    try:
        code = asyncio.run(_run())
    except _SCAN_ERRORS as exc:
        _die(str(exc))
    if code:
        raise typer.Exit(code)


@app.command("list-probes")
def list_probes() -> None:
    """List the probe library: OWASP category, scope, and payload count."""
    try:
        probes = load_probes()
    except ProbeLoadError as exc:
        _die(str(exc))
    table = Table(
        "OWASP", "Probe id", "Category", "Scope", "Payloads", title="Probe library"
    )
    for p in sorted(probes, key=lambda p: p.owasp_id):
        if p.out_of_scope:
            scope, payloads = "[dim]out of scope[/]", "—"
        else:
            scope, payloads = "[green]in scope[/]", str(len(p.payloads))
        table.add_row(p.owasp_id, p.id, p.category_name, scope, payloads)
    console.print(table)


@app.command()
def scan(
    config: Annotated[
        Path,
        typer.Option(
            "--config",
            "-c",
            exists=True,
            dir_okay=False,
            help="YAML run config (target, judge, probes). See config.yaml.",
        ),
    ],
    target: Annotated[
        str | None,
        typer.Option(
            "--target",
            help="Override the target: 'provider:model' (e.g. ollama:llama3.2) "
            "or a bare model name. For keys/URLs, edit the config instead.",
        ),
    ] = None,
    judge: Annotated[
        str | None,
        typer.Option(
            "--judge",
            help="Override the judge model, same syntax as --target.",
        ),
    ] = None,
    report: Annotated[
        Path | None,
        typer.Option(
            "--report",
            help="Report output path; extension picks the format (.html or .md). "
            "Defaults to a timestamped .html in --out-dir.",
        ),
    ] = None,
    min_confidence: Annotated[
        float | None,
        typer.Option(
            "--min-confidence",
            min=0.0,
            max=1.0,
            help="Override the false-positive confidence threshold for triage "
            "(default comes from the severity rubric).",
        ),
    ] = None,
    only: Annotated[
        str | None,
        typer.Option(
            "--only",
            help="Restrict to specific OWASP categories, comma-separated, "
            "e.g. LLM01,LLM07.",
        ),
    ] = None,
    out_dir: Annotated[
        Path,
        typer.Option(
            "--out-dir",
            help="Directory for the results JSON and default report.",
        ),
    ] = Path("."),
) -> None:
    """Run a scan end-to-end: scan → judge → triage → report.

    Raw findings are always written to a timestamped
    ``promptstrike-results-*.json`` so the scan and any later re-report are
    separable (see the [bold]report[/] command).
    """
    console.print(Panel(_AUTH_NOTICE, title="PromptStrike"))
    try:
        cfg: RunConfig = load_config(config)
        if target:
            cfg.target = _override_provider(cfg.target, target)
        if judge:
            cfg.judge = _override_provider(cfg.judge, judge)
        only_set = _normalise_only(only) if only else None

        run = asyncio.run(
            run_scan_with_config(
                cfg, config_path=str(config), only=only_set, console=console
            )
        )
        results_path = save_scan_run(run, out_dir)
        triaged = _triage_run(run, min_confidence=min_confidence, only=None)
        report_path = report or timestamped_path(
            out_dir, "promptstrike-report", "html", run.scanned_at
        )
        fmt = _write_report(
            triaged, target=run.target, scanned_at=run.scanned_at, path=report_path
        )
    except _SCAN_ERRORS as exc:
        _die(str(exc))

    _print_findings(triaged)
    console.print(
        f"\n[bold]{len(triaged)}[/] confirmed finding(s). "
        f"Raw results: [cyan]{results_path}[/] · "
        f"{fmt.upper()} report: [cyan]{report_path}[/]"
    )


@app.command()
def report(
    results: Annotated[
        Path,
        typer.Argument(
            exists=True,
            dir_okay=False,
            help="A promptstrike-results-*.json file from a previous scan.",
        ),
    ],
    report_path: Annotated[
        Path | None,
        typer.Option(
            "--report",
            "-o",
            help="Report output path; extension picks the format (.html or .md).",
        ),
    ] = None,
    min_confidence: Annotated[
        float | None,
        typer.Option(
            "--min-confidence",
            min=0.0,
            max=1.0,
            help="Override the triage false-positive confidence threshold.",
        ),
    ] = None,
    only: Annotated[
        str | None,
        typer.Option(
            "--only",
            help="Restrict to OWASP categories, comma-separated (e.g. LLM01,LLM07).",
        ),
    ] = None,
) -> None:
    """Re-render a report from saved raw results, without re-running the scan.

    Loads the raw findings, re-triages them (honouring ``--min-confidence`` and
    ``--only`` and the target's agentic flag from the saved run), and writes a
    fresh report — all offline.
    """
    try:
        run = load_scan_run(results)
        only_set = _normalise_only(only) if only else None
        triaged = _triage_run(run, min_confidence=min_confidence, only=only_set)
        out = report_path or timestamped_path(
            ".", "promptstrike-report", "html", run.scanned_at
        )
        fmt = _write_report(
            triaged, target=run.target, scanned_at=run.scanned_at, path=out
        )
    except _SCAN_ERRORS as exc:
        _die(str(exc))

    _print_findings(triaged)
    console.print(
        f"\n[bold]{len(triaged)}[/] confirmed finding(s). "
        f"{fmt.upper()} report: [cyan]{out}[/]"
    )


@app.command()
def version() -> None:
    """Print the PromptStrike version."""
    console.print(f"PromptStrike v{__version__}")


def main() -> None:
    """Console-script entry point."""
    app()


if __name__ == "__main__":
    main()
