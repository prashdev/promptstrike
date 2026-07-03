"""Rich-based CLI entrypoint and argument parsing for PromptStrike.

Parses command-line arguments, shows the authorised-use notice, and drives the
scan engine via the config-driven entry point. No scanning logic lives here —
this module only wires the CLI to ``engine.run_scan_from_config``.
"""

from __future__ import annotations

import argparse
import asyncio

from rich.console import Console
from rich.panel import Panel

from promptstrike.config.errors import ConfigError
from promptstrike.engine.scanner import run_scan_from_config
from promptstrike.models.triage import Severity
from promptstrike.probes.errors import ProbeLoadError
from promptstrike.providers.errors import ProviderError
from promptstrike.triage import TriageError

_AUTH_NOTICE = (
    "[bold]Authorised use only.[/] PromptStrike is a security-testing tool. "
    "Run it only against endpoints you own or have explicit written permission "
    "to test."
)

_SEVERITY_STYLE = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}


def _build_parser() -> argparse.ArgumentParser:
    """Construct the argument parser and its subcommands."""
    parser = argparse.ArgumentParser(
        prog="promptstrike",
        description="Black-box LLM red-teaming scanner (OWASP LLM Top 10).",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan", help="Run a scan described by a YAML config.")
    scan.add_argument(
        "-c",
        "--config",
        required=True,
        help="Path to the YAML run config (target, judge, probes).",
    )
    return parser


def _run_scan(config_path: str, console: Console) -> int:
    """Execute the config-driven scan and print a short summary."""
    console.print(Panel(_AUTH_NOTICE, title="PromptStrike"))
    try:
        findings = asyncio.run(run_scan_from_config(config_path, console=console))
    except (ConfigError, ProbeLoadError, ProviderError, TriageError) as exc:
        console.print(f"[red]Scan failed:[/] {exc}")
        return 1

    # findings are already triaged: confirmed, scored, and most-severe-first.
    for f in findings:
        style = _SEVERITY_STYLE.get(f.severity, "white")
        console.print(
            f"  [{style}]{f.severity.value:<8}[/] {f.owasp_id} {f.category_name} "
            f"(confidence {f.confidence:.2f})"
        )
    console.print(f"[bold]{len(findings)}[/] confirmed finding(s).")
    return 0


def main(argv: list[str] | None = None) -> int:
    """Run the PromptStrike CLI.

    Args:
        argv: Optional argument vector (defaults to ``sys.argv[1:]``).

    Returns:
        Process exit code.
    """
    args = _build_parser().parse_args(argv)
    console = Console()
    if args.command == "scan":
        return _run_scan(args.config, console)
    return 1  # pragma: no cover - argparse enforces a valid subcommand
