"""CLI smoke tests: the `scan` command drives run_scan_from_config."""

from __future__ import annotations

import pytest

from promptstrike import cli
from promptstrike.config.errors import ConfigError
from promptstrike.models.finding import Transcript
from promptstrike.models.triage import Severity, TriagedFinding


def _triaged(severity: Severity) -> TriagedFinding:
    return TriagedFinding(
        probe_id="llm01_prompt_injection",
        owasp_id="LLM01:2025",
        owasp_title="Prompt Injection",
        atlas_technique="AML.T0051",
        atlas_name="LLM Prompt Injection",
        category_name="Prompt Injection",
        confidence=0.9,
        evidence="e",
        severity=severity,
        severity_vector="PS:1.0/AV:N/AC:L/PR:N/UI:R/OW:LLM01:2025/EX:H/AG:N/SEV:High",
        severity_justification="j",
        impact="i",
        reproduction=["r"],
        remediation=["m"],
        transcript=Transcript(payload="p", response="x"),
    )


def test_scan_command_calls_config_entrypoint(monkeypatch) -> None:
    """`promptstrike scan -c PATH` invokes run_scan_from_config with that path."""
    seen: dict[str, object] = {}

    async def fake_entry(config_path, *, console=None):
        seen["path"] = config_path
        return [_triaged(Severity.CRITICAL), _triaged(Severity.LOW)]

    monkeypatch.setattr(cli, "run_scan_from_config", fake_entry)

    code = cli.main(["scan", "-c", "configs/vulnerable_demo.yaml"])

    assert code == 0
    assert seen["path"] == "configs/vulnerable_demo.yaml"


def test_scan_command_reports_config_error(monkeypatch) -> None:
    """A config error is caught and reported as a non-zero exit, not a traceback."""

    async def fake_entry(config_path, *, console=None):
        raise ConfigError("bad config")

    monkeypatch.setattr(cli, "run_scan_from_config", fake_entry)

    assert cli.main(["scan", "-c", "missing.yaml"]) == 1


def test_scan_requires_config_flag() -> None:
    """The scan subcommand requires --config."""
    with pytest.raises(SystemExit):
        cli.main(["scan"])
