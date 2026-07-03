"""CLI smoke tests: the `scan` command drives run_scan_from_config."""

from __future__ import annotations

import pytest

from promptstrike import cli
from promptstrike.config.errors import ConfigError
from promptstrike.models.finding import Finding, JudgeVerdict, Transcript


def _finding(success: bool) -> Finding:
    return Finding(
        probe_id="llm01_prompt_injection",
        owasp_id="LLM01:2025",
        atlas_technique="AML.T0051",
        category_name="Prompt Injection",
        success_criteria="leaks",
        verdict=JudgeVerdict(
            success=success, confidence=0.9, evidence="e", reasoning="r"
        ),
        transcript=Transcript(payload="p", response="x"),
    )


def test_scan_command_calls_config_entrypoint(monkeypatch) -> None:
    """`promptstrike scan -c PATH` invokes run_scan_from_config with that path."""
    seen: dict[str, object] = {}

    async def fake_entry(config_path, *, console=None):
        seen["path"] = config_path
        return [_finding(True), _finding(False)]

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
