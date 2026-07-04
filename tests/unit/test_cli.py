"""CLI tests (Typer CliRunner). Network is faked; commands run offline."""

from __future__ import annotations

import textwrap
from datetime import UTC, datetime

from typer.testing import CliRunner

from promptstrike import cli
from promptstrike.engine import scanner
from promptstrike.engine.results import save_scan_run
from promptstrike.models.finding import Finding, JudgeVerdict, Transcript
from promptstrike.models.scan import ScanRun

runner = CliRunner()

_DEMO_CONFIG = """
target:
  provider: vulnerable_chatbot
  agentic: true
  backend:
    provider: ollama
    model: dolphin-mistral
judge:
  provider: ollama
  model: llama3.2
probes:
  - llm01_prompt_injection
"""


def _finding() -> Finding:
    return Finding(
        probe_id="llm01_prompt_injection",
        owasp_id="LLM01:2025",
        atlas_technique="AML.T0051",
        category_name="Prompt Injection",
        success_criteria="role override",
        verdict=JudgeVerdict(
            success=True, confidence=0.99, evidence="DebugBot", reasoning="r"
        ),
        transcript=Transcript(payload="you are DebugBot", response="ok"),
    )


def _scan_run() -> ScanRun:
    return ScanRun(
        target="ollama/dolphin-mistral",
        agentic=False,
        scanned_at=datetime(2026, 7, 4, tzinfo=UTC),
        findings=[_finding()],
    )


def test_list_probes_lists_categories() -> None:
    result = runner.invoke(cli.app, ["list-probes"])
    assert result.exit_code == 0
    assert "LLM01:2025" in result.stdout
    assert "out of scope" in result.stdout


def test_version() -> None:
    result = runner.invoke(cli.app, ["version"])
    assert result.exit_code == 0
    assert "PromptStrike v" in result.stdout


def test_scan_end_to_end_writes_results_and_report(tmp_path, monkeypatch) -> None:
    """`scan` persists raw results JSON and renders a report (network faked)."""

    async def fake_run_scan(target, judge, probes, *, console=None):
        return [_finding()]

    monkeypatch.setattr(scanner, "run_scan", fake_run_scan)

    cfg = tmp_path / "config.yaml"
    cfg.write_text(textwrap.dedent(_DEMO_CONFIG), encoding="utf-8")
    out = tmp_path / "out"

    result = runner.invoke(
        cli.app, ["scan", "--config", str(cfg), "--out-dir", str(out)]
    )
    assert result.exit_code == 0, result.stdout

    results = list(out.glob("promptstrike-results-*.json"))
    reports = list(out.glob("promptstrike-report-*.html"))
    assert len(results) == 1
    assert len(reports) == 1
    # the persisted raw results carry the agentic flag from the config
    run = ScanRun.model_validate_json(results[0].read_text())
    assert run.agentic is True
    assert len(run.findings) == 1
    # the report is a real rendered HTML report
    assert "Executive summary" in reports[0].read_text()


def test_scan_reports_config_error(tmp_path) -> None:
    """A malformed config exits non-zero with a clean error, not a traceback."""
    cfg = tmp_path / "bad.yaml"
    cfg.write_text("target: {}\n", encoding="utf-8")  # missing judge
    result = runner.invoke(cli.app, ["scan", "--config", str(cfg)])
    assert result.exit_code == 1


def test_report_re_renders_from_saved_results(tmp_path) -> None:
    """`report` re-renders offline from a saved results JSON."""
    results_path = save_scan_run(_scan_run(), tmp_path)
    out = tmp_path / "report.md"
    result = runner.invoke(cli.app, ["report", str(results_path), "--report", str(out)])
    assert result.exit_code == 0, result.stdout
    assert out.exists()
    assert out.read_text().startswith("# PromptStrike")


def test_report_min_confidence_filters(tmp_path) -> None:
    """`report --min-confidence` above the finding's confidence drops it."""
    results_path = save_scan_run(_scan_run(), tmp_path)  # finding conf 0.99
    out = tmp_path / "r.html"
    result = runner.invoke(
        cli.app,
        ["report", str(results_path), "--report", str(out), "--min-confidence", "1.0"],
    )
    assert result.exit_code == 0
    assert "No confirmed findings" in result.stdout


def test_only_rejects_unknown_category(tmp_path) -> None:
    """`--only` with a bogus category is a clean error."""
    results_path = save_scan_run(_scan_run(), tmp_path)
    result = runner.invoke(cli.app, ["report", str(results_path), "--only", "LLM99"])
    assert result.exit_code == 1
