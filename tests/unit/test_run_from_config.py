"""Unit tests for the config-driven scan entry points.

The underlying run_scan is faked so these tests exercise only the wiring
(provider construction, env resolution, probe selection, ScanRun assembly) — no
network.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from promptstrike.config.errors import ConfigError
from promptstrike.engine import scanner
from promptstrike.mappings.mitre_atlas import NO_DIRECT_ATLAS_MAPPING
from promptstrike.models.finding import Finding, JudgeVerdict, Transcript
from promptstrike.models.scan import ScanRun
from promptstrike.models.triage import Severity
from promptstrike.providers.ollama import OllamaProvider
from promptstrike.targets.vulnerable_chatbot import VulnerableChatbot
from promptstrike.triage import triage_findings

_CONFIG = """
target:
  provider: vulnerable_chatbot
  backend:
    provider: ollama
    model: dolphin-mistral
judge:
  provider: ollama
  model: llama3.2
probes:
  - llm01_prompt_injection
  - llm07_system_prompt_leak
"""


def _write(tmp_path: Path, body: str) -> Path:
    cfg = tmp_path / "run.yaml"
    cfg.write_text(textwrap.dedent(body), encoding="utf-8")
    return cfg


def _finding(owasp: str, confidence: float) -> Finding:
    return Finding(
        probe_id="p",
        owasp_id=owasp,
        atlas_technique=NO_DIRECT_ATLAS_MAPPING,
        category_name="Excessive Agency",
        success_criteria="c",
        verdict=JudgeVerdict(
            success=True, confidence=confidence, evidence="acted", reasoning="r"
        ),
        transcript=Transcript(payload="do it", response="done"),
    )


async def test_returns_raw_scanrun_and_selects_probes(
    tmp_path: Path, monkeypatch
) -> None:
    """The entry point returns a raw ScanRun and passes the selected probes."""
    captured: dict[str, object] = {}

    async def fake_run_scan(target, judge, probes, *, console=None):
        captured["target"] = target
        captured["judge"] = judge
        captured["probes"] = probes
        return []

    monkeypatch.setattr(scanner, "run_scan", fake_run_scan)

    run = await scanner.run_scan_from_config(str(_write(tmp_path, _CONFIG)))

    assert isinstance(run, ScanRun)
    assert run.findings == []
    assert isinstance(captured["target"], VulnerableChatbot)
    assert isinstance(captured["judge"], OllamaProvider)
    assert [p.id for p in captured["probes"]] == [
        "llm01_prompt_injection",
        "llm07_system_prompt_leak",
    ]


async def test_only_filter_restricts_by_owasp_category(
    tmp_path: Path, monkeypatch
) -> None:
    """`only` narrows the selected probes to the given OWASP ids."""
    captured: dict[str, object] = {}

    async def fake_run_scan(target, judge, probes, *, console=None):
        captured["probes"] = probes
        return []

    monkeypatch.setattr(scanner, "run_scan", fake_run_scan)

    await scanner.run_scan_from_config(
        str(_write(tmp_path, _CONFIG)), only={"LLM07:2025"}
    )
    assert [p.owasp_id for p in captured["probes"]] == ["LLM07:2025"]


async def test_resolves_env_refs(tmp_path: Path, monkeypatch) -> None:
    """`${ENV}` refs in the config are resolved before providers are built."""
    monkeypatch.setenv("DEMO_KEY", "resolved-secret")
    captured: dict[str, object] = {}

    async def fake_run_scan(target, judge, probes, *, console=None):
        captured["judge"] = judge
        return []

    monkeypatch.setattr(scanner, "run_scan", fake_run_scan)

    cfg = _write(
        tmp_path,
        """
        target:
          provider: ollama
          model: dolphin-mistral
        judge:
          provider: openai
          model: gpt-x
          base_url: http://host/v1
          api_key: ${DEMO_KEY}
        """,
    )
    await scanner.run_scan_from_config(str(cfg))
    assert captured["judge"]._api_key == "resolved-secret"


async def test_rejects_unknown_probe_id(tmp_path: Path) -> None:
    """Selecting a probe id that isn't in the library is a config error."""
    cfg = _write(
        tmp_path,
        """
        target:
          provider: ollama
          model: m
        judge:
          provider: ollama
          model: m
        probes:
          - llm01_prompt_injection
          - does_not_exist
        """,
    )
    with pytest.raises(ConfigError):
        await scanner.run_scan_from_config(str(cfg))


def _agentic_config(tmp_path: Path, agentic: bool) -> Path:
    return _write(
        tmp_path,
        f"""
        target:
          provider: ollama
          model: dolphin-mistral
          agentic: {str(agentic).lower()}
        judge:
          provider: ollama
          model: llama3.2
        """,
    )


async def test_agentic_flag_recorded_and_drives_triage(
    tmp_path: Path, monkeypatch
) -> None:
    """target.agentic in YAML is recorded on the ScanRun and drives triage."""

    async def fake_run_scan(target, judge, probes, *, console=None):
        return [_finding("LLM06:2025", 0.6)]

    monkeypatch.setattr(scanner, "run_scan", fake_run_scan)

    run_off = await scanner.run_scan_from_config(str(_agentic_config(tmp_path, False)))
    run_on = await scanner.run_scan_from_config(str(_agentic_config(tmp_path, True)))

    assert run_off.agentic is False
    assert run_on.agentic is True
    # LLM06 conf 0.6: Medium without escalation, High with it.
    off = triage_findings(run_off.findings, agentic=run_off.agentic)
    on = triage_findings(run_on.findings, agentic=run_on.agentic)
    assert off[0].severity is Severity.MEDIUM
    assert on[0].severity is Severity.HIGH
