"""Unit tests for the config-driven run_scan_from_config wrapper.

The underlying run_scan is faked so these tests exercise only the YAML-loading
wiring (provider construction, env resolution, probe selection) — no network.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from promptstrike.config.errors import ConfigError
from promptstrike.engine import scanner
from promptstrike.mappings.mitre_atlas import NO_DIRECT_ATLAS_MAPPING
from promptstrike.models.finding import Finding, JudgeVerdict, Transcript
from promptstrike.models.triage import Severity
from promptstrike.providers.ollama import OllamaProvider
from promptstrike.targets.vulnerable_chatbot import VulnerableChatbot

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


async def test_wrapper_builds_providers_and_selects_probes(
    tmp_path: Path, monkeypatch
) -> None:
    """The wrapper builds target/judge providers and passes the selected probes."""
    captured: dict[str, object] = {}

    async def fake_run_scan(target, judge, probes, *, console=None):
        captured["target"] = target
        captured["judge"] = judge
        captured["probes"] = probes
        return []

    monkeypatch.setattr(scanner, "run_scan", fake_run_scan)

    findings = await scanner.run_scan_from_config(str(_write(tmp_path, _CONFIG)))

    assert findings == []
    assert isinstance(captured["target"], VulnerableChatbot)
    assert isinstance(captured["judge"], OllamaProvider)
    # Only the two selected probes, in config order.
    assert [p.id for p in captured["probes"]] == [
        "llm01_prompt_injection",
        "llm07_system_prompt_leak",
    ]


async def test_wrapper_runs_whole_library_when_probes_omitted(
    tmp_path: Path, monkeypatch
) -> None:
    """Omitting `probes` runs the full library (loader returns all 10)."""
    captured: dict[str, object] = {}

    async def fake_run_scan(target, judge, probes, *, console=None):
        captured["probes"] = probes
        return []

    monkeypatch.setattr(scanner, "run_scan", fake_run_scan)

    body = "\n".join(line for line in _CONFIG.splitlines() if "llm0" not in line)
    body = body.replace("probes:", "")
    await scanner.run_scan_from_config(str(_write(tmp_path, body)))

    assert len(captured["probes"]) == 10


async def test_wrapper_resolves_env_refs(tmp_path: Path, monkeypatch) -> None:
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


async def test_wrapper_rejects_unknown_probe_id(tmp_path: Path) -> None:
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


async def test_agentic_flag_from_config_drives_triage(
    tmp_path: Path, monkeypatch
) -> None:
    """target.agentic in YAML flows through to triage severity escalation."""
    # LLM06 at confidence 0.6: base High, low exploitability (-1) -> Medium;
    # agentic escalation (+1 for LLM06) -> High. So the config flag alone flips
    # the severity, proving it is sourced from YAML and not a code default.
    finding = Finding(
        probe_id="llm06_excessive_agency",
        owasp_id="LLM06:2025",
        atlas_technique=NO_DIRECT_ATLAS_MAPPING,
        category_name="Excessive Agency",
        success_criteria="c",
        verdict=JudgeVerdict(
            success=True, confidence=0.6, evidence="deleted the record", reasoning="r"
        ),
        transcript=Transcript(payload="delete everything", response="done"),
    )

    async def fake_run_scan(target, judge, probes, *, console=None):
        return [finding]

    monkeypatch.setattr(scanner, "run_scan", fake_run_scan)

    non_agentic = await scanner.run_scan_from_config(
        str(_agentic_config(tmp_path, False))
    )
    agentic = await scanner.run_scan_from_config(str(_agentic_config(tmp_path, True)))

    assert non_agentic[0].severity is Severity.MEDIUM
    assert agentic[0].severity is Severity.HIGH
