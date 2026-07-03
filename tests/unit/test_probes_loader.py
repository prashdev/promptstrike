"""Unit tests for the probe library and its loader.

Loads the real ``probes/`` YAMLs (no network) and checks structural invariants,
plus validation failures for malformed probes.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from promptstrike.models.probe import Probe
from promptstrike.probes.errors import ProbeLoadError
from promptstrike.probes.loader import load_probe_file, load_probes

IN_SCOPE = {
    "LLM01:2025",
    "LLM02:2025",
    "LLM05:2025",
    "LLM06:2025",
    "LLM07:2025",
    "LLM09:2025",
}
OUT_OF_SCOPE = {"LLM03:2025", "LLM04:2025", "LLM08:2025", "LLM10:2025"}


def test_default_library_loads_all_ten_categories() -> None:
    """The shipped probes/ directory yields all ten OWASP categories, once each."""
    probes = load_probes()
    owasp_ids = {p.owasp_id for p in probes}
    assert owasp_ids == IN_SCOPE | OUT_OF_SCOPE
    assert len(probes) == 10


def test_in_scope_probes_have_payloads_and_criteria() -> None:
    """Every in-scope probe carries at least one payload and success criteria."""
    for p in load_probes():
        if p.owasp_id in IN_SCOPE:
            assert not p.out_of_scope
            assert p.payloads
            assert p.success_criteria


def test_out_of_scope_probes_are_stubs_with_reason() -> None:
    """Out-of-scope stubs are flagged, have a reason, and carry no payloads."""
    for p in load_probes():
        if p.owasp_id in OUT_OF_SCOPE:
            assert p.out_of_scope
            assert p.out_of_scope_reason
            assert not p.payloads


def test_seed_payloads_from_manual_baseline_present() -> None:
    """LLM01/02/07 include the hand-validated baseline prompts as seed payloads."""
    by_id = {p.owasp_id: p for p in load_probes()}
    assert any("DebugBot" in pl for pl in by_id["LLM01:2025"].payloads), (
        "LLM01 seed (baseline Case 3) missing"
    )
    assert any("on-call engineer" in pl for pl in by_id["LLM02:2025"].payloads), (
        "LLM02 seed (baseline Case 2) missing"
    )
    assert any(
        'beginning with "You are"' in pl for pl in by_id["LLM07:2025"].payloads
    ), "LLM07 seed (baseline Case 1) missing"


def test_loader_rejects_unknown_owasp_id(tmp_path: Path) -> None:
    """An OWASP id absent from the catalogue fails validation."""
    f = tmp_path / "bad.yaml"
    f.write_text(
        textwrap.dedent(
            """
            id: bogus
            owasp_id: "LLM99:2025"
            atlas_technique: "no direct ATLAS mapping"
            category_name: "Nope"
            out_of_scope: true
            out_of_scope_reason: "n/a"
            """
        ),
        encoding="utf-8",
    )
    with pytest.raises(ProbeLoadError):
        load_probe_file(f)


def test_loader_rejects_fabricated_atlas_id(tmp_path: Path) -> None:
    """A non-catalogued ATLAS id (not the sentinel) is rejected."""
    f = tmp_path / "bad.yaml"
    f.write_text(
        textwrap.dedent(
            """
            id: llm01_x
            owasp_id: "LLM01:2025"
            atlas_technique: "AML.T9999"
            category_name: "Prompt Injection"
            success_criteria: "leaks"
            payloads: ["x"]
            """
        ),
        encoding="utf-8",
    )
    with pytest.raises(ProbeLoadError):
        load_probe_file(f)


def test_in_scope_without_payload_is_invalid() -> None:
    """An in-scope probe (out_of_scope False) with no payloads fails."""
    with pytest.raises(ValueError):
        Probe(
            id="x",
            owasp_id="LLM01:2025",
            atlas_technique="AML.T0051",
            category_name="Prompt Injection",
            success_criteria="leaks",
            payloads=[],
        )


def test_category_name_must_match_catalogue() -> None:
    """A category_name that disagrees with the OWASP title is rejected."""
    with pytest.raises(ValueError):
        Probe(
            id="x",
            owasp_id="LLM01:2025",
            atlas_technique="AML.T0051",
            category_name="Wrong Title",
            success_criteria="leaks",
            payloads=["x"],
        )
