"""Unit tests for config loading and ${ENV} resolution.

``config.loader`` is the single owner of environment-variable resolution, so the
resolution behaviour is tested here (not in the provider factory).
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from promptstrike.config.errors import ConfigError
from promptstrike.config.loader import load_config_dict, resolve_env_refs


def test_resolve_env_refs_recurses_through_dicts_and_lists(monkeypatch) -> None:
    """Resolution walks nested structures and leaves non-strings untouched."""
    monkeypatch.setenv("K", "secret")
    resolved = resolve_env_refs(
        {"api_key": "${K}", "list": ["${K}", 1], "nested": {"model": "x"}}
    )
    assert resolved == {
        "api_key": "secret",
        "list": ["secret", 1],
        "nested": {"model": "x"},
    }


def test_resolve_env_refs_missing_var_raises(monkeypatch) -> None:
    """An unset ${ENV} reference is a ConfigError, not a silent empty string."""
    monkeypatch.delenv("ABSENT", raising=False)
    with pytest.raises(ConfigError):
        resolve_env_refs("${ABSENT}")


def test_load_config_dict_reads_and_resolves(tmp_path: Path, monkeypatch) -> None:
    """load_config_dict returns a fully resolved plain dict from YAML."""
    monkeypatch.setenv("TARGET_API_KEY", "sk-live")
    cfg = tmp_path / "run.yaml"
    cfg.write_text(
        textwrap.dedent(
            """
            target:
              provider: openai
              model: gpt-x
              api_key: ${TARGET_API_KEY}
            """
        ),
        encoding="utf-8",
    )
    doc = load_config_dict(cfg)
    assert doc["target"]["api_key"] == "sk-live"
