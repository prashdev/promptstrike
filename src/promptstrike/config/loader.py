"""Load a YAML run config and resolve ``${ENV}`` credential refs.

**This module is the single owner of environment-variable resolution for a
run.** It resolves the *entire* config tree in one place, so no secrets live in
the YAML file, and every downstream consumer — the provider factory in
particular — receives an already-resolved plain dict and never touches
``os.environ`` itself. See CLAUDE.md ("No secrets in code or config").
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

import yaml

from promptstrike.config.errors import ConfigError
from promptstrike.config.schema import RunConfig

_ENV_REF = re.compile(r"\$\{([^}]+)\}")


def resolve_env_refs(value: Any) -> Any:
    """Recursively replace ``${ENV_VAR}`` refs throughout a config structure.

    Walks dicts and lists and substitutes ``${VAR}`` inside any string, so the
    whole config is resolved in one pass regardless of nesting.

    Args:
        value: Any config value (dict, list, str, or scalar).

    Returns:
        The same structure with all ``${VAR}`` refs replaced.

    Raises:
        ConfigError: If a referenced environment variable is unset.
    """
    if isinstance(value, dict):
        return {k: resolve_env_refs(v) for k, v in value.items()}
    if isinstance(value, list):
        return [resolve_env_refs(v) for v in value]
    if isinstance(value, str):

        def _sub(match: re.Match[str]) -> str:
            name = match.group(1)
            resolved = os.environ.get(name)
            if resolved is None:
                raise ConfigError(f"environment variable {name!r} is not set")
            return resolved

        return _ENV_REF.sub(_sub, value)
    return value


def load_config_dict(path: str | Path) -> dict[str, Any]:
    """Read a YAML file and return a fully env-resolved plain dict.

    This is the low-level entry point used by consumers that want resolved data
    without (yet) validating it against ``RunConfig`` — e.g. the provider
    factory's ``provider_from_yaml`` convenience.

    Args:
        path: Path to the YAML config file.

    Returns:
        The resolved config mapping.

    Raises:
        ConfigError: If the file's top level is not a mapping, or an ``${ENV}``
            reference is unset.
    """
    doc = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    if not isinstance(doc, dict):
        raise ConfigError(f"expected a mapping at top level of {path}")
    return resolve_env_refs(doc)


def load_config(path: str | Path) -> RunConfig:
    """Load a YAML config into a validated, env-resolved ``RunConfig``.

    Args:
        path: Path to the YAML run config.

    Returns:
        The validated run config with ``${ENV}`` references resolved.
    """
    # TODO: validate the resolved dict once RunConfig grows its fields:
    #   return RunConfig.model_validate(load_config_dict(path))
    raise NotImplementedError
