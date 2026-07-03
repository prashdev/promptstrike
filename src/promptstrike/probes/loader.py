"""Load probe definitions from YAML files into ``Probe`` models.

Probe definitions live as one YAML file per OWASP category under the repo-root
``probes/`` directory (kept as data, separate from this code package). This
loader reads them all into memory and validates each against the ``Probe`` model,
so unknown ids or malformed entries fail loudly at load time.
"""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import ValidationError

from promptstrike.models.probe import Probe
from promptstrike.probes.errors import ProbeLoadError

#: Repo-root ``probes/`` directory (this file is src/promptstrike/probes/loader.py).
DEFAULT_PROBE_DIR = Path(__file__).resolve().parents[3] / "probes"


def load_probe_file(path: str | Path) -> Probe:
    """Load and validate a single probe YAML file.

    Args:
        path: Path to a probe YAML file.

    Returns:
        The validated ``Probe``.

    Raises:
        ProbeLoadError: If the file is unreadable, not a mapping, or invalid.
    """
    path = Path(path)
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ProbeLoadError(f"could not read probe file {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ProbeLoadError(f"probe file {path} must contain a YAML mapping")
    try:
        return Probe.model_validate(data)
    except ValidationError as exc:
        raise ProbeLoadError(f"invalid probe in {path}:\n{exc}") from exc


def load_probes(directory: str | Path | None = None) -> list[Probe]:
    """Load every ``*.yaml`` probe in a directory into memory.

    Args:
        directory: Directory of probe YAMLs; defaults to ``DEFAULT_PROBE_DIR``.

    Returns:
        Probes sorted by ``owasp_id``.

    Raises:
        ProbeLoadError: If the directory is missing, empty, or has duplicate ids.
    """
    directory = Path(directory) if directory is not None else DEFAULT_PROBE_DIR
    if not directory.is_dir():
        raise ProbeLoadError(f"probe directory not found: {directory}")

    probes = [load_probe_file(p) for p in sorted(directory.glob("*.yaml"))]
    if not probes:
        raise ProbeLoadError(f"no probe YAML files found in {directory}")

    for key, label in (("id", "probe id"), ("owasp_id", "OWASP id")):
        seen: set[str] = set()
        for probe in probes:
            value = getattr(probe, key)
            if value in seen:
                raise ProbeLoadError(f"duplicate {label} across probe files: {value}")
            seen.add(value)

    return sorted(probes, key=lambda p: p.owasp_id)
