"""Persist and reload raw scan results (``ScanRun``) as timestamped JSON.

Keeping the raw findings on disk is what makes ``scan`` and ``report`` separable:
the scan writes ``promptstrike-results-<timestamp>.json``; ``report`` reads it
back and re-triages/re-renders without touching the target again.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from pydantic import ValidationError

from promptstrike.engine.errors import ResultsError
from promptstrike.models.scan import ScanRun


def timestamped_path(
    directory: str | Path, prefix: str, ext: str, when: datetime | None = None
) -> Path:
    """Build ``<directory>/<prefix>-YYYYMMDD-HHMMSSZ.<ext>``."""
    when = when or datetime.now(UTC)
    stamp = when.strftime("%Y%m%d-%H%M%SZ")
    return Path(directory) / f"{prefix}-{stamp}.{ext}"


def save_scan_run(run: ScanRun, directory: str | Path) -> Path:
    """Write a ``ScanRun`` to a timestamped JSON file and return its path."""
    path = timestamped_path(directory, "promptstrike-results", "json", run.scanned_at)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(run.model_dump_json(indent=2), encoding="utf-8")
    return path


def load_scan_run(path: str | Path) -> ScanRun:
    """Read a ``ScanRun`` back from a JSON file.

    Raises:
        ResultsError: If the file is unreadable or not a valid results file.
    """
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        raise ResultsError(f"could not read results file {path}: {exc}") from exc
    try:
        return ScanRun.model_validate_json(text)
    except ValidationError as exc:
        raise ResultsError(f"invalid results file {path}:\n{exc}") from exc
