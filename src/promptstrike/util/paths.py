"""Resolve bundled data (probes, configs) across source and wheel layouts.

The probe library and config data live at the repo root (``probes/``,
``configs/``) so they are easy to read and edit during development. When the
package is built as a wheel, those directories are force-included under the
package as ``promptstrike/_data/`` (see ``pyproject.toml``) so they ship with the
distribution. These helpers prefer the packaged copy and fall back to the
repo-root copy, so the same code path works whether PromptStrike is run from a
source checkout, an editable install, or an installed wheel.
"""

from __future__ import annotations

from pathlib import Path

#: ``.../promptstrike`` — the installed/importable package directory.
_PACKAGE_ROOT = Path(__file__).resolve().parent.parent
#: Repo root in a src-layout checkout (``.../<repo>``); only used as a fallback.
_REPO_ROOT = _PACKAGE_ROOT.parents[1]


def data_dir(name: str) -> Path:
    """Return the directory of a bundled data set (e.g. ``"probes"``).

    Prefers the packaged copy (``promptstrike/_data/<name>``, present in a built
    wheel); falls back to the repo-root ``<name>`` directory for source/editable
    runs.
    """
    packaged = _PACKAGE_ROOT / "_data" / name
    return packaged if packaged.is_dir() else _REPO_ROOT / name
