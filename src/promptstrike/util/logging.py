"""Rich-based logging setup for PromptStrike."""

from __future__ import annotations

import logging


def setup_logging(level: int = logging.INFO) -> None:
    """Configure a rich log handler for the process.

    Args:
        level: Minimum log level to emit.
    """
    raise NotImplementedError
