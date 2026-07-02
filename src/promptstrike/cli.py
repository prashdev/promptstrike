"""Rich-based CLI entrypoint and argument parsing for PromptStrike.

Parses command-line arguments, shows the authorised-use notice, loads the run
config, drives the scan engine, and writes the report. No scanning logic lives
here — this module only wires the CLI to the engine.
"""

from __future__ import annotations


def main(argv: list[str] | None = None) -> int:
    """Run the PromptStrike CLI.

    Args:
        argv: Optional argument vector (defaults to ``sys.argv[1:]``).

    Returns:
        Process exit code.
    """
    raise NotImplementedError
