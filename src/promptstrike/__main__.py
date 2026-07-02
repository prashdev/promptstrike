"""Enable ``python -m promptstrike`` by delegating to the CLI entrypoint."""

from promptstrike.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
