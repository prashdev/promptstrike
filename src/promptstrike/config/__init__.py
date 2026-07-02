"""Run-config loading, validation, and ``${ENV}`` resolution.

``config.loader`` is the single owner of environment-variable resolution for a
run (see CLAUDE.md); everything else receives already-resolved config.
"""
