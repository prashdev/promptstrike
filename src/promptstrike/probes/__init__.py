"""Probe library: declarative attack suites and the loader that reads them.

Probe definitions live as YAML data under the repo-root ``probes/`` directory,
one file per OWASP LLM category, and are loaded into ``models.probe.Probe``
instances by ``promptstrike.probes.loader``.
"""
