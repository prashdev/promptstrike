"""PromptStrike: a black-box LLM red-teaming scanner for the OWASP LLM Top 10.

Probes a target LLM endpoint, scores attack success with an LLM-as-judge,
filters false positives, and emits a penetration-test report. See CLAUDE.md
for architecture and conventions.
"""

__version__ = "0.0.1"
