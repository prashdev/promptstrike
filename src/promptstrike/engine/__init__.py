"""Scan orchestration: run probes against a target and collect findings.

``engine.scanner.run_scan`` wires the target provider, probe library, and
LLM-as-judge together and produces ``Finding`` objects. Orchestration only — no
attack payloads or scoring logic live here.
"""
