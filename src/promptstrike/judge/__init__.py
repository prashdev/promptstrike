"""LLM-as-judge: score attack success with a separate model under a strict rubric.

``judge_attack`` (in ``judge.judge``) sends the payload, the probe's success
criteria, and the target response to a separate judge provider and returns a
structured ``JudgeVerdict``. Kept apart from ``probes`` so scoring strategy and
model can change without touching attack logic.
"""
