"""Scoring rubrics per attack type used by the LLM-as-judge.

Holds the structured criteria the judge applies so scoring is consistent and
auditable. Kept separate from ``judge.py`` so rubrics can be tuned in isolation.
"""

from __future__ import annotations


def rubric_for(owasp_id: str) -> str:
    """Return the judge rubric text for a given OWASP LLM category.

    Args:
        owasp_id: OWASP LLM id, e.g. ``"LLM01:2025"``.

    Returns:
        The rubric prompt fragment for that category.
    """
    raise NotImplementedError
