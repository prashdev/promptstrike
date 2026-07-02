"""Post-verdict false-positive filtering.

Takes the judge's verdicts and drops likely false positives before they become
findings. A distinct, testable stage so the final verdict is never a raw
string match.
"""

from __future__ import annotations


def is_false_positive(verdict: object) -> bool:
    """Decide whether a judged verdict is a false positive.

    Args:
        verdict: A verdict produced by the judge.

    Returns:
        True if the verdict should be discarded.
    """
    raise NotImplementedError
