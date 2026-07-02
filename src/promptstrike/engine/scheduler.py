"""Concurrency, rate limiting, and retries for provider/judge calls.

Owns how many attacks run at once and how failed calls are retried, so probes
and the judge stay unaware of scheduling concerns.
"""

from __future__ import annotations

from collections.abc import Awaitable, Iterable
from typing import TypeVar

T = TypeVar("T")


async def gather_limited(
    tasks: Iterable[Awaitable[T]],
    *,
    concurrency: int,
) -> list[T]:
    """Run awaitables with a bounded concurrency limit.

    Args:
        tasks: The awaitables to run.
        concurrency: Maximum number in flight at once.

    Returns:
        Results in completion order. TODO: define ordering + retry policy.
    """
    raise NotImplementedError
