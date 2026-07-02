"""The ``LLMProvider`` abstraction: the only boundary that knows vendor APIs.

Design choices that make this the model-agnostic seam of the whole scanner:

* **One method, one shape.** Every backend implements ``chat(messages, system)``
  and returns a plain ``str``. The rest of the package (probes, judge, engine)
  only ever sees that method, so it never learns which vendor is behind it.
* **Neutral message type.** Messages are plain ``{"role", "content"}`` dicts, not
  vendor SDK objects or pydantic models. Each adapter translates this neutral
  shape into its vendor payload and translates the vendor response back to a
  string, so no vendor detail leaks upward.
* **Shared transport.** Timeouts and basic retry live here once, so every adapter
  inherits the same resilience instead of re-implementing it.
* **Injectable client.** ``chat`` runs over an ``httpx.AsyncClient`` that can be
  supplied by the caller — real code lets the provider create/pool one; tests
  pass a client backed by a mock transport, so no network is touched.

``async`` is deliberate: the scheduler drives many concurrent target/judge calls
(see CLAUDE.md), and ``httpx.AsyncClient`` gives us connection pooling for free.
An ``async def`` still fulfils the ``-> str`` contract: awaiting it yields a str.
"""

from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod
from typing import Self

import httpx

from promptstrike.providers.errors import ProviderResponseError

#: A single chat turn. Kept as a bare dict on purpose (see module docstring).
Message = dict[str, str]

#: Split timeouts: fail fast on a dead host, but allow slow model generations.
DEFAULT_TIMEOUT = httpx.Timeout(connect=5.0, read=60.0, write=10.0, pool=5.0)

#: Transient statuses worth retrying; everything else 4xx/5xx fails immediately.
_RETRYABLE_STATUS = frozenset({408, 409, 429, 500, 502, 503, 504})


class LLMProvider(ABC):
    """Abstract adapter for a chat LLM endpoint (a scan target or the judge)."""

    def __init__(
        self,
        *,
        model: str,
        timeout: httpx.Timeout = DEFAULT_TIMEOUT,
        max_retries: int = 2,
        backoff: float = 0.5,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        """Store common transport settings.

        Args:
            model: Model name/id passed through to the vendor request.
            timeout: Per-request timeout policy.
            max_retries: Extra attempts after the first on transient failures.
            backoff: Base seconds for exponential backoff between retries.
            client: Optional injected async client (tests supply a mock one).
        """
        self.model = model
        self._timeout = timeout
        self._max_retries = max_retries
        self._backoff = backoff
        self._client = client
        self._owns_client = client is None

    @abstractmethod
    async def chat(self, messages: list[Message], system: str | None = None) -> str:
        """Send a conversation to the target and return its reply text.

        Args:
            messages: Ordered ``{"role", "content"}`` turns.
            system: Optional system prompt, mapped to each vendor's convention.

        Returns:
            The assistant's reply as plain text.
        """
        raise NotImplementedError

    # -- shared transport ---------------------------------------------------

    def _get_client(self) -> httpx.AsyncClient:
        """Return the async client, lazily creating a pooled one if needed."""
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=self._timeout)
            self._owns_client = True
        return self._client

    async def _post_json(
        self,
        url: str,
        *,
        headers: dict[str, str],
        payload: dict[str, object],
    ) -> dict:
        """POST JSON with timeouts and exponential-backoff retry.

        Retries only transient failures (network errors and the statuses in
        ``_RETRYABLE_STATUS``); any other 4xx/5xx fails immediately so we don't
        hammer an endpoint over a bad request or bad credentials.
        """
        client = self._get_client()
        last_exc: Exception | None = None
        for attempt in range(self._max_retries + 1):
            try:
                response = await client.post(url, headers=headers, json=payload)
                response.raise_for_status()
                return response.json()
            except httpx.HTTPStatusError as exc:
                if exc.response.status_code not in _RETRYABLE_STATUS:
                    raise ProviderResponseError(
                        f"{url} returned {exc.response.status_code}: "
                        f"{exc.response.text[:200]}"
                    ) from exc
                last_exc = exc
            except httpx.TransportError as exc:  # timeouts, connection errors
                last_exc = exc
            if attempt < self._max_retries:
                await asyncio.sleep(self._backoff * (2**attempt))
        raise ProviderResponseError(
            f"{url} failed after {self._max_retries + 1} attempts"
        ) from last_exc

    async def aclose(self) -> None:
        """Close the underlying client if this provider created it."""
        if self._owns_client and self._client is not None:
            await self._client.aclose()
            self._client = None

    async def __aenter__(self) -> Self:
        """Support ``async with`` for deterministic client cleanup."""
        return self

    async def __aexit__(self, *exc: object) -> None:
        """Close the client on context exit."""
        await self.aclose()


#: Backwards-compatible alias for the earlier scaffold name used by probe/judge
#: stubs. ``LLMProvider`` is the canonical name going forward.
Provider = LLMProvider
