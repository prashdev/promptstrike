"""Provider adapter for Ollama's native ``/api/chat`` endpoint.

Ollama also exposes an OpenAI-compatible ``/v1`` surface (use
``OpenAICompatProvider`` for that). This adapter targets the *native* API, which
needs no auth, defaults to a local host, and streams unless told not to — so we
set ``stream: false`` to get a single JSON object back.
"""

from __future__ import annotations

import httpx

from promptstrike.providers.base import DEFAULT_TIMEOUT, LLMProvider, Message
from promptstrike.providers.errors import ProviderResponseError


class OllamaProvider(LLMProvider):
    """Talks to a local or remote Ollama server via its native chat API."""

    def __init__(
        self,
        *,
        model: str,
        base_url: str = "http://localhost:11434",
        options: dict[str, object] | None = None,
        timeout: httpx.Timeout = DEFAULT_TIMEOUT,
        max_retries: int = 2,
        backoff: float = 0.5,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        """Configure the endpoint.

        Args:
            model: Local model tag, e.g. ``"llama3"``.
            base_url: Ollama server root (defaults to the local daemon).
            options: Optional Ollama sampling options (e.g.
                ``{"temperature": 0}`` for deterministic output — useful for the
                judge, where a stable verdict matters more than diversity).
            timeout: Per-request timeout policy.
            max_retries: Extra attempts on transient failures.
            backoff: Base backoff seconds.
            client: Optional injected async client (tests supply a mock one).
        """
        super().__init__(
            model=model,
            timeout=timeout,
            max_retries=max_retries,
            backoff=backoff,
            client=client,
        )
        self._base_url = base_url.rstrip("/")
        self._options = options

    async def chat(self, messages: list[Message], system: str | None = None) -> str:
        """Send an Ollama native chat request and return the reply text.

        Ollama accepts a ``system`` role message, so we prepend one when given.
        ``stream`` is disabled to receive one complete JSON response.
        """
        wire_messages: list[Message] = []
        if system is not None:
            wire_messages.append({"role": "system", "content": system})
        wire_messages.extend(messages)

        payload: dict[str, object] = {
            "model": self.model,
            "messages": wire_messages,
            "stream": False,
        }
        if self._options:
            payload["options"] = self._options

        data = await self._post_json(
            f"{self._base_url}/api/chat",
            headers={"Content-Type": "application/json"},
            payload=payload,
        )
        try:
            return data["message"]["content"]
        except (KeyError, TypeError) as exc:
            raise ProviderResponseError(
                f"unexpected Ollama response shape: {data!r:.200}"
            ) from exc
