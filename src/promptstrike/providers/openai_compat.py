"""Provider adapter for OpenAI-compatible ``/chat/completions`` endpoints.

This one adapter covers a huge slice of the ecosystem: OpenAI itself, most
hosted gateways (Together, Groq, OpenRouter, vLLM, LM Studio), and Ollama's
``/v1`` compatibility shim. That's why the base URL is fully configurable —
only the host changes, the wire format doesn't.
"""

from __future__ import annotations

import httpx

from promptstrike.providers.base import DEFAULT_TIMEOUT, LLMProvider, Message
from promptstrike.providers.errors import ProviderResponseError


class OpenAICompatProvider(LLMProvider):
    """Talks to any OpenAI-compatible chat-completions endpoint."""

    def __init__(
        self,
        *,
        model: str,
        base_url: str = "https://api.openai.com/v1",
        api_key: str | None = None,
        timeout: httpx.Timeout = DEFAULT_TIMEOUT,
        max_retries: int = 2,
        backoff: float = 0.5,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        """Configure the endpoint.

        Args:
            model: Model id sent in the request body.
            base_url: API root ending at ``/v1`` (host varies, format doesn't).
            api_key: Bearer token; optional for local servers that ignore auth.
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
        self._api_key = api_key

    async def chat(self, messages: list[Message], system: str | None = None) -> str:
        """Send an OpenAI-style chat request and return the reply text.

        The system prompt is prepended as a ``system`` role message — the
        convention every OpenAI-compatible server understands.
        """
        wire_messages: list[Message] = []
        if system is not None:
            wire_messages.append({"role": "system", "content": system})
        wire_messages.extend(messages)

        headers = {"Content-Type": "application/json"}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"

        data = await self._post_json(
            f"{self._base_url}/chat/completions",
            headers=headers,
            payload={"model": self.model, "messages": wire_messages},
        )
        try:
            return data["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise ProviderResponseError(
                f"unexpected OpenAI-compatible response shape: {data!r:.200}"
            ) from exc
