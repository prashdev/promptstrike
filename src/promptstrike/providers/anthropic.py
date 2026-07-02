"""Provider adapter for the Anthropic Messages API.

Anthropic differs from the OpenAI shape in three ways this adapter absorbs so
nothing upstream has to care: auth is ``x-api-key`` (not bearer), a version
header is required, the system prompt is a top-level field (not a message), and
``max_tokens`` is mandatory.
"""

from __future__ import annotations

import httpx

from promptstrike.providers.base import DEFAULT_TIMEOUT, LLMProvider, Message
from promptstrike.providers.errors import ProviderResponseError

#: Pinned Messages API version; bump deliberately, not implicitly.
_ANTHROPIC_VERSION = "2023-06-01"


class AnthropicProvider(LLMProvider):
    """Talks to the Anthropic ``/v1/messages`` endpoint."""

    def __init__(
        self,
        *,
        model: str,
        api_key: str,
        base_url: str = "https://api.anthropic.com",
        max_tokens: int = 1024,
        timeout: httpx.Timeout = DEFAULT_TIMEOUT,
        max_retries: int = 2,
        backoff: float = 0.5,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        """Configure the endpoint.

        Args:
            model: Anthropic model id.
            api_key: Value for the ``x-api-key`` header (required).
            base_url: API root (override for proxies/gateways).
            max_tokens: Required response cap; a probe reply is usually short.
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
        self._max_tokens = max_tokens

    async def chat(self, messages: list[Message], system: str | None = None) -> str:
        """Send an Anthropic Messages request and return the reply text.

        Unlike OpenAI, the system prompt is a top-level ``system`` field, so we
        pass it through rather than folding it into ``messages``.
        """
        payload: dict[str, object] = {
            "model": self.model,
            "max_tokens": self._max_tokens,
            "messages": messages,
        }
        if system is not None:
            payload["system"] = system

        headers = {
            "x-api-key": self._api_key,
            "anthropic-version": _ANTHROPIC_VERSION,
            "Content-Type": "application/json",
        }

        data = await self._post_json(
            f"{self._base_url}/v1/messages",
            headers=headers,
            payload=payload,
        )
        try:
            # content is a list of typed blocks; concatenate the text blocks.
            return "".join(
                block["text"]
                for block in data["content"]
                if block.get("type") == "text"
            )
        except (KeyError, TypeError) as exc:
            raise ProviderResponseError(
                f"unexpected Anthropic response shape: {data!r:.200}"
            ) from exc
