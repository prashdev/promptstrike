"""Unit tests for the provider layer.

All HTTP is mocked with ``httpx.MockTransport`` and injected via the ``client``
kwarg, so these tests never touch the network — matching the project rule that
unit tests mock I/O.
"""

from __future__ import annotations

import httpx
import pytest

from promptstrike.providers import (
    ProviderConfigError,
    ProviderResponseError,
    create_provider,
)
from promptstrike.providers.anthropic import AnthropicProvider
from promptstrike.providers.ollama import OllamaProvider
from promptstrike.providers.openai_compat import OpenAICompatProvider


def _client(handler) -> httpx.AsyncClient:
    """Build an async client whose requests are served by ``handler``."""
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


async def test_openai_compat_maps_system_and_parses_reply() -> None:
    """System prompt becomes a system message; reply content is returned."""
    seen: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["path"] = request.url.path
        seen["auth"] = request.headers.get("authorization")
        import json

        seen["body"] = json.loads(request.content)
        return httpx.Response(
            200, json={"choices": [{"message": {"content": "hi there"}}]}
        )

    provider = OpenAICompatProvider(
        model="gpt-x",
        base_url="http://host/v1",
        api_key="secret",
        client=_client(handler),
    )
    reply = await provider.chat(
        [{"role": "user", "content": "hello"}], system="be brief"
    )

    assert reply == "hi there"
    assert seen["path"] == "/v1/chat/completions"
    assert seen["auth"] == "Bearer secret"
    assert seen["body"]["messages"][0] == {"role": "system", "content": "be brief"}


async def test_anthropic_sends_system_field_and_joins_text_blocks() -> None:
    """Anthropic gets system as a top-level field; text blocks are concatenated."""
    seen: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        import json

        seen["body"] = json.loads(request.content)
        seen["version"] = request.headers.get("anthropic-version")
        return httpx.Response(
            200,
            json={
                "content": [
                    {"type": "text", "text": "a"},
                    {"type": "text", "text": "b"},
                ]
            },
        )

    provider = AnthropicProvider(model="claude-x", api_key="k", client=_client(handler))
    reply = await provider.chat(
        [{"role": "user", "content": "hi"}], system="you are terse"
    )

    assert reply == "ab"
    assert seen["body"]["system"] == "you are terse"
    assert seen["version"] == "2023-06-01"


async def test_ollama_native_parses_message_content() -> None:
    """Ollama native returns message.content and posts to /api/chat."""
    seen: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["path"] = request.url.path
        return httpx.Response(200, json={"message": {"content": "pong"}})

    provider = OllamaProvider(model="llama3", client=_client(handler))
    reply = await provider.chat([{"role": "user", "content": "ping"}])

    assert reply == "pong"
    assert seen["path"] == "/api/chat"


async def test_retry_then_success_on_transient_500() -> None:
    """A retryable 500 is retried and the subsequent 200 succeeds."""
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(500, json={"error": "try again"})
        return httpx.Response(200, json={"choices": [{"message": {"content": "ok"}}]})

    provider = OpenAICompatProvider(
        model="m", base_url="http://h/v1", backoff=0.0, client=_client(handler)
    )
    reply = await provider.chat([{"role": "user", "content": "x"}])

    assert reply == "ok"
    assert calls["n"] == 2


async def test_non_retryable_400_raises_immediately() -> None:
    """A 400 is not retried and surfaces as a ProviderResponseError."""
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(400, json={"error": "bad request"})

    provider = OpenAICompatProvider(
        model="m", base_url="http://h/v1", client=_client(handler)
    )
    with pytest.raises(ProviderResponseError):
        await provider.chat([{"role": "user", "content": "x"}])
    assert calls["n"] == 1


def test_factory_builds_provider_from_resolved_dict() -> None:
    """create_provider selects the adapter from an already-resolved dict.

    Env resolution is the config loader's job (see test_config_loader), so the
    factory is handed literal, resolved values.
    """
    provider = create_provider(
        {
            "provider": "openai",
            "model": "gpt-x",
            "base_url": "http://host/v1",
            "api_key": "resolved-key",
        }
    )
    assert isinstance(provider, OpenAICompatProvider)
    assert provider._api_key == "resolved-key"


def test_factory_rejects_unknown_provider() -> None:
    """An unknown provider name is a config error."""
    with pytest.raises(ProviderConfigError):
        create_provider({"provider": "nope", "model": "m"})
