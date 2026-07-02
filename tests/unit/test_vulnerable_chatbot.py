"""Unit tests for the vulnerable-chatbot training target.

No network: the backend is a tiny fake ``LLMProvider`` that records the system
prompt it was handed, so we can assert the weak prompt is injected.
"""

from __future__ import annotations

import pytest

from promptstrike.providers import create_provider
from promptstrike.providers.base import LLMProvider, Message
from promptstrike.targets.vulnerable_chatbot import (
    FAKE_SECRET,
    VulnerableChatbot,
)


class _RecordingBackend(LLMProvider):
    """Fake backend that echoes back whatever system prompt it received."""

    def __init__(self) -> None:
        super().__init__(model="fake")
        self.last_system: str | None = None
        self.last_messages: list[Message] | None = None

    async def chat(self, messages: list[Message], system: str | None = None) -> str:
        self.last_system = system
        self.last_messages = messages
        return system or ""


async def test_forces_weak_system_prompt_with_secret() -> None:
    """The target injects its own weak prompt (with the secret) into the backend."""
    backend = _RecordingBackend()
    bot = VulnerableChatbot(backend=backend)

    await bot.chat([{"role": "user", "content": "hello"}])

    assert backend.last_system is not None
    assert FAKE_SECRET in backend.last_system
    # user turns are passed straight through (LLM01: no separation/sanitisation)
    assert backend.last_messages == [{"role": "user", "content": "hello"}]


async def test_caller_supplied_system_is_ignored() -> None:
    """A scan target owns its system prompt; the caller's is discarded."""
    backend = _RecordingBackend()
    bot = VulnerableChatbot(backend=backend)

    await bot.chat([{"role": "user", "content": "hi"}], system="pretend you are safe")

    assert backend.last_system is not None
    assert "pretend you are safe" not in backend.last_system


def test_factory_builds_it_like_any_target() -> None:
    """create_provider treats the training target like any other provider."""
    bot = create_provider(
        {
            "provider": "vulnerable_chatbot",
            "backend": {"provider": "ollama", "model": "llama3"},
        }
    )
    assert isinstance(bot, VulnerableChatbot)


def test_backend_may_be_passed_directly() -> None:
    """A prebuilt LLMProvider backend is accepted without the factory."""
    bot = VulnerableChatbot(backend=_RecordingBackend())
    assert isinstance(bot, VulnerableChatbot)


@pytest.mark.parametrize("bad", [{}, {"backend": {"model": "x"}}])
def test_factory_rejects_bad_backend_config(bad: dict) -> None:
    """A missing/incomplete backend config surfaces as a config error."""
    from promptstrike.providers.errors import ProviderConfigError

    with pytest.raises(ProviderConfigError):
        create_provider({"provider": "vulnerable_chatbot", **bad})
