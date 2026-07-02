"""Registry mapping provider names to concrete ``LLMProvider`` classes.

Single source of truth for "which string selects which adapter". The public
factory in ``providers/__init__.py`` reads this table, so adding a backend is:
implement the adapter, then add one line here.
"""

from __future__ import annotations

from promptstrike.providers.anthropic import AnthropicProvider
from promptstrike.providers.base import LLMProvider
from promptstrike.providers.ollama import OllamaProvider
from promptstrike.providers.openai_compat import OpenAICompatProvider
from promptstrike.targets.vulnerable_chatbot import VulnerableChatbot

#: Config ``provider:`` value -> adapter class.
PROVIDERS: dict[str, type[LLMProvider]] = {
    "openai": OpenAICompatProvider,
    "openai_compat": OpenAICompatProvider,
    "anthropic": AnthropicProvider,
    "ollama": OllamaProvider,
    # Local training target (see promptstrike.targets); selectable like any
    # provider so scans can point at it via config.
    "vulnerable_chatbot": VulnerableChatbot,
}
