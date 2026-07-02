"""Domain models for target endpoints and chat exchanges.

``TargetSpec`` describes how to reach and talk to a target LLM; ``Message`` and
``ChatResponse`` are the provider-agnostic request/response types every
``Provider`` speaks in.
"""

from __future__ import annotations

from pydantic import BaseModel


class Message(BaseModel):
    """A single chat message (role + content). TODO: define fields."""


class ChatResponse(BaseModel):
    """A provider-agnostic chat completion response. TODO: define fields."""


class TargetSpec(BaseModel):
    """How to reach and authenticate to a target LLM. TODO: define fields."""
