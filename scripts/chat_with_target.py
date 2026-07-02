#!/usr/bin/env python3
"""Tiny interactive REPL to chat with the vulnerable training target by hand.

Wraps a local Ollama model in ``VulnerableChatbot`` and loops: read a line, send
it through the target, print the reply. Handy for eyeballing how the planted
weaknesses behave before pointing the scanner at it.

Usage:
    python scripts/chat_with_target.py [MODEL]

    MODEL defaults to $OLLAMA_MODEL, then the target's RECOMMENDED_MODEL (a
    lightly-tuned model that actually follows the weak prompt). The Ollama server
    is read from $OLLAMA_HOST (default http://localhost:11434). Ctrl-C / Ctrl-D
    exits.
"""

from __future__ import annotations

import asyncio
import os
import sys

from promptstrike.providers.base import Message
from promptstrike.providers.ollama import OllamaProvider
from promptstrike.targets.vulnerable_chatbot import (
    RECOMMENDED_MODEL,
    VulnerableChatbot,
)


async def main() -> None:
    """Run the read/send/print loop against the vulnerable target."""
    # Default to the deliberately-weak research model (see RECOMMENDED_MODEL):
    # safety-tuned models like llama3.2 refuse even this careless prompt.
    default_model = os.environ.get("OLLAMA_MODEL") or RECOMMENDED_MODEL
    model = sys.argv[1] if len(sys.argv) > 1 else default_model
    base_url = os.environ.get("OLLAMA_HOST", "http://localhost:11434")

    backend = OllamaProvider(model=model, base_url=base_url)
    target = VulnerableChatbot(backend=backend)

    print(f"Chatting with vulnerable_chatbot (backend: ollama/{model}).")
    print("Training target only. Type a message; Ctrl-C or Ctrl-D to quit.\n")

    history: list[Message] = []
    try:
        while True:
            try:
                user = input("you> ").strip()
            except EOFError:
                break
            if not user:
                continue
            history.append({"role": "user", "content": user})
            reply = await target.chat(history)
            history.append({"role": "assistant", "content": reply})
            print(f"bot> {reply}\n")
    finally:
        await target.aclose()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print()
