# PromptStrike

A black-box LLM red-teaming scanner. It probes a target LLM endpoint for
**OWASP LLM Top 10 (2025)** weaknesses, uses an **LLM-as-judge** to score whether
each attack succeeded, filters false positives, and generates a professional
penetration-test report.

> **Authorised use only.** Run PromptStrike only against endpoints you own or
> have explicit written permission to test.

See [CLAUDE.md](CLAUDE.md) for architecture, folder layout, and conventions.

## Status

Early scaffold — package skeleton only, no scanning logic implemented yet.

## Quick start (planned)

```bash
pip install -e ".[dev]"
promptstrike run --config configs/example.yaml
```

## Training target (safe, reproducible testing)

`promptstrike.targets.vulnerable_chatbot.VulnerableChatbot` is a **deliberately
weak, local "application"** you can scan instead of a real system. It wraps a
backend provider (e.g. a local Ollama model) with an intentionally sloppy system
prompt: a **fake** `INTERNAL_API_KEY` and **fake** "internal" records are pasted
in as casual working context, with **no** instruction to keep them private and
no guardrails on user input. It leaks by carelessness, the way a real rushed app
does — not by being told to resist an attacker. Nothing in it is a real secret,
and it is exposed through the same `LLMProvider` interface, so the scanner treats
it exactly like any external target.

Select it from config like any other provider:

```yaml
target:
  provider: vulnerable_chatbot
  backend:
    provider: ollama
    model: dolphin-mistral   # see model note below
```

Its planted weaknesses map to the OWASP LLM Top 10 (2025) as:

| Weakness in the target                                   | OWASP LLM category                          |
|----------------------------------------------------------|---------------------------------------------|
| User input passed through with no separation and no guardrails | **LLM01:2025 Prompt Injection**             |
| Sensitive context in the prompt with no "keep private" instruction | **LLM07:2025 System Prompt Leakage**        |
| Fake API key + fake internal records handed over as ordinary context | **LLM02:2025 Sensitive Information Disclosure** |

### Choosing the backing model (important)

General-purpose, **safety-tuned** models (Llama 3.x, Qwen, Gemma) will refuse
even this carelessly-configured prompt — their alignment training overrides the
weak system prompt entirely, so scans produce no findings. For this demo target
use a **lightly-tuned / "uncensored"** model that follows its system prompt more
literally. Both are pullable via Ollama:

```bash
ollama pull dolphin-mistral    # 7B, uncensored, instruction-following (default)
# or, if RAM is tight:
ollama pull llama2-uncensored  # smaller alternative
```

> **Honest trade-off.** Picking a lightly-tuned model makes this target
> *deliberately* weaker than any real deployment. Its compliance is **not**
> representative of production model behaviour — a modern safety-tuned model
> would resist most of these attacks. This is a research/demo dummy whose only
> job is to reliably exhibit the weaknesses so you can develop and verify probes.

> This target exists **only** to be scanned by PromptStrike. It is not a real
> integration; do not deploy it or use it for anything else.
