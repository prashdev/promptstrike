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

## Quick start

```bash
pip install -e ".[dev]"
promptstrike scan -c configs/example.yaml
```

## Choosing the judge model

The judge decides whether each attack actually succeeded, so **its quality is
the credibility of the whole report** — a weak judge yields false positives and
false negatives that undermine every finding.

**Default for real scans: a strong Anthropic model.** The example config uses
**`claude-sonnet-5`** — the strongest *reasonably-priced* option, with near-Opus
reasoning at Sonnet cost. Set `ANTHROPIC_API_KEY` (or whatever env var the config
references) and run. Step up to `claude-opus-4-8` when you want the most rigorous
grading, or down to `claude-haiku-4-5` to cut cost on very high-volume runs.

```yaml
judge:
  provider: anthropic
  model: claude-sonnet-5
  api_key: ${JUDGE_API_KEY}
```

**Ollama is an explicit opt-in for cost-free testing**, not the default. It's
useful for local development and CI where you don't want to spend API credits,
but a small local model is a noticeably weaker judge — treat its verdicts as
indicative, not authoritative. (The [local demo](configs/vulnerable_demo.yaml)
uses `llama3.2` at `temperature: 0` for reproducibility.)

```yaml
judge:
  provider: ollama
  model: llama3.2
  options:
    temperature: 0
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
