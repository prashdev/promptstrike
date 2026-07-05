# PromptStrike

**A black-box LLM red-teaming scanner that turns raw attack output into a
triaged, severity-scored penetration-test report.** It probes an LLM endpoint
for **OWASP LLM Top 10 (2025)** weaknesses, uses an **LLM-as-judge** to decide
whether each attack actually succeeded, filters false positives, scores severity
with a documented rubric, and renders a self-contained HTML/Markdown report with
OWASP + MITRE ATLAS mappings and a GRC appendix.

![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue)
![License: MIT](https://img.shields.io/badge/license-MIT-green)
![Tests: pytest](https://img.shields.io/badge/tests-pytest-informational)

> **Authorised use only.** Run PromptStrike only against endpoints you own or
> have explicit written permission to test. See [Responsible testing](#responsible-testing).

---

## Why this exists

Existing LLM red-teaming tools are good at *generating attacks* and emitting
*raw signals*, but they stop short of the part a security team actually needs —
a defensible, prioritised finding.

- **[Garak](https://github.com/NVIDIA/garak)** runs many probes and reports
  per-probe pass/fail from string/heuristic detectors.
- **[Promptfoo](https://www.promptfoo.dev/)** produces an eval/red-team result
  matrix across prompts and assertions.
- **[PyRIT](https://github.com/Azure/PyRIT)** is a flexible orchestration
  framework — you assemble the attack, scoring, and reporting yourself.

They leave you with a pile of attempts and detector hits. **The gap is the last
mile:** which hits are real (not detector false positives), how severe each one
is, how it maps to a recognised taxonomy, and how to hand it to a CISO *and* an
engineer. PromptStrike is opinionated about exactly that:

```
raw attack attempts  →  LLM-as-judge verdict  →  FP filter + dedup  →
documented severity (CVSS-style vector)  →  OWASP/ATLAS mapping  →  report
```

It is not trying to have the most probes. It is trying to make each confirmed
finding **credible, ranked, and communicable**.

## Sample report

A real report generated from the baseline findings (full file:
[`docs/sample-report.html`](docs/sample-report.html), or the GitHub-rendered
[`docs/sample-report.md`](docs/sample-report.md)).

**Executive summary** — findings-by-severity, an inline SVG severity bar, and a
CISO-ready risk narrative:

![PromptStrike report — executive summary](docs/img/exec-summary.png)

**A finding** — severity badge, CVSS-style vector, OWASP + MITRE ATLAS, impact,
reproduction, and **redacted** request/response evidence:

![PromptStrike report — a finding card](docs/img/finding-card.png)

The HTML report is a **single self-contained file** (inline CSS, no external
assets, dark theme). Beyond the above it includes a coverage matrix over all 10
OWASP categories, per-finding remediation, and a GRC appendix cross-referencing
NIST AI RMF, ISO/IEC 42001, and EU AI Act articles.

## Quickstart

```bash
make install        # pip install -e ".[dev]"
promptstrike --help

# End-to-end demo against the bundled, deliberately-vulnerable target.
# Zero external services beyond a local Ollama with two small models:
ollama pull dolphin-mistral llama3.2
make scan-demo      # promptstrike scan --config config.yaml --out-dir .demo
```

`scan-demo` runs the **full pipeline** against a local target — scan → judge →
triage → report — and writes a timestamped results JSON and an HTML report to
`.demo/`. No API keys, no external endpoints.

## How it works

```mermaid
flowchart LR
  cfg["YAML config<br/>(config.loader, ${ENV})"] --> tgt["Target provider<br/>OpenAI / Anthropic / Ollama"]
  cfg --> jdg["Judge provider<br/>(separate model)"]
  lib[("Probe library<br/>probes/*.yaml")] --> scan

  tgt --> scan["engine.scanner<br/>send each payload"]
  scan -- "payload + response" --> jdg
  jdg -- "strict JSON verdict" --> raw[("Raw findings<br/>results-*.json")]

  raw --> triage["Triage<br/>FP filter · dedup ·<br/>severity rubric · enrich"]
  triage --> report["Report<br/>Jinja2 HTML + Markdown"]

  raw -. "re-report offline<br/>(different thresholds)" .-> triage
```

Design principles: the engine is **provider-agnostic** (one `LLMProvider`
interface), a run is fully **config-driven** (YAML), the **judge is a separate
model** from the target (see below), severity is a **documented rubric** not a
magic number, and every finding carries a **verified** OWASP ID + MITRE ATLAS
technique (or the explicit `NO_DIRECT_ATLAS_MAPPING` sentinel). Scan and report
are **separable**: raw findings persist to JSON so you can re-triage/re-render
offline without re-hitting the target.

## OWASP LLM Top 10 (2025) coverage

Black-box scanning only observes an endpoint's inputs and outputs. Categories
that require access to model internals, training data, or infrastructure are
marked out of scope (with the reason) rather than faked.

| ID | Category | Coverage | MITRE ATLAS |
|----|----------|----------|-------------|
| LLM01:2025 | Prompt Injection | ✅ Tested | `AML.T0051` LLM Prompt Injection |
| LLM02:2025 | Sensitive Information Disclosure | ✅ Tested | `AML.T0057` LLM Data Leakage |
| LLM03:2025 | Supply Chain | ⛔ Out of scope — needs artifact/provenance access | — |
| LLM04:2025 | Data and Model Poisoning | ⛔ Out of scope — needs training-data access | — |
| LLM05:2025 | Improper Output Handling | ✅ Tested | no direct 1:1 (closest `AML.T0077`) |
| LLM06:2025 | Excessive Agency | ✅ Tested | no direct 1:1 (design weakness) |
| LLM07:2025 | System Prompt Leakage | ✅ Tested | `AML.T0056` Extract LLM System Prompt |
| LLM08:2025 | Vector and Embedding Weaknesses | ⛔ Out of scope — needs RAG/index access | — |
| LLM09:2025 | Misinformation | ✅ Tested | no direct 1:1 |
| LLM10:2025 | Unbounded Consumption | ⛔ Out of scope — requires abusive load (DoS) | — |

ATLAS technique names were verified against the official catalogue
(`mitre-atlas/atlas-data`, v5.6.0); where a category has no clean 1:1 adversary
technique, PromptStrike records the honest `NO_DIRECT_ATLAS_MAPPING` sentinel
rather than forcing an approximate ID.

## CLI

```
promptstrike ping        -c config.yaml     # check target + judge are reachable
promptstrike list-probes                    # show the probe library
promptstrike scan        -c config.yaml \    # scan → judge → triage → report
    [--target ollama:llama3.2] [--judge …] \
    [--only LLM01,LLM07] [--min-confidence 0.6] [--report out.html]
promptstrike report  results-*.json         # re-render offline from saved results
```

## Choosing the judge model

The judge decides whether each attack actually succeeded, so **its quality is
the credibility of the whole report** — a weak judge yields false positives and
false negatives that undermine every finding.

**Default for real scans: a strong Anthropic model** (`claude-sonnet-5` — the
strongest reasonably-priced option). **Ollama is an explicit opt-in** for
cost-free local/CI runs; a small local model is a noticeably weaker judge, so
treat its verdicts as indicative, not authoritative.

```yaml
judge:
  provider: anthropic
  model: claude-sonnet-5
  api_key: ${JUDGE_API_KEY}
```

## Bundled training target

`vulnerable_chatbot` is a **deliberately weak, local "application"** you can scan
instead of a real system. It wraps a backend model with an intentionally sloppy
system prompt — a **fake** API key and **fake** internal records pasted in as
casual context, no "keep this private" instruction, no input guardrails. It leaks
by carelessness, the way a rushed real app does, and is exposed through the same
`LLMProvider` interface so the scanner treats it like any external target.

> **Model note.** Safety-tuned models (Llama 3.x, Qwen, Gemma) refuse even this
> careless prompt, so the demo uses a lightly-tuned model (`dolphin-mistral`).
> That makes the target *deliberately* weaker than production — it is a research
> dummy, not representative of real model behaviour. Nothing in it is a real
> secret; do not deploy it.

## Responsible testing

PromptStrike is a **defensive security tool** for authorised assessment.

- **Only scan systems you own or have explicit written permission to test.**
  Probing a third party's LLM without authorisation may be illegal.
- The engine and prompts are designed for **finding and reporting** weaknesses,
  not evasion of another party's safety controls.
- **Reports contain sensitive evidence.** Findings include (redacted, best-effort)
  request/response transcripts; treat results JSON and reports as sensitive and
  keep them out of version control (see `.gitignore`).
- The bundled vulnerable target exists **only** to be scanned; do not deploy it.

## Roadmap

- **Multi-turn / crescendo attacks** — stateful conversations that escalate over
  several turns, rather than single-shot payloads.
- **Agentic tool-abuse chains** — exercise LLM06 against real tool/function
  calling: chain injection → tool invocation → data exfiltration and score the
  end-to-end effect.
- **CI mode** — non-zero exit above a severity threshold, plus SARIF/JSON output
  so a scan can gate a pull request.
- Indirect (retrieval-borne) prompt injection, report diffing across runs, and
  additional provider adapters.

## What I learned building this

**The LLM-as-judge is itself a nondeterministic component — and that can silently
corrupt your findings.** While validating the pipeline against a hand-labelled
baseline, the three known-positive cases initially *failed*: the judge returned
`success=false` at confidence `0.00`, even though the target had demonstrably
leaked (the fake secret was right there in the response — I checked with a plain
substring match). The target wasn't the problem; the **judge** was. A small local
judge (`llama3.2`) at default temperature was nondeterministic and would
occasionally flip a blatant system-prompt leak to "no leak."

The fix was to make the judge deterministic: I added a sampling-`options`
passthrough to the Ollama provider and pinned **`temperature: 0`** for both the
target and the judge. The baseline then passed 4/4 reproducibly, run after run.
The lesson generalised into two design rules the tool now enforces:

1. **Pin sampling and validate the judge against ground truth.** A judge's
   verdict is data, not gospel — reproducibility requires `temperature: 0`, and
   correctness requires checking the judge against hand-labelled cases
   (`docs/manual-baseline.md`), not assuming it's right.
2. **Prefer a strong judge, and say so.** Judge quality is the report's
   credibility, so the default is a strong model with the local option clearly
   labelled as weaker.

Two smaller lessons baked into the codebase: **severity is a documented rubric**
(base impact + exploitability + agentic escalation → a CVSS-style vector), not an
opaque number a model emitted; and the HTML report **autoescapes** because an
attacker-controlled response can contain `<script>` — the report must never
execute the very payloads it documents.

## License

[MIT](LICENSE). See [SECURITY.md](SECURITY.md) to report a vulnerability, and
[CLAUDE.md](CLAUDE.md) for architecture, folder layout, and contributor
conventions.
