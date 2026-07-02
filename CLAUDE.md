# CLAUDE.md

Guidance for Claude Code (and human contributors) working in this repository.

## What PromptStrike is

PromptStrike is a **black-box LLM red-teaming scanner** written in Python 3.11+.
It probes a target LLM endpoint for **OWASP LLM Top 10 (2025)** weaknesses,
uses an **LLM-as-judge** to score whether each attack succeeded, filters out
false positives, and generates a **professional penetration-test report**.

It is black-box: it only needs an API endpoint and credentials. It never
requires access to model weights, training data, or system internals.

> **Authorised use only.** PromptStrike is a security-testing tool. It must only
> be run against endpoints you own or have explicit written permission to test.
> Every code path, prompt, and doc should reinforce this. Do not add features
> whose primary purpose is evasion of another party's safety controls without an
> authorisation gate.

## Core design principles

1. **Provider-agnostic.** The engine talks to targets through a `Provider`
   abstraction. Ship adapters for OpenAI-compatible APIs, Anthropic, and Ollama.
   No provider-specific logic leaks into the scanning engine, judge, or reporter.
2. **Config-driven.** A run is fully described by a YAML config (target,
   credentials via env refs, which probe suites to run, judge settings, report
   format). No behaviour is hard-coded that a user might reasonably want to
   change.
3. **Traceable findings.** Every finding maps to an **OWASP LLM ID**
   (e.g. `LLM01:2025`) *and* a **MITRE ATLAS technique** (e.g. `AML.T0051`).
   A finding without both mappings is a bug.
4. **Judged, not guessed.** Attack success is decided by an LLM-as-judge with a
   structured rubric, then passed through a false-positive filter. Raw
   string-matching is only a pre-filter, never the final verdict.
5. **Small, documented modules.** Prefer many focused modules over few large
   ones. Every public module, class, and function has a docstring.

## Tech stack

| Concern            | Choice                          |
|--------------------|---------------------------------|
| Language           | Python 3.11+                    |
| HTTP client        | `httpx` (async-capable)         |
| Data models        | `pydantic` v2                   |
| CLI output         | `rich`                          |
| Report templates   | `jinja2`                        |
| Config format      | YAML (`pyyaml`)                 |
| Tests              | `pytest`                        |
| Packaging          | `pyproject.toml` (PEP 621)      |

## Folder layout

```
PromptStrike/
├── CLAUDE.md                  # this file
├── README.md
├── pyproject.toml             # deps, build config, tool config (ruff, pytest)
├── LICENSE
│
├── src/
│   └── promptstrike/
│       ├── __init__.py
│       ├── __main__.py        # `python -m promptstrike`
│       ├── cli.py             # rich-based CLI entrypoint & arg parsing
│       │
│       ├── config/
│       │   ├── __init__.py
│       │   ├── schema.py      # pydantic models for the YAML config
│       │   └── loader.py      # load + validate YAML, resolve ${ENV} refs
│       │
│       ├── models/            # shared pydantic domain models
│       │   ├── __init__.py
│       │   ├── finding.py     # Finding: OWASP id, ATLAS id, severity, evidence
│       │   ├── probe.py       # Probe / AttackResult
│       │   └── target.py      # TargetSpec, Message, ChatResponse
│       │
│       ├── providers/         # target LLM adapters (Provider abstraction)
│       │   ├── __init__.py
│       │   ├── base.py        # Provider ABC: async chat(messages) -> response
│       │   ├── openai_compat.py
│       │   ├── anthropic.py
│       │   ├── ollama.py
│       │   └── registry.py    # name -> Provider factory
│       │
│       ├── probes/            # attack modules, one file per OWASP category
│       │   ├── __init__.py
│       │   ├── base.py        # Probe ABC + registration
│       │   ├── llm01_prompt_injection.py
│       │   ├── llm02_sensitive_info.py
│       │   ├── llm06_excessive_agency.py
│       │   ├── llm07_system_prompt_leak.py
│       │   └── ...            # one module per applicable LLM0x category
│       │
│       ├── judge/             # LLM-as-judge scoring
│       │   ├── __init__.py
│       │   ├── judge.py       # runs the judge model, returns a verdict + score
│       │   ├── rubric.py      # scoring rubric per attack type
│       │   └── false_positive.py  # post-verdict FP filtering
│       │
│       ├── engine/            # orchestration
│       │   ├── __init__.py
│       │   ├── scanner.py     # loads probes, runs them, collects findings
│       │   └── scheduler.py   # concurrency, rate limiting, retries
│       │
│       ├── report/            # report generation
│       │   ├── __init__.py
│       │   ├── reporter.py    # builds report context from findings
│       │   └── templates/     # jinja2 templates
│       │       ├── report.md.j2
│       │       └── report.html.j2
│       │
│       ├── mappings/          # static reference data
│       │   ├── owasp_llm_2025.py   # OWASP LLM Top 10 catalogue
│       │   └── mitre_atlas.py      # ATLAS technique catalogue
│       │
│       └── util/
│           ├── __init__.py
│           └── logging.py     # rich logging setup
│
├── configs/                   # example YAML run configs
│   └── example.yaml
│
└── tests/
    ├── conftest.py            # fixtures: fake provider, sample findings
    ├── unit/                  # mirrors src/ package layout
    └── integration/           # end-to-end scans against a mock target
```

## Architectural rationale

- **`src/` layout** keeps the importable package isolated from repo tooling and
  forces tests to run against the installed package (catches packaging bugs).
- **`providers/` is the only place that knows about vendor APIs.** Everything
  downstream depends on the `Provider` ABC in `providers/base.py`, so adding a
  new backend is one file plus a registry entry.
- **`probes/` is one module per OWASP category** so the attack surface maps 1:1
  to the report structure and stays easy to review, extend, and test in
  isolation. Each probe declares its OWASP + ATLAS ids so mappings can't drift.
- **`judge/` is separate from `probes/`.** Probes *produce* attempts; the judge
  *evaluates* them. Keeping them apart means we can swap the judging strategy
  (or the judge model) without touching attack logic, and FP filtering is a
  distinct, testable stage.
- **`engine/` owns orchestration only** (what to run, concurrency, retries) and
  holds no attack or scoring logic — it wires the other pieces together.
- **`report/` consumes `Finding` models** and is pure presentation, so a new
  output format is just a new jinja2 template.
- **`mappings/` is static reference data** kept out of code paths so the OWASP
  and ATLAS catalogues can be updated independently of logic.

## Data flow

```
YAML config ─▶ config.loader ─▶ engine.scanner
                                    │
              providers.registry ◀──┤ (resolves target Provider)
                                    ▼
                    probes.* run attacks via Provider
                                    ▼
                    judge.judge scores each AttackResult
                                    ▼
                    judge.false_positive filters verdicts
                                    ▼
                    engine.scanner collects Finding[]
                                    ▼
                    report.reporter ─▶ jinja2 ─▶ report.(md|html)
```

## Coding conventions

- **Python 3.11+**; use modern typing (`list[str]`, `X | None`, `Self`). Full
  type hints on all public signatures.
- **Pydantic v2** for every data structure that crosses a module boundary or
  gets serialised. No bare dicts as domain objects.
- **Async by default** for anything doing I/O (provider calls, judge calls) via
  `httpx.AsyncClient`. The scheduler owns concurrency and rate limiting.
- **Docstrings required** on every public module, class, and function
  (one-line summary minimum; describe args/return for non-trivial functions).
- **Small modules**: if a file exceeds ~200 lines or holds two unrelated
  responsibilities, split it.
- **Formatting & linting**: `ruff` (format + lint). Line length 88. Sort imports
  with ruff's isort rules. Keep the tree ruff-clean.
- **Naming**: `snake_case` functions/modules, `PascalCase` classes,
  `UPPER_SNAKE` constants. Probe modules are named `llmNN_short_slug.py`.
- **No secrets in code or config.** YAML references credentials as
  `${ENV_VAR}`; the loader resolves them from the environment.
- **`config.loader` is the single owner of `${ENV}` resolution.** It resolves the
  entire run config in one pass, and every downstream consumer receives an
  already-resolved plain dict. In particular, the provider factory
  (`providers.create_provider`) must never touch `os.environ` — it is handed
  resolved values only. (Decided deliberately; do not re-add resolution to the
  provider layer.)
- **Errors**: raise typed exceptions from a shared `errors.py` per subpackage as
  needed; never swallow exceptions silently. Surface actionable messages via
  `rich`.
- **Every new probe** must: subclass the `Probe` ABC, register itself, declare
  its OWASP LLM id and MITRE ATLAS technique, and ship a unit test.
- **Authorisation**: user-facing entrypoints display/confirm an authorised-use
  notice; keep that behaviour intact.

## Testing

- `pytest`; tests live in `tests/` mirroring the `src/` layout.
- Unit tests mock the network — use the fake `Provider` fixture, never hit real
  endpoints in unit tests.
- Each probe, each provider adapter, the judge, the FP filter, and the config
  loader must have unit coverage.
- Integration tests run a full scan against a mock target server.
- Run: `pytest` for the suite, `ruff check .` and `ruff format --check .`
  before committing.

## Conventions for Claude

- Keep modules small and documented; match the style already in the tree.
- When adding a probe, follow the `llmNN_slug.py` pattern and wire up both
  OWASP and ATLAS mappings.
- Never hard-code credentials or provider-specific behaviour outside
  `providers/`.
- Preserve the authorised-use-only posture in any user-facing change.
