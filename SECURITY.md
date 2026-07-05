# Security Policy

## Reporting a vulnerability

If you find a security issue in PromptStrike itself (the scanner code, not a
finding it produces about some target), please report it privately:

- Email **prashikk6@gmail.com** with a description, affected version/commit, and
  steps to reproduce.
- Or open a [GitHub security advisory](https://docs.github.com/en/code-security/security-advisories)
  if the repository has them enabled.

Please do **not** open a public issue for an unfixed vulnerability. Expect an
initial acknowledgement within a few days.

## Scope

In scope: the PromptStrike package, CLI, provider adapters, and report generation
(e.g. template injection, unsafe deserialization, credential/secret handling,
evidence redaction gaps).

Out of scope: weaknesses in third-party LLMs you scan (those are PromptStrike's
*output*, not its vulnerabilities), and issues that require an already-compromised
host.

## Responsible use

PromptStrike is a defensive security tool. Run it only against endpoints you own
or have explicit written permission to test. Scan results and the raw
`promptstrike-results-*.json` files may contain sensitive evidence (redacted on a
best-effort basis) — treat them as confidential and keep them out of version
control. See the "Responsible testing" section of the [README](README.md).

## Supported versions

This is pre-1.0 software; only the latest `main` is supported. Pin a commit if
you need stability.
