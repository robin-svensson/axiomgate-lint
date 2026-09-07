# Changelog

Notable changes to `axiomgate-lint`. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), versioning follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] — 2026-09-07

First public release.

### Added

- `AG-DEL-001`: flags CrewAI agents constructed with an explicit
  `allow_delegation=True` (OWASP LLM06, Excessive Agency).
- Output formats: `text`, `json`, and `github` for CI annotations.
- `--fail-on` threshold, `--version`, and `python -m axiomgate_lint`.
- A composite GitHub Action, and a CI workflow that runs the test suite on
  Python 3.10 through 3.13 and then lints its own source.
- `examples/` with one file the linter flags and one it doesn't, so the tool
  can be checked before a clean result on real code is trusted.

### Notes on what this release deliberately does not claim

Earlier drafts of the README said multi-agent frameworks enable delegation by
default and that AutoGen and OpenAI Swarm were supported. Neither was true:
CrewAI defaults to `allow_delegation=False`, and neither AutoGen nor Swarm has
that parameter at all, so the rule could never fire on their code. Both claims
were removed before release, and the README now carries a section on what the
linter cannot see.

Exit code `1` was added for a target that does not exist. Previously a
mistyped path reported "0 findings" and exited `0`, which in CI is a passing
check for a scan that never ran.
