# Changelog

Notable changes to `axiomgate-lint`. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), versioning follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] — 2026-09-08

An independent pre-launch review found seven bugs in 0.1.0. Every one of them
is reproduced by a test that failed before the fix.

### Fixed

- **False positives on any class named `Agent`.** The scanner matched the name
  alone, so an insurance broker's `Agent(name=..., allow_delegation=True)` —
  no CrewAI, no LLM — was reported as `LLM06: Excessive Agency`. The rule now
  requires the framework to be imported in the same file, and honours import
  aliases and module-qualified calls.
- **An ancestor directory's name silenced entire scans.** The directory filter
  tested every component of the absolute path, so a project cloned into
  `~/build/proj`, or a CI workspace under `build/`, reported "Total findings: 0"
  and exit 0 without opening a single file.
- **`site-packages` outside a virtualenv was skipped.** A project's own
  `src/site-packages/` is source, not dependencies. It is now pruned only
  under `lib/`.
- **A UTF-8 BOM turned real code into a syntax error.** Files saved by Windows
  editors are read with `utf-8-sig`, as Python itself reads them.
- **GitHub annotations broke on commas.** Workflow-command properties are
  comma-delimited and colon-terminated; both are now percent-encoded, along
  with newlines in messages.
- **Delegation enabled after construction was invisible.** `a = Agent(...)`
  followed by `a.allow_delegation = True` is now caught, as is the literal `1`.
- **A usage error exited 2** — the same code as "found a vulnerability".
  It now exits 1.

### Fixed — from the independent review of the fixes themselves

- **The false-positive fix had introduced a false negative.** Suppressing the
  import on any name collision anywhere in the file meant a method called
  `Agent`, in an unrelated class, silenced a genuine CrewAI finding for the
  whole file. Only a binding at module scope shadows the import now.
- **AutoGen and Swarm classes are no longer matched at all.** The code matched
  `ConversableAgent` and `AssistantAgent` while the README said, correctly,
  that `allow_delegation` is a CrewAI concept those frameworks have no
  equivalent for. The documentation was right and the code was not.
- **One agent is reported once.** A constructor with `allow_delegation=True`
  followed by a redundant `a.allow_delegation = True` counted two findings for
  a single risk.
- **A finding outranks `--strict`.** A run with a HIGH finding and an
  unreadable file exited 1 instead of 2, routing a real vulnerability to a
  pipeline's retry branch.

### Fixed — from the second review

- **Name resolution now follows scope.** It was a flat, file-wide guess:
  an import anywhere in the file bound the name everywhere, so a local class
  called `Agent` in a nested scope was matched against an import in an unused
  helper and reported. Imports, definitions and assignments are now resolved
  per scope. Module-level statements are read in order; function bodies are
  analysed afterwards, because that is when they run.
- **Rebinding a variable makes it a different agent.** `a = Agent(...
  allow_delegation=True)`, then `a = Agent(...)`, then
  `a.allow_delegation = True` reported one finding instead of two, silently
  missing the second agent's delegation.
- **Tuple unpacking is tracked.** `a, b = Agent(...), Agent(...)` bound
  neither name, so delegation set on either afterwards was invisible.
- **`except ImportError:` fallbacks no longer suppress findings.** The stub
  assigned by the optional-dependency guard was treated as a shadowing
  assignment, which would have hidden every finding in files that guard their
  imports.

### Fixed — from the third review

- **Default arguments are evaluated.** `def build(a=Agent(allow_delegation=True))`
  constructs an agent at import time and was invisible.
- **`a.allow_delegation |= True` is caught**, as is `a: Agent = Agent(...)`
  followed by an assignment — augmented and annotated assignments were not
  handled at all.
- **A helper written above its own import resolves.** Function bodies are now
  analysed after the module has bound its names, which is when they actually
  run.
- **`with open(...) as Agent` and `for Agent in ...` rebind the name.** Both
  left the import in place and produced a finding for an object that is not an
  agent at all.
- **Both branches of an `if`/`try` are reported.** The branches share a
  variable but not a code path; one branch's finding silenced the other's.

### Added

- `--strict`: exit 1 when any file could not be read or parsed and nothing was
  found.
- The count of unscannable files now appears in the text and JSON summaries.

### Changed

- The package description no longer claims AutoGen and Swarm support. The
  0.1.0 notes below record that this claim was removed before release; it had
  survived in `pyproject.toml`, which is what PyPI would have displayed.

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
