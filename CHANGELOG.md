# Changelog

Notable changes to `axiomgate-lint`. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), versioning follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `.github/workflows/release.yml` — tag-triggered publication to PyPI via Trusted
  Publishing, gated on the suite, a `twine check --strict` and a tag/version
  match. Documented in [RELEASING.md](RELEASING.md). Nothing is on PyPI yet.
- `.github/dependabot.yml` — weekly updates for the pinned GitHub Actions.
- A CI job that runs the suite against the built wheel from a directory where
  `pythonpath = ["src"]` cannot make the source tree shadow it.

### Changed
- Every GitHub Action is pinned to a commit SHA rather than a moving major tag —
  including in `action.yml`, which is the file every consumer of the composite
  action actually runs.
- The CI token is `permissions: contents: read`; no job here writes to the
  repository.
- `empty_parameter_set_mark = "fail_at_collect"` in `pyproject.toml`, so a
  parametrised test that ends up with nothing to check fails instead of being
  skipped and reading as green.

### Removed
- The `v0.2.2` release and tag. It pointed at the same commit as `v0.2.1`,
  carried no diff, no changelog entry and no CI run, and the package still
  reported `0.2.1`. Deleting it also removed the GitHub Marketplace listing
  that had been published from it.

## [0.2.1] — 2026-09-09

A second independent review before the community release. Six ways of turning
delegation on scanned clean; each is now reproduced by a test that failed
before the fix. No rule was loosened — every case below is a value the analyser
can read in the file, never one it guesses at.

### Fixed

- **Delegation set on an attribute of the receiver.** `self.researcher.allow_delegation
  = True` in a method was invisible: only plain names resolved to an agent, so
  the class pattern CrewAI's own docs use went unreported. Attributes bound in
  `__init__` are now visible to every method of the same class, each class keeps
  its own namespace, the receiver may be called anything, and a `staticmethod`
  has no receiver at all.
- **Delegation set through a container.** `agents["researcher"].allow_delegation
  = True` and `agents[0].allow_delegation = True` scanned clean. Literal lists,
  tuples and dicts are now tracked slot by slot, including negative indices.
  A computed index stays unreported.
- **`setattr(agent, "allow_delegation", True)`.** An assignment written as a
  call — the documented way to set an attribute, and the obvious way past a
  linter that only reads assignment statements. A computed attribute name, or a
  shadowed `setattr`, is still not guessed at.
- **A literal dict spread into the constructor.** `Agent(**{"allow_delegation":
  True})` is the same decision as the keyword, and the keyword was never read.
  A dict held in a variable remains out of scope, and is documented as such.
- **An agent bound by a walrus.** `if (a := Agent(role="r")): a.allow_delegation
  = True` bound nothing, so the mutation had no agent to attach to.
- **A second name for the same agent.** `b = a` now refers to the same agent
  rather than to nothing, so delegation switched on through either name is
  reported once.
- **A callback's argument read as the receiver.** Found by review before
  release, not in the field: a function defined inside a method was treated as
  a method itself, so its first parameter resolved to the enclosing class's
  attributes. `def helper(config): config.a.allow_delegation = True` reported a
  finding about an object the file never built. Only a method of the class body
  binds a receiver now, a nested function still closes over the real `self`,
  and a parameter of the same name shadows it.

### Changed

- **`README` states the blind spots as they now stand.** Every remaining gap is
  a value that is not knowable without executing the code, and says so.
- **The bundled action is documented at a pinned tag**, not `@main`. A workflow
  pinned to a branch runs whatever was pushed last.

### Added

- **CI builds the distribution, runs `twine check --strict`, and installs the
  wheel in a clean environment.** Broken packaging was previously found at
  release time, after the tag was pushed.
- **CI runs the composite action against both examples**, and fails if the
  known-vulnerable one passes. Nothing else in CI executed `action.yml`.
- **`MANIFEST.in`.** The sdist now ships the examples, `CHANGELOG.md`,
  `SECURITY.md`, `action.yml` and the tests.
- **Python 3.14** in the test matrix and the classifiers.
- **PEP 639 license metadata** (`License-Expression: MIT`), replacing the form
  setuptools deprecated.
- **`actions/checkout@v7` and `actions/setup-python@v7`**, in CI, in the bundled
  action and in the README's example workflow. The previous majors run on
  Node 20, which GitHub's runners now force onto Node 24 with a deprecation
  warning and will eventually refuse. The bundled action ships to every
  consumer, so that one was theirs to hit, not ours.

### Fixed in the documentation

- **The sample output in the README was not what the tool prints.** It showed a
  path relative to the target and wrapped the message across two lines. Text
  output gives an absolute path on a single line. A security tool whose own
  README misquotes it is not a good start.

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
