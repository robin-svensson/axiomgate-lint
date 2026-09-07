# AxiomGate Linter (`axiomgate-lint`)

> Someone on your team wrote `allow_delegation=True`. CrewAI ships that switch off, so turning it on was a decision. This linter finds those decisions and puts them in front of a reviewer.

[![CI](https://github.com/robinsvensson493-cyber/axiomgate-lint/actions/workflows/ci.yml/badge.svg)](https://github.com/robinsvensson493-cyber/axiomgate-lint/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![OWASP Top 10 for LLMs](https://img.shields.io/badge/Security-OWASP%20LLM%20Top%2010-emerald.svg)](https://owasp.org/www-project-top-10-for-large-language-model-applications/)

---

## Why

A CrewAI agent with `allow_delegation=True` can hand work to other agents, which can hand it on again. There's no depth limit and no approval step. It's one keyword, easy to add while debugging and easy to forget, and it disappears in a diff full of prompt changes.

Here's the shape it usually takes. A researcher agent delegates drafting to a writer. The writer hits a gap and delegates the missing fact back to the researcher, which delegates part of it onward again. Nothing is broken and nothing raises an error. Every hop is a fresh model call against a real budget, and the first thing anyone notices is the invoice. The second is that no human approved any step after the first one.

That's the cheap version. The expensive version is the same loop with a tool attached that writes to something.

CrewAI defaults to `allow_delegation=False` ([source](https://github.com/crewAIInc/crewAI/blob/main/lib/crewai/src/crewai/agents/agent_builder/base_agent.py)). That's a sensible default, and it's why the explicit `True` is worth finding. Nobody got it by accident. Somebody typed it, and this linter asks whether anyone reviewed that.

---

## What it does

`axiomgate-lint` reads Python with the standard library's `ast` module and reports what it finds, mapped to the [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/).

No dependencies. No network calls. No API keys. Nothing leaves your machine, and it never executes the code it reads, so it's safe to point at a repository you haven't looked at yet.

---

## What it catches

| Rule | Severity | OWASP LLM | Meaning |
|---|---|---|---|
| `AG-DEL-001` | HIGH | LLM06: Excessive Agency | An agent is built with an explicit `allow_delegation=True`, so it can delegate to other agents with no depth limit and no human approval |

One rule so far. It's a real one, and the tool doesn't claim more than it checks.

---

## What it misses

A security tool that hides its blind spots is worse than no tool, because people trust it. Here are the current ones.

- **Python files only.** CrewAI's newer pattern puts agent config in `agents.yaml`. Delegation turned on there is invisible to this linter.
- **Literal values only.** It catches `allow_delegation=True`. It won't catch `allow_delegation=cfg.delegate` or a value read from the environment.
- **CrewAI's parameter only.** `allow_delegation` is a CrewAI concept. AutoGen and OpenAI Swarm have no equivalent, so running this against their code finds nothing. That's a check that didn't apply, not a clean bill of health.
- **Source, not behaviour.** It doesn't run your agents, watch them, or prove anything about permission boundaries.

Zero findings means this rule didn't match. It doesn't mean your system is safe.

---

## Install

Not on PyPI yet. Install from the repository:

```bash
pip install git+https://github.com/robinsvensson493-cyber/axiomgate-lint.git
```

Or clone it:

```bash
git clone https://github.com/robinsvensson493-cyber/axiomgate-lint.git
cd axiomgate-lint
pip install .
```

Python 3.10 or newer, nothing else.

### Check it works

A linter that silently does nothing looks exactly like a linter that found nothing. The repository ships two small files so you can tell them apart:

```bash
axiomgate-lint examples/vulnerable_crew.py   # one HIGH finding, exit 2
axiomgate-lint examples/safe_crew.py         # nothing,          exit 0
```

If the first one is quiet, something is wrong with the install, not with your code.

---

## Use it

```bash
axiomgate-lint .
```

Nothing matched:

```
=== AxiomGate AI Agent Linter ===
Target: /path/to/your/project
Total findings: 0
```

Something matched:

```
=== AxiomGate AI Agent Linter ===
Target: /path/to/your/project
Total findings: 1

[HIGH] AG-DEL-001 at src/crew.py:29
  Unattenuated agent delegation enabled (allow_delegation=True).
  Vulnerable to excessive agency loops. (LLM06: Excessive Agency)
  -> Set allow_delegation=False or add a human-in-the-loop gate before delegation.
```

### Options

```
axiomgate-lint [target] [--fail-on critical|high|medium|low|any] [--format text|json|github] [--version]
```

| Flag | Default | Does |
|---|---|---|
| `target` | `.` | Directory or file to scan |
| `--fail-on` | `high` | Severity at or above which the run exits 2 |
| `--format` | `text` | `text` to read, `json` for tooling, `github` for CI annotations |

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Scanned, nothing at or above the threshold |
| `1` | Could not scan. The target doesn't exist |
| `2` | Scanned, found something at or above the threshold |

Code `1` earns its place. `axiomgate-lint ./scr` is a typo, and a tool that answers "0 findings, exit 0" to a path it never opened hands you a green pipeline for a scan that never ran. Scanning nothing and finding nothing are different results and only one of them should pass.

Individual files that can't be parsed or read are reported as warnings and don't change the exit code. If the linter couldn't read something, it says so instead of skipping it quietly.

---

## GitHub Actions

As a step in your own workflow:

```yaml
name: AI Agent Security Lint

on: [push, pull_request]

jobs:
  lint-agents:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - run: pip install git+https://github.com/robinsvensson493-cyber/axiomgate-lint.git
      - run: axiomgate-lint . --fail-on high --format github
```

Or use the bundled action:

```yaml
      - uses: robinsvensson493-cyber/axiomgate-lint@main
        with:
          target-path: ./src
          fail-on: high
```

With `--format github` the findings show up as annotations on the changed lines. Anything that fails the build is emitted as `::error` and the rest as `::warning`, so what the reviewer sees matches what the pipeline decided.

---

## Contributing

Issues and pull requests are welcome, especially new rules and especially evidence that an existing rule is wrong.

A new rule needs three things: a test that fails before the rule exists, a real pattern it matches, and a plain statement of what it can't see. A rule that guesses is worse than no rule.

```bash
git clone https://github.com/robinsvensson493-cyber/axiomgate-lint.git
cd axiomgate-lint
pip install -e ".[dev]"
pytest
```

---

## Where this comes from

`axiomgate-lint` is the open part of **AxiomGate**, a deterministic security and architecture auditor for multi-agent systems. The linter does one check, well and for free. The auditor maps agent topologies, delegation paths and capability boundaries, and produces evidence-backed reports for teams that need one before going to production or in front of investors.

Built by [Robin Svensson](https://github.com/robinsvensson493-cyber).

## License

MIT, see [LICENSE](LICENSE).
