# AxiomGate Linter (`axiomgate-lint`)

> Somebody on your team wrote `allow_delegation=True`. CrewAI ships that switch **off** — so turning it on was a decision. This linter finds those decisions and puts them in front of a reviewer before they reach production.

[![CI](https://github.com/robinsvensson493-cyber/axiomgate-lint/actions/workflows/ci.yml/badge.svg)](https://github.com/robinsvensson493-cyber/axiomgate-lint/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![OWASP Top 10 for LLMs](https://img.shields.io/badge/Security-OWASP%20LLM%20Top%2010-emerald.svg)](https://owasp.org/www-project-top-10-for-large-language-model-applications/)

---

## Why this exists

A CrewAI agent with `allow_delegation=True` can hand work to other agents, which can hand it on again. There is no built-in depth limit and no human approval step. One switch turns a bounded worker into a recursive task factory, and it is one keyword long — easy to add while debugging, easy to forget, and invisible in a diff full of prompt changes.

CrewAI's own default is `allow_delegation=False` ([source](https://github.com/crewAIInc/crewAI/blob/main/lib/crewai/src/crewai/agents/agent_builder/base_agent.py)). That is the right default, and it is exactly why an explicit `True` is worth catching: it is not an accident of the framework, it is somebody's choice. This linter asks whether that choice was reviewed.

---

## What it does

`axiomgate-lint` is a **zero-dependency, zero-network** static analysis tool. No model calls, no API keys, nothing leaves your machine. It parses Python with the standard library's `ast` module and reports what it finds, mapped to the [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/).

Because it never executes your code, it is safe to run against a repository you have not read yet.

---

## What it catches

| Rule | Severity | OWASP LLM | What it means |
|---|---|---|---|
| `AG-DEL-001` | HIGH | LLM06: Excessive Agency | An agent is constructed with an explicit `allow_delegation=True` — it can delegate to other agents with no depth limit and no human approval |

One rule. It is a real one, and the tool does not claim more than it checks.

---

## What it does *not* catch

A security tool that hides its blind spots is worse than no tool, because it gets trusted. These are the current ones:

- **Only `.py` files.** CrewAI's modern pattern puts agent configuration in `agents.yaml`. Delegation enabled there is invisible to this linter today.
- **Only literal values.** `allow_delegation=True` is caught; `allow_delegation=cfg.delegate`, or a value read from the environment, is not.
- **Only CrewAI's parameter.** `allow_delegation` is a CrewAI concept. AutoGen and OpenAI Swarm have no equivalent keyword, so scanning their code with this rule will correctly find nothing — that is the absence of this specific check, not a clean bill of health.
- **No runtime behaviour.** It does not execute agents, observe them, or verify permission boundaries. It reads source.

A run reporting zero findings means *this rule did not match*. It does not mean the system is safe.

---

## Install

Not yet published to PyPI. Install from the repository:

```bash
pip install git+https://github.com/robinsvensson493-cyber/axiomgate-lint.git
```

Or from a local clone:

```bash
git clone https://github.com/robinsvensson493-cyber/axiomgate-lint.git
cd axiomgate-lint
pip install .
```

Python 3.10 or newer. No other requirements.

---

## Use it

```bash
axiomgate-lint .
```

**Nothing matched:**

```
=== AxiomGate AI Agent Linter ===
Target: /path/to/your/project
Total findings: 0
```

**Something matched:**

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

| Flag | Default | What it does |
|---|---|---|
| `target` | `.` | Directory or file to scan |
| `--fail-on` | `high` | Severity at or above which the run exits 2 |
| `--format` | `text` | `text` to read, `json` for tooling, `github` for CI annotations |

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Nothing at or above the threshold |
| `2` | Something at or above the threshold — CI should fail |

Parse errors and unreadable files are reported as warnings and never change the exit code. A file the linter could not read is stated, not silently skipped.

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

Or as the bundled action:

```yaml
      - uses: robinsvensson493-cyber/axiomgate-lint@main
        with:
          target-path: ./src
          fail-on: high
```

With `--format github`, findings appear as annotations on the changed lines. Findings that fail the build are emitted as `::error` and the rest as `::warning`, so what a reviewer sees matches what the pipeline decided.

---

## Contributing

Issues and pull requests are welcome — particularly new rules, and particularly evidence that an existing rule is wrong.

A new rule needs three things: a test that fails before the rule exists, a real-world pattern it matches, and a clear statement of what it cannot see. Rules that guess are worse than no rule.

```bash
git clone https://github.com/robinsvensson493-cyber/axiomgate-lint.git
cd axiomgate-lint
pip install -e ".[dev]"
pytest
```

---

## Where this comes from

`axiomgate-lint` is the open part of **AxiomGate**, a deterministic security and architecture auditor for multi-agent systems. The linter does one check well and for free; the auditor maps agent topologies, delegation graphs and capability boundaries, and produces evidence-backed reports for teams that need one before going to production or in front of investors.

Built by [Robin Svensson](https://github.com/robinsvensson493-cyber).

## License

MIT — see [LICENSE](LICENSE).
