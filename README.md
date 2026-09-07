# AxiomGate Linter (`axiomgate-lint`)

> **Deterministic AST security and privilege linter for multi-agent AI systems (LangGraph, CrewAI, AutoGen, OpenAI Swarm).**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![OWASP Top 10 for LLMs](https://img.shields.io/badge/Security-OWASP%20LLM%20Top%2010-emerald.svg)](https://owasp.org/www-project-top-10-for-large-language-model-applications/)

`axiomgate-lint` is an open-source, zero-network static analysis tool designed for developers and security engineers building autonomous multi-agent systems. It runs via CLI or directly in your GitHub CI/CD pipeline to catch privilege escalations, unattenuated delegation chains, and credential leaks **before agents hit production**.

---

## Key Capabilities

* **AST-Based Agent Topology Inspection:** Analyzes agent-to-tool and agent-to-agent delegation topologies without executing untrusted code or making network calls.
* **OWASP LLM Top 10 Mapping:** Detects vulnerabilities mapped to:
  * **LLM06 (Excessive Agency):** Unattenuated delegation, missing human-in-the-loop gates.
  * **LLM01 (Prompt Injection Amplification):** Unfiltered input propagation between autonomous agents.
  * **LLM08 (Excessive Permissions):** Agent roles assigned destructive tools with wildcard scopes.
* **Multi-Framework Support:** Native AST parsers for:
  * [LangGraph](https://github.com/langchain-ai/langgraph)
  * [CrewAI](https://github.com/crewAIInc/crewAI)
  * [AutoGen](https://github.com/microsoft/autogen)
  * [OpenAI Swarm](https://github.com/openai/swarm)
* **GitHub Actions Integration:** Emits native workflow annotations, summary tables, and exit codes (0 = Clean, 1 = Scan Failure, 2 = Policy Gate Violated).

---

## Quickstart

### Installation (Local CLI)

```bash
pip install axiomgate-lint
```

### Run a Linter Scan

```bash
# Scan a multi-agent project directory
axiomgate-lint ./agents_repo/

# Enforce strict CI exit codes on High/Critical findings
axiomgate-lint ./agents_repo/ --fail-on high --format github
```

### GitHub Action Workflow

```yaml
name: AI Agent Security Lint

on: [push, pull_request]

jobs:
  audit-agents:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - name: Run AxiomGate Linter
        uses: axiomgate/lint-action@v1
        with:
          target-path: './src'
          fail-on: 'high'
```

---

---


## Commercial Relationship with AxiomGate

`axiomgate-lint` is an independent, community-focused open-source project created and maintained by **Robin Svensson**.

* **Open-Source Scope:** Static AST linting, community rule checks, and CI annotations.
* **Commercial Platform:** For deep enterprise governance, formal mathematical verification (TLA+ kernel), multi-tenant SaaS control planes, and certified executive audit reports, visit [AxiomGate](https://axiomgate.io).

---

## License

Distributed under the MIT License. See [LICENSE](LICENSE) for more details.
