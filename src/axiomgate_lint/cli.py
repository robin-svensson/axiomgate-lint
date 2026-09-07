"""CLI entrypoint for axiomgate-lint."""
import argparse
import ast
import os
import sys
from typing import List, Dict, Any


def scan_file(file_path: str) -> List[Dict[str, Any]]:
    """Scan a Python file for common multi-agent security and privilege issues."""
    findings = []
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            source = f.read()
        tree = ast.parse(source, filename=file_path)
    except Exception:
        return findings

    for node in ast.walk(tree):
        # Rule: Detect CrewAI / Agent unattenuated delegation
        if isinstance(node, ast.Call):
            func_name = ""
            if isinstance(node.func, ast.Name):
                func_name = node.func.id
            elif isinstance(node.func, ast.Attribute):
                func_name = node.func.attr

            if func_name in ("Agent", "ConversableAgent", "AssistantAgent"):
                allow_delegation = None
                for kw in node.keywords:
                    if kw.arg == "allow_delegation" and isinstance(kw.value, ast.Constant):
                        allow_delegation = kw.value.value

                if allow_delegation is True:
                    findings.append({
                        "rule_id": "AG-DEL-001",
                        "severity": "high",
                        "file": file_path,
                        "line": node.lineno,
                        "message": "Unattenuated agent delegation enabled (allow_delegation=True). Vulnerable to excessive agency loops.",
                        "owasp": "LLM06: Excessive Agency",
                    })

    return findings


def scan_directory(target_dir: str) -> List[Dict[str, Any]]:
    all_findings = []
    for root, _, files in os.walk(target_dir):
        if any(ignored in root for ignored in (".git", "venv", ".venv", "__pycache__", "build", "dist")):
            continue
        for file in files:
            if file.endswith(".py"):
                path = os.path.join(root, file)
                all_findings.extend(scan_file(path))
    return all_findings


def main():
    parser = argparse.ArgumentParser(description="AxiomGate AI Agent Security Linter")
    parser.add_argument("target", nargs="?", default=".", help="Target directory or file to scan")
    parser.add_argument("--fail-on", choices=["critical", "high", "medium", "low", "any"], default="high", help="Fail threshold")
    parser.add_argument("--format", choices=["text", "json", "github"], default="text", help="Output format")
    args = parser.parse_args()

    target = os.path.abspath(args.target)
    if os.path.isfile(target):
        findings = scan_file(target)
    else:
        findings = scan_directory(target)

    if args.format == "github":
        for f in findings:
            print(f"::warning file={f['file']},line={f['line']},title={f['rule_id']} ({f['owasp']})::{f['message']}")
    elif args.format == "json":
        import json
        print(json.dumps({"findings": findings, "count": len(findings)}, indent=2))
    else:
        print(f"=== AxiomGate AI Agent Linter ===")
        print(f"Target: {target}")
        print(f"Scanned files. Total findings: {len(findings)}\n")
        for f in findings:
            print(f"[{f['severity'].upper()}] {f['rule_id']} at {f['file']}:{f['line']}")
            print(f"  {f['message']} ({f['owasp']})\n")

    severity_levels = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    threshold = severity_levels.get(args.fail_on, 3)

    has_violation = any(severity_levels.get(f["severity"], 1) >= threshold for f in findings)
    if has_violation:
        sys.exit(2)
    sys.exit(0)


if __name__ == "__main__":
    main()
