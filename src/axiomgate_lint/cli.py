"""CLI entrypoint for axiomgate-lint."""
import argparse
import ast
import json
import os
import sys
from typing import List, Dict, Any, Tuple


from . import __version__

SEVERITY_LEVELS = {"critical": 4, "high": 3, "medium": 2, "low": 1, "any": 0}

RULE_HINTS = {
    "AG-DEL-001": "Set allow_delegation=False or add a human-in-the-loop gate before delegation.",
}

IGNORED_DIRS = (".git", "venv", ".venv", "__pycache__", "build", "dist", ".pytest_cache", "node_modules", ".tox", ".nox")


def scan_file(file_path: str) -> Tuple[List[Dict[str, Any]], List[str]]:
    """Scan a Python file for common multi-agent security and privilege issues.

    Returns (findings, warnings).
    """
    findings: List[Dict[str, Any]] = []
    warnings: List[str] = []

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            source = f.read()
    except Exception as e:
        warnings.append(f"Could not read {file_path}: {e}")
        return findings, warnings

    try:
        tree = ast.parse(source, filename=file_path)
    except SyntaxError as e:
        warnings.append(f"Syntax error in {file_path}:{e.lineno}: {e.msg}")
        return findings, warnings

    for node in ast.walk(tree):
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

    return findings, warnings


def scan_directory(target_dir: str) -> Tuple[List[Dict[str, Any]], List[str]]:
    """Scan a directory for agent security issues.

    Returns (findings, warnings).
    """
    all_findings: List[Dict[str, Any]] = []
    all_warnings: List[str] = []

    if not os.path.isdir(target_dir):
        all_warnings.append(f"Target path does not exist or is not a directory: {target_dir}")
        return all_findings, all_warnings

    for root, _, files in os.walk(target_dir):
        if any(part in IGNORED_DIRS for part in os.path.normpath(root).split(os.sep)):
            continue
        for file in files:
            if file.endswith(".py"):
                path = os.path.join(root, file)
                findings, warnings = scan_file(path)
                all_findings.extend(findings)
                all_warnings.extend(warnings)

    return all_findings, all_warnings


def _print_text(target: str, findings: List[Dict[str, Any]], warnings: List[str]):
    print("=== AxiomGate AI Agent Linter ===")
    print(f"Target: {target}")

    if warnings:
        for w in warnings:
            print(f"  WARNING: {w}", file=sys.stderr)

    print(f"Total findings: {len(findings)}\n")

    for f in findings:
        hint = RULE_HINTS.get(f["rule_id"], "")
        print(f"[{f['severity'].upper()}] {f['rule_id']} at {f['file']}:{f['line']}")
        print(f"  {f['message']} ({f['owasp']})")
        if hint:
            print(f"  -> {hint}")
        print()


def _rel(path: str) -> str:
    """Path relative to the working directory, when it lies below it.

    GitHub attaches an annotation to a diff only when the file path is
    relative to the repository root. Absolute paths — which is what the
    scanner uses internally — produce annotations that are accepted, counted,
    and then displayed nowhere, so a failing check looks like it found
    nothing.
    """
    try:
        rel = os.path.relpath(path, os.getcwd())
    except ValueError:              # different drive on Windows
        return path
    return path if rel.startswith("..") else rel


def _print_github(findings: List[Dict[str, Any]], warnings: List[str],
                  threshold: int) -> None:
    for w in warnings:
        print(f"::warning title=AxiomGate Lint::{w}")
    for f in findings:
        # A finding that fails the build is an error; the rest are warnings.
        # Emitting everything as ::warning while exiting 2 tells the reviewer
        # the run was clean and the pipeline that it was not.
        level = "error" if SEVERITY_LEVELS.get(f["severity"], 1) >= threshold else "warning"
        print(f"::{level} file={_rel(f['file'])},line={f['line']},"
              f"title={f['rule_id']} ({f['owasp']})::{f['message']}")


def main():
    parser = argparse.ArgumentParser(
        prog="axiomgate-lint",
        description="AxiomGate AI Agent Security Linter",
    )
    parser.add_argument("target", nargs="?", default=".", help="Target directory or file to scan")
    parser.add_argument("--fail-on", choices=["critical", "high", "medium", "low", "any"], default="high", help="Severity threshold to trigger exit code 2")
    parser.add_argument("--format", choices=["text", "json", "github"], default="text", help="Output format")
    parser.add_argument("--version", action="version", version=f"axiomgate-lint {__version__}")
    args = parser.parse_args()

    target = os.path.abspath(args.target)
    unscannable = False

    if os.path.isfile(target):
        findings, warnings = scan_file(target)
    elif os.path.isdir(target):
        findings, warnings = scan_directory(target)
    else:
        # Scanning nothing is not the same as finding nothing. A mistyped
        # path used to print "Total findings: 0" and exit 0, which in CI is a
        # green check for work that never ran.
        findings = []
        warnings = [f"Target path does not exist: {target}"]
        unscannable = True

    threshold = SEVERITY_LEVELS.get(args.fail_on, 3)

    if args.format == "github":
        _print_github(findings, warnings, threshold)
    elif args.format == "json":
        out = {"findings": findings, "count": len(findings)}
        if warnings:
            out["warnings"] = warnings
        print(json.dumps(out, indent=2))
    else:
        _print_text(target, findings, warnings)

    # Exit 1 means the scan could not run. Exit 2 means it ran and found
    # something. Collapsing the two would make a typo in a path look like a
    # security failure, and — worse in the other direction — let a path that
    # was never read pass as clean.
    if unscannable:
        sys.exit(1)

    has_violation = any(SEVERITY_LEVELS.get(f["severity"], 1) >= threshold for f in findings)
    if has_violation:
        sys.exit(2)
    sys.exit(0)


if __name__ == "__main__":
    main()
