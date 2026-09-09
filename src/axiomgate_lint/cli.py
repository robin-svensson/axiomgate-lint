"""CLI entrypoint for axiomgate-lint."""
import argparse
import ast
import json
import os
import sys
from typing import List, Dict, Any, Tuple, Set, Optional


from . import __version__

SEVERITY_LEVELS = {"critical": 4, "high": 3, "medium": 2, "low": 1, "any": 0}

RULE_HINTS = {
    "AG-DEL-001": "Set allow_delegation=False or add a human-in-the-loop gate before delegation.",
}

IGNORED_DIRS = (".git", "venv", ".venv", "__pycache__", "build", "dist", ".pytest_cache", "node_modules", ".tox", ".nox")

# The rule is about these frameworks' agent classes. A call to something merely
# spelled `Agent` is not evidence of any of them: an insurance broker's
# `Agent(name=..., allow_delegation=True)` was reported as LLM06 by a scanner
# that matched on the name alone.
# `allow_delegation` is a CrewAI parameter. AutoGen and Swarm have no
# equivalent, so matching their classes would claim a finding about a keyword
# those frameworks do not accept — the same overreach the 0.1.0 notes record
# being removed from the description before release.
FRAMEWORK_MODULES = ("crewai",)
AGENT_CLASSES = ("Agent",)

DELEGATION_MESSAGE = ("Unattenuated agent delegation enabled (allow_delegation=True). "
                      "Vulnerable to excessive agency loops.")
DELEGATION_OWASP = "LLM06: Excessive Agency"


def _enables_delegation(value: ast.AST) -> bool:
    """True for a literal that turns delegation on.

    `True` is the documented spelling; `1` is the same thing to Python and was
    silently missed. A non-literal (`cfg.delegate`) stays out of scope and is
    documented as a known blind spot.
    """
    if not isinstance(value, ast.Constant):
        return False
    v = value.value
    if v is True:
        return True
    return isinstance(v, int) and not isinstance(v, bool) and v == 1


def _finding_at(file_path: str, line: int) -> Dict[str, Any]:
    return {
        "rule_id": "AG-DEL-001",
        "severity": "high",
        "file": file_path,
        "line": line,
        "message": DELEGATION_MESSAGE,
        "owasp": DELEGATION_OWASP,
    }


class _Scope:
    """Names visible at one level of nesting.

    Name resolution used to be a flat, file-wide guess: an import anywhere in
    the file bound the name everywhere. A local class called `Agent`, three
    scopes below an import nobody calls, was matched against that import and
    reported as a CrewAI finding.
    """

    def __init__(self, parent: Optional["_Scope"] = None):
        self.parent = parent
        self.names: Dict[str, Any] = {}
        if parent is not None:
            # A closure sees every name that was visible where it was written,
            # including names bound inside branches or other nested scopes.
            # Without this, a function defined inside an `if` branch could not
            # see the agent bound there, because the branch scope was not an
            # ancestor of the deferred scope.
            current = parent
            while current is not None:
                for name, kind in current.names.items():
                    if name not in self.names:
                        self.names[name] = kind
                current = current.parent

    def bind(self, name: str, kind: Any) -> None:
        self.names[name] = kind

    def lookup(self, name: str) -> Any:
        scope: Optional["_Scope"] = self
        while scope is not None:
            if name in scope.names:
                return scope.names[name]
            scope = scope.parent
        return None


class _Agent:
    """A variable holding a framework agent, and whether it already delegates."""

    def __init__(self, delegating: bool):
        self.delegating = delegating


def _constructor_enables(call: ast.Call) -> bool:
    return any(kw.arg == "allow_delegation" and _enables_delegation(kw.value)
               for kw in call.keywords)


def _is_import_error_handler(handler: ast.ExceptHandler) -> bool:
    """`except ImportError:` — the optional-dependency guard.

    The stub assigned there does not mean the import above is not the
    framework's; when the package is installed, it is. Treating the fallback as
    a shadowing assignment would hide every finding in a file that guards its
    imports, which is an entirely ordinary pattern.
    """
    exc = handler.type
    names: List[str] = []
    if isinstance(exc, ast.Name):
        names = [exc.id]
    elif isinstance(exc, ast.Tuple):
        names = [e.id for e in exc.elts if isinstance(e, ast.Name)]
    return any(n in ("ImportError", "ModuleNotFoundError") for n in names)


class _Analyzer:
    """Walks statements in source order, one scope at a time."""

    def __init__(self, file_path: str):
        self.file_path = file_path
        self.findings: List[Dict[str, Any]] = []
        self._reported: Set[int] = set()
        self._deferred: List[Any] = []

    def run(self, tree: ast.Module) -> List[Dict[str, Any]]:
        scope = _Scope()
        self.block(tree.body, scope)
        # A function body runs after the module has finished binding its
        # names, so a helper written above its own import still sees it.
        # Analysing bodies where they appear made that a silent miss.
        while self._deferred:
            body, inner = self._deferred.pop(0)
            self.block(body, inner)
        self.findings.sort(key=lambda f: f["line"])
        return self.findings

    def _agents_in(self, scope: _Scope) -> List["_Agent"]:
        agents, current = [], scope
        while current is not None:
            agents.extend(v for v in current.names.values() if isinstance(v, _Agent))
            current = current.parent
        return agents

    def branches(self, bodies: List[List[Any]], scope: _Scope) -> None:
        """Analyse mutually exclusive paths without letting one silence another.

        Exactly one branch runs, so each is its own decision point. Sharing a
        single delegation state let the branch analysed first hide the line in
        the other — a line a reviewer needs to see.
        """
        before = [(a, a.delegating) for a in self._agents_in(scope)]
        enabled: Set[int] = set()
        for body in bodies:
            if not body:
                continue
            for agent, was in before:
                agent.delegating = was
            self.block(body, scope)
            for agent, _ in before:
                if agent.delegating:
                    enabled.add(id(agent))
        for agent, was in before:
            agent.delegating = was or id(agent) in enabled

    def _bind_targets(self, target: ast.AST, scope: _Scope) -> None:
        """`with ... as Agent` and `for Agent in ...` rebind the name."""
        for sub in ast.walk(target):
            if isinstance(sub, ast.Name):
                scope.bind(sub.id, "other")

    def attribute_finding(self, target: ast.AST, value: ast.AST,
                          lineno: int, scope: _Scope) -> None:
        if (isinstance(target, ast.Attribute)
                and target.attr == "allow_delegation"
                and isinstance(target.value, ast.Name)
                and _enables_delegation(value)):
            held = scope.lookup(target.value.id)
            if isinstance(held, _Agent) and not held.delegating:
                self.findings.append(_finding_at(self.file_path, lineno))
                held.delegating = True

    def is_agent_call(self, call: ast.Call, scope: _Scope) -> bool:
        if isinstance(call.func, ast.Name):
            return scope.lookup(call.func.id) == "agent"
        if isinstance(call.func, ast.Attribute) and call.func.attr in AGENT_CLASSES:
            root = call.func.value
            while isinstance(root, ast.Attribute):
                root = root.value
            return isinstance(root, ast.Name) and scope.lookup(root.id) == "module"
        return False

    def report(self, call: ast.Call) -> None:
        if id(call) not in self._reported:
            self._reported.add(id(call))
            self.findings.append(_finding_at(self.file_path, call.lineno))

    def block(self, body: List[Any], scope: _Scope) -> None:
        for stmt in body:
            self.stmt(stmt, scope)

    def calls_in(self, node: ast.AST, scope: _Scope) -> None:
        """Report agent constructions in an expression, binding nothing."""
        for sub in ast.walk(node):
            if isinstance(sub, ast.Call) and self.is_agent_call(sub, scope):
                if _constructor_enables(sub):
                    self.report(sub)

    def stmt(self, node: Any, scope: _Scope) -> None:
        if isinstance(node, ast.ImportFrom):
            root = (node.module or "").split(".")[0]
            for alias in node.names:
                agent = root in FRAMEWORK_MODULES and alias.name in AGENT_CLASSES
                scope.bind(alias.asname or alias.name, "agent" if agent else "other")
            return

        if isinstance(node, ast.Import):
            for alias in node.names:
                name = alias.asname or alias.name.split(".")[0]
                module = alias.name.split(".")[0] in FRAMEWORK_MODULES
                scope.bind(name, "module" if module else "other")
            return

        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for dec in node.decorator_list:
                self.calls_in(dec, scope)
            # Default arguments are evaluated where the def statement runs,
            # once, at import time. They construct real agents.
            self.calls_in(node.args, scope)
            scope.bind(node.name, "other")
            self._deferred.append((node.body, _Scope(scope)))
            return

        if isinstance(node, ast.ClassDef):
            for dec in node.decorator_list:
                self.calls_in(dec, scope)
            for base in node.bases:
                self.calls_in(base, scope)
            self.block(node.body, _Scope(scope))
            # Bound after the body, so a base class of the same name still
            # resolves to the import above it.
            scope.bind(node.name, "other")
            return

        if isinstance(node, ast.Try):
            paths = [node.body]
            for handler in node.handlers:
                if not _is_import_error_handler(handler):
                    paths.append(handler.body)
            paths.append(node.orelse)
            self.branches(paths, scope)
            for handler in node.handlers:
                if _is_import_error_handler(handler):
                    for sub in handler.body:
                        self.calls_in(sub, scope)
            self.block(node.finalbody, scope)
            return

        if isinstance(node, ast.If):
            self.calls_in(node.test, scope)
            self.branches([node.body, node.orelse], scope)
            return

        if isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                self.calls_in(item.context_expr, scope)
                if item.optional_vars is not None:
                    self._bind_targets(item.optional_vars, scope)
            self.block(node.body, scope)
            return

        if isinstance(node, (ast.For, ast.AsyncFor)):
            self.calls_in(node.iter, scope)
            self._bind_targets(node.target, scope)
            self.branches([node.body, node.orelse], scope)
            return

        if isinstance(node, ast.Assign):
            self.assign(node, scope)
            return

        if isinstance(node, ast.AnnAssign):
            if node.value is not None:
                self.calls_in(node.value, scope)
                if isinstance(node.target, ast.Name):
                    scope.bind(node.target.id, self.kind_of(node.value, scope))
                else:
                    self.attribute_finding(node.target, node.value,
                                           node.lineno, scope)
            return

        if isinstance(node, ast.AugAssign):
            # `a.allow_delegation |= True` turns it on exactly as `= True` does.
            self.calls_in(node.value, scope)
            self.attribute_finding(node.target, node.value, node.lineno, scope)
            return

        for _, value in ast.iter_fields(node):
            for item in (value if isinstance(value, list) else [value]):
                if isinstance(item, ast.stmt):
                    self.stmt(item, scope)
                elif isinstance(item, ast.AST):
                    self.calls_in(item, scope)

    def assign(self, node: ast.Assign, scope: _Scope) -> None:
        self.calls_in(node.value, scope)

        for target in node.targets:
            if isinstance(target, ast.Attribute):
                self.attribute_finding(target, node.value, node.lineno, scope)
                continue

            if isinstance(target, ast.Name):
                scope.bind(target.id, self.kind_of(node.value, scope))
                continue

            if isinstance(target, ast.Tuple) and isinstance(node.value, ast.Tuple):
                for name_node, value_node in zip(target.elts, node.value.elts):
                    if isinstance(name_node, ast.Name):
                        scope.bind(name_node.id, self.kind_of(value_node, scope))

    def kind_of(self, value: ast.AST, scope: _Scope) -> Any:
        """What a name now holds. Rebinding makes it a different agent, so the
        delegation state is replaced, never carried over from the old one."""
        if isinstance(value, ast.Call) and self.is_agent_call(value, scope):
            return _Agent(_constructor_enables(value))
        return "other"


def scan_file(file_path: str) -> Tuple[List[Dict[str, Any]], List[str]]:
    """Scan a Python file for common multi-agent security and privilege issues.

    Returns (findings, warnings).
    """
    findings: List[Dict[str, Any]] = []
    warnings: List[str] = []

    try:
        # utf-8-sig, not utf-8: a file saved by a Windows editor starts with a
        # BOM. Python reads those files; opening as plain utf-8 left the U+FEFF
        # in the source and turned real code into a reported syntax error.
        with open(file_path, "r", encoding="utf-8-sig") as f:
            source = f.read()
    except Exception as e:
        warnings.append(f"Could not read {file_path}: {e}")
        return findings, warnings

    try:
        tree = ast.parse(source, filename=file_path)
    except SyntaxError as e:
        warnings.append(f"Syntax error in {file_path}:{e.lineno}: {e.msg}")
        return findings, warnings

    return _Analyzer(file_path).run(tree), warnings


def scan_directory(target_dir: str) -> Tuple[List[Dict[str, Any]], List[str]]:
    """Scan a directory for agent security issues.

    Returns (findings, warnings).
    """
    all_findings: List[Dict[str, Any]] = []
    all_warnings: List[str] = []

    if not os.path.isdir(target_dir):
        all_warnings.append(f"Target path does not exist or is not a directory: {target_dir}")
        return all_findings, all_warnings

    for root, dirs, files in os.walk(target_dir):
        # Prune rather than skip. os.walk still descends into a directory that
        # the loop body ignores, so a large site-packages tree was being read
        # in full before every file in it was discarded.
        dirs[:] = [d for d in dirs if d not in IGNORED_DIRS]

        # A virtual environment is not the user's code. Naming them by hand
        # only catches the conventional names: a project whose environment was
        # called `.v` had its entire site-packages scanned, producing findings
        # in third-party packages nobody there had written. Every virtual
        # environment contains pyvenv.cfg, whatever the directory is called.
        dirs[:] = [d for d in dirs
                   if not os.path.isfile(os.path.join(root, d, "pyvenv.cfg"))]

        # site-packages is only a dependency directory where a dependency
        # directory belongs: under lib/. Matching the bare name anywhere meant
        # a project's own src/site-packages/ was skipped in silence — and the
        # comment above already says a name is not evidence.
        rel = os.path.relpath(root, target_dir)
        below_lib = any(part in ("lib", "lib64")
                        for part in rel.split(os.sep)) if rel != "." else False
        dirs[:] = [d for d in dirs if not (d == "site-packages" and below_lib)]

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

    print(f"Total findings: {len(findings)}")
    if warnings:
        # The count belongs in the summary, not only on stderr. "0 findings"
        # reads as a clean bill of health even when half the tree was skipped.
        print(f"Files that could not be scanned: {len(warnings)}")
    print()

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


def _esc_property(value: Any) -> str:
    """Escape a workflow-command property value.

    Properties are comma-delimited and colon-terminated, so a path containing
    either ended the property list early: GitHub dropped the annotation and a
    failing check displayed nothing.
    """
    return (str(value).replace("%", "%25").replace("\r", "%0D")
            .replace("\n", "%0A").replace(":", "%3A").replace(",", "%2C"))


def _esc_data(value: Any) -> str:
    """Escape a workflow-command message body."""
    return (str(value).replace("%", "%25").replace("\r", "%0D")
            .replace("\n", "%0A"))


def _print_github(findings: List[Dict[str, Any]], warnings: List[str],
                  threshold: int) -> None:
    for w in warnings:
        print(f"::warning title=AxiomGate Lint::{_esc_data(w)}")
    for f in findings:
        # A finding that fails the build is an error; the rest are warnings.
        # Emitting everything as ::warning while exiting 2 tells the reviewer
        # the run was clean and the pipeline that it was not.
        level = "error" if SEVERITY_LEVELS.get(f["severity"], 1) >= threshold else "warning"
        title = _esc_property(f"{f['rule_id']} ({f['owasp']})")
        print(f"::{level} file={_esc_property(_rel(f['file']))},line={f['line']},"
              f"title={title}::{_esc_data(f['message'])}")


class _ArgumentParser(argparse.ArgumentParser):
    """Exit 1 on a usage error, not argparse's default 2.

    Exit 2 is this tool's "scanned, found something". A CI script could not
    tell a mistyped flag from a security finding.
    """

    def error(self, message):
        self.print_usage(sys.stderr)
        self.exit(1, f"{self.prog}: error: {message}\n")


def main():
    parser = _ArgumentParser(
        prog="axiomgate-lint",
        description="AxiomGate AI Agent Security Linter",
    )
    parser.add_argument("target", nargs="?", default=".", help="Target directory or file to scan")
    parser.add_argument("--fail-on", choices=["critical", "high", "medium", "low", "any"], default="high", help="Severity threshold to trigger exit code 2")
    parser.add_argument("--format", choices=["text", "json", "github"], default="text", help="Output format")
    parser.add_argument("--strict", action="store_true", help="Exit 1 if any file could not be read or parsed")
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
            out["unscannable"] = len(warnings)
        print(json.dumps(out, indent=2))
    else:
        _print_text(target, findings, warnings)

    # Exit 1 means the scan could not run. Exit 2 means it ran and found
    # something. Collapsing the two would make a typo in a path look like a
    # security failure, and — worse in the other direction — let a path that
    # was never read pass as clean.
    if unscannable:
        sys.exit(1)

    # A finding is checked before --strict. Downgrading a real vulnerability to
    # "could not scan" would send a HIGH finding down a pipeline's retry branch
    # because some unrelated file in the tree had a syntax error.
    has_violation = any(SEVERITY_LEVELS.get(f["severity"], 1) >= threshold for f in findings)
    if has_violation:
        sys.exit(2)
    if args.strict and warnings:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
