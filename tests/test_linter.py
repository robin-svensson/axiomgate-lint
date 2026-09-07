import tempfile
import os
from axiomgate_lint.cli import scan_file, scan_directory


def test_scan_crewai_unattenuated_delegation():
    code = """
from crewai import Agent

agent = Agent(
    role="Researcher",
    goal="Find papers",
    backstory="Expert",
    allow_delegation=True
)
"""
    with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as f:
        f.write(code)
        f_path = f.name

    try:
        findings, warnings = scan_file(f_path)
        assert len(findings) == 1
        assert findings[0]["rule_id"] == "AG-DEL-001"
        assert findings[0]["severity"] == "high"
        assert "Excessive Agency" in findings[0]["owasp"]
        assert warnings == []
    finally:
        os.remove(f_path)


def test_scan_clean_agent():
    code = """
from crewai import Agent

agent = Agent(
    role="Researcher",
    goal="Find papers",
    backstory="Expert",
    allow_delegation=False
)
"""
    with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as f:
        f.write(code)
        f_path = f.name

    try:
        findings, warnings = scan_file(f_path)
        assert len(findings) == 0
        assert warnings == []
    finally:
        os.remove(f_path)


def test_scan_syntax_error_returns_warning():
    code = "def broken("

    with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as f:
        f.write(code)
        f_path = f.name

    try:
        findings, warnings = scan_file(f_path)
        assert findings == []
        assert len(warnings) == 1
        assert "Syntax error" in warnings[0]
    finally:
        os.remove(f_path)


def test_scan_nonexistent_path_returns_warning():
    findings, warnings = scan_directory("/nonexistent/path/xyz")
    assert findings == []
    assert len(warnings) == 1
    assert "does not exist" in warnings[0]


# --- CI output ---------------------------------------------------------------
# GitHub attaches an annotation to a diff only when the path is relative to the
# repository root. The scanner works in absolute paths internally, so an
# unconverted path produced annotations that were accepted, counted, and shown
# nowhere: a failing check that appeared to have found nothing.

import io
import contextlib
from axiomgate_lint.cli import _rel, _print_github, SEVERITY_LEVELS


def _finding(severity="high", file="/tmp/x/y.py", line=3):
    return {
        "rule_id": "AG-DEL-001", "severity": severity, "file": file,
        "line": line, "message": "msg", "owasp": "LLM06: Excessive Agency",
    }


def test_rel_makes_paths_below_cwd_relative():
    target = os.path.join(os.getcwd(), "src", "crew.py")
    assert _rel(target) == os.path.join("src", "crew.py")


def test_rel_leaves_paths_outside_cwd_absolute():
    """`../../..` is not a usable annotation path; keep the absolute one."""
    assert _rel("/definitely/not/under/cwd.py").startswith("/")


def _github_output(findings, threshold):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        _print_github(findings, [], threshold)
    return buf.getvalue()


def test_github_emits_error_for_findings_that_fail_the_build():
    out = _github_output([_finding("high")], SEVERITY_LEVELS["high"])
    assert out.startswith("::error ")


def test_github_emits_warning_for_findings_below_the_threshold():
    """Emitting ::error for something that did not fail the run tells the
    reviewer the build broke when it did not."""
    out = _github_output([_finding("high")], SEVERITY_LEVELS["critical"])
    assert out.startswith("::warning ")


def test_github_annotation_path_is_relative():
    target = os.path.join(os.getcwd(), "src", "crew.py")
    out = _github_output([_finding(file=target)], SEVERITY_LEVELS["high"])
    assert "file=" + os.path.join("src", "crew.py") + "," in out


def test_github_warnings_are_reported_and_do_not_become_errors():
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        _print_github([], ["could not read foo.py"], SEVERITY_LEVELS["any"])
    assert buf.getvalue().startswith("::warning title=AxiomGate Lint::")


# --- A target that is not there is not a clean scan ---------------------------
# `axiomgate-lint ./scr` (a typo for ./src) printed "Total findings: 0" and
# exited 0. In CI that is a green check for work that never happened: the
# warning goes to stderr, the annotation is a ::warning nobody reads, and the
# pipeline reports success. Scanning nothing is not the same as finding
# nothing, and only one of the two should pass.

import subprocess


def _run(*args):
    return subprocess.run(
        [sys.executable, "-m", "axiomgate_lint", *args],
        capture_output=True, text=True,
    )


import sys  # noqa: E402  (kept beside the helper that needs it)


def test_missing_target_does_not_exit_zero():
    r = _run("/nonexistent/path/xyz")
    assert r.returncode == 1, (
        "a target that does not exist must not report success; that is a "
        "green CI check for a scan that never ran"
    )


def test_missing_target_says_why():
    r = _run("/nonexistent/path/xyz")
    assert "does not exist" in (r.stdout + r.stderr)


def test_missing_target_is_distinct_from_findings():
    """Exit 1 is 'could not scan'. Exit 2 is 'scanned, found something'.
    Collapsing them would make a typo look like a security failure."""
    r = _run("/nonexistent/path/xyz")
    assert r.returncode != 2


def test_an_empty_directory_is_a_clean_pass(tmp_path):
    r = _run(str(tmp_path))
    assert r.returncode == 0
