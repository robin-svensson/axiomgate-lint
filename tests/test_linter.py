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


# --- Virtual environments are not your code ----------------------------------
# Found by running the GitHub Action against a project whose venv was called
# `.v`. IGNORED_DIRS listed "venv" and ".venv" by name, so anything named
# differently got its entire site-packages scanned: findings in third-party
# packages the user never wrote, a failing build for code they do not control,
# and a scan that walks tens of thousands of files. A venv is identifiable by
# the pyvenv.cfg that every one of them contains, whatever the directory is
# called.

def test_site_packages_is_never_scanned(tmp_path):
    pkg = tmp_path / "weirdname" / "lib" / "python3.12" / "site-packages" / "dep"
    pkg.mkdir(parents=True)
    (pkg / "agent.py").write_text(
        "from crewai import Agent\na = Agent(role='r', allow_delegation=True)\n"
    )
    findings, _ = scan_directory(str(tmp_path))
    assert findings == [], "a dependency inside site-packages is not the user's code"


def test_a_virtualenv_is_skipped_whatever_it_is_called(tmp_path):
    env = tmp_path / ".v"
    env.mkdir()
    (env / "pyvenv.cfg").write_text("home = /usr/bin\n")
    (env / "mod.py").write_text(
        "from crewai import Agent\na = Agent(role='r', allow_delegation=True)\n"
    )
    findings, _ = scan_directory(str(tmp_path))
    assert findings == [], "pyvenv.cfg marks a virtual environment regardless of name"


def test_the_users_own_code_is_still_scanned(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "crew.py").write_text(
        "from crewai import Agent\na = Agent(role='r', allow_delegation=True)\n"
    )
    findings, _ = scan_directory(str(tmp_path))
    assert len(findings) == 1, "skipping environments must not skip the project"


# =============================================================================
# Findings from the pre-launch review, 2026-09-08. Each test below reproduces a
# bug that shipped in the published repository. They were written to fail.
# =============================================================================

# --- A name is not a framework -----------------------------------------------
# The scanner matched any call to something spelled `Agent`, never checking
# where that name came from. An insurance broker's `Agent(name=..., 
# allow_delegation=True)` — no CrewAI, no LLM, no AI at all — was reported as
# `LLM06: Excessive Agency`. Claiming a vulnerability in code that does not
# import the framework is the fastest way to lose a technical audience.

def test_a_locally_defined_agent_class_is_not_crewai(tmp_path):
    """A class named Agent, defined in this very file, is not CrewAI's."""
    f = tmp_path / "broker.py"
    f.write_text(
        "class Agent:\n"
        "    def __init__(self, name, allow_delegation=False): ...\n"
        "seller = Agent(name='Anna', allow_delegation=True)\n"
    )
    findings, _ = scan_file(str(f))
    assert findings == [], "a local class that shares the name is not the framework"


def test_an_unrelated_librarys_agent_is_not_flagged(tmp_path):
    """`from myshop import Agent` is somebody's sales rep, not an LLM agent."""
    f = tmp_path / "shop.py"
    f.write_text(
        "from myshop import Agent\n"
        "rep = Agent(name='Bo', allow_delegation=True)\n"
    )
    findings, _ = scan_file(str(f))
    assert findings == [], "only the frameworks the rule is about should match"


def test_the_real_crewai_agent_is_still_caught(tmp_path):
    """Rejecting look-alikes must not start rejecting the genuine article."""
    f = tmp_path / "crew.py"
    f.write_text(
        "from crewai import Agent\n"
        "a = Agent(role='r', allow_delegation=True)\n"
    )
    findings, _ = scan_file(str(f))
    assert len(findings) == 1


def test_an_import_alias_is_still_caught(tmp_path):
    """`from crewai import Agent as A` is the same class under another name."""
    f = tmp_path / "aliased.py"
    f.write_text(
        "from crewai import Agent as A\n"
        "a = A(role='r', allow_delegation=True)\n"
    )
    findings, _ = scan_file(str(f))
    assert len(findings) == 1, "an alias hides the name, not the risk"


def test_a_module_qualified_call_is_caught(tmp_path):
    """`crewai.Agent(...)` is the framework's class, reached the other way."""
    f = tmp_path / "qualified.py"
    f.write_text(
        "import crewai\n"
        "a = crewai.Agent(role='r', allow_delegation=True)\n"
    )
    findings, _ = scan_file(str(f))
    assert len(findings) == 1


def test_autogen_is_not_flagged(tmp_path):
    """README says `allow_delegation` is a CrewAI concept and that AutoGen has
    no equivalent. Flagging AutoGen anyway would claim a finding about a
    parameter that framework does not have."""
    f = tmp_path / "ag.py"
    f.write_text(
        "from autogen import ConversableAgent\n"
        "a = ConversableAgent(name='x', allow_delegation=True)\n"
    )
    findings, _ = scan_file(str(f))
    assert findings == [], "the rule is about CrewAI, as the documentation says"


# --- Where the project happens to live is not a filter -----------------------
# The directory filter tested every component of the *absolute* path against
# IGNORED_DIRS. `main()` makes the target absolute, so a project cloned into
# ~/build/proj or a CI workspace under build/ had every one of its files
# skipped: "Total findings: 0", exit 0, no warning. A green pass for code that
# was never opened — the exact failure the exit-code design exists to prevent.

def test_a_parent_directory_named_build_does_not_silence_the_scan(tmp_path):
    """Cloning into ~/build/proj must not turn the scan into a green no-op."""
    proj = tmp_path / "build" / "proj"
    proj.mkdir(parents=True)
    (proj / "crew.py").write_text(
        "from crewai import Agent\na = Agent(role='r', allow_delegation=True)\n"
    )
    findings, _ = scan_directory(str(proj))
    assert len(findings) == 1, "an ancestor's name says nothing about the target"


def test_a_parent_directory_named_venv_does_not_silence_the_scan(tmp_path):
    """Same failure, and 'venv' is a likelier ancestor name than most."""
    proj = tmp_path / "venv" / "proj"
    proj.mkdir(parents=True)
    (proj / "crew.py").write_text(
        "from crewai import Agent\na = Agent(role='r', allow_delegation=True)\n"
    )
    findings, _ = scan_directory(str(proj))
    assert len(findings) == 1


def test_site_packages_outside_a_venv_is_the_users_own_code(tmp_path):
    """A directory called site-packages with no venv above it is just a
    directory. The comment in the source says a name is not evidence; the
    site-packages check went on treating it as evidence anyway."""
    d = tmp_path / "proj" / "site-packages"
    d.mkdir(parents=True)
    (d / "crew.py").write_text(
        "from crewai import Agent\na = Agent(role='r', allow_delegation=True)\n"
    )
    findings, _ = scan_directory(str(tmp_path))
    assert len(findings) == 1, "no pyvenv.cfg and no lib/ above it: this is source"


# --- A byte order mark is not a syntax error ---------------------------------
# Files saved by Windows editors begin with a UTF-8 BOM. Python itself reads
# them without complaint. Opening with "utf-8" instead of "utf-8-sig" left the
# BOM in the source, ast.parse raised on U+FEFF, and a real finding on line 2
# was reported as an unparseable file — a warning on stderr and exit 0.

def test_a_byte_order_mark_does_not_hide_a_finding(tmp_path):
    """A BOM is an encoding artefact. Python runs the file; so must we."""
    f = tmp_path / "windows.py"
    f.write_bytes(
        b"\xef\xbb\xbffrom crewai import Agent\n"
        b"a = Agent(role='r', allow_delegation=True)\n"
    )
    findings, warnings = scan_file(str(f))
    assert len(findings) == 1, "a BOM must not turn real code into a syntax error"
    assert warnings == []


# --- Unscannable files must at least be countable ----------------------------
# README documents that unreadable files stay warnings and do not change the
# exit code. That is a deliberate choice, so it stands — but a security tool
# whose default is "some of this was never read, exit 0" needs a way to be
# strict, and the count has to reach the summary rather than only stderr.

def test_strict_makes_an_unreadable_file_fail_the_run(tmp_path):
    (tmp_path / "bad.py").write_text("def broken(")
    r = _run(str(tmp_path), "--strict")
    assert r.returncode == 1, "--strict means a file we could not read is a failure"


def test_without_strict_an_unreadable_file_still_exits_zero(tmp_path):
    """The documented default must not change underneath existing users."""
    (tmp_path / "bad.py").write_text("def broken(")
    r = _run(str(tmp_path))
    assert r.returncode == 0


# --- GitHub annotation properties are comma-delimited ------------------------
# `::error file=<path>,line=...` splits on commas. A path containing one ended
# the file property early and GitHub dropped or misplaced the annotation. The
# workflow-command format requires percent-encoding.

def test_github_escapes_commas_in_the_file_path():
    """A comma in a path silently truncated the annotation's file property."""
    out = _github_output([_finding(file=os.path.join(os.getcwd(), "a,b", "c.py"))],
                         SEVERITY_LEVELS["high"])
    assert "a%2Cb" in out, "a comma in a property must be percent-encoded"
    assert out.count(",line=") == 1


def test_github_escapes_newlines_in_the_message():
    """A newline in a message ends the annotation early."""
    f = _finding()
    f["message"] = "line one\nline two"
    out = _github_output([f], SEVERITY_LEVELS["high"])
    assert "\n" not in out.rstrip("\n")
    assert "%0A" in out


# --- Delegation turned on after construction ---------------------------------
# `a = Agent(...)` then `a.allow_delegation = True` has exactly the runtime
# effect the rule is about, and was invisible: the keyword search only ever
# looked inside the Call node.

def test_delegation_enabled_after_construction_is_caught(tmp_path):
    """Same runtime effect, one line later, and the scanner saw nothing."""
    f = tmp_path / "later.py"
    f.write_text(
        "from crewai import Agent\n"
        "a = Agent(role='r')\n"
        "a.allow_delegation = True\n"
    )
    findings, _ = scan_file(str(f))
    assert len(findings) == 1, "the flag is the risk, not the line it is set on"


def test_attribute_assignment_on_an_unrelated_object_is_not_flagged(tmp_path):
    """Tracking assignment must not start flagging anything with the word."""
    f = tmp_path / "unrelated.py"
    f.write_text(
        "config = dict()\n"
        "config.allow_delegation = True\n"
    )
    findings, _ = scan_file(str(f))
    assert findings == []


# --- Exit 2 is a finding, not a usage error ----------------------------------
# argparse exits 2 on an unknown flag. Exit 2 is also this tool's "found a
# vulnerability". A CI script could not tell a typo in a flag from a security
# finding.

def test_a_bad_flag_is_not_reported_as_a_security_finding(tmp_path):
    r = _run(str(tmp_path), "--fail-on", "nonsense")
    assert r.returncode != 2, "a usage error must not look like a vulnerability"
    assert r.returncode == 1


# =============================================================================
# Findings from the independent review of the fixes, 2026-09-08. Fixing the
# false positives introduced a false negative, which is the worse direction.
# =============================================================================

def test_a_method_named_agent_elsewhere_does_not_hide_a_real_finding(tmp_path):
    """Requiring the import was right; suppressing on any name collision
    anywhere in the file was not. A method called Agent, in an unrelated class,
    silenced a genuine CrewAI finding for the whole file — a green CI run over
    an agent that really can delegate."""
    f = tmp_path / "shadow.py"
    f.write_text(
        "from crewai import Agent\n"
        "class Foo:\n"
        "    def Agent(self):\n"
        "        pass\n"
        "a = Agent(role='r', allow_delegation=True)\n"
    )
    findings, _ = scan_file(str(f))
    assert len(findings) == 1, "a name in another scope does not rebind the import"


def test_a_module_level_class_really_does_shadow_the_import(tmp_path):
    """The suppression still has to work where it is actually true."""
    f = tmp_path / "real_shadow.py"
    f.write_text(
        "from crewai import Agent\n"
        "class Agent:\n"
        "    def __init__(self, **kw): ...\n"
        "a = Agent(allow_delegation=True)\n"
    )
    findings, _ = scan_file(str(f))
    assert findings == [], "a module-level class of the same name is what runs"


def test_a_finding_outranks_an_unreadable_file_under_strict(tmp_path):
    """--strict must not downgrade a real vulnerability to 'could not scan'.
    A pipeline branching on exit 2 would route a HIGH finding to retry."""
    (tmp_path / "bad.py").write_text("def broken(")
    (tmp_path / "crew.py").write_text(
        "from crewai import Agent\na = Agent(role='r', allow_delegation=True)\n"
    )
    r = _run(str(tmp_path), "--strict")
    assert r.returncode == 2, "the finding is the more important signal"


def test_one_agent_is_reported_once(tmp_path):
    """Constructor plus a redundant reassignment is one risk, not two.
    Counting it twice inflates the total for the same underlying agent."""
    f = tmp_path / "double.py"
    f.write_text(
        "from crewai import Agent\n"
        "a = Agent(role='r', allow_delegation=True)\n"
        "a.allow_delegation = True\n"
    )
    findings, _ = scan_file(str(f))
    assert len(findings) == 1, "one agent, one finding"


# =============================================================================
# Second review of the fixes, 2026-09-08. Name resolution was still a flat,
# file-wide guess. These require it to follow scope.
# =============================================================================

def test_a_class_named_agent_in_a_nested_scope_is_not_crewai(tmp_path):
    """The import lives in a function nobody calls; the Agent being built is a
    local class three scopes down. Matching them to each other because both
    names appear somewhere in the file is the same false positive as before,
    one scope deeper."""
    f = tmp_path / "nested.py"
    f.write_text(
        "def unused_helper():\n"
        "    from crewai import Agent\n"
        "    return Agent\n"
        "class Foo:\n"
        "    def build(self):\n"
        "        class Agent:\n"
        "            def __init__(self, **kw): pass\n"
        "        return Agent(name='x', allow_delegation=True)\n"
    )
    findings, _ = scan_file(str(f))
    assert findings == [], "a class defined in this scope is the one being called"


def test_a_reused_variable_still_reports_the_second_agent(tmp_path):
    """Two constructions, one variable name. Deduplicating on the name meant
    the second agent's delegation was never reported — a silently missed HIGH,
    which is the worse direction for a security tool."""
    f = tmp_path / "reuse.py"
    f.write_text(
        "from crewai import Agent\n"
        "a = Agent(role='r1', allow_delegation=True)\n"
        "a = Agent(role='r2')\n"
        "a.allow_delegation = True\n"
    )
    findings, _ = scan_file(str(f))
    assert len(findings) == 2, "rebinding the name makes it a different agent"


def test_tuple_unpacked_agents_are_tracked(tmp_path):
    """`a, b = Agent(...), Agent(...)` binds two agents. Only handling a bare
    Call on the right-hand side lost both."""
    f = tmp_path / "tup.py"
    f.write_text(
        "from crewai import Agent\n"
        "a, b = Agent(role='a'), Agent(role='b')\n"
        "b.allow_delegation = True\n"
    )
    findings, _ = scan_file(str(f))
    assert len(findings) == 1
    assert findings[0]["line"] == 3


def test_an_import_error_fallback_does_not_suppress_the_import(tmp_path):
    """The optional-dependency pattern. When crewai is installed, the agent is
    the real one; treating the except-branch stub as a shadowing assignment
    would hide every finding in files that guard their imports."""
    f = tmp_path / "optional.py"
    f.write_text(
        "try:\n"
        "    from crewai import Agent\n"
        "except ImportError:\n"
        "    Agent = None\n"
        "a = Agent(role='r', allow_delegation=True)\n"
    )
    findings, _ = scan_file(str(f))
    assert len(findings) == 1


def test_a_function_local_agent_is_still_caught(tmp_path):
    """Scope awareness must not stop finding agents built inside functions."""
    f = tmp_path / "infunc.py"
    f.write_text(
        "from crewai import Agent\n"
        "def build():\n"
        "    a = Agent(role='r')\n"
        "    a.allow_delegation = True\n"
        "    return a\n"
    )
    findings, _ = scan_file(str(f))
    assert len(findings) == 1


# =============================================================================
# Third review, 2026-09-08. Scope resolution was right in shape and incomplete
# in coverage: ordinary Python that binds or mutates a name went unseen.
# =============================================================================

def test_an_agent_in_a_default_argument_is_caught(tmp_path):
    """A default argument is evaluated once, at import time. It is real code
    that really constructs the agent, and it was invisible."""
    f = tmp_path / "default.py"
    f.write_text(
        "from crewai import Agent\n"
        "def build(a=Agent(role='r', allow_delegation=True)):\n"
        "    return a\n"
    )
    findings, _ = scan_file(str(f))
    assert len(findings) == 1


def test_augmented_assignment_enabling_delegation_is_caught(tmp_path):
    """`a.allow_delegation |= True` turns it on exactly as `= True` does."""
    f = tmp_path / "aug.py"
    f.write_text(
        "from crewai import Agent\n"
        "a = Agent(role='r', allow_delegation=False)\n"
        "a.allow_delegation |= True\n"
    )
    findings, _ = scan_file(str(f))
    assert len(findings) == 1
    assert findings[0]["line"] == 3


def test_an_annotated_assignment_is_tracked(tmp_path):
    """`a: Agent = Agent(...)` binds the name like any other assignment."""
    f = tmp_path / "ann.py"
    f.write_text(
        "from crewai import Agent\n"
        "a: Agent = Agent(role='r')\n"
        "a.allow_delegation = True\n"
    )
    findings, _ = scan_file(str(f))
    assert len(findings) == 1
    assert findings[0]["line"] == 3


def test_a_function_defined_before_the_import_still_resolves(tmp_path):
    """Names in a function body are looked up when the function runs, not
    where it is written. Analysing bodies in text order meant a helper defined
    above its import saw no CrewAI at all."""
    f = tmp_path / "order.py"
    f.write_text(
        "def make():\n"
        "    return Agent(role='r', allow_delegation=True)\n"
        "from crewai import Agent\n"
        "make()\n"
    )
    findings, _ = scan_file(str(f))
    assert len(findings) == 1, "module-level imports are in place before any call"


def test_rebinding_the_name_with_as_is_not_an_agent(tmp_path):
    """`with open(...) as Agent` leaves Agent pointing at a file object."""
    f = tmp_path / "withas.py"
    f.write_text(
        "from crewai import Agent\n"
        "with open('x') as Agent:\n"
        "    pass\n"
        "a = Agent(role='r', allow_delegation=True)\n"
    )
    findings, _ = scan_file(str(f))
    assert findings == []


def test_a_loop_variable_rebinds_the_name(tmp_path):
    """`for Agent in ...` does the same."""
    f = tmp_path / "foras.py"
    f.write_text(
        "from crewai import Agent\n"
        "for Agent in [1, 2]:\n"
        "    pass\n"
        "a = Agent(role='r', allow_delegation=True)\n"
    )
    findings, _ = scan_file(str(f))
    assert findings == []


def test_both_branches_of_an_if_are_reported(tmp_path):
    """The branches are mutually exclusive, so each is its own decision point.
    Sharing one delegation state let the first branch analysed silence the
    second, hiding a line a reviewer needs to see."""
    f = tmp_path / "branch.py"
    f.write_text(
        "from crewai import Agent\n"
        "a = Agent(role='r', allow_delegation=False)\n"
        "if some_condition:\n"
        "    a.allow_delegation = True\n"
        "else:\n"
        "    a.allow_delegation = True\n"
    )
    findings, _ = scan_file(str(f))
    assert len(findings) == 2, "both branches set it; both should be shown"


# =============================================================================
# Fourth review, 2026-09-08. Branch isolation was half done: state was reset,
# but the bindings made inside a branch were not, so one branch's agent was
# still visible — and still marked as delegating — while the next was read.
# =============================================================================

def test_a_branch_does_not_inherit_the_previous_branchs_agent(tmp_path):
    """Each branch has to start from the state before the branch, bindings
    included. Otherwise the first branch's agent, already marked delegating,
    is what the second branch reads."""
    f = tmp_path / "leak.py"
    f.write_text(
        "from crewai import Agent\n"
        "if cond:\n"
        "    a = Agent(role='x')\n"
        "    a.allow_delegation = True\n"
        "else:\n"
        "    a = Agent(role='y')\n"
        "    a.allow_delegation = True\n"
    )
    findings, _ = scan_file(str(f))
    assert len(findings) == 2


def test_a_closure_sees_the_scope_where_it_was_defined(tmp_path):
    """A function body is analysed after the module, but the names it closes
    over are the ones in place where it was written. Reading the scope as the
    last branch left it hid the finding inside the closure."""
    f = tmp_path / "closure.py"
    f.write_text(
        "from crewai import Agent\n"
        "def outer(cond):\n"
        "    if cond:\n"
        "        a = Agent(role='x')\n"
        "        def inner():\n"
        "            a.allow_delegation = True\n"
        "    else:\n"
        "        a = Agent(role='y')\n"
        "        a.allow_delegation = True\n"
    )
    findings, _ = scan_file(str(f))
    assert len(findings) == 2, "the closure's line is a finding of its own"


# =============================================================================
# Fifth review, 2026-09-09, before the community release. Every case below is a
# real CrewAI file with delegation switched on that the linter reported clean —
# exit 0 — and that the README did not list as a blind spot. A false negative
# the documentation does not admit to is the failure mode this project exists
# to avoid: a clean result that means nothing.
# =============================================================================

# --- The keyword does not have to be written as a keyword ---------------------
# `_constructor_enables` read `kw.arg`, which is None for a `**` spread. A
# literal dict spread into the constructor is the same decision, written
# differently, and it is what a factory that builds config inline looks like.

def test_a_literal_dict_spread_into_the_constructor_is_caught(tmp_path):
    """`Agent(**{"allow_delegation": True})` turns delegation on exactly as the
    keyword does. The spread has kw.arg None, so it was never inspected."""
    f = tmp_path / "spread.py"
    f.write_text(
        "from crewai import Agent\n"
        "a = Agent(**{'role': 'r', 'allow_delegation': True})\n"
    )
    findings, _ = scan_file(str(f))
    assert len(findings) == 1


def test_a_literal_dict_spread_without_delegation_is_not_flagged(tmp_path):
    """Reading the spread must not turn every spread into a finding."""
    f = tmp_path / "spread_clean.py"
    f.write_text(
        "from crewai import Agent\n"
        "a = Agent(**{'role': 'r', 'allow_delegation': False})\n"
    )
    findings, _ = scan_file(str(f))
    assert len(findings) == 0


def test_a_dict_variable_spread_stays_a_documented_blind_spot(tmp_path):
    """A dict built elsewhere is not visible without executing the code.
    Guessing that any `**kwargs` enables delegation would report every factory
    in the project. It stays unreported, and the README says so."""
    f = tmp_path / "spread_var.py"
    f.write_text(
        "from crewai import Agent\n"
        "kw = {'allow_delegation': True}\n"
        "a = Agent(**kw)\n"
    )
    findings, _ = scan_file(str(f))
    assert len(findings) == 0


# --- setattr is an assignment spelled as a call -------------------------------
# `setattr(a, "allow_delegation", True)` is the documented way to set an
# attribute whose name is computed, and the obvious way around a linter that
# only reads assignments.

def test_setattr_with_a_literal_name_is_caught(tmp_path):
    f = tmp_path / "setattr_lit.py"
    f.write_text(
        "from crewai import Agent\n"
        "a = Agent(role='r')\n"
        "setattr(a, 'allow_delegation', True)\n"
    )
    findings, _ = scan_file(str(f))
    assert len(findings) == 1


def test_setattr_with_a_computed_name_is_not_guessed_at(tmp_path):
    """The attribute name is not knowable without running the code. Reporting
    it anyway would be a guess, and a guessing rule is worse than no rule."""
    f = tmp_path / "setattr_var.py"
    f.write_text(
        "from crewai import Agent\n"
        "a = Agent(role='r')\n"
        "setattr(a, name, True)\n"
    )
    findings, _ = scan_file(str(f))
    assert len(findings) == 0


def test_setattr_on_something_that_is_not_an_agent_is_not_flagged(tmp_path):
    f = tmp_path / "setattr_other.py"
    f.write_text(
        "from crewai import Agent\n"
        "cfg = object()\n"
        "setattr(cfg, 'allow_delegation', True)\n"
    )
    findings, _ = scan_file(str(f))
    assert len(findings) == 0


# --- The walrus binds a name --------------------------------------------------
# `if (a := Agent(...)):` constructs an agent and names it. The construction was
# reported when the constructor carried the flag, but the name was never bound,
# so delegation switched on afterwards was invisible.

def test_a_walrus_bound_agent_is_tracked(tmp_path):
    f = tmp_path / "walrus.py"
    f.write_text(
        "from crewai import Agent\n"
        "if (a := Agent(role='r')):\n"
        "    a.allow_delegation = True\n"
    )
    findings, _ = scan_file(str(f))
    assert len(findings) == 1


# --- An agent held on self ----------------------------------------------------
# `self.agent = Agent(...)` in __init__ and `self.agent.allow_delegation = True`
# in another method is the wrapper-class shape. `attribute_finding` required the
# object to be a plain Name, so `self.agent` matched nothing and the file was
# reported clean.

def test_delegation_set_on_a_self_attribute_is_caught(tmp_path):
    f = tmp_path / "selfattr.py"
    f.write_text(
        "from crewai import Agent\n"
        "class Wrapper:\n"
        "    def __init__(self):\n"
        "        self.a = Agent(role='r')\n"
        "    def enable(self):\n"
        "        self.a.allow_delegation = True\n"
    )
    findings, _ = scan_file(str(f))
    assert len(findings) == 1


def test_a_self_attribute_that_is_not_an_agent_is_not_flagged(tmp_path):
    """Only an attribute seen built from a framework agent counts. `self.cfg`
    is somebody's own object and claiming LLM06 about it is the false positive
    this project removed in 0.2.0."""
    f = tmp_path / "selfother.py"
    f.write_text(
        "from crewai import Agent\n"
        "class Wrapper:\n"
        "    def __init__(self):\n"
        "        self.cfg = dict()\n"
        "    def enable(self):\n"
        "        self.cfg.allow_delegation = True\n"
    )
    findings, _ = scan_file(str(f))
    assert len(findings) == 0


def test_a_self_attribute_is_not_shared_between_classes(tmp_path):
    """Two classes can both call an attribute `a`. One class holding an agent
    there does not make the other's attribute an agent."""
    f = tmp_path / "twoclasses.py"
    f.write_text(
        "from crewai import Agent\n"
        "class HasAgent:\n"
        "    def __init__(self):\n"
        "        self.a = Agent(role='r')\n"
        "class HasSomethingElse:\n"
        "    def __init__(self):\n"
        "        self.a = dict()\n"
        "    def enable(self):\n"
        "        self.a.allow_delegation = True\n"
    )
    findings, _ = scan_file(str(f))
    assert len(findings) == 0


def test_a_self_attribute_rebound_to_a_new_agent_is_a_new_agent(tmp_path):
    """Rebinding replaces the delegation state, exactly as for a plain name."""
    f = tmp_path / "selfrebind.py"
    f.write_text(
        "from crewai import Agent\n"
        "class Wrapper:\n"
        "    def __init__(self):\n"
        "        self.a = Agent(role='r', allow_delegation=True)\n"
        "        self.a = Agent(role='r2')\n"
        "        self.a.allow_delegation = True\n"
    )
    findings, _ = scan_file(str(f))
    assert len(findings) == 2


def test_the_receiver_name_does_not_have_to_be_self(tmp_path):
    """`self` is a convention, not a keyword. The first positional parameter is
    what the method actually binds."""
    f = tmp_path / "notself.py"
    f.write_text(
        "from crewai import Agent\n"
        "class Wrapper:\n"
        "    def __init__(this):\n"
        "        this.a = Agent(role='r')\n"
        "    def enable(this):\n"
        "        this.a.allow_delegation = True\n"
    )
    findings, _ = scan_file(str(f))
    assert len(findings) == 1


# --- Agents held in a literal container ---------------------------------------
# A registry — `agents = {"researcher": Agent(...)}` — then
# `agents["researcher"].allow_delegation = True`. The construction was reported
# only if the flag was in the constructor; the later mutation was invisible.

def test_delegation_set_through_a_literal_dict_is_caught(tmp_path):
    f = tmp_path / "dictreg.py"
    f.write_text(
        "from crewai import Agent\n"
        "agents = {'r': Agent(role='r')}\n"
        "agents['r'].allow_delegation = True\n"
    )
    findings, _ = scan_file(str(f))
    assert len(findings) == 1


def test_delegation_set_through_a_literal_list_is_caught(tmp_path):
    f = tmp_path / "listreg.py"
    f.write_text(
        "from crewai import Agent\n"
        "agents = [Agent(role='r'), Agent(role='w')]\n"
        "agents[1].allow_delegation = True\n"
    )
    findings, _ = scan_file(str(f))
    assert len(findings) == 1


def test_an_index_holding_something_else_is_not_flagged(tmp_path):
    f = tmp_path / "mixed.py"
    f.write_text(
        "from crewai import Agent\n"
        "things = [Agent(role='r'), dict()]\n"
        "things[1].allow_delegation = True\n"
    )
    findings, _ = scan_file(str(f))
    assert len(findings) == 0


def test_a_computed_index_is_not_guessed_at(tmp_path):
    """Which element `agents[i]` is cannot be known without running the code."""
    f = tmp_path / "computed.py"
    f.write_text(
        "from crewai import Agent\n"
        "agents = [Agent(role='r')]\n"
        "agents[i].allow_delegation = True\n"
    )
    findings, _ = scan_file(str(f))
    assert len(findings) == 0


def test_a_negative_index_reaches_the_agent_it_counts_back_to(tmp_path):
    """`agents[-1]` is a literal index, but `-1` parses as a unary minus over a
    constant, not a constant. The last agent in a list went unread."""
    f = tmp_path / "crew.py"
    f.write_text(
        "from crewai import Agent\n"
        "agents = [Agent(role='r'), Agent(role='s')]\n"
        "agents[-1].allow_delegation = True\n"
    )
    findings, _ = scan_file(str(f))
    assert len(findings) == 1
    assert findings[0]["line"] == 3


def test_a_negative_index_past_the_end_is_not_guessed_at(tmp_path):
    """`agents[-3]` of a two-item list raises at runtime. It holds no agent, and
    reporting one would be a finding about code that never runs."""
    f = tmp_path / "crew.py"
    f.write_text(
        "from crewai import Agent\n"
        "agents = [Agent(role='r'), Agent(role='s')]\n"
        "agents[-3].allow_delegation = True\n"
    )
    findings, _ = scan_file(str(f))
    assert findings == []


def test_a_function_nested_in_a_method_does_not_own_a_receiver(tmp_path):
    """A function defined inside a method is not a method. Its first parameter
    was read as the receiver, so an unrelated callback argument resolved to the
    class's attributes and reported a finding about an object it never saw."""
    f = tmp_path / "crew.py"
    f.write_text(
        "from crewai import Agent\n"
        "class C:\n"
        "    def outer(self):\n"
        "        self.a = Agent(role='r')\n"
        "        def helper(config):\n"
        "            config.a.allow_delegation = True\n"
        "        helper(object())\n"
    )
    findings, _ = scan_file(str(f))
    assert findings == []


def test_a_nested_function_cannot_invent_an_attribute_on_the_class(tmp_path):
    """The nested function's parameter wrote into the class's attribute table,
    so `self.b` resolved to an agent that the class never binds."""
    f = tmp_path / "crew.py"
    f.write_text(
        "from crewai import Agent\n"
        "class C:\n"
        "    def outer(self):\n"
        "        def helper(config):\n"
        "            config.b = Agent(role='s')\n"
        "        helper(object())\n"
        "        self.b.allow_delegation = True\n"
    )
    findings, _ = scan_file(str(f))
    assert findings == []


def test_a_closure_over_the_real_receiver_is_still_tracked(tmp_path):
    """`self` inside a nested function is the method's own receiver, closed
    over. Dropping the receiver entirely would reopen the gap 0.2.1 closed."""
    f = tmp_path / "crew.py"
    f.write_text(
        "from crewai import Agent\n"
        "class C:\n"
        "    def outer(self):\n"
        "        self.a = Agent(role='r')\n"
        "        def helper():\n"
        "            self.a.allow_delegation = True\n"
        "        helper()\n"
    )
    findings, _ = scan_file(str(f))
    assert len(findings) == 1
    assert findings[0]["line"] == 6


def test_a_parameter_that_shadows_the_receiver_is_not_the_receiver(tmp_path):
    """A nested function taking its own `self` shadows the method's. The name
    is the same; the object is whatever the caller passed."""
    f = tmp_path / "crew.py"
    f.write_text(
        "from crewai import Agent\n"
        "class C:\n"
        "    def outer(self):\n"
        "        self.a = Agent(role='r')\n"
        "        def helper(self):\n"
        "            self.a.allow_delegation = True\n"
        "        helper(object())\n"
    )
    findings, _ = scan_file(str(f))
    assert findings == []
