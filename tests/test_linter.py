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
        findings = scan_file(f_path)
        assert len(findings) == 1
        assert findings[0]["rule_id"] == "AG-DEL-001"
        assert findings[0]["severity"] == "high"
        assert "Excessive Agency" in findings[0]["owasp"]
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
        findings = scan_file(f_path)
        assert len(findings) == 0
    finally:
        os.remove(f_path)
