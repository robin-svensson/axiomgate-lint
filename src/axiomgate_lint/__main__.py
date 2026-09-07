"""Allow `python -m axiomgate_lint` alongside the installed entry point.

Guarded rather than executed at import time: without the guard, anything that
imports `axiomgate_lint.__main__` — a test collector walking the package, for
one — runs the linter and calls sys.exit() in the middle of the import.
"""
import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
