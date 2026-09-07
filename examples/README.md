# Examples

Two small CrewAI files, one the linter flags and one it doesn't. They exist so
you can check that the tool works before you trust a clean result on your own
code. A linter that silently does nothing looks exactly like a linter that
found nothing.

## Check the tool works

```bash
axiomgate-lint examples/vulnerable_crew.py
echo "exit: $?"
```

You should see one HIGH finding, `AG-DEL-001`, and exit code `2`.

```bash
axiomgate-lint examples/safe_crew.py
echo "exit: $?"
```

No findings, exit code `0`.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Scanned, nothing at or above the threshold |
| `1` | Could not scan. The target does not exist |
| `2` | Scanned, found something at or above the threshold |

Code `1` matters more than it looks. `axiomgate-lint ./scr` is a typo, and a
tool that answers "0 findings, exit 0" to a path it never opened hands you a
green pipeline for a scan that never ran.

## A note on running the whole repository

`axiomgate-lint .` from the repository root will flag `vulnerable_crew.py`,
because that is what the file is for. The project's own CI scans `./src`.
