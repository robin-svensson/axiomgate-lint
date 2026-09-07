# Security policy

## Reporting a vulnerability

Use GitHub's private reporting: **Security → Report a vulnerability** on
[this repository](https://github.com/robinsvensson493-cyber/axiomgate-lint/security/advisories/new).
That keeps the report private until there's a fix.

Please don't open a public issue for a vulnerability.

You'll get a first reply within 72 hours. This is maintained by one person, so
a fix may take longer than that, but you won't be left wondering whether the
report was seen.

## What counts as a vulnerability here

`axiomgate-lint` reads Python source and never executes it. It makes no
network calls and has no dependencies, so the usual supply chain and
credential problems mostly don't apply. What does:

- **Code execution while parsing.** The linter uses `ast.parse`, which does
  not evaluate the source. If you find input that makes it run something,
  that's the most serious thing you can report.
- **A false negative that a real project would hit.** A pattern that should
  match `AG-DEL-001` and doesn't is a security bug, not a feature request.
  The whole point is that a clean result means something.
- **Path handling.** Anything where a crafted filename or symlink makes the
  tool read or write outside the target it was pointed at.
- **Crashes on untrusted input.** This gets run against repositories nobody
  has read yet. A malformed file should produce a warning, not a traceback.

## What doesn't

- A rule that doesn't exist yet. Those are welcome as issues or pull
  requests, just not as security reports.
- Findings the linter reports about *your* code. That's the tool working.
- Anything requiring an attacker who already runs code on the machine doing
  the scan.

## Scope

This policy covers `axiomgate-lint` only.
