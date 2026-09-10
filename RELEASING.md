# Releasing

`axiomgate-lint` publishes to PyPI from `.github/workflows/release.yml`, which
runs only on a tag matching `v*`. Nothing publishes from a branch push.

## Trusted Publishing — no API token

PyPI verifies the workflow's OIDC identity instead of a stored token. There is
no secret in this repository and nothing to rotate. Setting it up is a one-time
step that only the PyPI account owner can do.

### One-time setup (manual)

**This was done 2026-09-11** — the pending publisher is registered and shows the
values below on PyPI's Publishing page. It is recorded here because it has to be
redone from scratch if it is ever removed, and because a pending publisher does
**not** reserve the name: until the first upload creates the project, anyone else
can still register `axiomgate-lint` on PyPI.

1. Sign in at <https://pypi.org> and go to
   **Your projects → Publishing → Add a new pending publisher**.
   `axiomgate-lint` does not exist on PyPI yet, so it is added as a *pending*
   publisher — the project gets created by the first successful run.
2. Fill in (PyPI's own labels may read slightly differently; these are the
   values, in the order the form asks for them):
   - PyPI Project Name: `axiomgate-lint`
   - Owner: `robin-svensson`
   - Repository name: `axiomgate-lint`
   - Workflow name: `release.yml`
   - Environment name: `pypi`
3. Save. Nothing is published by this step.

The environment name must match `environment: pypi` in the publish job. If they
differ, PyPI rejects the upload with an OIDC error and nothing is released.

### The GitHub side is already configured

The `pypi` environment exists in this repository with two protection rules set
2026-09-11, so the workflow does not publish unattended:

- **Required reviewer: `robin-svensson`.** The `publish` job waits for an
  explicit approval in the Actions tab before it uploads anything. This is the
  last reversible moment — after it, the version number is spent forever.
- **Deployments only from tags matching `v*`.** A branch cannot deploy to this
  environment at all.

Neither rule is set by the workflow file; both live in the repository settings
under Settings → Environments → pypi. If the environment is ever deleted, GitHub
recreates it on the next run **without** these rules, and the release then
publishes with no human gate.

## Releasing a version

1. Bump the version in `pyproject.toml` and add the CHANGELOG entry.
2. Commit and push to `main`; let CI go green.
3. Tag and push the tag:

   ```
   git tag v0.3.0
   git push origin v0.3.0
   ```

**The tag must be spelled the way the version is.** The workflow compares the tag,
minus its leading `v`, against the version of the wheel it just built, and Python
normalises versions — `0.3.0rc1`, never `0.3.0-rc1`. So a pre-release is tagged
`v0.3.0rc1`. A hyphen there fails the check rather than publishing the wrong
thing, which is the right outcome, but it fails after the tag is already pushed.

The workflow runs the suite on Python 3.10–3.14, builds, runs
`twine check --strict`, checks that the tag matches the built version, and only
then publishes.

**The tag is the point of no return.** PyPI never lets a version number be
reused, even after a deletion. Everything before the tag can be undone; nothing
after it can. This repository has already had a tag disagree with its tree —
`v0.2.2` was tagged on the `v0.2.1` commit and had to be deleted — which is why
the workflow now refuses to publish when the tag and the built version differ.
