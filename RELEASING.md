# Releasing

`axiomgate-lint` publishes to PyPI from `.github/workflows/release.yml`, which
runs only on a tag matching `v*`. Nothing publishes from a branch push.

## Trusted Publishing — no API token

PyPI verifies the workflow's OIDC identity instead of a stored token. There is
no secret in this repository and nothing to rotate. Setting it up is a one-time
step that only the PyPI account owner can do.

### One-time setup (manual)

1. Sign in at <https://pypi.org> and go to
   **Your projects → Publishing → Add a new pending publisher**.
   `axiomgate-lint` is not registered on PyPI yet, so it has to be added as a
   *pending* publisher — the project gets created by the first successful run.
2. Fill in exactly:
   - PyPI Project Name: `axiomgate-lint`
   - Owner: `robin-svensson`
   - Repository name: `axiomgate-lint`
   - Workflow name: `release.yml`
   - Environment name: `pypi`
3. Save. Nothing is published by this step.

The environment name must match `environment: pypi` in the publish job. If they
differ, PyPI rejects the upload with an OIDC error and nothing is released.

## Releasing a version

1. Bump the version in `pyproject.toml` and add the CHANGELOG entry.
2. Commit and push to `main`; let CI go green.
3. Tag and push the tag:

   ```
   git tag v0.3.0
   git push origin v0.3.0
   ```

The workflow runs the suite on Python 3.10–3.14, builds, runs
`twine check --strict`, checks that the tag matches the built version, and only
then publishes.

**The tag is the point of no return.** PyPI never lets a version number be
reused, even after a deletion. Everything before the tag can be undone; nothing
after it can. This repository has already had a tag disagree with its tree —
`v0.2.2` was tagged on the `v0.2.1` commit and had to be deleted — which is why
the workflow now refuses to publish when the tag and the built version differ.
