# Releasing

How a new version gets to PyPI. Read this before cutting a release;
it is short on purpose.

## One-time setup (already done for v0.1.0's tag, not for PyPI yet)

`.github/workflows/publish.yml` publishes via PyPI's **Trusted
Publishing** (OIDC): no API token is generated, stored as a repo
secret, or rotated. PyPI verifies the exact workflow (repo + workflow
filename + environment name) against a "pending publisher" configured
once, before the project exists on PyPI at all.

1. Sign in at [pypi.org](https://pypi.org) (2FA is mandatory).
2. Account settings -> **Publishing** -> "Add a new pending publisher".
3. Fill in:
   - PyPI project name: `custody-mcp`
   - Owner: `unmirihealth`
   - Repository name: `custody`
   - Workflow filename: `publish.yml`
   - Environment name: `pypi`
4. In the GitHub repo, Settings -> Environments -> create an
   environment named exactly `pypi` (matches step 3's environment
   name; `publish.yml`'s `environment: pypi` is what PyPI's OIDC check
   matches against). Protection rules (required reviewers, deployment
   branch restriction to `main` or to tags) are optional but
   recommended for an environment that can publish a public package.

Nothing else to configure. No token ever touches this repo, this CI
run, or any contributor's machine.

## Cutting a release

1. Bump `version` in `pyproject.toml`.
2. Update `CHANGELOG.md`: move `[Unreleased]` into a new dated
   version section, matching how `[0.1.0]` is already written.
3. Commit, tag (`git tag vX.Y.Z -F <a notes file>`), push the tag.
4. `gh release create vX.Y.Z -F <the same notes file>` (or the GitHub
   UI). **Publishing the Release is what triggers `publish.yml`** --
   pushing the tag alone does not.
5. Confirm the run went green and the new version shows up at
   [pypi.org/project/custody-mcp](https://pypi.org/project/custody-mcp/).

## Before the very first publish

`uv build` locally first, and confirm the wheel actually imports:

```bash
uv build
whl=$(ls dist/*.whl)
uv run --with "$whl" --no-project python3 -c "import custody; print('import OK')"
```

`publish.yml`'s own `build` job runs this exact check before anything
reaches PyPI, so this is "does the thing I'm about to publish even
work," not a step the workflow skips.

## Re-running a publish

`workflow_dispatch` on `publish.yml` re-runs the build-and-publish
pair without creating a new Release -- use it if the `build` job failed
and you want to retry against the existing, already-published Release.
Re-publishing the SAME version number to PyPI is not possible (PyPI
rejects a re-upload of a version that already exists, even if the
earlier upload failed partway); a fix after a bad publish needs a new,
higher version number, not a retry of the old one.
