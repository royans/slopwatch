# Releasing SlopWatch

The version is single-sourced from `pyproject.toml`. `slopwatch.__version__`, the
`slopwatch --version` output, and the `info` panel all read it back at runtime via
`importlib.metadata`, so **`pyproject.toml` is the only place a version literal
lives** (plus a fallback in `src/slopwatch/__init__.py` for uninstalled source
trees, which `scripts/release.py` keeps in sync).

## What triggers a PyPI publish

Publishing a **GitHub Release** runs `.github/workflows/publish.yml`, which
re-runs the leak check + tests, builds, `twine check`s, and pushes to PyPI via
Trusted Publishing (OIDC — no stored token). The workflow refuses to publish if
the release tag doesn't match `pyproject.toml`'s version.

`workflow_dispatch` on that workflow can also publish to TestPyPI on demand.

## Keeping the changelog

`CHANGELOG.md` follows [Keep a Changelog](https://keepachangelog.com). Curate the
`## [Unreleased]` section as you merge notable work — that section becomes the
release notes verbatim. (If you'd rather draft it from commit messages, run
`scripts/release.py --cliff …`, which seeds it with `git-cliff` per `cliff.toml`,
then edit.)

## Cutting a release

```bash
# 1. Local: bump, promote the changelog, verify, commit, tag — no network writes.
python scripts/release.py 0.3.0
#    (pauses once so you can review CHANGELOG.md before it runs tests + build)

# 2. Push the release commit and tag.
git push origin main --tags

# 3. Create the GitHub Release — this is what publishes to PyPI.
python scripts/release.py --notes 0.3.0 > /tmp/v0.3.0-notes.md
gh release create v0.3.0 --title "SlopWatch v0.3.0" --notes-file /tmp/v0.3.0-notes.md

# 4. Watch it land.
gh run watch --workflow publish.yml
```

`scripts/release.py 0.3.0 --dry-run` shows the plan and runs only the preflight
checks (clean tree, on `main`, synced with origin, tag not taken).

## One-time backfill

PyPI `0.1.0` was published before the repo used tags. Tag that commit so
changelog tooling and the `compare/` links have a floor:

```bash
git tag -a v0.1.0 b40c981 -m "v0.1.0 (retroactive — matches PyPI upload 2026-09-06)"
git push origin v0.1.0
```
