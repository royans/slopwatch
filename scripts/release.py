#!/usr/bin/env python3
"""Cut a SlopWatch release: bump the version, refresh the changelog, verify, tag.

This does everything *locally* and stops before any network mutation. The last
two steps — pushing the tag and creating the GitHub Release — stay manual so a
release is always a deliberate act. Creating the GitHub Release is what triggers
`.github/workflows/publish.yml` (Trusted Publishing to PyPI).

    python scripts/release.py 0.3.0            # bump + changelog + verify + tag
    python scripts/release.py 0.3.0 --dry-run  # show what would happen
    python scripts/release.py --notes 0.3.0    # print the CHANGELOG slice for gh

Version is single-sourced from pyproject.toml; `slopwatch.__version__` and the
CLI read it back via importlib.metadata at runtime.
"""
from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PYPROJECT = ROOT / "pyproject.toml"
INIT = ROOT / "src" / "slopwatch" / "__init__.py"
README = ROOT / "README.md"
CHANGELOG = ROOT / "CHANGELOG.md"

SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+(?:[-.][0-9A-Za-z.]+)?$")


def run(cmd: list[str], *, capture: bool = False, check: bool = True) -> str:
    print(f"  $ {' '.join(cmd)}")
    res = subprocess.run(
        cmd, cwd=ROOT, text=True, check=check,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
    )
    return (res.stdout or "").strip()


def fail(msg: str) -> None:
    print(f"\n✗ {msg}", file=sys.stderr)
    sys.exit(1)


def current_version() -> str:
    m = re.search(r'^version\s*=\s*"([^"]+)"', PYPROJECT.read_text(), re.M)
    return m.group(1) if m else "?"


def preflight(new: str) -> None:
    if not SEMVER_RE.match(new):
        fail(f"'{new}' is not a valid version (expected e.g. 0.3.0)")

    branch = run(["git", "rev-parse", "--abbrev-ref", "HEAD"], capture=True)
    if branch != "main":
        fail(f"on branch '{branch}', expected 'main'")

    if run(["git", "status", "--porcelain"], capture=True):
        fail("working tree is dirty — commit or stash first")

    run(["git", "fetch", "--quiet", "origin", "main"], check=False)
    local = run(["git", "rev-parse", "@"], capture=True)
    remote = run(["git", "rev-parse", "@{u}"], capture=True, check=False)
    if remote and local != remote:
        fail("local main is not in sync with origin/main")

    if run(["git", "tag", "-l", f"v{new}"], capture=True):
        fail(f"tag v{new} already exists")

    cur = current_version()
    if new == cur:
        fail(f"version is already {cur}")
    print(f"  {cur} -> {new}")


def bump_files(new: str) -> None:
    pp = PYPROJECT.read_text()
    pp = re.sub(r'^(version\s*=\s*")[^"]+(")', rf"\g<1>{new}\g<2>", pp, count=1, flags=re.M)
    PYPROJECT.write_text(pp)

    ini = INIT.read_text()
    ini = re.sub(r'(_FALLBACK_VERSION\s*=\s*")[^"]+(")', rf"\g<1>{new}\g<2>", ini, count=1)
    INIT.write_text(ini)

    rd = README.read_text()
    rd = re.sub(r"(\brev:\s*v)\d+\.\d+\.\d+", rf"\g<1>{new}", rd)
    README.write_text(rd)
    print("  bumped pyproject.toml, __init__.py fallback, README rev")


def update_changelog(new: str, *, use_cliff: bool) -> None:
    tag = f"v{new}"
    if use_cliff:
        if not shutil.which("git-cliff"):
            fail("--cliff given but git-cliff is not on PATH (pip install 'git-cliff')")
        run(["git-cliff", "--unreleased", "--tag", tag, "--prepend", str(CHANGELOG)])
        print("  CHANGELOG.md seeded from commits with git-cliff — curate the wording now")
        return

    # Default: promote the hand-curated [Unreleased] block to a dated section
    # and reseed an empty [Unreleased]. Curate [Unreleased] as you merge work.
    text = CHANGELOG.read_text()
    stamp = f"## [{new}] — {date.today().isoformat()}"
    if "## [Unreleased]" not in text:
        fail("CHANGELOG.md has no '## [Unreleased]' section to promote")
    text = text.replace(
        "## [Unreleased]",
        f"## [Unreleased]\n\n_Nothing yet._\n\n{stamp}",
        1,
    )
    # Refresh the compare links at the foot of the file.
    prev = current_version_before(new)
    links = (
        f"[Unreleased]: https://github.com/royans/slopwatch/compare/{tag}...HEAD\n"
        f"[{new}]: https://github.com/royans/slopwatch/compare/v{prev}...{tag}\n"
    )
    text = re.sub(r"\[Unreleased\]: \S+\n", links, text, count=1)
    CHANGELOG.write_text(text)
    print("  CHANGELOG.md [Unreleased] promoted -> review wording before continuing")


def current_version_before(new: str) -> str:
    # The pyproject was already bumped, so read the newest existing tag instead.
    tags = run(["git", "tag", "-l", "v*", "--sort=-v:refname"], capture=True).splitlines()
    return tags[0].lstrip("v") if tags else "0.0.0"


def verify() -> None:
    run(["python", "scripts/presubmit.py"])
    run(["python", "-m", "pytest", "-q"])
    if (ROOT / "dist").exists():
        shutil.rmtree(ROOT / "dist")
    run(["python", "-m", "build"])
    run(["python", "-m", "twine", "check", "dist/*"])


def commit_and_tag(new: str) -> None:
    tag = f"v{new}"
    run(["git", "add", "pyproject.toml", "src/slopwatch/__init__.py", "README.md", "CHANGELOG.md"])
    run(["git", "commit", "-m", f"release: {tag}"])
    run(["git", "tag", "-a", tag, "-m", tag])


def notes_slice(version: str) -> str:
    text = CHANGELOG.read_text()
    m = re.search(
        rf"^## \[{re.escape(version)}\][^\n]*\n(.*?)(?=^## \[|\Z)",
        text, re.M | re.S,
    )
    if not m:
        fail(f"no '## [{version}]' section found in CHANGELOG.md")
    return m.group(1).strip()


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("version", help="target version, e.g. 0.3.0")
    ap.add_argument("--dry-run", action="store_true", help="preflight + show plan, change nothing")
    ap.add_argument("--notes", action="store_true", help="print the CHANGELOG slice for this version and exit")
    ap.add_argument("--cliff", action="store_true", help="seed the changelog from commits with git-cliff instead of promoting [Unreleased]")
    args = ap.parse_args()

    if args.notes:
        print(notes_slice(args.version))
        return

    tag = f"v{args.version}"
    print(f"▶ Releasing {tag}\n")
    print("· preflight")
    preflight(args.version)

    if args.dry_run:
        print("\n(dry run — stopping here)")
        return

    print("\n· bump version")
    bump_files(args.version)
    print("\n· changelog")
    update_changelog(args.version, use_cliff=args.cliff)

    input("\n⏸  Review CHANGELOG.md now, then press Enter to run verification… ")

    print("\n· verify")
    verify()
    print("\n· commit + tag")
    commit_and_tag(args.version)

    print(f"""
✓ {tag} is committed and tagged locally.

Next (manual):

  git push origin main --tags
  python scripts/release.py --notes {args.version} > /tmp/{tag}-notes.md
  gh release create {tag} --title "SlopWatch {tag}" --notes-file /tmp/{tag}-notes.md

Creating the GitHub Release fires .github/workflows/publish.yml, which builds,
tests, runs twine check, and publishes to PyPI via Trusted Publishing.
""")


if __name__ == "__main__":
    main()
