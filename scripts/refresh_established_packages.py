#!/usr/bin/env python3
"""Regenerate the bundled lists of established (high-impact) npm and PyPI package names.

    python scripts/refresh_established_packages.py

Sources:
  npm  — npm-high-impact `lib/top.js` (most-downloaded ∪ most-depended-on packages)
  PyPI — hugovk/top-pypi-packages (top 15k projects by 30-day downloads)

Writes src/slopwatch/signatures/established_{npm,pypi}.txt, most popular first. These names
are never squat candidates; see slopwatch/core/established.py.
"""

from __future__ import annotations

import json
import re
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "src" / "slopwatch" / "signatures"
NPM_PKG = "npm-high-impact"
PYPI_URL = "https://hugovk.github.io/top-pypi-packages/top-pypi-packages.min.json"


def _get(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "slopwatch-refresh/1"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        return resp.read()


def npm_names() -> tuple[list[str], str]:
    version = json.loads(_get(f"https://registry.npmjs.org/{NPM_PKG}/latest"))["version"]
    src = _get(f"https://cdn.jsdelivr.net/npm/{NPM_PKG}@{version}/lib/top.js").decode()
    names = re.findall(r"^\s*'([^']+)',?\s*$", src, re.M)
    return names, f"{NPM_PKG}@{version} lib/top.js"


def pypi_names() -> tuple[list[str], str]:
    doc = json.loads(_get(PYPI_URL))
    names = [re.sub(r"[-_.]+", "-", r["project"].lower()) for r in doc["rows"]]
    return names, f"{PYPI_URL} (last_update {doc.get('last_update')})"


def write(eco: str, names: list[str], source: str) -> None:
    seen, ordered = set(), []
    for n in names:
        if n and n not in seen:
            seen.add(n)
            ordered.append(n)
    if len(ordered) < 1000:
        raise SystemExit(f"{eco}: only {len(ordered)} names — refusing to overwrite with a truncated list")
    header = (
        f"# Established {eco} package names, most popular first. Generated; do not edit by hand.\n"
        f"# Regenerate: python scripts/refresh_established_packages.py\n"
        f"# Source: {source}\n"
        f"# Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d')}  count: {len(ordered)}\n"
    )
    path = OUT / f"established_{eco}.txt"
    path.write_text(header + "\n".join(ordered) + "\n", encoding="utf-8")
    print(f"{path}: {len(ordered)} names")


def main() -> int:
    for eco, fn in (("npm", npm_names), ("pypi", pypi_names)):
        names, source = fn()
        write(eco, names, source)
    return 0


if __name__ == "__main__":
    sys.exit(main())
