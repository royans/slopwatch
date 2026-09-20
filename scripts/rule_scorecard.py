#!/usr/bin/env python3
"""Per-rule false-positive scorecard over a corpus of known-good packages.

Scans every .py/.js/.mjs/.cjs/.ts file under one or more roots (default: this
interpreter's site-packages) with the compiled YARA suites + composite heuristics and
reports, per rule label: files hit, distinct packages hit, and an example path.

Compare against a local baseline (data/benign_rule_baseline.json; corpus-specific, so not committed) so a rule change that starts firing on benign
code fails loudly:

    python scripts/rule_scorecard.py                       # report only
    python scripts/rule_scorecard.py --check               # exit 1 on new / grown rule hits
    python scripts/rule_scorecard.py --update-baseline     # accept the current numbers
    python scripts/rule_scorecard.py /path/to/node_modules /path/to/site-packages --json out.json

Point it at a bigger corpus (top-N PyPI / npm downloads unpacked into a directory) for
the weekly run; the default site-packages scan is the cheap smoke version.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

from slopwatch.assessor.yara_engine import get_yara_scanner

EXTS = {".py", ".js", ".mjs", ".cjs", ".ts"}
MAX_BYTES = 2_000_000
DEFAULT_BASELINE = Path(__file__).resolve().parent.parent / "data" / "benign_rule_baseline.json"


def package_of(path: Path, root: Path) -> str:
    parts = path.relative_to(root).parts
    if "node_modules" in parts:
        i = len(parts) - 1 - parts[::-1].index("node_modules")
        nxt = parts[i + 1:i + 3]
        return "/".join(nxt[:2]) if nxt and nxt[0].startswith("@") else (nxt[0] if nxt else parts[0])
    return parts[0].split("-")[0]


def scan(roots: list[Path]) -> dict:
    scanner = get_yara_scanner()
    files_hit: dict[str, int] = defaultdict(int)
    pkgs_hit: dict[str, set] = defaultdict(set)
    example: dict[str, str] = {}
    n_files = 0
    pkgs_seen: set = set()
    for root in roots:
        for f in root.rglob("*"):
            if f.suffix not in EXTS or not f.is_file():
                continue
            try:
                if f.stat().st_size > MAX_BYTES:
                    continue
                text = f.read_text(errors="ignore")
            except OSError:
                continue
            n_files += 1
            pkg = package_of(f, root)
            pkgs_seen.add(pkg)
            flags, _ = scanner.scan_file_content(text, str(f.relative_to(root)))
            for key, _rendered in flags:
                files_hit[key] += 1
                pkgs_hit[key].add(pkg)
                example.setdefault(key, f"{pkg}: {f.relative_to(root)}")
    return {
        "files_scanned": n_files,
        "packages_scanned": len(pkgs_seen),
        "rules": {
            k: {"files": files_hit[k], "packages": len(pkgs_hit[k]), "example": example[k]}
            for k in sorted(files_hit, key=lambda k: -len(pkgs_hit[k]))
        },
    }


def compare(current: dict, baseline: dict, tolerance: float) -> list[str]:
    problems = []
    for key, cur in current["rules"].items():
        base = baseline.get("rules", {}).get(key)
        if base is None:
            problems.append(f"NEW  {key}: now fires on {cur['packages']} benign package(s), e.g. {cur['example']}")
        elif cur["packages"] > base["packages"] * (1 + tolerance) + 1:
            problems.append(f"GREW {key}: {base['packages']} -> {cur['packages']} benign packages, e.g. {cur['example']}")
    return problems


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("roots", nargs="*", type=Path, help="directories of unpacked known-good packages")
    ap.add_argument("--baseline", type=Path, default=DEFAULT_BASELINE)
    ap.add_argument("--check", action="store_true", help="exit 1 if any rule fires on more benign packages than the baseline")
    ap.add_argument("--update-baseline", action="store_true")
    ap.add_argument("--tolerance", type=float, default=0.10, help="allowed relative growth in benign packages hit (default 10%%)")
    ap.add_argument("--json", type=Path, help="also write the full result here")
    args = ap.parse_args()

    roots = args.roots or [Path(sys.prefix) / "lib" / f"python{sys.version_info.major}.{sys.version_info.minor}" / "site-packages"]
    result = scan([r.resolve() for r in roots])

    print(f"scanned {result['files_scanned']} files / {result['packages_scanned']} packages")
    for key, r in result["rules"].items():
        print(f"{r['packages']:5d} pkgs {r['files']:6d} files  {key}   e.g. {r['example']}")
    if args.json:
        args.json.write_text(json.dumps(result, indent=2))

    if args.update_baseline:
        args.baseline.parent.mkdir(parents=True, exist_ok=True)
        args.baseline.write_text(json.dumps(result, indent=2) + "\n")
        print(f"baseline written: {args.baseline}")
        return 0
    if args.check:
        if not args.baseline.exists():
            print(f"no baseline at {args.baseline}; run with --update-baseline", file=sys.stderr)
            return 2
        problems = compare(result, json.loads(args.baseline.read_text()), args.tolerance)
        for p in problems:
            print(p, file=sys.stderr)
        return 1 if problems else 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
