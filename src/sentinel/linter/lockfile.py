"""
SlopGuard Multi-Ecosystem Lockfile & Dependency Linter.

Audits requirements.txt, pyproject.toml, Pipfile, poetry.lock, package.json,
package-lock.json, yarn.lock, and pnpm-lock.yaml for hallucinated, unregistered,
or actively slopsquatted dependencies.
"""

import asyncio
import json
import re
import tomllib
from pathlib import Path
from typing import List, Dict, Any, Tuple, Optional, Set

import aiohttp

from sentinel.core.dto import Ecosystem
from sentinel.db.repository import SentinelRepository
from sentinel.core.taxonomies import ENTITIES

# Common popular packages to defend against typosquatting
POPULAR_PACKAGES = set(ENTITIES) | {
    "requests", "urllib3", "flask", "django", "fastapi", "numpy", "pandas",
    "scipy", "scikit-learn", "torch", "tensorflow", "pydantic", "pytest",
    "cryptography", "click", "rich", "setuptools", "wheel", "pip", "boto3",
    "express", "react", "vue", "next", "lodash", "axios", "chalk", "commander",
}


def _damerau_levenshtein(s1: str, s2: str) -> int:
    d = {}
    len1, len2 = len(s1), len(s2)
    for i in range(-1, len1 + 1):
        d[(i, -1)] = i + 1
    for j in range(-1, len2 + 1):
        d[(-1, j)] = j + 1
    for i in range(len1):
        for j in range(len2):
            cost = 0 if s1[i] == s2[j] else 1
            d[(i, j)] = min(
                d[(i - 1, j)] + 1,
                d[(i, j - 1)] + 1,
                d[(i - 1, j - 1)] + cost
            )
            if i > 0 and j > 0 and s1[i] == s2[j - 1] and s1[i - 1] == s2[j]:
                d[(i, j)] = min(d[(i, j)], d[(i - 2, j - 2)] + 1)
    return d[(len1 - 1, len2 - 1)]

_levenshtein = _damerau_levenshtein


class DependencyLinter:
    def __init__(
        self,
        repository: Optional[SentinelRepository] = None,
        offline: bool = False,
        session: Optional[aiohttp.ClientSession] = None,
    ):
        self.repository = repository
        self.offline = offline
        self._session = session

    async def audit_file(self, file_path: Path) -> Dict[str, Any]:
        """Audit a dependency lockfile and identify dangerous or hallucinated packages."""
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        filename = path.name.lower()
        if (
            filename.endswith(".txt")
            or filename in ("pipfile", "pipfile.lock", "poetry.lock")
            or filename.endswith(".toml")
        ):
            ecosystem = Ecosystem.PYPI
            dependencies = self._parse_python_dependencies(path)
        elif (
            filename in ("package.json", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml")
            or filename.endswith((".json", ".yaml", ".yml", ".lock"))
        ):
            ecosystem = Ecosystem.NPM
            dependencies = self._parse_npm_dependencies(path)
        else:
            ecosystem = Ecosystem.PYPI
            dependencies = self._parse_python_dependencies(path)

        # Deduplicate dependencies while preserving appearance order
        seen = set()
        unique_deps: List[Tuple[str, str]] = []
        for d, v in dependencies:
            if (d, v) not in seen:
                seen.add((d, v))
                unique_deps.append((d, v))
        dependencies = unique_deps

        registered_set: Set[str] = set()
        watchlist_set: Set[str] = set()
        if self.repository:
            try:
                registered_set = await self.repository.get_registered_names_set(ecosystem)
                watchlist_set = await self.repository.get_watchlist_names_set(ecosystem)
            except Exception:
                pass

        flagged_items = []
        to_verify_online: List[Tuple[str, str, str]] = []

        for raw_dep, version in dependencies:
            norm_dep = self._normalize_dep_name(raw_dep, ecosystem)

            # Check 0: Direct VCS or unpinned URL dependency (bypasses registry audit)
            if version == "VCS_OR_URL":
                flagged_items.append({
                    "package": raw_dep,
                    "normalized": norm_dep,
                    "version": version,
                    "severity": "MEDIUM",
                    "reason": "DIRECT_VCS_OR_RAW_URL_DEPENDENCY",
                    "risk_weight": 50,
                })
                continue

            # Check 1: Active slopsquat watchlist from database
            if norm_dep in watchlist_set:
                candidate = None
                if self.repository:
                    try:
                        candidate = await self.repository.get_candidate_by_name(ecosystem, norm_dep)
                    except Exception:
                        pass
                flagged_items.append({
                    "package": raw_dep,
                    "normalized": norm_dep,
                    "version": version,
                    "severity": "CRITICAL",
                    "reason": "MATCHES_UNREGISTERED_SLOPSQUAT_WATCHLIST",
                    "risk_weight": candidate.risk_weight if candidate else 75,
                })
                continue

            # Check 2: Already verified in local registered catalog
            if registered_set and norm_dep in registered_set:
                continue

            # Check 3: Popular brand typosquat heuristic (offline)
            is_typosquat = False
            if len(norm_dep) >= 4 and norm_dep not in POPULAR_PACKAGES:
                for brand in POPULAR_PACKAGES:
                    if abs(len(norm_dep) - len(brand)) <= 1 and _levenshtein(norm_dep, brand) == 1:
                        flagged_items.append({
                            "package": raw_dep,
                            "normalized": norm_dep,
                            "version": version,
                            "severity": "HIGH",
                            "reason": f"SUSPICIOUS_TYPOSQUAT_OF_{brand.upper().replace('-', '_')}",
                            "risk_weight": 80,
                        })
                        is_typosquat = True
                        break
            if is_typosquat:
                continue

            # If not in local registered set and not offline, queue for online verification
            if not self.offline:
                to_verify_online.append((raw_dep, norm_dep, version))

        # Check 4: Online live registry verification (detect 404 / hallucinated packages)
        if to_verify_online and not self.offline:
            results = await self._verify_upstream_batch(to_verify_online, ecosystem)
            for raw_dep, norm_dep, version, status in results:
                if status == 404:
                    flagged_items.append({
                        "package": raw_dep,
                        "normalized": norm_dep,
                        "version": version,
                        "severity": "HIGH",
                        "reason": "UNREGISTERED_OR_HALLUCINATED_PACKAGE",
                        "risk_weight": 85,
                    })

        return {
            "target_file": str(path),
            "ecosystem": ecosystem.value,
            "total_dependencies": len(dependencies),
            "flagged_count": len(flagged_items),
            "flagged_dependencies": flagged_items,
            "is_clean": len(flagged_items) == 0,
        }

    async def _verify_upstream_batch(
        self,
        items: List[Tuple[str, str, str]],
        ecosystem: Ecosystem,
    ) -> List[Tuple[str, str, str, Optional[int]]]:
        """Verify package existence against public PyPI or npm registry APIs."""
        sem = asyncio.Semaphore(10)
        own_session = False
        session = self._session
        if session is None:
            session = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=4.0))
            own_session = True

        async def check_one(raw: str, norm: str, ver: str):
            async with sem:
                if ecosystem == Ecosystem.PYPI:
                    url = f"https://pypi.org/pypi/{norm}/json"
                else:
                    url = f"https://registry.npmjs.org/{norm}"
                try:
                    async with session.head(url, allow_redirects=True) as resp:
                        return (raw, norm, ver, resp.status)
                except Exception:
                    return (raw, norm, ver, None)

        try:
            tasks = [check_one(raw, norm, ver) for raw, norm, ver in items]
            return await asyncio.gather(*tasks)
        finally:
            if own_session:
                await session.close()

    def _normalize_dep_name(self, name: str, ecosystem: Ecosystem) -> str:
        if ecosystem == Ecosystem.PYPI:
            return re.sub(r"[-_.]+", "-", name).lower()
        return name.strip().lower()

    def _parse_python_dependencies(self, path: Path) -> List[Tuple[str, str]]:
        """Extract package names and versions from requirements.txt, pyproject.toml, Pipfile, or poetry.lock."""
        dependencies: List[Tuple[str, str]] = []
        filename = path.name.lower()
        content = path.read_text(encoding="utf-8", errors="ignore")

        # 1. poetry.lock (TOML format)
        if filename == "poetry.lock":
            try:
                data = tomllib.loads(content)
                for pkg in data.get("package", []):
                    if isinstance(pkg, dict) and "name" in pkg:
                        dependencies.append((pkg["name"], pkg.get("version", "*")))
                return dependencies
            except Exception:
                pass

        # 2. Pipfile.lock (JSON format)
        if filename == "pipfile.lock":
            try:
                data = json.loads(content)
                for section in ("default", "develop"):
                    for pkg_name, info in data.get(section, {}).items():
                        ver = info.get("version", "*") if isinstance(info, dict) else str(info)
                        dependencies.append((pkg_name, ver))
                return dependencies
            except Exception:
                pass

        # 3. pyproject.toml (TOML format)
        if filename.endswith(".toml"):
            try:
                data = tomllib.loads(content)
                proj_deps = data.get("project", {}).get("dependencies", [])
                if isinstance(proj_deps, list):
                    for line in proj_deps:
                        m = re.match(r"^([a-zA-Z0-9_\-\.]+)(?:[><=\~!^]=?([a-zA-Z0-9_\-\.]+))?", line.strip())
                        if m:
                            dependencies.append((m.group(1), m.group(2) or "*"))

                opt_deps = data.get("project", {}).get("optional-dependencies", {})
                if isinstance(opt_deps, dict):
                    for group_deps in opt_deps.values():
                        if isinstance(group_deps, list):
                            for line in group_deps:
                                m = re.match(r"^([a-zA-Z0-9_\-\.]+)(?:[><=\~!^]=?([a-zA-Z0-9_\-\.]+))?", line.strip())
                                if m:
                                    dependencies.append((m.group(1), m.group(2) or "*"))

                poetry_deps = data.get("tool", {}).get("poetry", {}).get("dependencies", {})
                if isinstance(poetry_deps, dict):
                    for name, ver in poetry_deps.items():
                        if name.lower() != "python":
                            dependencies.append((name, str(ver)))

                if dependencies:
                    return dependencies
            except Exception:
                pass

        # 4. requirements.txt / Pipfile plain text parsing
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue

            if line.startswith("git+") or line.startswith("http://") or line.startswith("https://") or " @ git+" in line or " @ https://" in line:
                pkg_name = line.split("#egg=")[-1] if "#egg=" in line else line.split("@")[0].strip()
                dependencies.append((pkg_name or line[:35], "VCS_OR_URL"))
                continue

            match = re.match(r"^([a-zA-Z0-9_\-\.]+)(?:[><=\~!^]=?([a-zA-Z0-9_\-\.]+))?", line)
            if match:
                pkg_name = match.group(1)
                pkg_ver = match.group(2) or "*"
                dependencies.append((pkg_name, pkg_ver))

        return dependencies

    def _parse_npm_dependencies(self, path: Path) -> List[Tuple[str, str]]:
        """Extract package names from package.json, package-lock.json, yarn.lock, or pnpm-lock.yaml."""
        dependencies: List[Tuple[str, str]] = []
        filename = path.name.lower()
        content = path.read_text(encoding="utf-8", errors="ignore")

        # 1. package.json / package-lock.json (JSON format)
        if filename.endswith(".json"):
            try:
                data = json.loads(content)
            except Exception:
                return dependencies

            deps = data.get("dependencies", {})
            dev_deps = data.get("devDependencies", {})
            if isinstance(deps, dict) and isinstance(dev_deps, dict):
                all_deps = {**deps, **dev_deps}
                for name, ver in all_deps.items():
                    if isinstance(ver, dict):
                        ver = ver.get("version", "*")
                    ver_str = str(ver)
                    if any(ver_str.startswith(pfx) for pfx in ("git+", "http://", "https://", "github:", "file:")):
                        dependencies.append((name, "VCS_OR_URL"))
                    else:
                        dependencies.append((name, ver_str))

            packages = data.get("packages", {})
            if isinstance(packages, dict):
                for key, pinfo in packages.items():
                    if "node_modules/" in key:
                        pkg_name = key.split("node_modules/")[-1]
                        ver = pinfo.get("version", "*") if isinstance(pinfo, dict) else "*"
                        dependencies.append((pkg_name, str(ver)))
            return dependencies

        # 2. yarn.lock (Yarn v1 & Berry lockfile format)
        if filename == "yarn.lock" or filename.endswith(".lock"):
            current_pkg = None
            for line in content.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                header_match = re.match(r"""^['"]?(@?[a-zA-Z0-9_.-]+(?:/[a-zA-Z0-9_.-]+)?)@[^:]*:""", line)
                if header_match:
                    current_pkg = header_match.group(1)
                elif current_pkg and line.startswith("version"):
                    ver_match = re.search(r"""version(?:\s+|:\s+)['"]?([^'"]+)['"]?""", line)
                    ver = ver_match.group(1) if ver_match else "*"
                    dependencies.append((current_pkg, ver))
                    current_pkg = None
            return dependencies

        # 3. pnpm-lock.yaml (YAML format)
        if filename.endswith((".yaml", ".yml")):
            in_dep_section = False
            for line in content.splitlines():
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                if stripped.rstrip(":") in ("dependencies", "devDependencies", "specifiers"):
                    in_dep_section = True
                    continue
                if in_dep_section:
                    if not line.startswith("  "):
                        in_dep_section = False
                        continue
                    if line.startswith("    "):
                        continue
                    m = re.match(r"""^\s+['"]?(@?[a-zA-Z0-9_.-]+(?:/[a-zA-Z0-9_.-]+)?)['"]?:\s*(.*)""", line)
                    if m:
                        pkg_name = m.group(1)
                        ver = m.group(2).strip().strip("'\"") or '*'
                        dependencies.append((pkg_name, ver))
            return dependencies

        return dependencies
