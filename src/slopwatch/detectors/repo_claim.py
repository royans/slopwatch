"""
Plugin detector: repository-claim impersonation (starjacking).

A package's `repository` / project URLs are self-declared. Pointing them at a vendor's
repository borrows that vendor's stars and credibility — and, before this detector, also
earned slopwatch's trusted-vendor discount. This checks the claim against the repository
itself: the root manifest (package.json / pyproject.toml / setup.cfg / setup.py) at HEAD
must name this package, or the repository must be a monorepo.

Only claims that would matter are checked — repositories under a known vendor organisation,
the high-profile repos, or an org named exactly like the brand being claimed — so the cost is
one or two raw.githubusercontent.com fetches (not the rate-limited REST API) for those.

Outcomes: REPO_CLAIM_MISMATCH (the repo is some other package's), REPO_CLAIM_NONEXISTENT
(no such repo). Both carry ``revokes_repo_trust`` so the scorer withdraws any vendor trust
that rested on the claimed URL. Inconclusive cases (monorepo, unreadable manifest, network
error) emit nothing.
"""

from __future__ import annotations

import json
import re
from typing import List, Optional, Set

import aiohttp

from slopwatch.core.signals import Finding
from slopwatch.detectors.base import Detector, PackageContext, Stage, register_detector

_RAW = "https://raw.githubusercontent.com/{owner}/{repo}/HEAD/{path}"
_TIMEOUT = aiohttp.ClientTimeout(total=6.0)
_SETUP_PY_NAME = re.compile(r"""\bname\s*=\s*['"]([A-Za-z0-9_.\-@/]+)['"]""")
_PY_WORKSPACE = re.compile(r"^\[tool\.(?:uv\.workspace|hatch\.envs|pdm\.workspace|poetry\.packages)", re.M)


def _vendor_orgs() -> Set[str]:
    from slopwatch.assessor.scorer import OFFICIAL_VENDOR_ORGS, TRUSTED_VENDORS

    orgs = {o.lower() for v in OFFICIAL_VENDOR_ORGS.values() for o in v}
    orgs |= {o.lower() for v in TRUSTED_VENDORS.values() for o in v.get("github_orgs", [])}
    return orgs


def _high_profile_repos() -> Set[str]:
    from slopwatch.assessor.scorer import HIGH_PROFILE_OFFICIAL_REPOS

    return {f"github.com/{r.lower()}" for r in HIGH_PROFILE_OFFICIAL_REPOS}


def _norm(eco: str, name: str) -> str:
    name = name.strip().lower()
    return re.sub(r"[-_.]+", "-", name) if eco == "pypi" else name


def _pypi_manifest_name(path: str, text: str) -> Optional[str]:
    if path == "pyproject.toml":
        if _PY_WORKSPACE.search(text):
            return None
        try:
            import tomllib

            doc = tomllib.loads(text)
        except Exception:
            return None
        return (doc.get("project") or {}).get("name") or ((doc.get("tool") or {}).get("poetry") or {}).get("name")
    if path == "setup.cfg":
        m = re.search(r"^\[metadata\][^\[]*?^name\s*=\s*(\S+)", text, re.M | re.S)
        return m.group(1) if m else None
    m = _SETUP_PY_NAME.search(text)
    return m.group(1) if m else None


async def _fetch(session: aiohttp.ClientSession, url: str) -> tuple[int, str]:
    try:
        async with session.get(url, timeout=_TIMEOUT) as resp:
            return resp.status, (await resp.text()) if resp.status == 200 else ""
    except Exception:
        return 0, ""


@register_detector
class RepoClaimDetector(Detector):
    name = "repo_claim"
    version = "1"
    stage = Stage.METADATA
    applies_to = frozenset({"npm", "pypi"})

    def _worth_checking(self, ctx: PackageContext, repo: str) -> bool:
        owner = repo.rsplit("/", 1)[0]
        if owner in _vendor_orgs() or repo in _high_profile_repos():
            return True
        entity = (ctx.candidate.entity_token if ctx.candidate else "") or ""
        return bool(entity) and owner == f"github.com/{entity.lower()}"

    async def analyze(self, ctx: PackageContext) -> List[Finding]:
        meta = ctx.metadata
        if meta is None:
            return []
        from slopwatch.core.established import established_scope, is_established
        from slopwatch.core.provenance import first_repo

        eco = ctx.ecosystem.value
        repo = getattr(meta, "declared_repository", None) or first_repo(
            [meta.homepage, *(meta.project_urls or {}).values()]
        )
        if not repo or not repo.startswith("github.com/"):
            return []
        if repo == getattr(meta, "provenance_repository", None):
            return []  # the signed build provenance already confirms this repository
        if is_established(eco, ctx.package_name) or established_scope(eco, ctx.package_name):
            return []
        if not self._worth_checking(ctx, repo):
            return []

        _, owner, name = repo.split("/", 2)
        paths = ["package.json"] if eco == "npm" else ["pyproject.toml", "setup.cfg", "setup.py"]
        async with aiohttp.ClientSession(headers={"User-Agent": "slopwatch"}) as session:
            declared: Optional[str] = None
            any_found = False
            for path in paths:
                status, text = await _fetch(session, _RAW.format(owner=owner, repo=name, path=path))
                if status == 0:
                    return []  # network trouble: inconclusive
                if status != 200:
                    continue
                any_found = True
                if eco == "npm":
                    try:
                        pj = json.loads(text)
                    except ValueError:
                        return []
                    if pj.get("private") or pj.get("workspaces"):
                        return []  # monorepo root: published packages live in subdirectories
                    declared = pj.get("name")
                else:
                    declared = _pypi_manifest_name(path, text)
                if declared:
                    break

            if not any_found:
                status, _ = await _fetch(session, f"https://github.com/{owner}/{name}")
                if status != 404:
                    return []
                return [Finding.from_spec(
                    "REPO_CLAIM_NONEXISTENT",
                    detector=self.name,
                    description=f"Links to {repo}, which does not exist.",
                    locations=[f"metadata -> {repo}"],
                    metadata={"claimed_repository": repo, "revokes_repo_trust": True},
                )]

        if not declared or _norm(eco, declared) == _norm(eco, ctx.package_name):
            return []
        return [Finding.from_spec(
            "REPO_CLAIM_MISMATCH",
            detector=self.name,
            description=f"Links to {repo}, but that repository publishes '{declared}', not '{ctx.package_name}'.",
            locations=[f"metadata -> {repo}"],
            metadata={"claimed_repository": repo, "repository_package": declared, "revokes_repo_trust": True},
        )]
