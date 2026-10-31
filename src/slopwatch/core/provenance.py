"""
Build provenance: which source repository a release was actually built from.

Provenance is a statement signed in CI ("this artifact was built by workflow W in
repository R"). It proves *where the code came from*, not that the publisher is who
the package name suggests: anyone can publish with provenance from their own repo.
So it only vouches for a brand when the attested repository belongs to that brand's
organisation.

What counts as provenance:
  * npm  — ``dist.attestations`` (SLSA provenance via Sigstore). NOT ``dist.signatures``:
           the registry signs every tarball it serves, so that field is on every package.
  * PyPI — the Integrity API (``/integrity/<name>/<version>/<file>/provenance``). The JSON
           API carries no provenance field at all.
"""

from __future__ import annotations

import base64
import json
import re
from typing import Any, Dict, Iterable, Optional, Tuple

import aiohttp

_REPO_URL_RE = re.compile(
    r"(?:^|[/@:])(github\.com|gitlab\.com)[/:]([\w.-]+)/([\w.-]+?)(?:\.git)?(?:[/#?@]|$)",
    re.IGNORECASE,
)
_NPM_SHORTHAND_RE = re.compile(r"^(?:(github|gitlab):)?([\w.-]+)/([\w.-]+?)(?:\.git)?$", re.IGNORECASE)

PYPI_INTEGRITY_ACCEPT = "application/vnd.pypi.integrity.v1+json"


def normalize_repo(url: Any) -> Optional[str]:
    """``git+https://github.com/Microsoft/playwright.git`` -> ``github.com/microsoft/playwright``.

    Also accepts npm's shorthand forms (``owner/repo``, ``github:owner/repo``) and a
    package.json ``repository`` object. Returns None for anything not on GitHub/GitLab.
    """
    if isinstance(url, dict):
        url = url.get("url")
    if not isinstance(url, str) or not url.strip():
        return None
    url = url.strip()
    m = _REPO_URL_RE.search(url)
    if m:
        host, owner, repo = m.group(1), m.group(2), m.group(3)
        return f"{host.lower()}/{owner.lower()}/{repo.lower()}"
    m = _NPM_SHORTHAND_RE.match(url)
    if m and "://" not in url:
        host = f"{(m.group(1) or 'github').lower()}.com"
        return f"{host}/{m.group(2).lower()}/{m.group(3).lower()}"
    return None


def repo_owner(repo: Optional[str]) -> Optional[str]:
    """``github.com/microsoft/playwright`` -> ``github.com/microsoft``."""
    if not repo or repo.count("/") < 2:
        return None
    return repo.rsplit("/", 1)[0]


def first_repo(urls: Iterable[Any]) -> Optional[str]:
    """First GitHub/GitLab repository among candidate URLs."""
    for u in urls:
        r = normalize_repo(u)
        if r:
            return r
    return None


def declared_pypi_repo(project_urls: Optional[Dict[str, str]], homepage: Optional[str]) -> Optional[str]:
    """The source repository a PyPI project claims, preferring explicit source-ish labels."""
    project_urls = project_urls or {}
    preferred = [v for k, v in project_urls.items() if re.search(r"source|repo|code|github|gitlab", k, re.I)]
    return first_repo([*preferred, *project_urls.values(), homepage])


def repo_in_orgs(repo: Optional[str], orgs: Iterable[str]) -> bool:
    """True if ``repo``'s owner is one of ``orgs`` (``github.com/<org>`` strings)."""
    owner = repo_owner(repo)
    if not owner:
        return False
    return any(owner == o.lower().rstrip("/") for o in orgs)


def _npm_repo_from_statement(statement: Dict[str, Any]) -> Optional[str]:
    pred = statement.get("predicate") or {}
    # SLSA v1
    wf = ((pred.get("buildDefinition") or {}).get("externalParameters") or {}).get("workflow") or {}
    if wf.get("repository"):
        return normalize_repo(wf["repository"])
    # SLSA v0.2
    uri = ((pred.get("invocation") or {}).get("configSource") or {}).get("uri")
    return normalize_repo(uri) if uri else None


def npm_repo_from_attestations(doc: Dict[str, Any]) -> Optional[str]:
    """Source repository named by the SLSA provenance in an npm attestations document."""
    for att in doc.get("attestations") or []:
        if "slsa.dev/provenance" not in str(att.get("predicateType", "")):
            continue
        env = ((att.get("bundle") or {}).get("dsseEnvelope") or {})
        try:
            statement = json.loads(base64.b64decode(env.get("payload") or ""))
        except (ValueError, TypeError):
            continue
        repo = _npm_repo_from_statement(statement)
        if repo:
            return repo
    return None


def pypi_repo_from_provenance(doc: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
    """(has_provenance, repository) from a PyPI Integrity API provenance document."""
    bundles = doc.get("attestation_bundles") or []
    if not bundles:
        return False, None
    for b in bundles:
        pub = b.get("publisher") or {}
        kind = str(pub.get("kind", "")).lower()
        repo = pub.get("repository")
        if repo and kind in ("github", "gitlab"):
            return True, f"{kind}.com/{str(repo).lower()}"
    # Google / ActiveState trusted publishers attest provenance without a repository.
    return True, None


async def fetch_npm_provenance_repo(session: aiohttp.ClientSession, attestations_url: str) -> Optional[str]:
    try:
        async with session.get(attestations_url, timeout=aiohttp.ClientTimeout(total=8.0)) as resp:
            if resp.status != 200:
                return None
            return npm_repo_from_attestations(await resp.json(content_type=None))
    except Exception:
        return None


async def fetch_pypi_provenance(
    session: aiohttp.ClientSession, name: str, version: str, filename: str
) -> Tuple[bool, Optional[str]]:
    url = f"https://pypi.org/integrity/{name}/{version}/{filename}/provenance"
    try:
        async with session.get(
            url, headers={"Accept": PYPI_INTEGRITY_ACCEPT}, timeout=aiohttp.ClientTimeout(total=8.0)
        ) as resp:
            if resp.status != 200:
                return False, None
            return pypi_repo_from_provenance(await resp.json(content_type=None))
    except Exception:
        return False, None
