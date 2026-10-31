"""
Plugin detector: maintainer email on an unregistered domain (account-takeover exposure).

Registries reset passwords by email. When a maintainer's email domain lapses, anyone who
registers it receives the reset mail and owns the package — how `ctx` (PyPI, 2022) and
other established packages were hijacked. GuardDog checks for this; slopwatch did not.

Only packages with something worth taking over are checked (established, or real usage /
history), since a lapsed domain on a week-old package is not an attack path. The registered
domain is resolved with a DNS-over-HTTPS NS query; only an authoritative NXDOMAIN counts.
Any other answer, or a network failure, is "unknown" and emits nothing.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Dict, List, Optional

import aiohttp

from slopwatch.core.signals import Finding
from slopwatch.detectors.base import Detector, PackageContext, Stage, register_detector

_DOH = "https://cloudflare-dns.com/dns-query"
_TIMEOUT = aiohttp.ClientTimeout(total=5.0)
_MAX_DOMAINS = 5
_SECOND_LEVEL = {"co", "com", "net", "org", "ac", "gov", "edu", "or", "ne", "go"}
_cache: Dict[str, Optional[bool]] = {}


def registered_domain(domain: str) -> Optional[str]:
    """``mail.example.co.uk`` -> ``example.co.uk``; ``dev.acme.io`` -> ``acme.io`` (approximate eTLD+1)."""
    labels = [l for l in domain.strip(".").lower().split(".") if l]
    if len(labels) < 2:
        return None
    if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in _SECOND_LEVEL:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


async def _domain_exists(session: aiohttp.ClientSession, domain: str) -> Optional[bool]:
    """True = resolves, False = NXDOMAIN, None = unknown."""
    if domain in _cache:
        return _cache[domain]
    result: Optional[bool] = None
    try:
        async with session.get(
            _DOH, params={"name": domain, "type": "NS"},
            headers={"accept": "application/dns-json"}, timeout=_TIMEOUT,
        ) as resp:
            if resp.status == 200:
                status = (await resp.json(content_type=None)).get("Status")
                result = True if status == 0 else False if status == 3 else None
    except Exception:
        result = None
    if result is not None:
        _cache[domain] = result
    return result


def _worth_taking_over(ctx: PackageContext) -> bool:
    from slopwatch.core.established import is_established

    meta = ctx.metadata
    if is_established(ctx.ecosystem, ctx.package_name):
        return True
    if (meta.monthly_downloads or 0) >= 1000:
        return True
    first = meta.first_published_at
    if first is not None and first.tzinfo is None:
        first = first.replace(tzinfo=timezone.utc)
    return bool(first and (datetime.now(timezone.utc) - first).days >= 365 and (meta.release_count or 0) >= 5)


def _maintainer_domains(meta) -> List[str]:
    from slopwatch.core.taxonomies import DISPOSABLE_EMAIL_DOMAINS, PUBLIC_EMAIL_PROVIDERS

    skip = {d.lower() for d in (*PUBLIC_EMAIL_PROVIDERS, *DISPOSABLE_EMAIL_DOMAINS)}
    emails = [meta.author_email or ""]
    emails += [m.split("<", 1)[1].rstrip(">") for m in (meta.maintainers or []) if "<" in m]
    out: List[str] = []
    for e in emails:
        if "@" not in e:
            continue
        reg = registered_domain(e.rsplit("@", 1)[1])
        if reg and reg not in skip and reg not in out:
            out.append(reg)
    return out[:_MAX_DOMAINS]


@register_detector
class MaintainerDomainDetector(Detector):
    name = "maintainer_domain"
    version = "1"
    stage = Stage.METADATA
    applies_to = frozenset({"npm", "pypi"})

    async def analyze(self, ctx: PackageContext) -> List[Finding]:
        meta = ctx.metadata
        if meta is None or not _worth_taking_over(ctx):
            return []
        domains = _maintainer_domains(meta)
        if not domains:
            return []
        async with aiohttp.ClientSession() as session:
            dead = [d for d in domains if await _domain_exists(session, d) is False]
        if not dead:
            return []
        return [Finding.from_spec(
            "MAINTAINER_EMAIL_DOMAIN_UNREGISTERED",
            detector=self.name,
            description=(
                f"Maintainer email domain(s) {', '.join(dead)} do not exist; whoever registers them can "
                f"reset the publishing account's password."
            ),
            locations=[f"maintainer email -> @{d}" for d in dead],
            metadata={"unregistered_domains": dead},
        )]
