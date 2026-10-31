"""Maintainer email domains that anyone could register (account-takeover exposure)."""

from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest

from slopwatch.core.dto import Ecosystem, PackageMetadata
from slopwatch.detectors import maintainer_domain
from slopwatch.detectors.base import PackageContext
from slopwatch.detectors.maintainer_domain import MaintainerDomainDetector, registered_domain


@pytest.mark.parametrize("raw,expected", [
    ("mail.example.co.uk", "example.co.uk"),
    ("dev.acme.io", "acme.io"),
    ("acme.io", "acme.io"),
    ("localhost", None),
])
def test_registered_domain(raw, expected):
    assert registered_domain(raw) == expected


def _ctx(name="some-lib", downloads=5000, **kw):
    meta = PackageMetadata(ecosystem=Ecosystem.NPM, package_name=name, latest_version="1",
                           monthly_downloads=downloads, **kw)
    return PackageContext(ecosystem=Ecosystem.NPM, package_name=name, metadata=meta)


def _resolver(dead):
    async def exists(session, domain):
        return domain not in dead
    return exists


@pytest.mark.asyncio
async def test_flags_lapsed_maintainer_domain_and_skips_webmail():
    ctx = _ctx(author_email="a@gmail.com", maintainers=["bob <bob@lapsed-co.dev>", "carol <c@live-co.dev>"])
    with patch.object(maintainer_domain, "_domain_exists", _resolver({"lapsed-co.dev"})):
        out = await MaintainerDomainDetector().analyze(ctx)
    assert [f.code for f in out] == ["MAINTAINER_EMAIL_DOMAIN_UNREGISTERED"]
    assert out[0].metadata["unregistered_domains"] == ["lapsed-co.dev"]


@pytest.mark.asyncio
async def test_unknown_resolution_is_not_a_finding():
    async def unknown(session, domain):
        return None
    with patch.object(maintainer_domain, "_domain_exists", unknown):
        assert await MaintainerDomainDetector().analyze(_ctx(author_email="a@whatever.dev")) == []


@pytest.mark.asyncio
async def test_new_unused_packages_are_not_checked():
    async def boom(session, domain):
        raise AssertionError("must not resolve")
    new = _ctx(downloads=3, author_email="a@lapsed.dev", first_published_at=datetime.now(timezone.utc) - timedelta(days=3))
    with patch.object(maintainer_domain, "_domain_exists", boom):
        assert await MaintainerDomainDetector().analyze(new) == []
