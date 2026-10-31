"""Established packages and registry-enforced same-owner evidence."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from slopwatch.assessor.scorer import ProgressiveThreatEvaluator
from slopwatch.core.dto import ASTSecurityReport, Ecosystem, PackageMetadata, ThreatVerdict, WatchlistCandidate
from slopwatch.core.established import (
    established_identity,
    established_scope,
    established_siblings,
    is_established,
    publisher_accounts,
)


def test_bundled_lists_load():
    assert is_established("npm", "react")
    assert is_established(Ecosystem.PYPI, "Requests")
    assert is_established("pypi", "typing_extensions")  # PEP 503 normalisation
    assert not is_established("npm", "openai-node-sdk-helper-xyz")


def test_scope_ownership():
    assert established_scope("npm", "@playwright/browser-firefox") == "@playwright"
    assert established_scope("npm", "@nobody-owns-this-scope-xyz/pkg") is None
    assert established_scope("pypi", "@playwright/x") is None


def test_siblings_prefer_exact_token():
    sibs = established_siblings("npm", "playwright-firefox")
    assert sibs and sibs[0] == "playwright"
    assert established_siblings("npm", "abc-thing") == []  # token too short


def test_publisher_accounts_parsing():
    assert publisher_accounts(["Alice <a@x.com>", "bob", ""]) == {"alice", "bob"}


@pytest.mark.asyncio
async def test_publisher_overlap_requires_shared_npm_account():
    adapter = MagicMock()
    adapter.inspect_package_metadata = AsyncMock(return_value=PackageMetadata(
        ecosystem=Ecosystem.NPM, package_name="playwright", latest_version="1.0.0",
        maintainers=["microsoft-bot <x@microsoft.com>"],
    ))
    mine = PackageMetadata(ecosystem=Ecosystem.NPM, package_name="playwright-firefox", latest_version="1.0.0",
                           maintainers=["microsoft-bot <x@microsoft.com>"])
    other = PackageMetadata(ecosystem=Ecosystem.NPM, package_name="playwright-firefox-stealer", latest_version="1.0.0",
                            maintainers=["mallory <m@evil.io>"])
    assert await established_identity(adapter, Ecosystem.NPM, "playwright-firefox", mine) == ("publisher", "playwright")
    assert await established_identity(adapter, Ecosystem.NPM, "playwright-firefox-stealer", other) is None


async def _evaluate(meta, ast, entity):
    candidate = WatchlistCandidate(
        ecosystem=meta.ecosystem, normalized_name=meta.package_name,
        entity_token=entity, capability_token="sdk", framework_token="node", risk_weight=50,
    )
    adapter = MagicMock()
    adapter.inspect_package_metadata = AsyncMock(return_value=meta)
    adapter.download_and_inspect_payload = AsyncMock(return_value=ast)
    with patch("slopwatch.adapters.get_adapter", return_value=adapter):
        return await ProgressiveThreatEvaluator().evaluate_candidate(candidate)


@pytest.mark.asyncio
async def test_established_scope_stub_is_not_a_squat():
    meta = PackageMetadata(ecosystem=Ecosystem.NPM, package_name="@playwright/browser-firefox",
                           latest_version="1.0.0", monthly_downloads=0)
    ast = ASTSecurityReport(total_source_files=1, total_lines_of_code=10, is_empty_stub=False,
                            flags=["LIFECYCLE_SCRIPT: 'install' -> 'node install.js'"])
    det = await _evaluate(meta, ast, "playwright")
    assert det.verdict not in (ThreatVerdict.SQUATTED_STUB, ThreatVerdict.SUSPICIOUS, ThreatVerdict.MALICIOUS)
    assert any(s["signal_id"] == "SIGNAL_ESTABLISHED_IDENTITY" for s in det.analysis_details["signals"])


@pytest.mark.asyncio
async def test_malware_in_established_scope_is_still_a_takeover():
    meta = PackageMetadata(ecosystem=Ecosystem.NPM, package_name="@playwright/browser-firefox",
                           latest_version="1.0.0", monthly_downloads=0)
    ast = ASTSecurityReport(
        total_source_files=2, total_lines_of_code=60, has_credential_harvesting=True,
        flags=[
            "INSTALL_TIME_NETWORK_SOCKET: 'postinstall' script runs package/x.js, which makes network calls",
            "SOURCE_CODE_CONFIRMED_STEALER: potential exfiltration endpoint combined with credential harvesting in x.js",
        ],
    )
    det = await _evaluate(meta, ast, "playwright")
    assert det.verdict == ThreatVerdict.MALICIOUS
