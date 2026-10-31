"""Repository-claim impersonation (starjacking) detector."""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from slopwatch.assessor.scorer import ProgressiveThreatEvaluator
from slopwatch.core.dto import ASTSecurityReport, Ecosystem, PackageMetadata, WatchlistCandidate
from slopwatch.detectors.base import PackageContext
from slopwatch.detectors import repo_claim
from slopwatch.detectors.repo_claim import RepoClaimDetector


def _ctx(eco, name, repo, entity="openai", **meta_kw):
    meta = PackageMetadata(ecosystem=eco, package_name=name, latest_version="1", declared_repository=repo, **meta_kw)
    cand = WatchlistCandidate(ecosystem=eco, normalized_name=name, entity_token=entity,
                              capability_token="x", framework_token="y", risk_weight=1)
    return PackageContext(ecosystem=eco, package_name=name, candidate=cand, metadata=meta)


def _fake_fetch(responses):
    async def fetch(session, url):
        for frag, resp in responses.items():
            if url.endswith(frag):
                return resp
        return 404, ""
    return fetch


@pytest.mark.asyncio
async def test_mismatch_npm():
    fetch = _fake_fetch({"package.json": (200, json.dumps({"name": "openai"}))})
    with patch.object(repo_claim, "_fetch", fetch):
        out = await RepoClaimDetector().analyze(_ctx(Ecosystem.NPM, "openai-helper-x", "github.com/openai/openai-node"))
    assert [f.code for f in out] == ["REPO_CLAIM_MISMATCH"]
    assert out[0].metadata["revokes_repo_trust"] is True


@pytest.mark.asyncio
async def test_monorepo_root_is_inconclusive():
    fetch = _fake_fetch({"package.json": (200, json.dumps({"name": "root", "private": True}))})
    with patch.object(repo_claim, "_fetch", fetch):
        assert await RepoClaimDetector().analyze(_ctx(Ecosystem.NPM, "openai-x", "github.com/openai/openai-node")) == []


@pytest.mark.asyncio
async def test_matching_pypi_name_with_normalisation():
    fetch = _fake_fetch({"pyproject.toml": (200, '[project]\nname = "Openai_Helper"\n')})
    with patch.object(repo_claim, "_fetch", fetch):
        assert await RepoClaimDetector().analyze(_ctx(Ecosystem.PYPI, "openai-helper", "github.com/openai/x")) == []


@pytest.mark.asyncio
async def test_nonexistent_repo():
    fetch = _fake_fetch({})  # every manifest and the repo page 404
    with patch.object(repo_claim, "_fetch", fetch):
        out = await RepoClaimDetector().analyze(_ctx(Ecosystem.NPM, "openai-x", "github.com/openai/nope"))
    assert [f.code for f in out] == ["REPO_CLAIM_NONEXISTENT"]


@pytest.mark.asyncio
async def test_network_error_is_inconclusive():
    with patch.object(repo_claim, "_fetch", AsyncMock(return_value=(0, ""))):
        assert await RepoClaimDetector().analyze(_ctx(Ecosystem.NPM, "openai-x", "github.com/openai/x")) == []


@pytest.mark.asyncio
async def test_unrelated_org_and_provenance_confirmed_repo_are_skipped():
    fetch = AsyncMock(side_effect=AssertionError("must not fetch"))
    with patch.object(repo_claim, "_fetch", fetch):
        assert await RepoClaimDetector().analyze(_ctx(Ecosystem.NPM, "foo-x", "github.com/someone/foo")) == []
        assert await RepoClaimDetector().analyze(_ctx(
            Ecosystem.NPM, "openai-x", "github.com/openai/x", provenance_repository="github.com/openai/x")) == []


@pytest.mark.asyncio
async def test_scorer_withdraws_repo_based_vendor_trust():
    meta = PackageMetadata(
        ecosystem=Ecosystem.NPM, package_name="openai-agents-helper-x", latest_version="1.0.0",
        author="someone", author_email="someone@gmail.com", monthly_downloads=60,
        homepage="https://github.com/openai/openai-node", declared_repository="github.com/openai/openai-node",
    )
    cand = WatchlistCandidate(ecosystem=Ecosystem.NPM, normalized_name=meta.package_name, entity_token="openai",
                              capability_token="agents", framework_token="node", risk_weight=50)
    adapter = MagicMock()
    adapter.inspect_package_metadata = AsyncMock(return_value=meta)
    adapter.download_and_inspect_payload = AsyncMock(
        return_value=ASTSecurityReport(total_source_files=2, total_lines_of_code=60))
    fetch = _fake_fetch({"package.json": (200, json.dumps({"name": "openai"}))})
    with patch("slopwatch.adapters.get_adapter", return_value=adapter), patch.object(repo_claim, "_fetch", fetch):
        det = await ProgressiveThreatEvaluator().evaluate_candidate(cand)
    ids = {s["signal_id"] for s in det.analysis_details["signals"]}
    assert "REPO_CLAIM_MISMATCH" in ids
    assert "SIGNAL_TRUSTED_VENDOR_DISCOUNT" not in ids
    assert det.verdict.value != "VERIFIED_OFFICIAL"
