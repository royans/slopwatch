"""Build provenance: real attestation parsing, and trust only when the build repo is the brand's."""

import base64
import json
from unittest.mock import AsyncMock, patch

import pytest

from slopwatch.assessor.scorer import ProgressiveThreatEvaluator, provenance_repo_matches_identity
from slopwatch.core.dto import ASTSecurityReport, Ecosystem, PackageMetadata, WatchlistCandidate
from slopwatch.core.provenance import (
    declared_pypi_repo,
    normalize_repo,
    npm_repo_from_attestations,
    pypi_repo_from_provenance,
)


@pytest.mark.parametrize("raw,expected", [
    ("git+https://github.com/Microsoft/playwright.git", "github.com/microsoft/playwright"),
    ({"type": "git", "url": "git+ssh://git@github.com/openai/openai-node.git"}, "github.com/openai/openai-node"),
    ("github:vercel/next.js", "github.com/vercel/next.js"),
    ("stevemao/left-pad", "github.com/stevemao/left-pad"),
    ("https://gitlab.com/group/proj/-/tree/main", "gitlab.com/group/proj"),
    ("https://example.com/foo", None),
    (None, None),
])
def test_normalize_repo(raw, expected):
    assert normalize_repo(raw) == expected


def _npm_attestations(repo_url, slsa_v1=True):
    pred = (
        {"buildDefinition": {"externalParameters": {"workflow": {"repository": repo_url}}}}
        if slsa_v1 else {"invocation": {"configSource": {"uri": f"git+{repo_url}@refs/tags/v1"}}}
    )
    payload = base64.b64encode(json.dumps({"predicate": pred}).encode()).decode()
    return {"attestations": [
        {"predicateType": "https://github.com/npm/attestation/tree/main/specs/publish/v0.1",
         "bundle": {"dsseEnvelope": {"payload": base64.b64encode(b"{}").decode()}}},
        {"predicateType": "https://slsa.dev/provenance/v1" if slsa_v1 else "https://slsa.dev/provenance/v0.2",
         "bundle": {"dsseEnvelope": {"payload": payload}}},
    ]}


def test_npm_attestation_repo_slsa_v1_and_v02():
    assert npm_repo_from_attestations(_npm_attestations("https://github.com/microsoft/playwright")) == "github.com/microsoft/playwright"
    assert npm_repo_from_attestations(_npm_attestations("https://github.com/acme/x", slsa_v1=False)) == "github.com/acme/x"
    assert npm_repo_from_attestations({}) is None


def test_pypi_integrity_publisher():
    doc = {"attestation_bundles": [{"publisher": {"kind": "GitHub", "repository": "urllib3/urllib3"}}]}
    assert pypi_repo_from_provenance(doc) == (True, "github.com/urllib3/urllib3")
    assert pypi_repo_from_provenance({"attestation_bundles": [{"publisher": {"kind": "Google"}}]}) == (True, None)
    assert pypi_repo_from_provenance({}) == (False, None)


def test_declared_pypi_repo_prefers_source_label():
    urls = {"Homepage": "https://github.com/someone/fork", "Source": "https://github.com/psf/requests"}
    assert declared_pypi_repo(urls, None) == "github.com/psf/requests"


def test_provenance_identity_requires_owner_equality_not_prefix():
    assert provenance_repo_matches_identity("github.com/openai/openai-node", "openai")
    assert provenance_repo_matches_identity("github.com/googleapis/js-genai", "google")
    assert not provenance_repo_matches_identity("github.com/openai-tools/openai-node", "openai")
    assert not provenance_repo_matches_identity("github.com/randomdev/thing", "openai")
    assert not provenance_repo_matches_identity(None, "openai")


async def _evaluate(mocker, meta, entity="openai"):
    candidate = WatchlistCandidate(
        ecosystem=meta.ecosystem, normalized_name=meta.package_name,
        entity_token=entity, capability_token="sdk", framework_token="node", risk_weight=50,
    )
    ast = ASTSecurityReport(total_source_files=3, total_lines_of_code=80, composite_threat_score=0)
    adapter = mocker.MagicMock()
    adapter.inspect_package_metadata = AsyncMock(return_value=meta)
    adapter.download_and_inspect_payload = AsyncMock(return_value=ast)
    with patch("slopwatch.adapters.get_adapter", return_value=adapter):
        det = await ProgressiveThreatEvaluator().evaluate_candidate(candidate)
    return det, {s["signal_id"]: s for s in det.analysis_details.get("signals", [])}


@pytest.mark.asyncio
async def test_unaligned_provenance_does_not_make_brand_squat_official(mocker):
    meta = PackageMetadata(
        ecosystem=Ecosystem.NPM, package_name="openai-node-sdk-helper", latest_version="1.0.0",
        author="someone", author_email="someone@gmail.com", monthly_downloads=60,
        has_provenance=True, provenance_type="npm_slsa_sigstore",
        provenance_repository="github.com/someone/openai-node-sdk-helper",
        declared_repository="github.com/someone/openai-node-sdk-helper",
    )
    det, sigs = await _evaluate(mocker, meta)
    assert "SIGNAL_CRYPTOGRAPHIC_PROVENANCE" not in sigs
    assert "SIGNAL_BUILD_PROVENANCE" in sigs
    assert det.verdict.value != "VERIFIED_OFFICIAL"


@pytest.mark.asyncio
async def test_provenance_vs_declared_repo_mismatch_is_flagged(mocker):
    meta = PackageMetadata(
        ecosystem=Ecosystem.NPM, package_name="openai-node-sdk-helper", latest_version="1.0.0",
        author="someone", author_email="someone@gmail.com", monthly_downloads=60,
        homepage="https://github.com/openai/openai-node",
        has_provenance=True, provenance_type="npm_slsa_sigstore",
        provenance_repository="github.com/someone/stuff",
        declared_repository="github.com/openai/openai-node",
    )
    det, sigs = await _evaluate(mocker, meta)
    assert "SIGNAL_PROVENANCE_REPO_MISMATCH" in sigs
    assert det.verdict.value != "VERIFIED_OFFICIAL"


@pytest.mark.asyncio
async def test_brand_owned_provenance_still_trusted(mocker):
    meta = PackageMetadata(
        ecosystem=Ecosystem.NPM, package_name="@openai/agents-helper", latest_version="1.0.0",
        author="openai", monthly_downloads=500,
        has_provenance=True, provenance_type="npm_slsa_sigstore",
        provenance_repository="github.com/openai/agents-helper",
        declared_repository="github.com/openai/agents-helper",
    )
    det, sigs = await _evaluate(mocker, meta)
    assert "SIGNAL_CRYPTOGRAPHIC_PROVENANCE" in sigs
