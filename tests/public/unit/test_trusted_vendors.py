"""Unit tests for Trusted Vendors taxonomy, 50% threat score dampening, and hijack detection."""

import pytest
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

from slopwatch.assessor.scorer import ProgressiveThreatEvaluator
from slopwatch.core.dto import (
    WatchlistCandidate,
    ThreatVerdict,
    PackageMetadata,
    ASTSecurityReport,
    Ecosystem,
)
from slopwatch.core.taxonomies import TRUSTED_VENDORS


def test_trusted_vendors_taxonomy_completeness():
    """Ensure essential industry vendors, AI labs, and foundation orgs are registered."""
    assert "google" in TRUSTED_VENDORS
    assert "microsoft" in TRUSTED_VENDORS
    assert "amazon" in TRUSTED_VENDORS
    assert "openai" in TRUSTED_VENDORS
    assert "anthropic" in TRUSTED_VENDORS
    assert "pybind" in TRUSTED_VENDORS
    assert "openjs" in TRUSTED_VENDORS

    # Check structure
    for key, data in TRUSTED_VENDORS.items():
        assert "domains" in data, f"{key} missing domains"
        assert "github_orgs" in data, f"{key} missing github_orgs"
        assert "npm_scopes" in data, f"{key} missing npm_scopes"


def test_identify_trusted_vendor_by_scope():
    evaluator = ProgressiveThreatEvaluator()
    assert evaluator.identify_trusted_vendor("@google-cloud/storage")[0] == "google"
    assert evaluator.identify_trusted_vendor("@types/react")[0] == "microsoft"
    assert evaluator.identify_trusted_vendor("@npm/cli")[0] == "openjs"
    assert evaluator.identify_trusted_vendor("@anthropic-ai/sdk")[0] == "anthropic"
    assert evaluator.identify_trusted_vendor("@aws-sdk/client-s3")[0] == "amazon"
    assert evaluator.identify_trusted_vendor("random-unaffiliated-pkg") is None


def test_identify_trusted_vendor_by_author_email():
    evaluator = ProgressiveThreatEvaluator()
    res = evaluator.identify_trusted_vendor("my-cloud-tool", author_email="dev@google.com")
    assert res is not None
    assert res[0] == "google"
    assert res[1] == "domain:google.com"

    res2 = evaluator.identify_trusted_vendor("claude-helper", author_email="support@anthropic.com")
    assert res2 is not None
    assert res2[0] == "anthropic"
    assert res2[1] == "domain:anthropic.com"

    res3 = evaluator.identify_trusted_vendor("fast-models", author_email="attacker@gmail.com")
    assert res3 is None


def test_identify_trusted_vendor_by_repo_lineage():
    evaluator = ProgressiveThreatEvaluator()
    res = evaluator.identify_trusted_vendor("pybind-util", homepage="https://github.com/pybind/pybind11")
    assert res is not None
    assert res[0] == "pybind"
    assert res[1] == "repo:github.com/pybind"

    res2 = evaluator.identify_trusted_vendor(
        "azure-client",
        project_urls={"Repository": "https://github.com/azure/azure-sdk-for-python"}
    )
    assert res2 is not None
    assert res2[0] == "microsoft"


@pytest.mark.asyncio
async def test_trusted_vendor_receives_50_percent_score_dampening():
    """Verify that a package from a trusted vendor gets a 50% threat score discount on non-zero points."""
    evaluator = ProgressiveThreatEvaluator()

    cand = WatchlistCandidate(
        ecosystem=Ecosystem.PYPI,
        normalized_name="anthropic-bedrock-connector",
        framework_token="bedrock",
        entity_token="anthropic",
        capability_token="connector",
        risk_weight=50,
    )

    mock_meta = PackageMetadata(
        package_name="anthropic-bedrock-connector",
        ecosystem="pypi",
        latest_version="1.0.0",
        author_email="engineering@anthropic.com",
        homepage="https://github.com/anthropics/anthropic-sdk",
        description="Official connector for Anthropic models on AWS Bedrock." + (" x" * 150),
        monthly_downloads=5000,
        weekly_downloads=1200,
        first_published_at=datetime.now(timezone.utc),
    )

    # Empty stub or small AST to simulate non-malicious code
    mock_ast = ASTSecurityReport(
        is_empty_stub=False,
        total_lines_of_code=400,
        total_source_files=5,
        total_code_size_bytes=15000,
        flags=[],
    )

    with patch("slopwatch.adapters.get_adapter") as mock_get_adapter:
        mock_adapter = AsyncMock()
        mock_adapter.inspect_package_metadata.return_value = mock_meta
        mock_adapter.download_and_inspect_payload.return_value = mock_ast
        mock_get_adapter.return_value = mock_adapter

        detection = await evaluator.evaluate_candidate(cand)

        # Verified vendor with clean AST should be VERIFIED_OFFICIAL or BENIGN_COMMUNITY
        assert detection.verdict in {ThreatVerdict.VERIFIED_OFFICIAL, ThreatVerdict.BENIGN_COMMUNITY}
        assert detection.threat_score <= 20

        signal_ids = [s["signal_id"] for s in detection.analysis_details.get("signals", [])]
        assert "SIGNAL_OFFICIAL_VENDOR_DOMAIN_VERIFIED" in signal_ids


@pytest.mark.asyncio
async def test_trusted_vendor_with_malware_hooks_triggers_hijack_alert():
    """
    CRITICAL: A trusted vendor package with weaponized code MUST NOT be silenced with score 0.
    It must trigger MALICIOUS verdict with SIGNAL_POTENTIAL_VENDOR_ACCOUNT_TAKEOVER.
    """
    evaluator = ProgressiveThreatEvaluator()

    cand = WatchlistCandidate(
        ecosystem=Ecosystem.NPM,
        normalized_name="@google-cloud/storage-helper",
        framework_token="storage",
        entity_token="google",
        capability_token="helper",
        risk_weight=50,
    )

    mock_meta = PackageMetadata(
        package_name="@google-cloud/storage-helper",
        ecosystem="npm",
        latest_version="2.4.1",
        author_email="google-cloud-team@google.com",
        homepage="https://github.com/googleapis/nodejs-storage",
        description="Google Cloud Storage helper utility." * 10,
        monthly_downloads=25000,
        weekly_downloads=6000,
        first_published_at=datetime(2023, 1, 1, tzinfo=timezone.utc),
    )

    # Simulated hijacked release with install-time execution / credential stealer
    mock_ast = ASTSecurityReport(
        is_empty_stub=False,
        total_lines_of_code=600,
        total_source_files=10,
        total_code_size_bytes=45000,
        flags=[
            "INSTALL_TIME_EXECUTION: 'subprocess.Popen' spawned reverse shell in postinstall.js:14",
            "SOURCE_CODE_CONFIRMED_STEALER: exfiltration of ~/.aws credentials to c2.darknet.io:443",
        ],
    )

    with patch("slopwatch.adapters.get_adapter") as mock_get_adapter:
        mock_adapter = AsyncMock()
        mock_adapter.inspect_package_metadata.return_value = mock_meta
        mock_adapter.download_and_inspect_payload.return_value = mock_ast
        mock_get_adapter.return_value = mock_adapter

        detection = await evaluator.evaluate_candidate(cand)

        # Must NOT be VERIFIED_OFFICIAL! Must be MALICIOUS!
        assert detection.verdict == ThreatVerdict.MALICIOUS
        assert detection.threat_score >= 75

        signal_ids = [s["signal_id"] for s in detection.analysis_details.get("signals", [])]
        # Must flag the potential account takeover
        assert "SIGNAL_POTENTIAL_VENDOR_ACCOUNT_TAKEOVER" in signal_ids
        # Must have applied the 50% dampening on baseline scoring
        assert "SIGNAL_TRUSTED_VENDOR_DISCOUNT" in signal_ids
