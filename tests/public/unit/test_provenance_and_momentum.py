"""
Unit tests for Cryptographic Provenance, Download Momentum, and Materialized Domain Reputations.
"""

import pytest
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch
from slopwatch.core.dto import Ecosystem, WatchlistCandidate, PackageMetadata, ASTSecurityReport, ThreatVerdict
from slopwatch.assessor.scorer import ProgressiveThreatEvaluator
from slopwatch.core.domain_trust import DomainReputation, get_shared_domain_trust_engine
from slopwatch.db.engine import DatabaseManager
from slopwatch.db.repository import SlopWatchRepository


@pytest.mark.asyncio
async def test_provenance_boosts_domain_trust_and_emits_signal(mocker):
    """Verify that cryptographic provenance emits SIGNAL_CRYPTOGRAPHIC_PROVENANCE and elevates trust."""
    engine = get_shared_domain_trust_engine()
    engine.register_reputation(DomainReputation(
        domain="startup-ai.io",
        package_count=1,
        first_published_at=datetime(2025, 1, 1, tzinfo=timezone.utc),
        latest_published_at=datetime(2025, 1, 2, tzinfo=timezone.utc),
        span_days=1,
        trust_score=0.1,
    ))

    candidate = WatchlistCandidate(
        ecosystem=Ecosystem.PYPI,
        normalized_name="startup-ai-core",
        entity_token="startup-ai",
        capability_token="core",
        framework_token="general",
        risk_weight=50,
    )

    mock_meta = PackageMetadata(
        ecosystem=Ecosystem.PYPI,
        package_name="startup-ai-core",
        latest_version="0.1.0",
        author="Founder",
        author_email="founder@startup-ai.io",
        has_provenance=True,
        provenance_type="pypi_trusted_publisher_oidc",
        monthly_downloads=500,
    )

    mock_ast = ASTSecurityReport(
        total_source_files=3,
        total_lines_of_code=80,
        composite_threat_score=0,
    )

    mock_adapter = mocker.MagicMock()
    mock_adapter.inspect_package_metadata = AsyncMock(return_value=mock_meta)
    mock_adapter.download_and_inspect_payload = AsyncMock(return_value=mock_ast)

    evaluator = ProgressiveThreatEvaluator()
    with patch("slopwatch.adapters.get_adapter", return_value=mock_adapter):
        detection = await evaluator.evaluate_candidate(candidate)

    raw_details = detection.analysis_details or {}
    signals = raw_details.get("signals", [])
    signal_ids = {s.get("signal_id") for s in signals}

    assert "SIGNAL_CRYPTOGRAPHIC_PROVENANCE" in signal_ids
    prov_signal = next(s for s in signals if s.get("signal_id") == "SIGNAL_CRYPTOGRAPHIC_PROVENANCE")
    assert prov_signal.get("metadata", {}).get("provenance_type") == "pypi_trusted_publisher_oidc"
    assert prov_signal.get("metadata", {}).get("effective_trust_score") >= 0.85
    assert detection.verdict in (ThreatVerdict.VERIFIED_OFFICIAL, ThreatVerdict.BENIGN_COMMUNITY)


@pytest.mark.asyncio
async def test_high_download_momentum_emits_signal_and_dampens_score(mocker):
    """Verify that >100k downloads emits SIGNAL_HIGH_DOWNLOAD_MOMENTUM and applies adoption dampening."""
    candidate = WatchlistCandidate(
        ecosystem=Ecosystem.PYPI,
        normalized_name="community-popular-auth",
        entity_token="popular",
        capability_token="auth",
        framework_token="general",
        risk_weight=60,
    )

    mock_meta = PackageMetadata(
        ecosystem=Ecosystem.PYPI,
        package_name="community-popular-auth",
        latest_version="1.2.0",
        author="Open Source Dev",
        author_email="dev@gmail.com",
        monthly_downloads=250_000,
    )

    mock_ast = ASTSecurityReport(
        total_source_files=10,
        total_lines_of_code=1500,
        composite_threat_score=0,
    )

    mock_adapter = mocker.MagicMock()
    mock_adapter.inspect_package_metadata = AsyncMock(return_value=mock_meta)
    mock_adapter.download_and_inspect_payload = AsyncMock(return_value=mock_ast)

    evaluator = ProgressiveThreatEvaluator()
    with patch("slopwatch.adapters.get_adapter", return_value=mock_adapter):
        detection = await evaluator.evaluate_candidate(candidate)

    raw_details = detection.analysis_details or {}
    signals = raw_details.get("signals", [])
    signal_ids = {s.get("signal_id") for s in signals}

    assert "SIGNAL_HIGH_DOWNLOAD_MOMENTUM" in signal_ids
    assert detection.threat_score <= 10


@pytest.mark.asyncio
async def test_materialized_domain_reputation_repository():
    """Verify creating and querying the materialized domain_reputations table in SQLite."""
    db = DatabaseManager(database_url="sqlite+aiosqlite:///:memory:")
    await db.init_db()

    async with db.get_session() as session:
        repo = SlopWatchRepository(session)

        # Refresh domain reputations on empty DB should return 0
        count = await repo.refresh_domain_reputations()
        assert count == 0

        # Querying an unmaterialized domain returns None or falls back gracefully
        rep = await repo.get_domain_reputation("nonexistent.org")
        assert rep is None

    await db.close()
