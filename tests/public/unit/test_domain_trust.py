"""
Unit tests for SlopWatch Dynamic Domain Trustworthiness Engine and dynamic scoring.
"""

import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, patch

from slopwatch.core.domain_trust import (
    DomainTrustEngine,
    DomainReputation,
    get_shared_domain_trust_engine,
)
from slopwatch.assessor.scorer import ProgressiveThreatEvaluator
from slopwatch.core.dto import (
    WatchlistCandidate,
    ThreatVerdict,
    PackageMetadata,
    ASTSecurityReport,
    Ecosystem,
)


def test_generic_esps_are_never_trusted():
    engine = DomainTrustEngine()
    for esp in ["gmail.com", "yahoo.com", "outlook.com", "qq.com", "proton.me", "tempmail.org", "example.com"]:
        assert not engine.is_custom_domain(esp)
        score = engine.compute_trust_score(
            package_count=50,
            span_days=2000,
            days_since_latest=5,
            malicious_count=0,
            is_custom=False,
        )
        assert score == 0.0


def test_malicious_history_zeros_trust():
    engine = DomainTrustEngine()
    score = engine.compute_trust_score(
        package_count=100,
        span_days=3000,
        days_since_latest=10,
        malicious_count=1,
        is_custom=True,
    )
    assert score == 0.0


def test_single_day_burst_is_heavily_discounted():
    engine = DomainTrustEngine()
    # 50 packages uploaded in a single afternoon (span = 0)
    score = engine.compute_trust_score(
        package_count=50,
        span_days=0,
        days_since_latest=1,
        malicious_count=0,
        is_custom=True,
    )
    # Longevity factor is 0, so maximum score is volume weight (0.4)
    assert score <= 0.4


def test_established_domain_reaches_maximum_trust():
    engine = DomainTrustEngine()
    # 12 packages maintained over 400 days, active last week
    score = engine.compute_trust_score(
        package_count=12,
        span_days=400,
        days_since_latest=7,
        malicious_count=0,
        is_custom=True,
    )
    assert score == 1.0


def test_recency_decay_for_abandoned_domains():
    engine = DomainTrustEngine()
    # Active domain vs abandoned domain
    score_active = engine.compute_trust_score(package_count=10, span_days=365, days_since_latest=30, is_custom=True)
    score_dormant_2yr = engine.compute_trust_score(package_count=10, span_days=365, days_since_latest=550, is_custom=True)
    score_abandoned = engine.compute_trust_score(package_count=10, span_days=365, days_since_latest=900, is_custom=True)

    assert score_active == 1.0
    assert 0.4 <= score_dormant_2yr < 1.0
    assert score_abandoned == 0.2


@pytest.mark.asyncio
async def test_dynamic_domain_trust_applies_score_dampening():
    """Verify that a package from a dynamically trusted domain receives SIGNAL_DYNAMIC_DOMAIN_TRUST."""
    engine = get_shared_domain_trust_engine()
    now = datetime.now(timezone.utc)

    # Register dynamic reputation for an unlisted enterprise domain 'airbyte.io'
    engine.set_domain_reputation(
        DomainReputation(
            domain="airbyte.io",
            package_count=13,
            span_days=1600,
            days_since_latest=10,
            total_age_days=1700,
            malicious_count=0,
            is_custom_domain=True,
            trust_score=1.0,
            first_published_at=now - timedelta(days=1700),
            latest_published_at=now - timedelta(days=10),
        )
    )

    evaluator = ProgressiveThreatEvaluator()
    cand = WatchlistCandidate(
        ecosystem=Ecosystem.PYPI,
        normalized_name="airbyte-source-mysql",
        framework_token="source",
        entity_token="mysql",
        capability_token="connector",
        risk_weight=50,
    )

    mock_meta = PackageMetadata(
        package_name="airbyte-source-mysql",
        ecosystem="pypi",
        latest_version="1.2.0",
        author_email="integrations@airbyte.io",
        homepage="https://airbyte.io",
        description="Airbyte MySQL connector" + (" details" * 30),
        monthly_downloads=8000,
        weekly_downloads=2000,
        first_published_at=now - timedelta(days=500),
    )

    mock_ast = ASTSecurityReport(
        is_empty_stub=False,
        total_lines_of_code=800,
        total_source_files=10,
        total_code_size_bytes=25000,
        flags=[],
    )

    with patch("slopwatch.adapters.get_adapter") as mock_get_adapter:
        mock_adapter = AsyncMock()
        mock_adapter.inspect_package_metadata.return_value = mock_meta
        mock_adapter.download_and_inspect_payload.return_value = mock_ast
        mock_get_adapter.return_value = mock_adapter

        detection = await evaluator.evaluate_candidate(cand)

        # High trust domain resolves cleanly
        assert detection.verdict in {ThreatVerdict.VERIFIED_OFFICIAL, ThreatVerdict.BENIGN_COMMUNITY}
        assert detection.threat_score <= 20

        signal_ids = [s["signal_id"] for s in detection.analysis_details.get("signals", [])]
        # Must have applied trusted vendor discount or dynamic trust dampening
        assert any(sig in signal_ids for sig in ("SIGNAL_TRUSTED_VENDOR_DISCOUNT", "SIGNAL_DYNAMIC_DOMAIN_TRUST", "SIGNAL_OFFICIAL_VENDOR_DOMAIN_VERIFIED"))


@pytest.mark.asyncio
async def test_dynamic_trusted_domain_with_malware_triggers_hijack_alert():
    """Even if domain has 100% trust, malicious payload must trigger account takeover alert."""
    engine = get_shared_domain_trust_engine()
    now = datetime.now(timezone.utc)

    engine.set_domain_reputation(
        DomainReputation(
            domain="acme-corp.com",
            package_count=20,
            span_days=1000,
            days_since_latest=5,
            total_age_days=1100,
            malicious_count=0,
            is_custom_domain=True,
            trust_score=1.0,
            first_published_at=now - timedelta(days=1100),
            latest_published_at=now - timedelta(days=5),
        )
    )

    evaluator = ProgressiveThreatEvaluator()
    cand = WatchlistCandidate(
        ecosystem=Ecosystem.NPM,
        normalized_name="acme-internal-logger",
        framework_token="internal",
        entity_token="acme",
        capability_token="logger",
        risk_weight=50,
    )

    mock_meta = PackageMetadata(
        package_name="acme-internal-logger",
        ecosystem="npm",
        latest_version="3.0.1",
        author_email="core@acme-corp.com",
        homepage="https://acme-corp.com",
        description="Acme Corp internal logger" * 5,
        monthly_downloads=1000,
        weekly_downloads=250,
        first_published_at=now - timedelta(days=600),
    )

    mock_ast = ASTSecurityReport(
        is_empty_stub=False,
        total_lines_of_code=400,
        total_source_files=6,
        total_code_size_bytes=18000,
        flags=[
            "INSTALL_TIME_EXECUTION: 'subprocess.Popen' spawned reverse shell in postinstall.js:20",
        ],
    )

    with patch("slopwatch.adapters.get_adapter") as mock_get_adapter:
        mock_adapter = AsyncMock()
        mock_adapter.inspect_package_metadata.return_value = mock_meta
        mock_adapter.download_and_inspect_payload.return_value = mock_ast
        mock_get_adapter.return_value = mock_adapter

        detection = await evaluator.evaluate_candidate(cand)

        # Must NOT be silenced! Must be MALICIOUS!
        assert detection.verdict == ThreatVerdict.MALICIOUS
        assert detection.threat_score >= 75

        signal_ids = [s["signal_id"] for s in detection.analysis_details.get("signals", [])]
        assert "SIGNAL_POTENTIAL_VENDOR_ACCOUNT_TAKEOVER" in signal_ids
