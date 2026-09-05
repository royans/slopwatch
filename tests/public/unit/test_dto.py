import pytest
from datetime import datetime, timezone
from slopguard.core.dto import (
    Ecosystem,
    WatchlistState,
    ThreatVerdict,
    RegisteredPackage,
    WatchlistCandidate,
    PackageCreationEvent,
    PackageMetadata,
    ASTSecurityReport,
    SquatDetection,
    format_iso_seconds,
)


def test_format_iso_seconds():
    # 1. None should return current time formatted with second precision
    res_none = format_iso_seconds(None)
    assert len(res_none) == 20
    assert res_none.endswith("Z")

    # 2. Timezone-naive datetime
    dt_naive = datetime(2026, 8, 23, 14, 30, 45, 123456)
    res_naive = format_iso_seconds(dt_naive)
    assert res_naive == "2026-08-23T14:30:45Z"

    # 3. Timezone-aware datetime
    dt_aware = datetime(2026, 8, 23, 14, 30, 45, 999999, tzinfo=timezone.utc)
    res_aware = format_iso_seconds(dt_aware)
    assert res_aware == "2026-08-23T14:30:45Z"


def test_registered_package():
    pkg = RegisteredPackage(
        ecosystem=Ecosystem.PYPI,
        normalized_name="fastapi-azure-auth",
        raw_name="fastapi_azure_auth",
    )
    assert pkg.ecosystem == Ecosystem.PYPI
    assert pkg.normalized_name == "fastapi-azure-auth"
    assert len(pkg.package_id) == 36


def test_watchlist_candidate():
    candidate = WatchlistCandidate(
        ecosystem=Ecosystem.NPM,
        normalized_name="@auth/azure-jwt",
        entity_token="azure",
        capability_token="jwt",
        framework_token="auth",
        risk_weight=85,
    )
    assert candidate.ecosystem == Ecosystem.NPM
    assert candidate.state == WatchlistState.WATCHING
    assert candidate.risk_weight == 85


def test_ast_security_report_code_metrics():
    report = ASTSecurityReport(
        total_source_files=3,
        total_lines_of_code=450,
        total_code_size_bytes=16384,
        is_empty_stub=False,
        code_size_tier="MODERATE_CODEBASE",
        flags=["INSTALL_TIME_EXECUTION: os.system"],
        composite_threat_score=95,
        verdict=ThreatVerdict.MALICIOUS,
    )
    assert report.total_source_files == 3
    assert report.total_lines_of_code == 450
    assert report.total_code_size_bytes == 16384
    assert report.is_empty_stub is False
    assert report.code_size_tier == "MODERATE_CODEBASE"
    assert report.verdict == ThreatVerdict.MALICIOUS


def test_package_metadata_usage():
    meta = PackageMetadata(
        ecosystem=Ecosystem.PYPI,
        package_name="django-slack-oauth",
        latest_version="1.0.0",
        monthly_downloads=4500,
        weekly_downloads=1100,
        daily_downloads=150,
    )
    assert meta.package_name == "django-slack-oauth"
    assert meta.monthly_downloads == 4500
    assert meta.weekly_downloads == 1100
    assert meta.daily_downloads == 150


def test_squat_detection():
    now = datetime(2026, 8, 23, 12, 0, 0, tzinfo=timezone.utc)
    det = SquatDetection(
        ecosystem=Ecosystem.PYPI,
        package_name="fastapi-azure-b2c",
        author_username="test_author",
        threat_score=95,
        verdict=ThreatVerdict.MALICIOUS,
        created_at=now,
        updated_at=now,
        content_hash="abc123hash",
    )
    assert det.threat_score == 95
    assert det.verdict == ThreatVerdict.MALICIOUS
    assert det.created_at == now
    assert det.updated_at == now
    assert det.content_hash == "abc123hash"

