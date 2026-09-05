import pytest
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

from slopguard.core.dto import (
    Ecosystem,
    PackageCreationEvent,
    PackageMetadata,
    ASTSecurityReport,
    ThreatVerdict,
)
from slopguard.db.engine import DatabaseManager
from slopguard.db.repository import SentinelRepository
from slopguard.monitor import InboundTripwireMonitor


@pytest.mark.asyncio
async def test_inbound_monitor_scans_and_flags_unlisted_dangerous_package():
    """
    Universal Inbound Scanning:
    Even if a new package does not match any brand keywords in the pre-computed watchlist,
    if its payload contains dangerous execution hooks, it must be flagged immediately.
    """
    db = DatabaseManager(database_url="sqlite+aiosqlite:///:memory:", wal_mode=False)
    await db.init_db()

    async with db.get_session() as session:
        repo = SentinelRepository(session)
        monitor = InboundTripwireMonitor(repo)

        # Empty watchlist — no keywords configured
        events = [
            PackageCreationEvent(
                ecosystem=Ecosystem.NPM,
                package_name="random-utility-lib",
                release_version="1.0.0",
                author_username="stealth_author",
                published_at=datetime.now(timezone.utc),
            )
        ]

        # AST report with confirmed dangerous code loader
        mock_report = ASTSecurityReport(
            total_source_files=2,
            total_lines_of_code=60,
            total_code_size_bytes=1200,
            is_empty_stub=False,
            code_size_tier="TINY_CODEBASE",
            flags=["SOURCE_CODE_DYNAMIC_CODE_LOADER: exec + network in index.js"],
            composite_threat_score=80,
            verdict=ThreatVerdict.MALICIOUS,
        )

        mock_meta = PackageMetadata(
            ecosystem=Ecosystem.NPM,
            package_name="random-utility-lib",
            latest_version="1.0.0",
            author="stealth_author",
        )

        mock_adapter = AsyncMock()
        mock_adapter.normalize_name = lambda n: n.lower()
        mock_adapter.fetch_recent_creations = AsyncMock(return_value=events)
        mock_adapter.download_and_inspect_payload = AsyncMock(return_value=mock_report)
        mock_adapter.inspect_package_metadata = AsyncMock(return_value=mock_meta)

        with patch("slopguard.monitor.get_adapter", return_value=mock_adapter):
            detections = await monitor.check_inbound_stream(Ecosystem.NPM, limit=10)

            # Successfully flagged despite not being on the watchlist
            assert len(detections) == 1
            det = detections[0]
            assert det.package_name == "random-utility-lib"
            assert det.verdict == ThreatVerdict.MALICIOUS
            assert det.analysis_details["has_confirmed_dangerous_execution"] is True
            assert det.analysis_details["is_watchlist_match"] is False

    await db.close()


@pytest.mark.asyncio
async def test_inbound_monitor_ignores_clean_unlisted_package():
    """
    Clean inbound packages outside the watchlist must pass without false alarm.
    """
    db = DatabaseManager(database_url="sqlite+aiosqlite:///:memory:", wal_mode=False)
    await db.init_db()

    async with db.get_session() as session:
        repo = SentinelRepository(session)
        monitor = InboundTripwireMonitor(repo)

        events = [
            PackageCreationEvent(
                ecosystem=Ecosystem.PYPI,
                package_name="ordinary-clean-calc",
                release_version="0.1.0",
                author_username="good_dev",
                published_at=datetime.now(timezone.utc),
            )
        ]

        mock_report = ASTSecurityReport(
            total_source_files=1,
            total_lines_of_code=40,
            total_code_size_bytes=800,
            is_empty_stub=False,
            code_size_tier="TINY_CODEBASE",
            flags=[],
            composite_threat_score=0,
            verdict=ThreatVerdict.BENIGN_COMMUNITY,
        )

        mock_meta = PackageMetadata(
            ecosystem=Ecosystem.PYPI,
            package_name="ordinary-clean-calc",
            latest_version="0.1.0",
            author="good_dev",
        )

        mock_adapter = AsyncMock()
        mock_adapter.normalize_name = lambda n: n.lower()
        mock_adapter.fetch_recent_creations = AsyncMock(return_value=events)
        mock_adapter.download_and_inspect_payload = AsyncMock(return_value=mock_report)
        mock_adapter.inspect_package_metadata = AsyncMock(return_value=mock_meta)

        with patch("slopguard.monitor.get_adapter", return_value=mock_adapter):
            detections = await monitor.check_inbound_stream(Ecosystem.PYPI, limit=10)
            assert len(detections) == 0

    await db.close()


@pytest.mark.asyncio
async def test_inbound_monitor_prioritizes_tracked_keywords_over_untracked():
    """
    Ensure inbound stream events matching tracked keywords/brands are prioritized
    and inspected before un-tracked packages.
    """
    db = DatabaseManager(database_url="sqlite+aiosqlite:///:memory:", wal_mode=False)
    await db.init_db()

    async with db.get_session() as session:
        repo = SentinelRepository(session)
        monitor = InboundTripwireMonitor(repo)

        # Inbound stream returns an untracked package first, then a tracked keyword package
        events = [
            PackageCreationEvent(
                ecosystem=Ecosystem.PYPI,
                package_name="random-untracked-lib",
                release_version="1.0.0",
                author_username="dev1",
                published_at=datetime.now(timezone.utc),
            ),
            PackageCreationEvent(
                ecosystem=Ecosystem.PYPI,
                package_name="openai-fake-agent",
                release_version="1.0.0",
                author_username="attacker",
                published_at=datetime.now(timezone.utc),
            ),
        ]

        inspected_order = []

        async def _mock_download(pkg_name, ver):
            inspected_order.append(pkg_name)
            return ASTSecurityReport(
                total_source_files=1,
                total_lines_of_code=10,
                total_code_size_bytes=200,
                is_empty_stub=False,
                code_size_tier="TINY_CODEBASE",
                flags=[],
                composite_threat_score=0,
                verdict=ThreatVerdict.BENIGN_COMMUNITY,
            )

        mock_meta = PackageMetadata(
            ecosystem=Ecosystem.PYPI,
            package_name="pkg",
            latest_version="1.0.0",
            author="author",
        )

        mock_adapter = AsyncMock()
        mock_adapter.normalize_name = lambda n: n.lower()
        mock_adapter.fetch_recent_creations = AsyncMock(return_value=events)
        mock_adapter.download_and_inspect_payload = AsyncMock(side_effect=_mock_download)
        mock_adapter.inspect_package_metadata = AsyncMock(return_value=mock_meta)

        with patch("slopguard.monitor.get_adapter", return_value=mock_adapter):
            await monitor.check_inbound_stream(Ecosystem.PYPI, limit=10)

            # Tracked keyword package ('openai-fake-agent') MUST be inspected first!
            assert len(inspected_order) == 2
            assert inspected_order[0] == "openai-fake-agent", (
                f"Expected tracked keyword 'openai-fake-agent' to be inspected first, got: {inspected_order}"
            )
            assert inspected_order[1] == "random-untracked-lib"

    await db.close()

