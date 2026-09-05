import pytest
from datetime import datetime, timezone
from slopguard.core.dto import (
    Ecosystem,
    WatchlistState,
    ThreatVerdict,
    WatchlistCandidate,
    SquatDetection,
)
from slopguard.db.engine import DatabaseManager
from slopguard.db.repository import SentinelRepository


@pytest.mark.asyncio
async def test_record_detection_persists_install_hook_flags():
    """has_install_hook/has_network_socket must be read from analysis_details and
    persisted onto the indexed squat_detections columns, on both insert and update."""
    db = DatabaseManager(database_url="sqlite+aiosqlite:///:memory:", wal_mode=False)
    await db.init_db()

    async with db.get_session() as session:
        repo = SentinelRepository(session)

        detection = SquatDetection(
            ecosystem=Ecosystem.NPM,
            package_name="react-azure-auth-helper",
            threat_score=95,
            analysis_details={
                "flags": ["LIFECYCLE_SCRIPT: 'postinstall' -> 'curl x | bash'"],
                "has_install_hook": True,
                "has_network_socket": False,
            },
            verdict=ThreatVerdict.MALICIOUS,
        )
        await repo.record_detection(detection)

        from slopguard.db.models import SquatDetectionModel
        from sqlalchemy import select
        result = await session.execute(select(SquatDetectionModel).where(SquatDetectionModel.package_name == "react-azure-auth-helper"))
        row = result.scalars().first()
        assert row.has_install_hook is True
        assert row.has_network_socket is False

        # Update path: re-record with different flags, should overwrite.
        detection2 = SquatDetection(
            ecosystem=Ecosystem.NPM,
            package_name="react-azure-auth-helper",
            threat_score=10,
            analysis_details={"flags": [], "has_install_hook": False, "has_network_socket": False},
            verdict=ThreatVerdict.BENIGN_COMMUNITY,
        )
        await repo.record_detection(detection2)
        result = await session.execute(select(SquatDetectionModel).where(SquatDetectionModel.package_name == "react-azure-auth-helper"))
        row = result.scalars().first()
        assert row.has_install_hook is False

    await db.close()


@pytest.mark.asyncio
async def test_backfill_install_hook_flags_from_stored_json():
    """Existing detections recorded before has_install_hook existed in their stored
    JSON must be correctly backfilled by re-deriving from the raw AST flags."""
    db = DatabaseManager(database_url="sqlite+aiosqlite:///:memory:", wal_mode=False)
    await db.init_db()

    async with db.get_session() as session:
        repo = SentinelRepository(session)

        # Simulate a pre-fix detection: flags present, but no has_install_hook key at all.
        old_style = SquatDetection(
            ecosystem=Ecosystem.PYPI,
            package_name="legacy-detection-pkg",
            threat_score=80,
            analysis_details={"flags": ["INSTALL_TIME_EXECUTION: 'os.system' executed at top-level in setup.py:5"]},
            verdict=ThreatVerdict.MALICIOUS,
        )
        await repo.record_detection(old_style)

        # Directly reset the columns to simulate them never having been populated.
        from sqlalchemy import text
        await session.execute(text("UPDATE squat_detections SET has_install_hook = 0, has_network_socket = 0"))
        await session.commit()

        stats = await repo.backfill_install_hook_flags()
        assert stats["with_install_hook"] == 1

        from slopguard.db.models import SquatDetectionModel
        from sqlalchemy import select
        result = await session.execute(select(SquatDetectionModel).where(SquatDetectionModel.package_name == "legacy-detection-pkg"))
        row = result.scalars().first()
        assert row.has_install_hook is True

    await db.close()


@pytest.mark.asyncio
async def test_mark_grammar_matching_packages_scopes_historical_backfill():
    """
    Only packages matching the combinatorial naming grammar should be flagged
    matches_grammar=1 and returned by get_historical_backfill_targets — an unrelated
    catalog package (e.g. a random real-world library name) must never be selected
    for backfill audit just because it exists in the catalog.
    """
    db = DatabaseManager(database_url="sqlite+aiosqlite:///:memory:", wal_mode=False)
    await db.init_db()

    async with db.get_session() as session:
        repo = SentinelRepository(session)

        # "fastapi-azure-auth" matches the {framework}-{entity}-{capability} grammar.
        # "some-totally-unrelated-project" does not match any generated combination.
        await repo.bulk_sync_registered_packages(
            Ecosystem.PYPI,
            {"fastapi-azure-auth", "some-totally-unrelated-project"},
        )

        updated = await repo.mark_grammar_matching_packages(Ecosystem.PYPI, candidate_limit=5000)
        assert updated == 1

        backfill_targets = await repo.get_historical_backfill_targets(Ecosystem.PYPI, limit=10)
        assert backfill_targets == ["fastapi-azure-auth"]

    await db.close()


@pytest.mark.asyncio
async def test_taxonomy_gap_report_surfaces_untracked_tokens_only():
    """
    Tokens already covered by ENTITIES/CAPABILITIES/FRAMEWORKS/PRIORITY_BRAND_WEIGHTS
    must be excluded — the report should only surface genuinely new candidates.
    "azure" and "auth" are already tracked; "turborepo" is not.
    """
    db = DatabaseManager(database_url="sqlite+aiosqlite:///:memory:", wal_mode=False)
    await db.init_db()

    async with db.get_session() as session:
        repo = SentinelRepository(session)

        await repo.bulk_sync_registered_packages(
            Ecosystem.NPM,
            {
                "turborepo-cache-client", "turborepo-remote-cache",
                "turborepo-shared-utils", "fastapi-azure-auth",
            },
        )

        results = await repo.get_taxonomy_gap_report(Ecosystem.NPM, top_n=10)
        tokens = dict(results)

        assert "turborepo" in tokens
        assert tokens["turborepo"] == 3
        assert "azure" not in tokens  # already a known entity
        assert "auth" not in tokens   # already a known capability
        assert "fastapi" not in tokens  # already a known framework

    await db.close()


@pytest.mark.asyncio
async def test_try_claim_daily_review_enforces_once_per_day():
    """A package may only be claimed for review once per UTC day; repeat attempts are blocked but tracked."""
    db = DatabaseManager(database_url="sqlite+aiosqlite:///:memory:", wal_mode=False)
    await db.init_db()

    async with db.get_session() as session:
        repo = SentinelRepository(session)

        # First attempt today: allowed.
        assert await repo.try_claim_daily_review(Ecosystem.PYPI, "fastapi-azure-auth") is True

        # Second and third attempts on the same package, same day: blocked.
        assert await repo.try_claim_daily_review(Ecosystem.PYPI, "fastapi-azure-auth") is False
        assert await repo.try_claim_daily_review(Ecosystem.PYPI, "fastapi-azure-auth") is False

        # A different package is unaffected.
        assert await repo.try_claim_daily_review(Ecosystem.PYPI, "django-google-login") is True

        # Same package name, different ecosystem: independent.
        assert await repo.try_claim_daily_review(Ecosystem.NPM, "fastapi-azure-auth") is True

        reviewed_pypi = await repo.get_packages_reviewed_today(Ecosystem.PYPI)
        assert reviewed_pypi == {"fastapi-azure-auth", "django-google-login"}

        report = await repo.get_daily_review_compliance_report()
        assert report["rule_compliant"] is True
        assert report["rule_violations"] == []
        assert report["distinct_packages_reviewed"] == 3  # fastapi-azure-auth(pypi), django-google-login(pypi), fastapi-azure-auth(npm)
        assert report["duplicate_attempts_blocked"] == 2  # the 2 blocked re-attempts on fastapi-azure-auth/pypi

    await db.close()


@pytest.mark.asyncio
async def test_repository_multi_ecosystem_lifecycle():
    db = DatabaseManager(database_url="sqlite+aiosqlite:///:memory:", wal_mode=False)
    await db.init_db()

    async with db.get_session() as session:
        repo = SentinelRepository(session)

        # 1. Sync catalog
        pypi_pkgs = {"requests", "fastapi", "pydantic"}
        npm_pkgs = {"react", "express", "lodash"}

        await repo.bulk_sync_registered_packages(Ecosystem.PYPI, pypi_pkgs)
        await repo.bulk_sync_registered_packages(Ecosystem.NPM, npm_pkgs)

        registered_pypi = await repo.get_registered_names_set(Ecosystem.PYPI)
        assert "fastapi" in registered_pypi
        assert "react" not in registered_pypi

        # 2. Add Watchlist Candidates
        candidates = [
            WatchlistCandidate(
                ecosystem=Ecosystem.PYPI,
                normalized_name="fastapi-azure-auth",
                entity_token="azure",
                capability_token="auth",
                framework_token="fastapi",
                risk_weight=90,
            ),
            WatchlistCandidate(
                ecosystem=Ecosystem.NPM,
                normalized_name="@auth/azure-jwt",
                entity_token="azure",
                capability_token="jwt",
                framework_token="auth",
                risk_weight=85,
            ),
        ]
        await repo.bulk_upsert_watchlist(candidates)

        watchlist_pypi = await repo.get_watchlist_names_set(Ecosystem.PYPI)
        assert "fastapi-azure-auth" in watchlist_pypi

        # 3. Record Detection
        detection = SquatDetection(
            candidate_id=candidates[0].candidate_id,
            ecosystem=Ecosystem.PYPI,
            package_name="fastapi-azure-auth",
            author_username="attacker_user",
            release_version="0.1.0",
            threat_score=95,
            analysis_details={"flags": ["socket.connect"]},
            verdict=ThreatVerdict.MALICIOUS,
        )
        saved = await repo.record_detection(detection)
        assert saved.package_name == "fastapi-azure-auth"
        assert saved.created_at is not None
        assert saved.updated_at is not None
        initial_created = saved.created_at
        initial_updated = saved.updated_at

        # Re-recording same detection data should NOT modify created_at or updated_at
        saved_again = await repo.record_detection(detection)
        assert saved_again.created_at == initial_created
        assert saved_again.updated_at == initial_updated

        # Check candidate state moved to SQUATTED
        updated_candidate = await repo.get_candidate_by_name(Ecosystem.PYPI, "fastapi-azure-auth")
        assert updated_candidate.state == WatchlistState.SQUATTED

        # 4. List Detections & Unexported
        unexported = await repo.get_unexported_detections()
        assert len(unexported) == 1

        await repo.mark_detections_exported([unexported[0].detection_id])
        unexported_after = await repo.get_unexported_detections()
        assert len(unexported_after) == 0

    await db.close()



# ==================== Modular detection layer (sentinel_findings) ====================

@pytest.mark.asyncio
async def test_record_detection_materializes_findings_rows():
    db = DatabaseManager(database_url="sqlite+aiosqlite:///:memory:", wal_mode=False)
    await db.init_db()

    async with db.get_session() as session:
        repo = SentinelRepository(session)
        detection = SquatDetection(
            ecosystem=Ecosystem.NPM,
            package_name="react-azure-auth-helper",
            threat_score=140,
            published_at=datetime(2026, 1, 2, tzinfo=timezone.utc),
            analysis_details={
                "flags": [
                    "LIFECYCLE_SCRIPT: 'postinstall' -> 'node setup.js'",
                    "SOURCE_CODE_DYNAMIC_CODE_LOADER: exec + fetch in setup.js",
                    "EXFILTRATION_DESTINATION_DETECTED: Discord Webhook in setup.js:4",
                ],
                "signals": [{
                    "signal_id": "SIGNAL_HIGH_VALUE_BRAND_TARGET", "category": "NAMING_HEURISTIC",
                    "severity": "HIGH", "score_impact": 15, "rule_code": "RULE_HIGH_VALUE_BRAND",
                    "human_description": "claims azure",
                }],
            },
            verdict=ThreatVerdict.MALICIOUS,
        )
        await repo.record_detection(detection)

        from slopguard.db.models import SignalFindingModel
        from sqlalchemy import select
        rows = (await session.execute(select(SignalFindingModel))).scalars().all()
        codes = {r.signal_code for r in rows}
        assert "LIFECYCLE_SCRIPT" in codes
        assert "SOURCE_CODE_DYNAMIC_CODE_LOADER" in codes
        assert "SIGNAL_HIGH_VALUE_BRAND_TARGET" in codes
        loader = next(r for r in rows if r.signal_code == "SOURCE_CODE_DYNAMIC_CODE_LOADER")
        assert loader.gates_malicious is True
        assert loader.threat_score == 140          # denormalized from parent
        assert loader.verdict == "MALICIOUS"
        assert loader.published_at is not None

    await db.close()


@pytest.mark.asyncio
async def test_findings_are_replaced_not_appended_on_reaudit():
    db = DatabaseManager(database_url="sqlite+aiosqlite:///:memory:", wal_mode=False)
    await db.init_db()

    async with db.get_session() as session:
        repo = SentinelRepository(session)
        pkg = "pypi-internal-billing-sdk"

        await repo.record_detection(SquatDetection(
            ecosystem=Ecosystem.PYPI, package_name=pkg, threat_score=95,
            analysis_details={"flags": ["INSTALL_TIME_EXECUTION: 'exec' in setup.py:3"]},
            verdict=ThreatVerdict.MALICIOUS,
        ))

        from slopguard.db.models import SignalFindingModel
        from sqlalchemy import select, func
        n1 = (await session.execute(
            select(func.count()).select_from(SignalFindingModel).where(SignalFindingModel.package_name == pkg)
        )).scalar()
        assert n1 >= 1

        # Re-audit: now clean. Stale malware finding must be gone.
        await repo.record_detection(SquatDetection(
            ecosystem=Ecosystem.PYPI, package_name=pkg, threat_score=10,
            analysis_details={"flags": []},
            verdict=ThreatVerdict.BENIGN_COMMUNITY,
        ))
        rows = (await session.execute(
            select(SignalFindingModel).where(SignalFindingModel.package_name == pkg)
        )).scalars().all()
        assert all(r.signal_code != "INSTALL_TIME_EXECUTION" for r in rows)

    await db.close()


@pytest.mark.asyncio
async def test_find_detections_by_signals_any_and_all_modes():
    db = DatabaseManager(database_url="sqlite+aiosqlite:///:memory:", wal_mode=False)
    await db.init_db()

    async with db.get_session() as session:
        repo = SentinelRepository(session)

        await repo.record_detection(SquatDetection(
            ecosystem=Ecosystem.NPM, package_name="pkg-exfil-only", threat_score=80,
            analysis_details={"flags": ["EXFILTRATION_DESTINATION_DETECTED: Discord in a.js:1"]},
            verdict=ThreatVerdict.SUSPICIOUS,
        ))
        await repo.record_detection(SquatDetection(
            ecosystem=Ecosystem.NPM, package_name="pkg-exfil-and-creds", threat_score=150,
            analysis_details={"flags": [
                "EXFILTRATION_DESTINATION_DETECTED: Discord in a.js:1",
                "CREDENTIAL_PATH_HARVESTING: ~/.aws in a.js:9",
            ]},
            verdict=ThreatVerdict.MALICIOUS,
        ))
        await repo.record_detection(SquatDetection(
            ecosystem=Ecosystem.PYPI, package_name="pkg-creds-pypi", threat_score=120,
            analysis_details={"flags": ["CREDENTIAL_PATH_HARVESTING: ~/.ssh in setup.py:2"]},
            verdict=ThreatVerdict.MALICIOUS,
        ))

        any_hits = await repo.find_detections_by_signals(
            ["EXFILTRATION_DESTINATION_DETECTED", "CREDENTIAL_PATH_HARVESTING"], mode="any"
        )
        assert {d.package_name for d in any_hits} == {
            "pkg-exfil-only", "pkg-exfil-and-creds", "pkg-creds-pypi"
        }
        # ordered by threat score desc
        assert any_hits[0].package_name == "pkg-exfil-and-creds"

        all_hits = await repo.find_detections_by_signals(
            ["EXFILTRATION_DESTINATION_DETECTED", "CREDENTIAL_PATH_HARVESTING"], mode="all"
        )
        assert {d.package_name for d in all_hits} == {"pkg-exfil-and-creds"}

        npm_only = await repo.find_detections_by_signals(
            ["CREDENTIAL_PATH_HARVESTING"], mode="any", ecosystem=Ecosystem.NPM
        )
        assert {d.package_name for d in npm_only} == {"pkg-exfil-and-creds"}

    await db.close()


@pytest.mark.asyncio
async def test_get_signal_stats_and_backfill_findings():
    db = DatabaseManager(database_url="sqlite+aiosqlite:///:memory:", wal_mode=False)
    await db.init_db()

    async with db.get_session() as session:
        repo = SentinelRepository(session)

        # Insert a detection row WITHOUT going through record_detection's findings sync
        from slopguard.db.models import SquatDetectionModel
        import json as _json
        session.add(SquatDetectionModel(
            detection_id="d-legacy-1", ecosystem="npm", package_name="legacy-pkg",
            release_version="9.9.9", threat_score=77, verdict="SUSPICIOUS",
            analysis_details_json=_json.dumps({"flags": ["LIFECYCLE_SCRIPT: 'postinstall' -> x"]}),
            published_at=datetime(2026, 2, 1, tzinfo=timezone.utc),
        ))
        await session.commit()

        stats0 = await repo.get_signal_stats()
        assert stats0 == []

        res = await repo.backfill_findings()
        assert res["detections_processed"] == 1
        assert res["findings_written"] >= 1

        stats = await repo.get_signal_stats()
        by_code = {s["signal_code"]: s for s in stats}
        assert "LIFECYCLE_SCRIPT" in by_code
        assert by_code["LIFECYCLE_SCRIPT"]["package_count"] == 1

    await db.close()


@pytest.mark.asyncio
async def test_bulk_sync_registered_packages_chunking():
    db = DatabaseManager(database_url="sqlite+aiosqlite:///:memory:", wal_mode=False)
    await db.init_db()

    async with db.get_session() as session:
        repo = SentinelRepository(session)
        names = {f"pkg-{i}" for i in range(5005)}
        count = await repo.bulk_sync_registered_packages(Ecosystem.PYPI, names)
        assert count == 5005

        names_set = await repo.get_registered_names_set(Ecosystem.PYPI)
        assert len(names_set) == 5005
        assert "pkg-5004" in names_set

    await db.close()

