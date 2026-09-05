import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock
from sqlalchemy import text

from sentinel.core.dto import Ecosystem, PackageMetadata, ThreatVerdict, PackageCreationEvent, SquatDetection
from sentinel.db.engine import DatabaseManager
from sentinel.db.repository import SentinelRepository
from sentinel.scheduler.queue import (
    CrawlTask,
    TaskPriorityTier,
    compute_brand_priority,
)
from sentinel.scheduler.worker import ContinuousCrawlerWorker


def test_compute_brand_priority():
    # 🚨 Top Tier 1: Crypto Priority brands
    res_crypto1 = compute_brand_priority("bitcoin-wallet-bridge")
    assert res_crypto1 is not None
    brand_c1, weight_c1 = res_crypto1
    assert brand_c1 == "bitcoin"
    assert weight_c1 >= 990

    res_crypto2 = compute_brand_priority("metamask-auth-connector")
    assert res_crypto2 is not None
    assert res_crypto2[0] == "metamask"
    assert res_crypto2[1] >= 990

    # Top AI Priority brands
    res_ai1 = compute_brand_priority("openai-agent-kit")
    assert res_ai1 is not None
    brand, weight = res_ai1
    assert brand == "openai"
    assert weight >= 940

    res_ai2 = compute_brand_priority("deepseek-rag-wrapper")
    assert res_ai2 is not None
    assert res_ai2[0] == "deepseek"
    assert res_ai2[1] >= 940

    res_ai3 = compute_brand_priority("langchain-azure-auth")
    assert res_ai3 is not None
    assert res_ai3[0] in ("langchain", "azure")

    # Cloud & Identity Priority brands
    res = compute_brand_priority("django-azure-auth")
    assert res is not None
    brand, weight = res
    assert brand == "azure"
    assert weight >= 850

    res2 = compute_brand_priority("fastapi-google-oauth")
    assert res2 is not None
    brand2, weight2 = res2
    assert brand2 == "google"
    assert weight2 >= 850

    # Non-brand package
    res3 = compute_brand_priority("simple-calculator-utils")
    assert res3 is None


def test_task_priority_sorting():
    t_inbound_brand = CrawlTask(priority=1950, package_name="new-azure-pkg", ecosystem=Ecosystem.PYPI, task_type="NEW_INBOUND_RELEASE")
    t_threat_actor = CrawlTask(priority=920, package_name="squatted-openai-client", ecosystem=Ecosystem.PYPI, task_type="THREAT_ACTOR_PIVOT")
    t_brand = CrawlTask(priority=800, package_name="django-google-auth", ecosystem=Ecosystem.PYPI, task_type="HIGH_RISK_BRAND_WATCHLIST")
    t_reaudit = CrawlTask(priority=500, package_name="fastapi-aws-sso", ecosystem=Ecosystem.PYPI, task_type="FRESHNESS_REAUDIT")
    t_inbound_untracked = CrawlTask(priority=300, package_name="new-random-pkg", ecosystem=Ecosystem.PYPI, task_type="NEW_INBOUND_RELEASE")
    t_backfill = CrawlTask(priority=100, package_name="old-generic-lib", ecosystem=Ecosystem.PYPI, task_type="HISTORICAL_CATALOG_BACKFILL")

    tasks = [t_backfill, t_brand, t_inbound_untracked, t_inbound_brand, t_reaudit, t_threat_actor]
    tasks.sort(reverse=True)

    # Tracked brand inbound -> Threat actor -> Brand watchlist -> Re-audit -> Untracked inbound -> Backfill
    assert tasks[0].package_name == "new-azure-pkg"
    assert tasks[1].task_type == "THREAT_ACTOR_PIVOT"
    assert tasks[2].task_type == "HIGH_RISK_BRAND_WATCHLIST"
    assert tasks[3].task_type == "FRESHNESS_REAUDIT"
    assert tasks[4].package_name == "new-random-pkg"
    assert tasks[5].task_type == "HISTORICAL_CATALOG_BACKFILL"


@pytest.mark.asyncio
async def test_worker_collects_tracked_keyword_inbound_ahead_of_untracked():
    """Verify ContinuousCrawlerWorker gives higher priority to tracked keyword inbound releases."""
    db = DatabaseManager(database_url="sqlite+aiosqlite:///:memory:", wal_mode=False)
    await db.init_db()

    async with db.get_session() as session:
        repo = SentinelRepository(session)
        worker = ContinuousCrawlerWorker(repository=repo)

        inbound = [
            PackageCreationEvent(
                ecosystem=Ecosystem.PYPI,
                package_name="random-untracked-lib",
                release_version="1.0.0",
                author_username="dev1",
                published_at=datetime.now(timezone.utc),
            ),
            PackageCreationEvent(
                ecosystem=Ecosystem.PYPI,
                package_name="solana-web3-bridge",
                release_version="1.0.0",
                author_username="crypto_dev",
                published_at=datetime.now(timezone.utc),
            ),
        ]

        tasks = await worker.collect_crawl_tasks(
            limit=10,
            npm_limit=0,
            inbound_events=inbound,
        )

        inbound_tasks = [t for t in tasks if t.task_type == "NEW_INBOUND_RELEASE"]
        assert len(inbound_tasks) == 2

        # The tracked crypto/brand package ('solana-web3-bridge') must have higher priority
        solana_task = next(t for t in inbound_tasks if t.package_name == "solana-web3-bridge")
        untracked_task = next(t for t in inbound_tasks if t.package_name == "random-untracked-lib")

        assert solana_task.priority > untracked_task.priority
        assert solana_task.priority >= 1500 + 990  # TRACKED_KEYWORD_INBOUND + solana weight
        assert untracked_task.priority == TaskPriorityTier.UNTRACKED_NEW_INBOUND.value

    await db.close()



@pytest.mark.asyncio
async def test_crawler_worker_cycle_mocked():
    db = DatabaseManager(database_url="sqlite+aiosqlite:///:memory:", wal_mode=False)
    await db.init_db()

    async with db.get_session() as session:
        repo = SentinelRepository(session)

        # Seed catalog with some packages
        await repo.bulk_sync_registered_packages(
            Ecosystem.PYPI,
            {"fastapi-azure-auth", "django-google-login", "random-helper-pkg"}
        )

        worker = ContinuousCrawlerWorker(repository=repo)

        async def _mock_eval(candidate, version=None):
            return SquatDetection(
                ecosystem=candidate.ecosystem,
                package_name=candidate.normalized_name,
                release_version=version or "0.1.0",
                author_username="Dev",
                threat_score=85,
                published_at=datetime.now(timezone.utc) - timedelta(days=5),
                verdict=ThreatVerdict.SUSPICIOUS,
            )

        worker.evaluator.evaluate_candidate = AsyncMock(side_effect=_mock_eval)

        inbound_event = PackageCreationEvent(
            ecosystem=Ecosystem.PYPI,
            package_name="django-google-login",
            published_at=datetime.now(timezone.utc),
        )

        result = await worker.run_crawl_cycle(
            batch_size=10,
            inbound_events=[inbound_event],
            target_brands=["azure", "google"],
        )

        assert result["tasks_collected"] >= 1
        assert result["breakdown"]["inbound_new"] == 1
        assert result["detections_recorded"] >= 1

        # Verify saved in DB with freshness schedule
        detections = await repo.list_detections(limit=10)
        assert len(detections) >= 1
        d = detections[0]
        assert d.next_audit_due_at is not None
        assert d.audit_count >= 1

    await db.close()


@pytest.mark.asyncio
async def test_crawler_worker_cycle_npm_sampling_mocked():
    db = DatabaseManager(database_url="sqlite+aiosqlite:///:memory:", wal_mode=False)
    await db.init_db()

    async with db.get_session() as session:
        repo = SentinelRepository(session)

        # Seed catalog with some PyPI packages
        await repo.bulk_sync_registered_packages(
            Ecosystem.PYPI,
            {"django-google-login", "random-helper-pkg"}
        )

        worker = ContinuousCrawlerWorker(repository=repo)

        async def _mock_eval(candidate, version=None):
            return SquatDetection(
                ecosystem=candidate.ecosystem,
                package_name=candidate.normalized_name,
                release_version=version or "1.0.0",
                author_username="NpmDev",
                threat_score=65 if candidate.ecosystem == Ecosystem.NPM else 85,
                published_at=datetime.now(timezone.utc) - timedelta(days=10),
                verdict=ThreatVerdict.SUSPICIOUS,
            )

        worker.evaluator.evaluate_candidate = AsyncMock(side_effect=_mock_eval)

        result = await worker.run_crawl_cycle(
            batch_size=20,
            npm_limit=5,
            target_brands=["azure", "openai", "google"],
        )

        assert result["tasks_collected"] >= 5
        assert result["breakdown"]["npm_tasks"] == 5
        assert result["detections_recorded"] >= 5

        # Verify npm detections saved in DB
        npm_detections = await repo.list_detections(ecosystem=Ecosystem.NPM, limit=10)
        assert len(npm_detections) == 5
        for d in npm_detections:
            assert d.ecosystem == Ecosystem.NPM

    await db.close()


@pytest.mark.asyncio
async def test_budget_split_75_25_allocation():
    """Verify that collect_crawl_tasks respects the 75/25 budget split."""
    db = DatabaseManager(database_url="sqlite+aiosqlite:///:memory:", wal_mode=False)
    await db.init_db()

    async with db.get_session() as session:
        repo = SentinelRepository(session)

        # Seed brand-matching packages (newer budget) and a separate, non-overlapping
        # pool of generic packages (older/backfill budget) — a package can only ever
        # be queued once per cycle, so brand and backfill candidates must be disjoint.
        # Backfill is oldest-first, so seed it first to give it an earlier synced_at.
        backfill_packages = {f"generic-lib-{i}" for i in range(200)}
        await repo.bulk_sync_registered_packages(Ecosystem.PYPI, backfill_packages)
        # get_historical_backfill_targets now requires matches_grammar=1 (the crawl
        # tier is scoped to plausible slopsquat candidates, not any registered
        # package) — these synthetic names don't match the real grammar, so flag
        # them directly rather than via mark_grammar_matching_packages().
        await session.execute(text("UPDATE registered_packages SET matches_grammar = 1 WHERE normalized_name LIKE 'generic-lib-%'"))
        await session.commit()
        pypi_packages = {f"azure-tool-{i}" for i in range(100)}
        await repo.bulk_sync_registered_packages(Ecosystem.PYPI, pypi_packages)

        worker = ContinuousCrawlerWorker(repository=repo)

        async def _mock_eval(candidate, version=None):
            return SquatDetection(
                ecosystem=candidate.ecosystem,
                package_name=candidate.normalized_name,
                release_version=version or "0.1.0",
                author_username="Dev",
                threat_score=50,
                published_at=datetime.now(timezone.utc) - timedelta(days=5),
                verdict=ThreatVerdict.BENIGN_COMMUNITY,
            )

        worker.evaluator.evaluate_candidate = AsyncMock(side_effect=_mock_eval)

        # Collect tasks with limit=100, default 75/25 split
        tasks = await worker.collect_crawl_tasks(
            limit=100,
            npm_limit=0,
            target_brands=["azure"],
        )

        # No package should ever be queued twice in the same cycle.
        seen = [(t.ecosystem, t.package_name) for t in tasks]
        assert len(seen) == len(set(seen)), "collect_crawl_tasks must not double-queue the same package in one cycle"

        brand_tasks = [t for t in tasks if t.task_type == "HIGH_RISK_BRAND_WATCHLIST"]
        backfill_tasks = [t for t in tasks if t.task_type == "HISTORICAL_CATALOG_BACKFILL"]
        reaudit_tasks = [t for t in tasks if t.task_type == "FRESHNESS_REAUDIT"]

        # Newer budget (25%) should cap brand watchlist at ~25 tasks
        assert len(brand_tasks) <= 25, f"Brand tasks ({len(brand_tasks)}) should be at most 25 (25% of 100)"

        # Older budget (75%) should fill with backfill since no re-audits are due
        older_total = len(backfill_tasks) + len(reaudit_tasks)
        assert older_total >= 75, f"Older budget tasks ({older_total}) should be at least 75 (75% of 100)"

    await db.close()


@pytest.mark.asyncio
async def test_budget_split_unused_newer_rolls_into_older():
    """When fewer newer tasks are available, unused slots roll into the older budget."""
    db = DatabaseManager(database_url="sqlite+aiosqlite:///:memory:", wal_mode=False)
    await db.init_db()

    async with db.get_session() as session:
        repo = SentinelRepository(session)

        # Seed only 5 brand-matching packages — fewer than the 25% newer budget (25 of 100)
        pypi_packages = {f"azure-tool-{i}" for i in range(5)}
        await repo.bulk_sync_registered_packages(Ecosystem.PYPI, pypi_packages)
        # Also seed non-brand packages for backfill
        backfill_packages = {f"generic-lib-{i}" for i in range(200)}
        await repo.bulk_sync_registered_packages(Ecosystem.PYPI, backfill_packages)
        # get_historical_backfill_targets now requires matches_grammar=1 (the crawl
        # tier is scoped to plausible slopsquat candidates, not any registered
        # package) — these synthetic names don't match the real grammar, so flag
        # them directly rather than via mark_grammar_matching_packages().
        await session.execute(text("UPDATE registered_packages SET matches_grammar = 1 WHERE normalized_name LIKE 'generic-lib-%'"))
        await session.commit()

        worker = ContinuousCrawlerWorker(repository=repo)

        tasks = await worker.collect_crawl_tasks(
            limit=100,
            npm_limit=0,
            target_brands=["azure"],
        )

        brand_tasks = [t for t in tasks if t.task_type == "HIGH_RISK_BRAND_WATCHLIST"]
        backfill_tasks = [t for t in tasks if t.task_type == "HISTORICAL_CATALOG_BACKFILL"]

        # Only 5 brand tasks should be collected
        assert len(brand_tasks) == 5

        # Remaining 20 unused newer slots should roll into older budget
        # So backfill should get 75 + 20 = 95
        assert len(backfill_tasks) >= 90, f"Backfill tasks ({len(backfill_tasks)}) should absorb rollover from unused newer slots"

    await db.close()


@pytest.mark.asyncio
async def test_execute_task_enforces_once_per_day_review():
    """execute_task must refuse to re-evaluate a package already reviewed today, even
    across separate calls (simulating overlapping/duplicate scheduling)."""
    db = DatabaseManager(database_url="sqlite+aiosqlite:///:memory:", wal_mode=False)
    await db.init_db()

    async with db.get_session() as session:
        repo = SentinelRepository(session)
        worker = ContinuousCrawlerWorker(repository=repo)

        eval_calls = []

        async def _mock_eval(candidate, version=None):
            eval_calls.append(candidate.normalized_name)
            return SquatDetection(
                ecosystem=candidate.ecosystem,
                package_name=candidate.normalized_name,
                release_version=version or "0.1.0",
                author_username="Dev",
                threat_score=70,
                published_at=datetime.now(timezone.utc) - timedelta(days=5),
                verdict=ThreatVerdict.SUSPICIOUS,
            )

        worker.evaluator.evaluate_candidate = AsyncMock(side_effect=_mock_eval)

        task = CrawlTask(
            priority=1000,
            package_name="fastapi-azure-auth",
            ecosystem=Ecosystem.PYPI,
            task_type="HIGH_RISK_BRAND_WATCHLIST",
        )

        first_result = await worker.execute_task(task)
        second_result = await worker.execute_task(task)  # same package, same day

        assert first_result is not None
        assert second_result is None  # blocked by the daily-review gate
        assert eval_calls == ["fastapi-azure-auth"]  # evaluator only ever invoked once

        report = await repo.get_daily_review_compliance_report()
        assert report["rule_compliant"] is True
        assert report["duplicate_attempts_blocked"] == 1

    await db.close()


@pytest.mark.asyncio
async def test_budget_split_custom_percentage():
    """Verify that the older_budget_pct parameter is respected."""
    db = DatabaseManager(database_url="sqlite+aiosqlite:///:memory:", wal_mode=False)
    await db.init_db()

    async with db.get_session() as session:
        repo = SentinelRepository(session)

        # Backfill is oldest-first, so seed it first to give it an earlier synced_at.
        backfill_packages = {f"generic-lib-{i}" for i in range(200)}
        await repo.bulk_sync_registered_packages(Ecosystem.PYPI, backfill_packages)
        # get_historical_backfill_targets now requires matches_grammar=1 (the crawl
        # tier is scoped to plausible slopsquat candidates, not any registered
        # package) — these synthetic names don't match the real grammar, so flag
        # them directly rather than via mark_grammar_matching_packages().
        await session.execute(text("UPDATE registered_packages SET matches_grammar = 1 WHERE normalized_name LIKE 'generic-lib-%'"))
        await session.commit()
        pypi_packages = {f"azure-tool-{i}" for i in range(200)}
        await repo.bulk_sync_registered_packages(Ecosystem.PYPI, pypi_packages)

        worker = ContinuousCrawlerWorker(repository=repo)

        # Use 50/50 split instead of 75/25
        tasks = await worker.collect_crawl_tasks(
            limit=100,
            npm_limit=0,
            target_brands=["azure"],
            older_budget_pct=0.50,
        )

        brand_tasks = [t for t in tasks if t.task_type == "HIGH_RISK_BRAND_WATCHLIST"]
        backfill_tasks = [t for t in tasks if t.task_type == "HISTORICAL_CATALOG_BACKFILL"]

        # With 50/50 split, newer budget should be ~50
        assert len(brand_tasks) <= 50, f"Brand tasks ({len(brand_tasks)}) should be at most 50 (50% of 100)"
        assert len(backfill_tasks) >= 50, f"Backfill tasks ({len(backfill_tasks)}) should be at least 50 (50% of 100)"

        seen = [(t.ecosystem, t.package_name) for t in tasks]
        assert len(seen) == len(set(seen)), "collect_crawl_tasks must not double-queue the same package in one cycle"

    await db.close()

