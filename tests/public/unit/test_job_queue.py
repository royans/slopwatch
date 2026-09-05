import pytest
import sqlite3
import asyncio
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, patch

from slopguard.core.dto import Ecosystem, ThreatVerdict, PackageMetadata, ASTSecurityReport
from slopguard.scheduler.jobs import JobQueueManager


@pytest.fixture
def temp_db(tmp_path):
    db_file = tmp_path / "sentinel_test.db"
    conn = sqlite3.connect(db_file)
    conn.execute("""
    CREATE TABLE squat_detections (
        detection_id TEXT PRIMARY KEY,
        ecosystem TEXT NOT NULL,
        package_name TEXT NOT NULL,
        author_username TEXT,
        release_version TEXT DEFAULT '0.1.0',
        threat_score INTEGER NOT NULL,
        verdict TEXT NOT NULL,
        analysis_details_json TEXT,
        is_exported INTEGER DEFAULT 0,
        needs_reprocess INTEGER DEFAULT 0,
        refresh_network_data INTEGER DEFAULT 0,
        reprocess_priority INTEGER DEFAULT 100,
        reprocess_reason TEXT,
        published_at TEXT,
        created_at TEXT,
        updated_at TEXT
    );
    """)
    conn.execute("""
    INSERT INTO squat_detections (detection_id, ecosystem, package_name, threat_score, verdict, analysis_details_json, published_at, created_at, updated_at)
    VALUES 
    ('det-1', 'pypi', 'fastapi-azure-auth', 100, 'SUSPICIOUS', '{"entity": "azure", "capability": "auth", "framework": "fastapi"}', '2025-01-01T00:00:00Z', '2025-01-01T00:00:00Z', '2025-01-01T00:00:00Z'),
    ('det-2', 'pypi', 'django-okta-auth', 90, 'SUSPICIOUS', '{"entity": "okta", "capability": "auth", "framework": "django"}', '2025-01-01T00:00:00Z', '2025-01-01T00:00:00Z', '2025-01-01T00:00:00Z');
    """)
    conn.commit()
    conn.close()
    return db_file


def test_enqueue_recalc_jobs(temp_db):
    mgr = JobQueueManager(db_path=temp_db)
    count = mgr.enqueue_recalc_jobs()
    assert count == 2

    summary = mgr.get_queue_summary()
    assert summary["PENDING"] == 2
    assert summary["TOTAL"] == 2


def test_lease_batch_and_complete(temp_db):
    mgr = JobQueueManager(db_path=temp_db)
    mgr.enqueue_recalc_jobs()

    batch = mgr.lease_batch(batch_size=1, lease_seconds=30)
    assert len(batch) == 1
    job = batch[0]
    assert job["attempts"] == 0  # pre-increment in returned copy, updated in DB to 1

    summary = mgr.get_queue_summary()
    assert summary["PENDING"] == 1
    assert summary["IN_PROGRESS"] == 1

    # Mark completed
    mgr.mark_job_completed(job["job_id"])
    summary = mgr.get_queue_summary()
    assert summary["COMPLETED"] == 1
    assert summary["IN_PROGRESS"] == 0


def test_lease_timeout_recovery(temp_db):
    mgr = JobQueueManager(db_path=temp_db)
    mgr.enqueue_recalc_jobs()

    # Lease with negative duration (already expired)
    batch = mgr.lease_batch(batch_size=1, lease_seconds=-10)
    assert len(batch) == 1
    expired_job_id = batch[0]["job_id"]

    # Re-leasing should immediately recover the expired lease
    re_batch = mgr.lease_batch(batch_size=2, lease_seconds=60)
    assert any(j["job_id"] == expired_job_id for j in re_batch)


@pytest.mark.asyncio
async def test_process_queue_with_time_budget(temp_db, mocker):
    mgr = JobQueueManager(db_path=temp_db)
    mgr.enqueue_recalc_jobs()

    mock_meta = PackageMetadata(
        ecosystem=Ecosystem.PYPI,
        package_name="test-pkg",
        latest_version="1.0.0",
        author="Dev",
        author_email="dev@example.com",
    )
    mock_ast = ASTSecurityReport(
        total_source_files=1,
        total_lines_of_code=10,
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

    with patch("slopguard.adapters.get_adapter", return_value=mock_adapter):
        res = await mgr.process_queue_with_budget(time_budget_seconds=5.0, batch_size=5, concurrency=2)
        assert res["completed_in_run"] == 2
        assert res["PENDING"] == 0
        assert res["COMPLETED"] == 2


def test_flag_package_for_reprocess_and_priority_ordering(temp_db):
    mgr = JobQueueManager(db_path=temp_db)
    # Flag det-2 with high priority 500 and fresh network pull
    count1 = mgr.flag_package_for_reprocess(
        package_name="django-okta-auth",
        refresh_network=True,
        priority=500,
        reason="HIGH_RISK_MALWARE_ALERT",
    )
    assert count1 == 1

    # Flag det-1 with standard priority 100 and local rescore
    count2 = mgr.flag_package_for_reprocess(
        package_name="fastapi-azure-auth",
        refresh_network=False,
        priority=100,
        reason="ALGORITHM_UPDATE",
    )
    assert count2 == 1

    # Status check
    status = mgr.get_reprocessing_status()
    assert status["total_flagged_for_reprocess"] == 2
    assert status["flagged_fresh_network_pull"] == 1
    assert status["flagged_local_rescore_only"] == 1
    assert status["priority_distribution"]["priority_500"] == 1
    assert status["priority_distribution"]["priority_100"] == 1

    # Lease order: highest priority (500) must be leased FIRST
    batch = mgr.lease_batch(batch_size=1)
    assert len(batch) == 1
    assert batch[0]["package_name"] == "django-okta-auth"
    assert batch[0]["priority"] == 500
    assert batch[0]["refresh_network_data"] == 1


def _insert_detection(db_file, det_id, pkg, score, verdict, published_at):
    conn = sqlite3.connect(db_file)
    conn.execute(
        "INSERT INTO squat_detections (detection_id, ecosystem, package_name, threat_score, verdict, analysis_details_json, published_at, created_at, updated_at) "
        "VALUES (?, 'npm', ?, ?, ?, '{}', ?, ?, ?)",
        (det_id, pkg, score, verdict, published_at, published_at, published_at),
    )
    conn.commit()
    conn.close()


def test_bulk_flag_min_score_filter(temp_db):
    mgr = JobQueueManager(db_path=temp_db)
    # temp_db has det-1 (score 100) and det-2 (score 90)
    count = mgr.bulk_flag_for_reprocess(min_score=100, reason="SUBSET")
    assert count == 1
    batch = mgr.lease_batch(batch_size=10)
    assert [b["package_name"] for b in batch] == ["fastapi-azure-auth"]


def test_bulk_flag_max_age_days_filter(temp_db):
    recent = (datetime.now(timezone.utc) - timedelta(days=2)).isoformat()
    _insert_detection(temp_db, "det-recent", "fresh-base-pkg", 120, "MALICIOUS", recent)
    mgr = JobQueueManager(db_path=temp_db)
    # det-1/det-2 are dated 2025-01-01 (old); only det-recent is within 7 days
    count = mgr.bulk_flag_for_reprocess(max_age_days=7, reason="SUBSET")
    assert count == 1
    batch = mgr.lease_batch(batch_size=10)
    assert [b["package_name"] for b in batch] == ["fresh-base-pkg"]


def test_bulk_flag_min_score_and_age_combined(temp_db):
    recent = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    old = (datetime.now(timezone.utc) - timedelta(days=400)).isoformat()
    _insert_detection(temp_db, "det-hi-recent", "hi-recent", 150, "MALICIOUS", recent)
    _insert_detection(temp_db, "det-hi-old", "hi-old", 150, "MALICIOUS", old)
    _insert_detection(temp_db, "det-lo-recent", "lo-recent", 40, "BENIGN_COMMUNITY", recent)
    mgr = JobQueueManager(db_path=temp_db)
    count = mgr.bulk_flag_for_reprocess(min_score=90, max_age_days=7, reason="SUBSET")
    assert count == 1
    batch = mgr.lease_batch(batch_size=10)
    assert [b["package_name"] for b in batch] == ["hi-recent"]


def test_bulk_flag_keyword_matches_name_or_details(temp_db):
    now = datetime.now(timezone.utc).isoformat()
    conn = sqlite3.connect(temp_db)
    # name match
    conn.execute(
        "INSERT INTO squat_detections (detection_id, ecosystem, package_name, threat_score, verdict, analysis_details_json, published_at, created_at, updated_at) "
        "VALUES ('kw-1', 'npm', 'claude-anthropic-helper', 60, 'SUSPICIOUS', '{}', ?, ?, ?)",
        (now, now, now),
    )
    # details match (entity), name does not contain the term
    conn.execute(
        "INSERT INTO squat_detections (detection_id, ecosystem, package_name, threat_score, verdict, analysis_details_json, published_at, created_at, updated_at) "
        "VALUES ('kw-2', 'npm', 'claude-code-fork', 60, 'SUSPICIOUS', '{\"entity\": \"anthropic\"}', ?, ?, ?)",
        (now, now, now),
    )
    conn.commit()
    conn.close()
    mgr = JobQueueManager(db_path=temp_db)
    count = mgr.bulk_flag_for_reprocess(keywords=["anthropic"], reason="AUDIT")
    assert count == 2
    names = sorted(b["package_name"] for b in mgr.lease_batch(batch_size=10))
    assert names == ["claude-anthropic-helper", "claude-code-fork"]


def test_bulk_flag_dry_run_writes_nothing(temp_db):
    mgr = JobQueueManager(db_path=temp_db)
    count = mgr.bulk_flag_for_reprocess(min_score=90, dry_run=True)
    assert count == 2  # both temp_db rows match, but nothing is written
    assert mgr.get_reprocessing_status()["total_flagged_for_reprocess"] == 0
    assert mgr.get_queue_summary()["TOTAL"] == 0
    assert mgr.lease_batch(batch_size=10) == []


@pytest.mark.asyncio
async def test_network_refresh_evicts_cache(temp_db, mocker):
    mgr = JobQueueManager(db_path=temp_db)
    mgr.flag_package_for_reprocess(
        package_name="django-okta-auth",
        refresh_network=True,
        priority=200,
        reason="TEST_CACHE_EVICTION",
    )

    mock_meta = PackageMetadata(
        ecosystem=Ecosystem.PYPI,
        package_name="django-okta-auth",
        latest_version="1.0.0",
        author="Dev",
        author_email="dev@example.com",
    )
    mock_ast = ASTSecurityReport(
        total_source_files=1,
        total_lines_of_code=10,
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

    mock_cache = mocker.MagicMock()

    with patch("slopguard.adapters.get_adapter", return_value=mock_adapter), \
         patch("slopguard.core.cache.DiskCacheManager.evict_package", mock_cache):
        res = await mgr.process_queue_with_budget(time_budget_seconds=5.0, batch_size=5)
        assert res["completed_in_run"] == 1
        # Verify evict_package was called for the package requesting fresh network data
        mock_cache.assert_called_once_with("pypi", "django-okta-auth")



def test_bulk_flag_unprocessed_only(temp_db):
    mgr = JobQueueManager(db_path=temp_db)
    # temp_db has det-1 (score 100) and det-2 (score 90)
    # Flag det-1 and mark it completed
    mgr.flag_package_for_reprocess(package_name="fastapi-azure-auth", ecosystem=Ecosystem.PYPI)
    batch = mgr.lease_batch(batch_size=10)
    assert len(batch) == 1
    job_id = batch[0]["job_id"]
    mgr.mark_job_completed(job_id)
    # Now clear needs_reprocess in squat_detections for det-1 to simulate completed reprocess
    conn = sqlite3.connect(temp_db)
    conn.execute("UPDATE squat_detections SET needs_reprocess = 0 WHERE package_name = 'fastapi-azure-auth'")
    conn.commit()
    conn.close()

    # bulk_flag with unprocessed_only=True should find 0 packages with score >= 100
    count = mgr.bulk_flag_for_reprocess(min_score=100, unprocessed_only=True)
    assert count == 0

    # But without unprocessed_only, it will flag it again
    count_all = mgr.bulk_flag_for_reprocess(min_score=100, unprocessed_only=False)
    assert count_all == 1
