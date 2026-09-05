"""
Sentinel Persistent Job Queue Manager.

Provides crash-resilient asynchronous job enqueueing, lease-based batch execution,
and bounded time-budget workers for re-evaluations, metadata refreshes, and AST backfills.
"""

import time
import json
import uuid
import sqlite3
import asyncio
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime, timezone, timedelta

from slopguard.core.dto import Ecosystem, WatchlistCandidate
from slopguard.assessor.scorer import ProgressiveThreatEvaluator

logger = logging.getLogger("slopguard.jobs")


class JobQueueManager:
    """Manages persistent SQLite job queue with time budgets and automatic recovery."""

    def __init__(self, db_path: Optional[Path] = None):
        if db_path is None:
            db_path = Path("data/slopguard.db")
        self.db_path = Path(db_path)
        self._ensure_tables()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        # Enable WAL mode and busy timeout for high concurrency
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA busy_timeout=15000;")
        return conn

    def _ensure_tables(self) -> None:
        """Create sentinel_jobs_queue table and ensure columns exist."""
        if not self.db_path.parent.exists():
            self.db_path.parent.mkdir(parents=True, exist_ok=True)

        conn = self._get_connection()
        conn.execute("""
        CREATE TABLE IF NOT EXISTS sentinel_jobs_queue (
            job_id TEXT PRIMARY KEY,
            ecosystem TEXT NOT NULL,
            package_name TEXT NOT NULL,
            job_type TEXT NOT NULL DEFAULT 'RECALCULATE_SCORE',
            priority INTEGER NOT NULL DEFAULT 100,
            status TEXT NOT NULL DEFAULT 'PENDING',
            refresh_network_data INTEGER NOT NULL DEFAULT 0,
            attempts INTEGER NOT NULL DEFAULT 0,
            max_attempts INTEGER NOT NULL DEFAULT 3,
            leased_until TEXT,
            error_message TEXT,
            payload_json TEXT,
            enqueued_at TEXT NOT NULL,
            completed_at TEXT,
            UNIQUE(ecosystem, package_name, job_type)
        );
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_jobs_status_priority ON sentinel_jobs_queue (status, priority, leased_until);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_jobs_pkg ON sentinel_jobs_queue (ecosystem, package_name);")

        cur = conn.cursor()
        # Migrate sentinel_jobs_queue if table existed
        cur.execute("PRAGMA table_info(sentinel_jobs_queue)")
        job_cols = {row[1] for row in cur.fetchall()}
        if "refresh_network_data" not in job_cols:
            conn.execute("ALTER TABLE sentinel_jobs_queue ADD COLUMN refresh_network_data INTEGER NOT NULL DEFAULT 0")

        # Migrate squat_detections if table exists
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='squat_detections'")
        if cur.fetchone():
            cur.execute("PRAGMA table_info(squat_detections)")
            det_cols = {row[1] for row in cur.fetchall()}
            if "needs_reprocess" not in det_cols:
                conn.execute("ALTER TABLE squat_detections ADD COLUMN needs_reprocess INTEGER NOT NULL DEFAULT 0")
            if "refresh_network_data" not in det_cols:
                conn.execute("ALTER TABLE squat_detections ADD COLUMN refresh_network_data INTEGER NOT NULL DEFAULT 0")
            if "reprocess_priority" not in det_cols:
                conn.execute("ALTER TABLE squat_detections ADD COLUMN reprocess_priority INTEGER NOT NULL DEFAULT 100")
            if "reprocess_reason" not in det_cols:
                conn.execute("ALTER TABLE squat_detections ADD COLUMN reprocess_reason TEXT")

        conn.commit()
        conn.close()

    def flag_package_for_reprocess(
        self,
        package_name: str,
        ecosystem: Optional[Ecosystem] = None,
        refresh_network: bool = False,
        priority: int = 100,
        reason: Optional[str] = None,
    ) -> int:
        """
        Flag a single package in squat_detections for prioritized reprocessing
        and enqueue into the persistent job queue.
        """
        conn = self._get_connection()
        cur = conn.cursor()
        now_iso = datetime.now(timezone.utc).isoformat()

        eco_filter = f"AND ecosystem = '{ecosystem.value}'" if ecosystem else ""
        cur.execute(
            f"""
            UPDATE squat_detections
            SET needs_reprocess = 1,
                refresh_network_data = ?,
                reprocess_priority = ?,
                reprocess_reason = ?,
                updated_at = ?
            WHERE package_name = ? {eco_filter}
            """,
            (1 if refresh_network else 0, priority, reason or "MANUAL_REQUEST", now_iso, package_name)
        )
        updated = cur.rowcount

        # Fetch row details to enqueue job
        cur.execute(
            f"""
            SELECT ecosystem, package_name, analysis_details_json
            FROM squat_detections
            WHERE package_name = ? {eco_filter}
            """,
            (package_name,)
        )
        row = cur.fetchone()
        if row:
            job_id = str(uuid.uuid4())
            cur.execute(
                """
                INSERT INTO sentinel_jobs_queue
                (job_id, ecosystem, package_name, job_type, priority, status, refresh_network_data, attempts, max_attempts, payload_json, enqueued_at)
                VALUES (?, ?, ?, 'RECALCULATE_SCORE', ?, 'PENDING', ?, 0, 3, ?, ?)
                ON CONFLICT(ecosystem, package_name, job_type) DO UPDATE SET
                    status = 'PENDING',
                    priority = excluded.priority,
                    refresh_network_data = excluded.refresh_network_data,
                    attempts = 0,
                    error_message = NULL,
                    leased_until = NULL,
                    enqueued_at = excluded.enqueued_at
                """,
                (job_id, row["ecosystem"], row["package_name"], priority, 1 if refresh_network else 0, row["analysis_details_json"] or "{}", now_iso)
            )

        conn.commit()
        conn.close()
        logger.info(f"Flagged '{package_name}' for reprocess (priority: {priority}, refresh_network: {refresh_network}, reason: {reason}).")
        return updated

    def bulk_flag_for_reprocess(
        self,
        ecosystem: Optional[Ecosystem] = None,
        verdict: Optional[str] = None,
        refresh_network: bool = False,
        priority: int = 100,
        reason: Optional[str] = None,
        min_score: Optional[int] = None,
        max_age_days: Optional[int] = None,
        keywords: Optional[List[str]] = None,
        unprocessed_only: bool = False,
        dry_run: bool = False,
    ) -> int:
        """
        Bulk flag packages matching criteria in squat_detections and enqueue into
        the job queue. Filters combine with AND:

          - ecosystem    : 'pypi' | 'npm'
          - verdict      : exact verdict string (MALICIOUS, SUSPICIOUS, ...)
          - min_score    : threat_score >= min_score
          - max_age_days : first published within the last N days
                           (published_at >= now - N days; rows with a NULL
                           published_at are excluded)
          - keywords     : audit every row *mentioning* any of these terms —
                           case-insensitive substring of the package name OR of
                           the stored analysis details (entity, homepage, author).
                           Keywords OR together; the group ANDs with the rest.

        With dry_run=True nothing is written and the count of matching rows is
        returned, so a caller can preview the scope before committing.
        """
        conn = self._get_connection()
        cur = conn.cursor()
        now = datetime.now(timezone.utc)
        now_iso = now.isoformat()

        filters: List[str] = []
        where_params: List[Any] = []
        if ecosystem:
            filters.append("ecosystem = ?")
            where_params.append(ecosystem.value)
        if verdict:
            filters.append("verdict = ?")
            where_params.append(verdict.upper())
        if min_score is not None:
            filters.append("threat_score >= ?")
            where_params.append(int(min_score))
        if max_age_days is not None:
            cutoff_iso = (now - timedelta(days=int(max_age_days))).isoformat()
            filters.append("published_at IS NOT NULL AND published_at >= ?")
            where_params.append(cutoff_iso)
        if unprocessed_only:
            filters.append("(needs_reprocess = 1 OR NOT EXISTS (SELECT 1 FROM sentinel_jobs_queue q WHERE q.ecosystem = squat_detections.ecosystem AND q.package_name = squat_detections.package_name AND q.status = 'COMPLETED'))")
        kw_clean = [k.strip().lower() for k in (keywords or []) if k and k.strip()]
        if kw_clean:
            ors = []
            for kw in kw_clean:
                ors.append("(LOWER(package_name) LIKE ? OR LOWER(COALESCE(analysis_details_json, '')) LIKE ?)")
                where_params.extend([f"%{kw}%", f"%{kw}%"])
            filters.append("(" + " OR ".join(ors) + ")")

        where_clause = f"WHERE {' AND '.join(filters)}" if filters else ""

        if dry_run:
            cur.execute(f"SELECT COUNT(*) AS c FROM squat_detections {where_clause}", where_params)
            match_count = cur.fetchone()["c"]
            conn.close()
            logger.info(
                f"[dry-run] bulk_flag_for_reprocess would flag {match_count} package(s) "
                f"({where_clause or 'no filters'})."
            )
            return match_count

        cur.execute(
            f"""
            UPDATE squat_detections
            SET needs_reprocess = 1,
                refresh_network_data = ?,
                reprocess_priority = ?,
                reprocess_reason = ?,
                updated_at = ?
            {where_clause}
            """,
            [1 if refresh_network else 0, priority, reason or "BULK_REPROCESS", now_iso, *where_params],
        )
        updated_count = cur.rowcount

        # Bulk enqueue into queue
        cur.execute(
            f"""
            SELECT ecosystem, package_name, analysis_details_json
            FROM squat_detections
            {where_clause}
            """,
            where_params,
        )
        rows = cur.fetchall()
        insert_tuples = []
        for r in rows:
            insert_tuples.append((
                str(uuid.uuid4()),
                r["ecosystem"],
                r["package_name"],
                "RECALCULATE_SCORE",
                priority,
                "PENDING",
                1 if refresh_network else 0,
                0,
                3,
                r["analysis_details_json"] or "{}",
                now_iso,
            ))

        if insert_tuples:
            upsert_sql = """
            INSERT INTO sentinel_jobs_queue
            (job_id, ecosystem, package_name, job_type, priority, status, refresh_network_data, attempts, max_attempts, payload_json, enqueued_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(ecosystem, package_name, job_type) DO UPDATE SET
                status = 'PENDING',
                priority = excluded.priority,
                refresh_network_data = excluded.refresh_network_data,
                attempts = 0,
                error_message = NULL,
                leased_until = NULL,
                enqueued_at = excluded.enqueued_at
            """
            cur.executemany(upsert_sql, insert_tuples)

        conn.commit()
        conn.close()
        logger.info(f"Bulk flagged {updated_count} packages for reprocess (priority: {priority}, refresh_network: {refresh_network}).")
        return updated_count

    def enqueue_recalc_jobs(
        self,
        ecosystem: Optional[Ecosystem] = None,
        job_type: str = "RECALCULATE_SCORE",
        priority: int = 100,
        refresh_network: bool = False,
    ) -> int:
        """
        Bulk enqueue detections from squat_detections into the persistent job queue.
        """
        return self.bulk_flag_for_reprocess(
            ecosystem=ecosystem,
            refresh_network=refresh_network,
            priority=priority,
            reason="MANUAL_ENQUEUE",
        )

    def lease_batch(
        self,
        batch_size: int = 25,
        lease_seconds: int = 60,
        job_type: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Lease a batch of highest-priority PENDING jobs (or expired IN_PROGRESS leases).
        Atomically marks them IN_PROGRESS with lease timestamp.
        """
        conn = self._get_connection()
        now_utc = datetime.now(timezone.utc)
        now_iso = now_utc.isoformat()
        lease_until_iso = (now_utc + timedelta(seconds=lease_seconds)).isoformat()

        type_filter = "AND job_type = ?" if job_type else ""
        type_params = [job_type] if job_type else []

        # Find candidates
        query = f"""
        SELECT job_id, ecosystem, package_name, job_type, priority, status, refresh_network_data, attempts, payload_json
        FROM sentinel_jobs_queue
        WHERE (status = 'PENDING' OR (status = 'IN_PROGRESS' AND leased_until <= ?))
          AND attempts < max_attempts
          {type_filter}
        ORDER BY priority DESC, enqueued_at ASC
        LIMIT ?
        """
        params = [now_iso] + type_params + [batch_size]

        cur = conn.cursor()
        cur.execute(query, params)
        rows = cur.fetchall()

        if not rows:
            conn.close()
            return []

        job_ids = [r["job_id"] for r in rows]
        placeholders = ",".join(["?"] * len(job_ids))

        # Atomically update to IN_PROGRESS
        update_sql = f"""
        UPDATE sentinel_jobs_queue
        SET status = 'IN_PROGRESS',
            leased_until = ?,
            attempts = attempts + 1
        WHERE job_id IN ({placeholders})
        """
        cur.execute(update_sql, [lease_until_iso] + job_ids)
        conn.commit()

        results = [dict(r) for r in rows]
        conn.close()
        return results

    def mark_job_completed(self, job_id: str) -> None:
        """Mark a job as successfully COMPLETED."""
        conn = self._get_connection()
        now_iso = datetime.now(timezone.utc).isoformat()
        conn.execute(
            "UPDATE sentinel_jobs_queue SET status = 'COMPLETED', completed_at = ?, leased_until = NULL WHERE job_id = ?",
            (now_iso, job_id)
        )
        conn.commit()
        conn.close()

    def mark_job_failed(self, job_id: str, error_message: str) -> None:
        """Mark a job as FAILED or return to PENDING if attempts remain."""
        conn = self._get_connection()
        conn.execute(
            """
            UPDATE sentinel_jobs_queue 
            SET status = CASE WHEN attempts >= max_attempts THEN 'FAILED' ELSE 'PENDING' END,
                error_message = ?,
                leased_until = NULL
            WHERE job_id = ?
            """,
            (error_message, job_id)
        )
        conn.commit()
        conn.close()

    def get_queue_summary(self) -> Dict[str, Any]:
        """Return counts and statistics of the persistent job queue."""
        conn = self._get_connection()
        cur = conn.cursor()
        cur.execute("""
        SELECT status, COUNT(*) as cnt 
        FROM sentinel_jobs_queue 
        GROUP BY status
        """)
        rows = cur.fetchall()
        summary = {
            "PENDING": 0,
            "IN_PROGRESS": 0,
            "COMPLETED": 0,
            "FAILED": 0,
            "TOTAL": 0,
        }
        for r in rows:
            st = r["status"]
            cnt = r["cnt"]
            summary[st] = cnt
            summary["TOTAL"] += cnt

        # Add network refresh statistics
        cur.execute("SELECT COUNT(*) as cnt FROM sentinel_jobs_queue WHERE status = 'PENDING' AND refresh_network_data = 1")
        pending_fresh_net = cur.fetchone()["cnt"]
        summary["PENDING_FRESH_NETWORK"] = pending_fresh_net
        summary["PENDING_LOCAL_RESCORE"] = summary["PENDING"] - pending_fresh_net

        conn.close()
        return summary

    def get_reprocessing_status(self) -> Dict[str, Any]:
        """Return status of row-level flags in squat_detections and the queue."""
        conn = self._get_connection()
        cur = conn.cursor()

        cur.execute("SELECT COUNT(*) as cnt FROM squat_detections WHERE needs_reprocess = 1")
        total_flagged = cur.fetchone()["cnt"]

        cur.execute("SELECT COUNT(*) as cnt FROM squat_detections WHERE needs_reprocess = 1 AND refresh_network_data = 1")
        flagged_fresh_net = cur.fetchone()["cnt"]

        cur.execute("SELECT reprocess_priority, COUNT(*) as cnt FROM squat_detections WHERE needs_reprocess = 1 GROUP BY reprocess_priority ORDER BY reprocess_priority DESC")
        prio_rows = cur.fetchall()
        prio_breakdown = {f"priority_{r['reprocess_priority']}": r["cnt"] for r in prio_rows}

        conn.close()

        queue_summary = self.get_queue_summary()
        return {
            "total_flagged_for_reprocess": total_flagged,
            "flagged_fresh_network_pull": flagged_fresh_net,
            "flagged_local_rescore_only": total_flagged - flagged_fresh_net,
            "priority_distribution": prio_breakdown,
            "job_queue": queue_summary,
        }

    async def process_queue_with_budget(
        self,
        time_budget_seconds: float = 60.0,
        batch_size: int = 25,
        concurrency: int = 5,
        job_type: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Process queued jobs with strict time-budget monitoring and bounded concurrency.
        Stops when time budget is exhausted or queue is drained, saving checkpoints to SQLite.
        """
        start_time = time.time()
        deadline = start_time + time_budget_seconds
        evaluator = ProgressiveThreatEvaluator(concurrency_limit=concurrency)
        sem = asyncio.Semaphore(concurrency)

        from slopguard.core.cache import DiskCacheManager
        cache_manager = DiskCacheManager()

        total_processed = 0
        total_completed = 0
        total_failed = 0

        logger.info(
            f"Starting queue processor (time budget: {time_budget_seconds:.1f}s, "
            f"batch size: {batch_size}, concurrency: {concurrency})..."
        )

        while True:
            remaining_time = deadline - time.time()
            if remaining_time <= 1.0:
                logger.info(f"Time budget exhausted ({time_budget_seconds:.1f}s reached). Gracefully yielding.")
                break

            batch = self.lease_batch(batch_size=batch_size, lease_seconds=60, job_type=job_type)
            if not batch:
                logger.info("No pending or retryable jobs found in queue.")
                break

            async def process_single_job(job: Dict[str, Any]):
                nonlocal total_completed, total_failed
                job_id = job["job_id"]
                eco = Ecosystem(job["ecosystem"])
                pkg_name = job["package_name"]
                refresh_network = bool(job.get("refresh_network_data", 0))

                try:
                    payload = json.loads(job["payload_json"] or "{}")
                except Exception:
                    payload = {}

                entity = payload.get("entity", pkg_name.split("-")[0])
                cap = payload.get("capability", "general")
                fw = payload.get("framework", "python" if eco == Ecosystem.PYPI else "npm")

                candidate = WatchlistCandidate(
                    ecosystem=eco,
                    normalized_name=pkg_name,
                    entity_token=entity,
                    capability_token=cap,
                    framework_token=fw,
                    risk_weight=75,
                )

                try:
                    if refresh_network:
                        # Invalidate disk cache to force clean network download
                        cache_manager.evict_package(eco.value, pkg_name)

                    async with sem:
                        new_detection = await evaluator.evaluate_candidate(candidate)

                    # Preserve existing download statistics if present and not re-fetched
                    if "usage_metrics" in payload and not refresh_network:
                        new_detection.analysis_details["usage_metrics"] = payload["usage_metrics"]

                    # Update squat_detections table, clearing needs_reprocess flags
                    pub_dt_iso = (new_detection.first_published_at or new_detection.published_at).isoformat()
                    conn = self._get_connection()
                    conn.execute(
                        """
                        UPDATE squat_detections
                        SET published_at = ?,
                            author_username = ?,
                            release_version = ?,
                            threat_score = ?,
                            verdict = ?,
                            analysis_details_json = ?,
                            needs_reprocess = 0,
                            refresh_network_data = 0,
                            reprocess_reason = NULL,
                            is_exported = 0,
                            updated_at = ?
                        WHERE ecosystem = ? AND package_name = ?
                        """,
                        (
                            pub_dt_iso,
                            new_detection.author_username,
                            new_detection.release_version,
                            new_detection.threat_score,
                            new_detection.verdict.value,
                            json.dumps(new_detection.analysis_details),
                            datetime.now(timezone.utc).isoformat(),
                            eco.value,
                            pkg_name,
                        )
                    )
                    conn.commit()
                    conn.close()

                    self.mark_job_completed(job_id)
                    total_completed += 1
                except Exception as e:
                    logger.warning(f"Error processing job for {pkg_name}: {e}")
                    self.mark_job_failed(job_id, str(e))
                    total_failed += 1

            await asyncio.gather(*[process_single_job(j) for j in batch])
            total_processed += len(batch)
            logger.info(f"Processed batch of {len(batch)} jobs (Elapsed: {time.time() - start_time:.1f}s)")

        summary = self.get_queue_summary()
        summary.update({
            "elapsed_seconds": round(time.time() - start_time, 2),
            "processed_in_run": total_processed,
            "completed_in_run": total_completed,
            "failed_in_run": total_failed,
        })
        logger.info(f"Run finished: {summary}")
        return summary
