"""
Sentinel Database Repository.

Data access layer providing asynchronous high-throughput CRUD operations,
bulk catalog syncing, and O(1) watchlist matching.
"""

import json
import re
import asyncio
import logging
from typing import List, Optional, Set, Tuple, Dict
from datetime import datetime, timezone
from sqlalchemy import select, update, delete, text, func
from sqlalchemy.exc import OperationalError

from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger("sentinel.repository")

from sentinel.core.dto import (
    Ecosystem,
    WatchlistState,
    ThreatVerdict,
    RegisteredPackage,
    WatchlistCandidate,
    SquatDetection,
)
from sentinel.db.models import (
    RegisteredPackageModel,
    UnregisteredWatchlistModel,
    SquatDetectionModel,
    SignalFindingModel,
    ScanAuditLogModel,
    DailyReviewLogModel,
)
from sentinel.core.signals import findings_from_analysis_details, severity_rank


def _ensure_utc(dt: Optional[datetime]) -> Optional[datetime]:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


class SentinelRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def _write_with_retry(self, write_fn, retries: int = 5, base_delay: float = 0.2):
        """
        Run an async write callback (which performs its own session.execute()/commit())
        with exponential backoff retry on transient 'database is locked' contention.

        A bare retry of commit() alone is unsafe here: when SQLite raises 'database is
        locked' it's typically during the implicit flush of a pending execute(), which
        leaves the session needing rollback() before reuse — simply retrying commit()
        after that would silently drop the write. So the whole execute+commit unit is
        re-run on each attempt; write_fn must be safe to call more than once (every
        write method that uses this performs idempotent SET-style updates).

        SQLite's PRAGMA busy_timeout already retries internally for a bounded window,
        but under sustained overlap with other concurrent writers against the same
        database file, that window can still be exhausted — this is the second layer
        of resilience so a transient lock doesn't abort an otherwise-successful cycle.
        """
        for attempt in range(retries):
            try:
                return await write_fn()
            except OperationalError as e:
                if "database is locked" in str(e).lower() and attempt < retries - 1:
                    delay = base_delay * (2 ** attempt)
                    logger.warning(f"SQLite locked (attempt {attempt + 1}/{retries}); retrying in {delay:.2f}s.")
                    await self.session.rollback()
                    await asyncio.sleep(delay)
                    continue
                raise

    # ==================== Registered Packages Catalog ====================

    async def bulk_sync_registered_packages(self, ecosystem: Ecosystem, package_names: Set[str]) -> int:
        """
        Bulk upsert full catalog of package names for an ecosystem.
        Uses thread-safe aiosqlite executemany.
        """
        from sentinel.scheduler.queue import compute_brand_priority

        now_str = datetime.now(timezone.utc).isoformat()
        sql = """
        INSERT OR REPLACE INTO registered_packages 
        (package_id, ecosystem, normalized_name, raw_name, is_brand_target, priority_score, synced_at) 
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """
        tuples = []
        for name in package_names:
            brand_res = compute_brand_priority(name)
            is_brand = 1 if brand_res is not None else 0
            score = brand_res[1] if brand_res is not None else 10
            tuples.append((
                f"{ecosystem.value}_{name}",
                ecosystem.value,
                name,
                name,
                is_brand,
                score,
                now_str,
            ))

        if not tuples:
            return 0

        conn = await self.session.connection()
        raw = await conn.get_raw_connection()
        driver = getattr(raw, "driver_connection", raw)

        CHUNK_SIZE = 5000
        for i in range(0, len(tuples), CHUNK_SIZE):
            chunk = tuples[i : i + CHUNK_SIZE]
            if hasattr(driver, "executemany"):
                await driver.executemany(sql, chunk)
                await driver.commit()
            else:
                await conn.exec_driver_sql(sql, chunk)
                await self.session.commit()

        return len(tuples)

    async def get_registered_names_set(self, ecosystem: Ecosystem) -> Set[str]:
        """Fetch all registered package names for an ecosystem as a fast in-memory set."""
        query = select(RegisteredPackageModel.normalized_name).where(
            RegisteredPackageModel.ecosystem == ecosystem.value
        )
        result = await self.session.execute(query)
        return set(result.scalars().all())

    # ==================== Unregistered Watchlist ====================

    async def bulk_upsert_watchlist(self, candidates: List[WatchlistCandidate]) -> int:
        """Bulk insert generated candidate space into the unregistered watchlist."""
        if not candidates:
            return 0

        sql = """
        INSERT OR IGNORE INTO unregistered_watchlist 
        (candidate_id, ecosystem, normalized_name, entity_token, capability_token, framework_token, risk_weight, state, generated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        now_str = datetime.now(timezone.utc).isoformat()
        tuples = [
            (
                c.candidate_id,
                c.ecosystem.value,
                c.normalized_name,
                c.entity_token,
                c.capability_token,
                c.framework_token,
                c.risk_weight,
                c.state.value,
                now_str,
            )
            for c in candidates
        ]

        conn = await self.session.connection()
        raw = await conn.get_raw_connection()
        driver = getattr(raw, "driver_connection", raw)

        CHUNK_SIZE = 5000
        for i in range(0, len(tuples), CHUNK_SIZE):
            chunk = tuples[i : i + CHUNK_SIZE]
            if hasattr(driver, "executemany"):
                await driver.executemany(sql, chunk)
                await driver.commit()
            else:
                await conn.exec_driver_sql(sql, chunk)
                await self.session.commit()

        return len(tuples)






    async def get_watchlist_names_set(self, ecosystem: Ecosystem) -> Set[str]:
        """Fetch all currently WATCHING candidates as an in-memory set for O(1) matching."""
        query = select(UnregisteredWatchlistModel.normalized_name).where(
            UnregisteredWatchlistModel.ecosystem == ecosystem.value,
            UnregisteredWatchlistModel.state == WatchlistState.WATCHING.value,
        )
        result = await self.session.execute(query)
        return set(result.scalars().all())

    async def get_candidate_by_name(self, ecosystem: Ecosystem, normalized_name: str) -> Optional[WatchlistCandidate]:
        """Lookup a candidate record by name."""
        query = select(UnregisteredWatchlistModel).where(
            UnregisteredWatchlistModel.ecosystem == ecosystem.value,
            UnregisteredWatchlistModel.normalized_name == normalized_name,
        )
        result = await self.session.execute(query)
        r = result.scalars().first()
        if not r:
            return None

        return WatchlistCandidate(
            candidate_id=r.candidate_id,
            ecosystem=Ecosystem(r.ecosystem),
            normalized_name=r.normalized_name,
            entity_token=r.entity_token,
            capability_token=r.capability_token,
            framework_token=r.framework_token,
            risk_weight=r.risk_weight,
            state=WatchlistState(r.state),
            generated_at=r.generated_at,
        )

    # ==================== Daily Review Rule Enforcement ====================
    # Invariant: a package may only be REVIEWED (i.e. actually evaluated — network
    # metadata/tarball fetch + scoring) at most once per UTC calendar day. This is
    # enforced here at the persistence layer so it holds regardless of bugs or races
    # in task-collection logic upstream (scheduler/worker.py calls this before doing
    # any network work).

    async def try_claim_daily_review(self, ecosystem: Ecosystem, package_name: str) -> bool:
        """
        Atomically record a review attempt for (ecosystem, package_name) on today's UTC date.

        Returns True if this is the FIRST attempt today (caller must proceed with the
        review). Returns False if the package was already reviewed today (caller MUST
        skip — do not re-evaluate). Every attempt, allowed or not, increments
        review_count so duplicate-attempt volume stays visible for compliance checks.
        """
        today_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        now_iso = datetime.now(timezone.utc).replace(microsecond=0).isoformat()

        sql = """
        INSERT INTO daily_review_log (ecosystem, package_name, review_date, review_count, first_reviewed_at, last_attempted_at)
        VALUES (:eco, :pkg, :date, 1, :now, :now)
        ON CONFLICT(ecosystem, package_name, review_date) DO UPDATE SET
            review_count = review_count + 1,
            last_attempted_at = excluded.last_attempted_at
        """
        async def _do():
            await self.session.execute(text(sql), {"eco": ecosystem.value, "pkg": package_name, "date": today_str, "now": now_iso})
            await self.session.commit()

        await self._write_with_retry(_do)

        check_sql = """
        SELECT review_count FROM daily_review_log
        WHERE ecosystem = :eco AND package_name = :pkg AND review_date = :date
        """
        result = await self.session.execute(text(check_sql), {"eco": ecosystem.value, "pkg": package_name, "date": today_str})
        row = result.first()
        review_count = row[0] if row else 1
        return review_count == 1

    async def get_packages_reviewed_today(self, ecosystem: Ecosystem) -> Set[str]:
        """Fetch the set of packages already reviewed today, for proactive task-collection filtering."""
        today_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        query = select(DailyReviewLogModel.package_name).where(
            DailyReviewLogModel.ecosystem == ecosystem.value,
            DailyReviewLogModel.review_date == today_str,
        )
        result = await self.session.execute(query)
        return set(result.scalars().all())

    async def get_daily_review_compliance_report(self, review_date: Optional[str] = None) -> dict:
        """
        Report on same-day review compliance. Because try_claim_daily_review() only ever
        lets the FIRST attempt for a package proceed, real violations should always be 0 —
        this surfaces that guarantee plus how much duplicate-attempt volume the scheduler
        is generating (worth investigating/tuning down even though it's harmless).
        """
        if review_date is None:
            review_date = datetime.now(timezone.utc).strftime("%Y-%m-%d")

        query = select(DailyReviewLogModel).where(DailyReviewLogModel.review_date == review_date)
        result = await self.session.execute(query)
        rows = result.scalars().all()

        distinct_packages = len(rows)
        duplicate_attempts_blocked = sum(max(0, r.review_count - 1) for r in rows)
        violations = [
            {"ecosystem": r.ecosystem, "package_name": r.package_name, "review_count": r.review_count}
            for r in rows if r.review_count < 1
        ]  # structurally impossible given the enforcement above; kept as an explicit tripwire

        return {
            "review_date": review_date,
            "distinct_packages_reviewed": distinct_packages,
            "duplicate_attempts_blocked": duplicate_attempts_blocked,
            "rule_violations": violations,
            "rule_compliant": len(violations) == 0,
        }

    # ==================== Squat Detections ====================

    @staticmethod
    def _compute_detection_hash(
        ecosystem: str,
        package_name: str,
        author_username: Optional[str],
        release_version: str,
        threat_score: int,
        verdict: str,
        analysis_details: dict,
    ) -> str:
        """Compute deterministic SHA-256 hash of substantive detection payload."""
        import hashlib
        # Omit volatile audit runtime timestamps when computing substantive hash
        filtered_analysis = {k: v for k, v in analysis_details.items() if k not in ("last_audited_at", "updated_at")}
        raw_repr = json.dumps({
            "ecosystem": ecosystem,
            "package_name": package_name,
            "author_username": author_username or "",
            "release_version": release_version,
            "threat_score": threat_score,
            "verdict": verdict,
            "analysis_details": filtered_analysis,
        }, sort_keys=True)
        return hashlib.sha256(raw_repr.encode("utf-8")).hexdigest()

    async def record_detection(self, detection: SquatDetection) -> SquatDetection:
        """
        Record or update a slopsquatting detection event.
        Preserves created_at; updates updated_at with second precision only if data changes.
        """
        now_second = datetime.now(timezone.utc).replace(microsecond=0)
        content_hash = self._compute_detection_hash(
            detection.ecosystem.value,
            detection.package_name,
            detection.author_username,
            detection.release_version or "0.1.0",
            detection.threat_score,
            detection.verdict.value,
            detection.analysis_details,
        )

        cid = None
        if detection.candidate_id:
            query = select(UnregisteredWatchlistModel).where(UnregisteredWatchlistModel.candidate_id == detection.candidate_id)
            res = await self.session.execute(query)
            existing_candidate = res.scalars().first()
            if existing_candidate:
                cid = detection.candidate_id
                existing_candidate.state = WatchlistState.SQUATTED.value

        # Check if record already exists for (ecosystem, package_name) or detection_id
        query = select(SquatDetectionModel).where(
            (SquatDetectionModel.ecosystem == detection.ecosystem.value) &
            (SquatDetectionModel.package_name == detection.package_name)
        )
        res = await self.session.execute(query)
        existing_model = res.scalars().first()

        from sentinel.scheduler.freshness import calculate_next_audit_time

        pub_dt = detection.published_at or now_second
        next_due = calculate_next_audit_time(pub_dt, last_audited_at=now_second, now_utc=now_second)

        has_install_hook = bool(detection.analysis_details.get("has_install_hook", False))
        has_network_socket = bool(detection.analysis_details.get("has_network_socket", False))
        is_deprecated = bool(getattr(detection, "is_deprecated", False))
        deprecation_reason = getattr(detection, "deprecation_reason", None)

        if existing_model:
            existing_model.last_audited_at = now_second
            existing_model.audit_count = (existing_model.audit_count or 1) + 1
            existing_model.next_audit_due_at = next_due

            # Check if content has changed
            if existing_model.content_hash != content_hash:
                existing_model.author_username = detection.author_username
                existing_model.release_version = detection.release_version or "0.1.0"
                existing_model.threat_score = detection.threat_score
                existing_model.verdict = detection.verdict.value
                existing_model.analysis_details_json = json.dumps(detection.analysis_details)
                existing_model.content_hash = content_hash
                existing_model.updated_at = now_second
                existing_model.is_exported = False
                existing_model.has_install_hook = has_install_hook
                existing_model.has_network_socket = has_network_socket
                existing_model.is_deprecated = is_deprecated
                existing_model.deprecation_reason = deprecation_reason
                if cid:
                    existing_model.candidate_id = cid

            detection.created_at = _ensure_utc(existing_model.created_at)
            detection.updated_at = _ensure_utc(existing_model.updated_at)
            detection.content_hash = existing_model.content_hash
            detection.detection_id = existing_model.detection_id
            detection.audit_count = existing_model.audit_count
            detection.next_audit_due_at = _ensure_utc(existing_model.next_audit_due_at)
            detection.last_audited_at = _ensure_utc(existing_model.last_audited_at)
            detection.is_deprecated = existing_model.is_deprecated
            detection.deprecation_reason = existing_model.deprecation_reason
        else:
            model = SquatDetectionModel(
                detection_id=detection.detection_id,
                candidate_id=cid,
                ecosystem=detection.ecosystem.value,
                package_name=detection.package_name,
                author_username=detection.author_username,
                release_version=detection.release_version or "0.1.0",
                published_at=detection.published_at.replace(microsecond=0) if detection.published_at else now_second,
                threat_score=detection.threat_score,
                analysis_details_json=json.dumps(detection.analysis_details),
                is_exported=detection.is_exported,
                verdict=detection.verdict.value,
                content_hash=content_hash,
                audit_count=1,
                last_audited_at=now_second,
                next_audit_due_at=next_due,
                priority_tier=detection.priority_tier,
                has_install_hook=has_install_hook,
                has_network_socket=has_network_socket,
                is_deprecated=is_deprecated,
                deprecation_reason=deprecation_reason,
                created_at=detection.created_at.replace(microsecond=0) if detection.created_at else now_second,
                updated_at=detection.updated_at.replace(microsecond=0) if detection.updated_at else now_second,
            )
            self.session.add(model)
            detection.created_at = _ensure_utc(model.created_at)
            detection.updated_at = _ensure_utc(model.updated_at)
            detection.content_hash = content_hash
            detection.audit_count = 1
            detection.next_audit_due_at = _ensure_utc(next_due)
            detection.last_audited_at = _ensure_utc(now_second)

        await self.session.commit()

        # Normalized per-signal rows for the query-anywhere findings layer. Kept
        # best-effort: a findings write failure must never lose the detection.
        try:
            await self._replace_findings(detection)
        except Exception as e:
            logger.warning(f"findings sync failed for {detection.package_name}: {e}")

        return detection

    async def _replace_findings(self, detection: SquatDetection) -> int:
        """
        Rewrite ``sentinel_findings`` rows for one detection: delete the old set,
        insert the current one. Findings-per-package is tiny (< ~30), so a full
        replace is cheaper and simpler than a diff and keeps the table an exact
        materialization of the detection's current signal set.
        """
        findings = findings_from_analysis_details(detection.analysis_details)
        det_id = detection.detection_id
        eco = detection.ecosystem.value
        pkg = detection.package_name
        score = int(detection.threat_score or 0)
        verdict = detection.verdict.value
        pub = _ensure_utc(detection.published_at)

        rows = []
        for f in findings:
            rows.append({
                "detection_id": det_id,
                "ecosystem": eco,
                "package_name": pkg,
                "signal_code": f.code[:64],
                "category": (f.category or "GENERAL")[:32],
                "severity": (f.severity or "MEDIUM")[:16],
                "severity_rank": severity_rank(f.severity),
                "score": int(f.score or 0),
                "confidence": max(0, min(100, int(round((f.confidence or 1.0) * 100)))),
                "kind": (f.kind or "ASSESSMENT")[:16],
                "detector": (f.detector or "unknown")[:64],
                "is_code_execution": bool(f.is_code_execution),
                "gates_malicious": bool(f.gates_malicious),
                "metadata_json": json.dumps(f.metadata or {}),
                "threat_score": score,
                "verdict": verdict,
                "published_at": pub,
            })

        async def _do():
            await self.session.execute(
                delete(SignalFindingModel).where(SignalFindingModel.detection_id == det_id)
            )
            if rows:
                await self.session.execute(SignalFindingModel.__table__.insert(), rows)
            await self.session.commit()

        await self._write_with_retry(_do)
        return len(rows)

    async def find_detections_by_signals(
        self,
        signal_codes: List[str],
        *,
        mode: str = "any",
        ecosystem: Optional[Ecosystem] = None,
        min_score: int = 0,
        order_by: str = "threat_score",
        limit: int = 50,
        offset: int = 0,
    ) -> List[SquatDetection]:
        """
        Web-UI query: every detection carrying (any|all of) the given signal
        codes. Runs entirely against the indexed ``sentinel_findings`` table
        until the final hydration of ``squat_detections`` rows.
        """
        codes = [c for c in {c.strip() for c in signal_codes} if c]
        if not codes:
            return []

        order_col = (
            SignalFindingModel.published_at.desc()
            if order_by == "published_at"
            else SignalFindingModel.threat_score.desc()
        )

        where = [SignalFindingModel.signal_code.in_(codes)]
        if ecosystem:
            where.append(SignalFindingModel.ecosystem == ecosystem.value)
        if min_score:
            where.append(SignalFindingModel.threat_score >= min_score)

        sort_col = (
            SignalFindingModel.published_at if order_by == "published_at"
            else SignalFindingModel.threat_score
        )

        if len(codes) == 1:
            # No dedup needed — (detection_id, signal_code) is unique. A plain
            # indexed range scan on idx_finding_signal_feed / _signal_recent.
            base = (
                select(SignalFindingModel.detection_id)
                .where(*where)
                .order_by(sort_col.desc())
                .limit(limit)
                .offset(offset)
            )
        else:
            base = select(SignalFindingModel.detection_id).where(*where).group_by(SignalFindingModel.detection_id)
            if mode == "all":
                base = base.having(func.count(func.distinct(SignalFindingModel.signal_code)) == len(codes))
            base = base.order_by(func.max(sort_col).desc()).limit(limit).offset(offset)

        result = await self.session.execute(base)
        det_ids = [r[0] for r in result.all()]
        if not det_ids:
            return []

        det_rows = await self.session.execute(
            select(SquatDetectionModel).where(SquatDetectionModel.detection_id.in_(det_ids))
        )
        by_id = {r.detection_id: r for r in det_rows.scalars().all()}
        ordered = [by_id[i] for i in det_ids if i in by_id]
        return [self._row_to_detection(r) for r in ordered]

    async def get_signal_stats(self, ecosystem: Optional[Ecosystem] = None) -> List[Dict]:
        """
        Facet-sidebar payload: package/instance counts per signal code. Cache this
        upstream (it's a full index scan) — it does not need to be real-time.
        """
        q = select(
            SignalFindingModel.signal_code,
            SignalFindingModel.category,
            func.max(SignalFindingModel.severity_rank),
            func.count(func.distinct(SignalFindingModel.package_name)),
            func.count(SignalFindingModel.id),
        )
        if ecosystem:
            q = q.where(SignalFindingModel.ecosystem == ecosystem.value)
        q = q.group_by(SignalFindingModel.signal_code, SignalFindingModel.category)

        result = await self.session.execute(q)
        out = []
        for code, category, sev_rank, pkgs, instances in result.all():
            out.append({
                "signal_code": code,
                "category": category,
                "severity_rank": int(sev_rank or 0),
                "package_count": int(pkgs or 0),
                "instance_count": int(instances or 0),
            })
        out.sort(key=lambda r: (-r["package_count"], r["signal_code"]))
        return out

    async def backfill_findings(self, batch_size: int = 500) -> Dict[str, int]:
        """
        Populate ``sentinel_findings`` for every existing detection from its stored
        ``analysis_details_json`` — no re-crawl or network calls. Mirrors
        ``backfill_install_hook_flags``.
        """
        result = await self.session.execute(
            select(
                SquatDetectionModel.detection_id,
                SquatDetectionModel.ecosystem,
                SquatDetectionModel.package_name,
                SquatDetectionModel.threat_score,
                SquatDetectionModel.verdict,
                SquatDetectionModel.published_at,
                SquatDetectionModel.analysis_details_json,
            )
        )
        rows = result.all()
        total_findings = 0
        processed = 0

        pending: List[dict] = []
        del_ids: List[str] = []

        async def _flush():
            if not del_ids:
                return
            async def _do():
                await self.session.execute(
                    delete(SignalFindingModel).where(SignalFindingModel.detection_id.in_(del_ids))
                )
                if pending:
                    await self.session.execute(SignalFindingModel.__table__.insert(), pending)
                await self.session.commit()
            await self._write_with_retry(_do)
            del_ids.clear()
            pending.clear()

        for det_id, eco, pkg, score, verdict, pub, details_json in rows:
            try:
                details = json.loads(details_json or "{}")
            except Exception:
                details = {}
            findings = findings_from_analysis_details(details)
            del_ids.append(det_id)
            pub_dt = _ensure_utc(pub)
            for f in findings:
                pending.append({
                    "detection_id": det_id, "ecosystem": eco, "package_name": pkg,
                    "signal_code": f.code[:64], "category": (f.category or "GENERAL")[:32],
                    "severity": (f.severity or "MEDIUM")[:16], "severity_rank": severity_rank(f.severity),
                    "score": int(f.score or 0),
                    "confidence": max(0, min(100, int(round((f.confidence or 1.0) * 100)))),
                    "kind": (f.kind or "ASSESSMENT")[:16], "detector": (f.detector or "unknown")[:64],
                    "is_code_execution": bool(f.is_code_execution), "gates_malicious": bool(f.gates_malicious),
                    "metadata_json": json.dumps(f.metadata or {}),
                    "threat_score": int(score or 0), "verdict": verdict, "published_at": pub_dt,
                })
                total_findings += 1
            processed += 1
            if len(del_ids) >= batch_size:
                await _flush()

        await _flush()
        return {"detections_processed": processed, "findings_written": total_findings}

    def _row_to_detection(self, r: SquatDetectionModel) -> SquatDetection:
        now = datetime.now(timezone.utc).replace(microsecond=0)
        return SquatDetection(
            detection_id=r.detection_id,
            candidate_id=r.candidate_id,
            ecosystem=Ecosystem(r.ecosystem),
            package_name=r.package_name,
            author_username=r.author_username,
            release_version=r.release_version,
            published_at=_ensure_utc(r.published_at),
            threat_score=r.threat_score,
            analysis_details=json.loads(r.analysis_details_json or "{}"),
            is_exported=r.is_exported,
            verdict=ThreatVerdict(r.verdict),
            content_hash=r.content_hash,
            audit_count=r.audit_count or 1,
            last_audited_at=_ensure_utc(r.last_audited_at) or now,
            next_audit_due_at=_ensure_utc(r.next_audit_due_at),
            priority_tier=r.priority_tier or 2,
            is_deprecated=bool(getattr(r, "is_deprecated", False)),
            deprecation_reason=getattr(r, "deprecation_reason", None),
            created_at=_ensure_utc(r.created_at) or _ensure_utc(r.published_at) or now,
            updated_at=_ensure_utc(r.updated_at) or _ensure_utc(r.published_at) or now,
        )

    async def get_due_freshness_reaudits(self, limit: int = 50, now_utc: Optional[datetime] = None) -> List[SquatDetection]:
        """Fetch detections that are due for a scheduled freshness re-audit."""
        if now_utc is None:
            now_utc = datetime.now(timezone.utc).replace(microsecond=0)
        elif now_utc.tzinfo is None:
            now_utc = now_utc.replace(tzinfo=timezone.utc, microsecond=0)

        query = (
            select(SquatDetectionModel)
            .where(
                (SquatDetectionModel.next_audit_due_at.isnot(None)) &
                (SquatDetectionModel.next_audit_due_at <= now_utc)
            )
            .order_by(SquatDetectionModel.threat_score.desc(), SquatDetectionModel.next_audit_due_at.asc())
            .limit(limit)
        )
        result = await self.session.execute(query)
        rows = result.scalars().all()
        return [
            SquatDetection(
                detection_id=r.detection_id,
                candidate_id=r.candidate_id,
                ecosystem=Ecosystem(r.ecosystem),
                package_name=r.package_name,
                author_username=r.author_username,
                release_version=r.release_version,
                published_at=_ensure_utc(r.published_at),
                threat_score=r.threat_score,
                analysis_details=json.loads(r.analysis_details_json or "{}"),
                is_exported=r.is_exported,
                verdict=ThreatVerdict(r.verdict),
                content_hash=r.content_hash,
                audit_count=r.audit_count or 1,
                last_audited_at=_ensure_utc(r.last_audited_at) or now_utc,
                next_audit_due_at=_ensure_utc(r.next_audit_due_at),
                priority_tier=r.priority_tier or 2,
                is_deprecated=bool(getattr(r, "is_deprecated", False)),
                deprecation_reason=getattr(r, "deprecation_reason", None),
                created_at=_ensure_utc(r.created_at) or now_utc,
                updated_at=_ensure_utc(r.updated_at) or now_utc,
            )
            for r in rows
        ]

    async def get_brand_targets_to_crawl(
        self,
        ecosystem: Ecosystem,
        brand_tokens: List[str],
        limit: int = 50,
    ) -> List[str]:
        """Fetch un-crawled packages matching high-priority brand name tokens."""
        if not brand_tokens:
            return []

        conditions = []
        for b in brand_tokens:
            b_clean = b.lower().strip()
            conditions.append(RegisteredPackageModel.normalized_name.like(f"{b_clean}-%"))
            conditions.append(RegisteredPackageModel.normalized_name.like(f"%-{b_clean}-%"))
            conditions.append(RegisteredPackageModel.normalized_name.like(f"%-{b_clean}"))

        from sqlalchemy import or_
        query = (
            select(RegisteredPackageModel.normalized_name)
            .where(
                (RegisteredPackageModel.ecosystem == ecosystem.value) &
                (RegisteredPackageModel.crawled_at.is_(None)) &
                or_(*conditions)
            )
            .order_by(RegisteredPackageModel.synced_at.desc())
            .limit(limit)
        )
        result = await self.session.execute(query)
        return list(result.scalars().all())

    async def get_high_threat_actor_identifiers(self, min_score: int = 90) -> Tuple[Set[str], Set[str]]:
        """
        Fetch all author emails and author usernames linked to existing high-threat packages (score >= min_score).
        Excludes official vendor domains and generic placeholders.
        """
        query = select(SquatDetectionModel).where(
            (SquatDetectionModel.threat_score >= min_score) &
            (SquatDetectionModel.verdict != ThreatVerdict.VERIFIED_OFFICIAL.value)
        )
        result = await self.session.execute(query)
        rows = result.scalars().all()
        emails: Set[str] = set()
        authors: Set[str] = set()
        from sentinel.core.normalizers import extract_clean_email_and_domain
        for r in rows:
            details = json.loads(r.analysis_details_json or "{}")
            raw_email = details.get("author_email")
            clean_email, clean_domain = extract_clean_email_and_domain(raw_email)
            if clean_email and clean_domain not in ("google.com", "microsoft.com", "amazon.com", "apple.com", "stripe.com"):
                emails.add(clean_email)
            if r.author_username and r.author_username.lower() not in ("unknown", "none", "unspecified"):
                authors.add(r.author_username.lower())
        return emails, authors

    async def get_historical_backfill_targets(
        self,
        ecosystem: Ecosystem,
        limit: int = 50,
        oldest_first: bool = False,
    ) -> List[str]:
        """
        Fetch un-crawled packages whose name matches the combinatorial naming grammar
        (matches_grammar=1 — see mark_grammar_matching_packages()). Default newest-first;
        set oldest_first=True for older-budget allocation.

        Deliberately scoped to grammar matches only, not "every registered package" —
        auditing an unrelated catalog entry that never matched any entity/capability/
        framework combination doesn't serve the slopsquatting mission and was the
        dominant driver of both wasted crawl budget and disk usage (84.9% of recorded
        detections were BENIGN_COMMUNITY packages swept up by an unscoped backfill).
        """
        order = RegisteredPackageModel.synced_at.asc() if oldest_first else RegisteredPackageModel.synced_at.desc()
        query = (
            select(RegisteredPackageModel.normalized_name)
            .where(
                (RegisteredPackageModel.ecosystem == ecosystem.value) &
                (RegisteredPackageModel.crawled_at.is_(None)) &
                (RegisteredPackageModel.matches_grammar.is_(True))
            )
            .order_by(order)
            .limit(limit)
        )
        result = await self.session.execute(query)
        return list(result.scalars().all())

    async def mark_grammar_matching_packages(
        self,
        ecosystem: Ecosystem,
        candidate_limit: int = 500000,
    ) -> int:
        """
        Flag registered_packages rows whose normalized_name matches the combinatorial
        entity+capability+framework naming grammar (sentinel.matrix.generator), using
        the same candidate-generation + set-intersection approach as `audit-catalog`.
        Returns the number of newly-flagged rows.
        """
        from sentinel.matrix.generator import generate_ecosystem_candidates

        candidates = generate_ecosystem_candidates(ecosystem, limit=candidate_limit)
        candidate_names = {c.normalized_name for c in candidates}

        registered_set = await self.get_registered_names_set(ecosystem)
        matches = list(registered_set & candidate_names)
        if not matches:
            return 0

        batch_size = 500
        updated = 0
        for i in range(0, len(matches), batch_size):
            batch = matches[i:i + batch_size]
            placeholders = ", ".join(f":n{j}" for j in range(len(batch)))
            params = {f"n{j}": name for j, name in enumerate(batch)}
            params["eco"] = ecosystem.value
            sql = f"""
            UPDATE registered_packages
            SET matches_grammar = 1
            WHERE ecosystem = :eco AND normalized_name IN ({placeholders})
            """

            async def _do(sql=sql, params=params):
                await self.session.execute(text(sql), params)
                await self.session.commit()

            await self._write_with_retry(_do)
            updated += len(batch)

        return updated

    # Generic filler words that show up constantly in package names but carry no
    # brand/capability/framework signal of their own — excluded from the taxonomy
    # gap report so real candidates aren't buried under noise. Deliberately
    # separate from the taxonomy-membership check below (a word can be common
    # AND already tracked, e.g. "sdk"/"cli"/"api" are CAPABILITIES entries).
    TAXONOMY_GAP_STOPWORDS = {
        "the", "and", "for", "with", "from", "this", "that", "our", "your", "you",
        "are", "was", "not", "but", "all", "can", "has", "have", "will", "new",
        "app", "lib", "src", "dev", "test", "demo", "example", "sample", "temp",
        "tmp", "old", "backup", "copy", "final", "beta", "alpha", "release",
        "package", "module", "project", "code", "file", "data", "util", "utils",
        "helper", "helpers", "common", "shared", "base", "main", "index", "js",
        "py", "python", "node", "npm", "pip",
    }

    async def get_taxonomy_gap_report(
        self,
        ecosystem: Ecosystem,
        top_n: int = 50,
        min_token_length: int = 3,
    ) -> List[Tuple[str, int]]:
        """
        Tokenize the full registered catalog and surface the most frequent tokens
        NOT already covered by the naming-grammar taxonomies (entities, capabilities,
        frameworks, priority brand weights) — candidates worth a human reviewing for
        taxonomy expansion. Intended for periodic (e.g. quarterly) review as part of
        the naming-grammar's ongoing maintenance, not automated self-expansion.
        """
        from sentinel.core.taxonomies import ENTITIES, CAPABILITIES, FRAMEWORKS
        from sentinel.scheduler.queue import PRIORITY_BRAND_WEIGHTS
        from collections import Counter

        known_tokens: Set[str] = {t.lower() for t in ENTITIES} | {t.lower() for t in CAPABILITIES}
        for fw_list in FRAMEWORKS.values():
            known_tokens |= {t.lower() for t in fw_list}
        known_tokens |= set(PRIORITY_BRAND_WEIGHTS.keys())

        names = await self.get_registered_names_set(ecosystem)

        token_pattern = re.compile(r"[a-z0-9]+")
        counter: "Counter[str]" = Counter()
        for name in names:
            for tok in token_pattern.findall(name.lower()):
                if len(tok) < min_token_length or tok.isdigit():
                    continue
                if tok in known_tokens or tok in self.TAXONOMY_GAP_STOPWORDS:
                    continue
                counter[tok] += 1

        return counter.most_common(top_n)

    async def get_watchlist_candidates_to_audit(
        self,
        ecosystem: Ecosystem,
        limit: int = 10,
    ) -> List[WatchlistCandidate]:
        """Fetch candidates from the unregistered watchlist that haven't been audited/detected yet."""
        query = (
            select(UnregisteredWatchlistModel)
            .where(
                (UnregisteredWatchlistModel.ecosystem == ecosystem.value) &
                (UnregisteredWatchlistModel.state == WatchlistState.WATCHING.value)
            )
            .order_by(UnregisteredWatchlistModel.risk_weight.desc())
            .limit(limit)
        )
        result = await self.session.execute(query)
        rows = result.scalars().all()
        return [
            WatchlistCandidate(
                candidate_id=r.candidate_id,
                ecosystem=Ecosystem(r.ecosystem),
                normalized_name=r.normalized_name,
                entity_token=r.entity_token,
                capability_token=r.capability_token,
                framework_token=r.framework_token,
                risk_weight=r.risk_weight,
                state=WatchlistState(r.state),
                generated_at=r.generated_at,
            )
            for r in rows
        ]

    async def mark_registered_package_crawled(
        self,
        ecosystem: Ecosystem,
        package_name: str,
        now_utc: Optional[datetime] = None,
    ) -> None:
        """Mark a package in registered_packages as crawled with UTC timestamp, upserting if not present."""
        if now_utc is None:
            now_utc = datetime.now(timezone.utc).replace(microsecond=0)

        from sentinel.scheduler.queue import compute_brand_priority
        brand_info = compute_brand_priority(package_name)
        is_brand = 1 if brand_info else 0
        score = brand_info[1] if brand_info else 10

        pkg_id = f"{ecosystem.value}_{package_name.lower()}"
        now_str = now_utc.strftime("%Y-%m-%dT%H:%M:%SZ")

        sql = """
        INSERT INTO registered_packages (package_id, ecosystem, raw_name, normalized_name, is_brand_target, priority_score, synced_at, crawled_at)
        VALUES (:pkg_id, :eco, :name, :norm_name, :is_brand, :score, :synced_at, :crawled_at)
        ON CONFLICT(ecosystem, normalized_name) DO UPDATE SET
            crawled_at = excluded.crawled_at;
        """
        params = {
            "pkg_id": pkg_id,
            "eco": ecosystem.value,
            "name": package_name,
            "norm_name": package_name.lower(),
            "is_brand": is_brand,
            "score": score,
            "synced_at": now_str,
            "crawled_at": now_str,
        }

        async def _do():
            await self.session.execute(text(sql), params)
            await self.session.commit()

        await self._write_with_retry(_do)

    async def backfill_install_hook_flags(self, batch_size: int = 500) -> Dict[str, int]:
        """
        Recompute has_install_hook / has_network_socket for existing squat_detections
        rows from their already-stored analysis_details_json.flags — no re-crawl or
        network calls needed. For rows whose stored JSON predates these fields, derives
        them from the raw AST flags directly (same classification scorer.py now applies
        going forward), so historical data lights up the new indexed columns too.
        """
        from sentinel.assessor.scorer import has_install_time_code_execution, has_install_time_network_socket

        query = select(SquatDetectionModel.detection_id, SquatDetectionModel.analysis_details_json)
        result = await self.session.execute(query)
        rows = result.all()

        updates = []
        for detection_id, details_json in rows:
            try:
                details = json.loads(details_json or "{}")
            except Exception:
                details = {}
            flags = details.get("flags", [])
            if "has_install_hook" in details:
                install_hook = bool(details["has_install_hook"])
            else:
                install_hook = has_install_time_code_execution(flags)
            if "has_network_socket" in details:
                network_socket = bool(details["has_network_socket"])
            else:
                network_socket = has_install_time_network_socket(flags)
            updates.append({"id": detection_id, "hook": install_hook, "socket": network_socket})

        changed = 0
        for i in range(0, len(updates), batch_size):
            batch = updates[i:i + batch_size]

            async def _do(batch=batch):
                for u in batch:
                    await self.session.execute(
                        text("UPDATE squat_detections SET has_install_hook = :hook, has_network_socket = :socket WHERE detection_id = :id"),
                        {"hook": 1 if u["hook"] else 0, "socket": 1 if u["socket"] else 0, "id": u["id"]},
                    )
                await self.session.commit()

            await self._write_with_retry(_do)
            changed += len(batch)

        return {
            "total_rows": len(rows),
            "updated": changed,
            "with_install_hook": sum(1 for u in updates if u["hook"]),
            "with_network_socket": sum(1 for u in updates if u["socket"]),
        }

    async def list_detections(self, ecosystem: Optional[Ecosystem] = None, limit: int = 100) -> List[SquatDetection]:
        """List detected slopsquatting events."""
        query = select(SquatDetectionModel).order_by(SquatDetectionModel.published_at.desc())
        if ecosystem:
            query = query.where(SquatDetectionModel.ecosystem == ecosystem.value)
        query = query.limit(limit)

        result = await self.session.execute(query)
        rows = result.scalars().all()

        return [
            SquatDetection(
                detection_id=r.detection_id,
                candidate_id=r.candidate_id,
                ecosystem=Ecosystem(r.ecosystem),
                package_name=r.package_name,
                author_username=r.author_username,
                release_version=r.release_version,
                published_at=_ensure_utc(r.published_at),
                threat_score=r.threat_score,
                analysis_details=json.loads(r.analysis_details_json or "{}"),
                is_exported=r.is_exported,
                verdict=ThreatVerdict(r.verdict),
                content_hash=r.content_hash,
                audit_count=r.audit_count or 1,
                last_audited_at=_ensure_utc(r.last_audited_at) or datetime.now(timezone.utc).replace(microsecond=0),
                next_audit_due_at=_ensure_utc(r.next_audit_due_at),
                priority_tier=r.priority_tier or 2,
                is_deprecated=bool(getattr(r, "is_deprecated", False)),
                deprecation_reason=getattr(r, "deprecation_reason", None),
                created_at=_ensure_utc(r.created_at) or _ensure_utc(r.published_at) or datetime.now(timezone.utc).replace(microsecond=0),
                updated_at=_ensure_utc(r.updated_at) or _ensure_utc(r.published_at) or datetime.now(timezone.utc).replace(microsecond=0),
            )
            for r in rows
        ]

    async def get_unexported_detections(self) -> List[SquatDetection]:
        """Fetch detections not yet marked as exported."""
        query = select(SquatDetectionModel).where(SquatDetectionModel.is_exported == False)
        result = await self.session.execute(query)
        rows = result.scalars().all()
        return [
            SquatDetection(
                detection_id=r.detection_id,
                candidate_id=r.candidate_id,
                ecosystem=Ecosystem(r.ecosystem),
                package_name=r.package_name,
                author_username=r.author_username,
                release_version=r.release_version,
                published_at=_ensure_utc(r.published_at),
                threat_score=r.threat_score,
                analysis_details=json.loads(r.analysis_details_json or "{}"),
                is_exported=r.is_exported,
                verdict=ThreatVerdict(r.verdict),
                content_hash=r.content_hash,
                audit_count=r.audit_count or 1,
                last_audited_at=_ensure_utc(r.last_audited_at) or datetime.now(timezone.utc).replace(microsecond=0),
                next_audit_due_at=_ensure_utc(r.next_audit_due_at),
                priority_tier=r.priority_tier or 2,
                is_deprecated=bool(getattr(r, "is_deprecated", False)),
                deprecation_reason=getattr(r, "deprecation_reason", None),
                created_at=_ensure_utc(r.created_at) or _ensure_utc(r.published_at) or datetime.now(timezone.utc).replace(microsecond=0),
                updated_at=_ensure_utc(r.updated_at) or _ensure_utc(r.published_at) or datetime.now(timezone.utc).replace(microsecond=0),
            )
            for r in rows
        ]

    async def mark_detections_exported(self, detection_ids: List[str]) -> None:
        """Mark detection records as exported."""
        if not detection_ids:
            return
        stmt = (
            update(SquatDetectionModel)
            .where(SquatDetectionModel.detection_id.in_(detection_ids))
            .values(is_exported=True)
        )

        async def _do():
            await self.session.execute(stmt)
            await self.session.commit()

        # This bulk UPDATE is the write most frequently observed colliding with
        # concurrent crawl-cycle / internal_db_sync.sh writes in production (see
        # sentinel_cron.log 'database is locked' failures) — retry with backoff.
        await self._write_with_retry(_do)


