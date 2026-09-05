"""
Sentinel Continuous Crawler Worker.

Asynchronously coordinates priority ingestion, brand crawling, dynamic
exponential freshness scheduling, and registry rate limiting.
"""

import asyncio
import logging
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any

logger = logging.getLogger("slopguard.worker")

from slopguard.core.dto import Ecosystem, SquatDetection, PackageCreationEvent, WatchlistCandidate
from slopguard.assessor.scorer import ProgressiveThreatEvaluator
from slopguard.db.engine import DatabaseManager
from slopguard.db.repository import SentinelRepository
from slopguard.scheduler.queue import CrawlTask, TaskPriorityTier, compute_brand_priority, PRIORITY_BRAND_WEIGHTS, OLDER_PACKAGE_BUDGET_PCT, OLDER_PACKAGE_AGE_THRESHOLD_DAYS
from slopguard.scheduler.freshness import calculate_next_audit_time


class ContinuousCrawlerWorker:
    def __init__(
        self,
        repository: Optional[SentinelRepository] = None,
        db_manager: Optional[DatabaseManager] = None,
        evaluator: Optional[ProgressiveThreatEvaluator] = None,
        concurrency_limit: int = 8,
    ):
        self.repo = repository
        self.db_manager = db_manager
        self.evaluator = evaluator or ProgressiveThreatEvaluator(concurrency_limit=concurrency_limit)
        self.semaphore = asyncio.Semaphore(concurrency_limit)

    async def collect_crawl_tasks(
        self,
        limit: int = 50,
        npm_limit: int = 10,
        inbound_events: Optional[List[PackageCreationEvent]] = None,
        target_brands: Optional[List[str]] = None,
        older_budget_pct: float = OLDER_PACKAGE_BUDGET_PCT,
    ) -> List[CrawlTask]:
        """
        Assemble a multi-tier prioritized batch of crawl tasks with budget splitting:

        Budget allocation (configurable, default 75/25):
        - OLDER budget (75%): Freshness re-audits + historical backfill (oldest-first)
        - NEWER budget (25%): Inbound releases, threat actor pivots, npm, brand watchlist

        Phase 1 (Newer budget):
          Tier 1: Brand new inbound stream events (Weight 1000)
          Tier 1.5: Threat Actor Pivot Crawling (Weight 900)
          Tier 1.8: NPM Target Sampling & Exploratory Ingestion (Weight 850)
          Tier 2: High-risk PyPI brand watchlist targets (Weight 800 - 950)

        Phase 2 (Older budget + unused newer slots):
          Tier 3: Due freshness re-audits (Weight 500)
          Tier 4: Historical catalog backfill, oldest-first (Weight 100)
        """
        tasks: List[CrawlTask] = []
        now_utc = datetime.now(timezone.utc).replace(microsecond=0)

        # Upfront budget split
        older_budget = int(limit * older_budget_pct)
        newer_budget = limit - older_budget
        newer_remaining = newer_budget

        # ── Phase 1: NEWER BUDGET (25%) ──────────────────────────────────

        # 1. Tier 1: Inbound new releases (prioritizing tracked keywords over untracked releases)
        if inbound_events:
            for ev in inbound_events:
                brand_info = compute_brand_priority(ev.package_name)
                brand_name = brand_info[0] if brand_info else None
                is_tracked = brand_info is not None

                if is_tracked:
                    # Inbound release matching a tracked keyword/brand gets highest priority tier
                    weight = TaskPriorityTier.TRACKED_KEYWORD_INBOUND.value + (brand_info[1] if brand_info else 0)
                else:
                    # Untracked new package: lower priority so tracked brand watchlist packages run first
                    weight = TaskPriorityTier.UNTRACKED_NEW_INBOUND.value

                tasks.append(
                    CrawlTask(
                        priority=weight,
                        package_name=ev.package_name,
                        ecosystem=ev.ecosystem,
                        task_type="NEW_INBOUND_RELEASE",
                        targeted_brand=brand_name,
                        release_version=ev.release_version,
                        published_at=ev.published_at,
                    )
                )
                newer_remaining -= 1
                if newer_remaining <= 0:
                    break

        if newer_remaining <= 0:
            # Roll unused newer slots (0 in this case) into older budget
            older_budget += max(0, newer_remaining)
            newer_remaining = 0

        # 2. Tier 1.5: Threat Actor Pivot Crawling (Authors/Emails with Score >= 90)
        if newer_remaining > 0 and self.repo:
            try:
                high_risk_emails, high_risk_authors = await self.repo.get_high_threat_actor_identifiers(min_score=90)
                for author in list(high_risk_authors)[:10]:
                    if newer_remaining <= 0:
                        break
                    author_targets = await self.repo.get_brand_targets_to_crawl(Ecosystem.PYPI, [author], limit=min(newer_remaining, 5))
                    for pkg in author_targets:
                        tasks.append(
                            CrawlTask(
                                priority=TaskPriorityTier.THREAT_ACTOR_PIVOT.value,
                                package_name=pkg,
                                ecosystem=Ecosystem.PYPI,
                                task_type="THREAT_ACTOR_PIVOT",
                                targeted_brand=author,
                            )
                        )
                        newer_remaining -= 1
                        if newer_remaining <= 0:
                            break
            except Exception:
                pass

        # 3. Tier 1.8: NPM Target Sampling & Exploratory Ingestion
        brand_tokens = target_brands or list(PRIORITY_BRAND_WEIGHTS.keys())
        if npm_limit > 0 and newer_remaining > 0 and self.repo:
            try:
                npm_quota = min(npm_limit, newer_remaining)
                npm_found = 0

                # Check registered brand targets for npm
                npm_brand_targets = await self.repo.get_brand_targets_to_crawl(Ecosystem.NPM, brand_tokens, limit=npm_quota)
                for pkg in npm_brand_targets:
                    brand_info = compute_brand_priority(pkg)
                    brand_name = brand_info[0] if brand_info else "brand"
                    weight = TaskPriorityTier.HIGH_RISK_BRAND_WATCHLIST.value + (brand_info[1] if brand_info else 0)
                    tasks.append(
                        CrawlTask(
                            priority=weight,
                            package_name=pkg,
                            ecosystem=Ecosystem.NPM,
                            task_type="HIGH_RISK_BRAND_WATCHLIST",
                            targeted_brand=brand_name,
                        )
                    )
                    npm_found += 1
                    newer_remaining -= 1
                    if newer_remaining <= 0 or npm_found >= npm_quota:
                        break

                # If not enough in registered_packages, pull from unregistered_watchlist
                if npm_found < npm_quota and newer_remaining > 0:
                    needed = npm_quota - npm_found
                    unreg_cands = await self.repo.get_watchlist_candidates_to_audit(Ecosystem.NPM, limit=needed)
                    for cand in unreg_cands:
                        brand_info = compute_brand_priority(cand.normalized_name)
                        brand_name = brand_info[0] if brand_info else cand.entity_token
                        tasks.append(
                            CrawlTask(
                                priority=TaskPriorityTier.HIGH_RISK_BRAND_WATCHLIST.value,
                                package_name=cand.normalized_name,
                                ecosystem=Ecosystem.NPM,
                                task_type="HIGH_RISK_BRAND_WATCHLIST",
                                targeted_brand=brand_name,
                                candidate_id=cand.candidate_id,
                            )
                        )
                        npm_found += 1
                        newer_remaining -= 1
                        if newer_remaining <= 0 or npm_found >= npm_quota:
                            break

                # If still needed, dynamically generate candidate brand combinations for npm
                if npm_found < npm_quota and newer_remaining > 0:
                    from slopguard.matrix.generator import generate_ecosystem_candidates
                    needed = npm_quota - npm_found
                    dynamic_cands = generate_ecosystem_candidates(
                        Ecosystem.NPM,
                        entities=brand_tokens[:12],
                        limit=needed * 6,
                    )
                    existing_names = {t.package_name for t in tasks if t.ecosystem == Ecosystem.NPM}
                    for cand in dynamic_cands:
                        if cand.normalized_name not in existing_names:
                            existing_names.add(cand.normalized_name)
                            tasks.append(
                                CrawlTask(
                                    priority=TaskPriorityTier.HIGH_RISK_BRAND_WATCHLIST.value,
                                    package_name=cand.normalized_name,
                                    ecosystem=Ecosystem.NPM,
                                    task_type="HIGH_RISK_BRAND_WATCHLIST",
                                    targeted_brand=cand.entity_token,
                                )
                            )
                            npm_found += 1
                            newer_remaining -= 1
                            if newer_remaining <= 0 or npm_found >= npm_quota:
                                break
            except Exception:
                pass

        # 4. Tier 2: High-Risk PyPI Brand Watchlist Crawling (remaining newer budget)
        if newer_remaining > 0:
            brand_targets = await self.repo.get_brand_targets_to_crawl(Ecosystem.PYPI, brand_tokens, limit=newer_remaining)
            for pkg in brand_targets:
                brand_info = compute_brand_priority(pkg)
                brand_name = brand_info[0] if brand_info else "brand"
                weight = TaskPriorityTier.HIGH_RISK_BRAND_WATCHLIST.value + (brand_info[1] if brand_info else 0)
                tasks.append(
                    CrawlTask(
                        priority=weight,
                        package_name=pkg,
                        ecosystem=Ecosystem.PYPI,
                        task_type="HIGH_RISK_BRAND_WATCHLIST",
                        targeted_brand=brand_name,
                    )
                )
                newer_remaining -= 1
                if newer_remaining <= 0:
                    break

        # Roll any unused newer slots into the older budget
        older_budget += max(0, newer_remaining)

        # ── Phase 2: OLDER BUDGET (75% + rollover) ───────────────────────
        older_remaining = older_budget

        # 5. Tier 3: Due Freshness Re-audits (prioritized by threat score)
        if older_remaining > 0:
            reaudit_limit = max(1, int(older_remaining * 0.5))
            due_detections = await self.repo.get_due_freshness_reaudits(limit=reaudit_limit, now_utc=now_utc)
            for d in due_detections:
                weight = TaskPriorityTier.FRESHNESS_REAUDIT_DUE.value + d.threat_score
                tasks.append(
                    CrawlTask(
                        priority=weight,
                        package_name=d.package_name,
                        ecosystem=d.ecosystem,
                        task_type="FRESHNESS_REAUDIT",
                        targeted_brand=d.analysis_details.get("entity"),
                        release_version=d.release_version,
                        published_at=d.published_at,
                    )
                )
                older_remaining -= 1
                if older_remaining <= 0:
                    break

        # 6. Tier 4: Historical Catalog Backfill (oldest-first for the older budget)
        if older_remaining > 0:
            backfill_pkgs = await self.repo.get_historical_backfill_targets(
                Ecosystem.PYPI, limit=older_remaining, oldest_first=True,
            )
            for pkg in backfill_pkgs:
                tasks.append(
                    CrawlTask(
                        priority=TaskPriorityTier.HISTORICAL_CATALOG_BACKFILL.value,
                        package_name=pkg,
                        ecosystem=Ecosystem.PYPI,
                        task_type="HISTORICAL_CATALOG_BACKFILL",
                    )
                )

        # ── Rule enforcement: at most one review per package per UTC day ─────
        # Proactively drop anything already reviewed today (so today's budget isn't
        # wasted on a no-op task) and collapse any duplicate (ecosystem, package_name)
        # that landed in this batch from more than one tier. This is a belt-and-braces
        # optimization — the authoritative, race-safe gate lives in execute_task() via
        # SentinelRepository.try_claim_daily_review().
        if self.repo:
            reviewed_today: Dict[Ecosystem, set] = {
                Ecosystem.PYPI: await self.repo.get_packages_reviewed_today(Ecosystem.PYPI),
                Ecosystem.NPM: await self.repo.get_packages_reviewed_today(Ecosystem.NPM),
            }
            seen_in_batch = set()
            deduped: List[CrawlTask] = []
            for t in tasks:
                key = (t.ecosystem, t.package_name)
                if key in seen_in_batch:
                    continue
                if t.package_name in reviewed_today.get(t.ecosystem, set()):
                    continue
                seen_in_batch.add(key)
                deduped.append(t)
            tasks = deduped

        tasks.sort(reverse=True)
        return tasks[:limit]

    async def execute_task(self, task: CrawlTask) -> Optional[SquatDetection]:
        """Execute inspection on a single crawl task with rate-limiting semaphore."""
        async with self.semaphore:
            now_utc = datetime.now(timezone.utc).replace(microsecond=0)

            # ── Rule enforcement: at most one review per package per UTC day ─────
            # Authoritative, race-safe gate — checked immediately before any network
            # calls so a duplicate task never re-evaluates a package that already had
            # its one review today, even if it slipped past the collect_crawl_tasks
            # pre-filter (e.g. two overlapping cycles, or a stale in-memory batch).
            try:
                if self.db_manager:
                    async with self.db_manager.get_session() as session:
                        r = SentinelRepository(session)
                        can_review = await r.try_claim_daily_review(task.ecosystem, task.package_name)
                elif self.repo:
                    can_review = await self.repo.try_claim_daily_review(task.ecosystem, task.package_name)
                else:
                    can_review = True
            except Exception:
                # If the claim itself fails (e.g. DB contention), fail safe by skipping
                # rather than risking a duplicate same-day review.
                logger.warning(f"Daily-review claim failed for '{task.package_name}' ({task.ecosystem.value}); skipping this cycle.")
                return None

            if not can_review:
                logger.info(f"Skipping '{task.package_name}' ({task.ecosystem.value}): already reviewed today.")
                return None

            try:
                default_fw = "node" if task.ecosystem == Ecosystem.NPM else "python"
                if task.package_name.startswith("@"):
                    scope, _, rest = task.package_name.lstrip("@").partition("/")
                    entity_tok = task.targeted_brand or scope
                    cap_tok = rest or "core"
                    fw_tok = default_fw
                else:
                    raw_tokens = task.package_name.split("-")
                    if len(raw_tokens) == 1:
                        entity_tok = task.targeted_brand or raw_tokens[0]
                        cap_tok = "core"
                        fw_tok = default_fw
                    elif len(raw_tokens) == 2:
                        entity_tok = task.targeted_brand or raw_tokens[0]
                        cap_tok = raw_tokens[1] if entity_tok == raw_tokens[0] else raw_tokens[0]
                        fw_tok = default_fw
                    else:
                        fw_tok = raw_tokens[0]
                        entity_tok = task.targeted_brand or raw_tokens[1]
                        cap_tok = raw_tokens[2]

                candidate_kwargs = dict(
                    ecosystem=task.ecosystem,
                    normalized_name=task.package_name,
                    entity_token=entity_tok,
                    capability_token=cap_tok,
                    framework_token=fw_tok,
                )
                if task.candidate_id:
                    # Preserve the original watchlist row's id so record_detection() can
                    # correctly flip its state to SQUATTED instead of leaving it WATCHING
                    # forever (which previously caused the same watchlist candidates to be
                    # re-selected by get_watchlist_candidates_to_audit on every cycle).
                    candidate_kwargs["candidate_id"] = task.candidate_id
                candidate = WatchlistCandidate(**candidate_kwargs)

                detection = await self.evaluator.evaluate_candidate(candidate, version=task.release_version)
                if not detection:
                    if self.db_manager:
                        async with self.db_manager.get_session() as session:
                            r = SentinelRepository(session)
                            await r.mark_registered_package_crawled(task.ecosystem, task.package_name, now_utc=now_utc)
                    elif self.repo:
                        await self.repo.mark_registered_package_crawled(task.ecosystem, task.package_name, now_utc=now_utc)
                    return None

                pub_dt = detection.published_at or now_utc
                detection.next_audit_due_at = calculate_next_audit_time(pub_dt, last_audited_at=now_utc, now_utc=now_utc)
                detection.last_audited_at = now_utc
                detection.priority_tier = 1 if task.task_type == "NEW_INBOUND_RELEASE" else 2

                if self.db_manager:
                    async with self.db_manager.get_session() as session:
                        r = SentinelRepository(session)
                        saved = await r.record_detection(detection)
                        await r.mark_registered_package_crawled(task.ecosystem, task.package_name, now_utc=now_utc)
                        return saved
                elif self.repo:
                    saved = await self.repo.record_detection(detection)
                    await self.repo.mark_registered_package_crawled(task.ecosystem, task.package_name, now_utc=now_utc)
                    return saved
                return None

            except Exception:
                if self.db_manager:
                    async with self.db_manager.get_session() as session:
                        r = SentinelRepository(session)
                        await r.mark_registered_package_crawled(task.ecosystem, task.package_name, now_utc=now_utc)
                elif self.repo:
                    await self.repo.mark_registered_package_crawled(task.ecosystem, task.package_name, now_utc=now_utc)
                return None

    async def run_crawl_cycle(
        self,
        batch_size: int = 50,
        npm_limit: int = 10,
        inbound_events: Optional[List[PackageCreationEvent]] = None,
        target_brands: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Run a single bounded crawl cycle across prioritized tasks."""
        start_time = datetime.now(timezone.utc)
        
        if self.db_manager and not self.repo:
            async with self.db_manager.get_session() as session:
                self.repo = SentinelRepository(session)
                tasks = await self.collect_crawl_tasks(
                    limit=batch_size,
                    npm_limit=npm_limit,
                    inbound_events=inbound_events,
                    target_brands=target_brands,
                )
        else:
            tasks = await self.collect_crawl_tasks(
                limit=batch_size,
                npm_limit=npm_limit,
                inbound_events=inbound_events,
                target_brands=target_brands,
            )

        if not tasks:
            return {"tasks_collected": 0, "tasks_completed": 0, "detections_recorded": 0, "duration_seconds": 0.0}

        # If using single session repository, execute sequentially; if db_manager present, execute concurrently
        if self.db_manager:
            results = await asyncio.gather(*[self.execute_task(t) for t in tasks])
        else:
            results = []
            for t in tasks:
                res = await self.execute_task(t)
                results.append(res)

        completed = [r for r in results if r is not None]

        duration = (datetime.now(timezone.utc) - start_time).total_seconds()
        return {
            "tasks_collected": len(tasks),
            "tasks_completed": len(results),
            "detections_recorded": len(completed),
            "duration_seconds": round(duration, 2),
            "breakdown": {
                "inbound_new": sum(1 for t in tasks if t.task_type == "NEW_INBOUND_RELEASE"),
                "brand_watchlist": sum(1 for t in tasks if t.task_type == "HIGH_RISK_BRAND_WATCHLIST"),
                "freshness_reaudits": sum(1 for t in tasks if t.task_type == "FRESHNESS_REAUDIT"),
                "historical_backfill": sum(1 for t in tasks if t.task_type == "HISTORICAL_CATALOG_BACKFILL"),
                "npm_tasks": sum(1 for t in tasks if t.ecosystem == Ecosystem.NPM),
                "pypi_tasks": sum(1 for t in tasks if t.ecosystem == Ecosystem.PYPI),
            }
        }
