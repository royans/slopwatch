"""
FlagThis Sentinel Inbound Feed Tripwire Monitor.

Polls registry new-package streams, executes O(1) in-memory watchlist matching,
and triggers automatic static malware inspection upon detection.
"""

from typing import List, Optional, Callable, Dict, Any
from datetime import datetime, timezone
import aiohttp

from sentinel.core.dto import (
    Ecosystem,
    SquatDetection,
    ThreatVerdict,
)
from sentinel.adapters import get_adapter
from sentinel.db.repository import SentinelRepository


class InboundTripwireMonitor:
    def __init__(self, repository: SentinelRepository):
        self.repository = repository

    async def check_inbound_stream(
        self,
        ecosystem: Ecosystem,
        limit: int = 50,
        webhook_url: Optional[str] = None,
    ) -> List[SquatDetection]:
        """
        Poll recent package creation events for an ecosystem.
        Prioritizes packages matching tracked keywords and brand watchlist entities
        before scanning untracked packages.
        """
        from sentinel.assessor.scorer import has_install_time_code_execution, has_confirmed_dangerous_execution
        from sentinel.scheduler.queue import compute_brand_priority

        adapter = get_adapter(ecosystem)
        watchlist_set = await self.repository.get_watchlist_names_set(ecosystem) or set()
        detections: List[SquatDetection] = []

        events = await adapter.fetch_recent_creations(limit=limit)

        # ── Prioritize by Tracked Keywords ────────────────────────────────
        # Separate inbound events: tracked keyword matches are processed FIRST
        def _is_tracked(ev) -> bool:
            norm = adapter.normalize_name(ev.package_name)
            return norm in watchlist_set or compute_brand_priority(norm) is not None

        tracked_events = [ev for ev in events if _is_tracked(ev)]
        untracked_events = [ev for ev in events if not _is_tracked(ev)]

        # Ordered: all tracked keyword packages evaluated before untracked packages
        ordered_events = tracked_events + untracked_events

        for ev in ordered_events:
            norm_name = adapter.normalize_name(ev.package_name)
            is_watchlist_match = norm_name in watchlist_set or compute_brand_priority(norm_name) is not None

            # Inspect payload with AST & manifest analyzer
            report = await adapter.download_and_inspect_payload(norm_name, ev.release_version)

            # Fetch metadata
            meta = await adapter.inspect_package_metadata(norm_name)
            author = meta.author if meta else ev.author_username
            is_dep = bool(getattr(meta, "is_deprecated", False)) if meta else False
            dep_msg = getattr(meta, "deprecation_reason", None) if meta else None

            # Determine whether this package should be flagged
            has_dangerous = has_confirmed_dangerous_execution(report.flags)
            has_install_hook = has_install_time_code_execution(report.flags)
            is_threat = (
                is_watchlist_match
                or has_dangerous
                or has_install_hook
                or report.composite_threat_score >= 50
                or report.verdict in (ThreatVerdict.MALICIOUS, ThreatVerdict.SUSPICIOUS)
            )

            if is_threat:
                candidate = await self.repository.get_candidate_by_name(ecosystem, norm_name) if is_watchlist_match else None
                candidate_id = candidate.candidate_id if candidate else None

                detection = SquatDetection(
                    candidate_id=candidate_id,
                    ecosystem=ecosystem,
                    package_name=norm_name,
                    author_username=author,
                    release_version=ev.release_version or "0.1.0",
                    published_at=ev.published_at,
                    threat_score=report.composite_threat_score,
                    is_deprecated=is_dep,
                    deprecation_reason=dep_msg,
                    analysis_details={
                        "flags": report.flags,
                        "line_details": report.line_details,
                        "has_socket": report.has_socket,
                        "has_subprocess": report.has_subprocess,
                        "has_os_system": report.has_os_system,
                        "has_lifecycle_scripts": report.has_lifecycle_scripts,
                        "has_install_hook": has_install_hook,
                        "has_network_socket": report.has_socket,
                        "has_confirmed_dangerous_execution": has_dangerous,
                        "is_watchlist_match": is_watchlist_match,
                        "is_deprecated": is_dep,
                        "deprecation_reason": dep_msg,
                    },
                    verdict=report.verdict,
                )

                saved_detection = await self.repository.record_detection(detection)
                detections.append(saved_detection)

                # Dispatch webhook if configured
                if webhook_url:
                    await self._dispatch_webhook(webhook_url, saved_detection)

        return detections

    async def _dispatch_webhook(self, webhook_url: str, detection: SquatDetection) -> None:
        """Dispatch JSON alert to configured webhook endpoint."""
        payload = {
            "event": "SLOPSQUAT_DETECTED",
            "detection_id": detection.detection_id,
            "ecosystem": detection.ecosystem.value,
            "package_name": detection.package_name,
            "author": detection.author_username,
            "version": detection.release_version,
            "threat_score": detection.threat_score,
            "verdict": detection.verdict.value,
            "flags": detection.analysis_details.get("flags", []),
            "published_at": detection.published_at.isoformat(),
        }

        try:
            async with aiohttp.ClientSession() as session:
                await session.post(webhook_url, json=payload, timeout=aiohttp.ClientTimeout(total=5.0))
        except Exception:
            pass
