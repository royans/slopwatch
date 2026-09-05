"""
Sentinel — Detection Engine.

Runs every applicable plugin detector over a ``PackageContext`` and returns their
findings. Each detector runs behind its own try/except and timeout so a slow or
broken plugin degrades gracefully instead of failing the crawl cycle.

The engine is deliberately *additive*: the progressive scorer
(``slopguard.assessor.scorer``) still owns the verdict ladder and the authoritative
``threat_score``. Plugin findings are folded into that scorer flow via
``Finding.to_evidence_signal()`` / ``Finding.score`` — see
``ProgressiveThreatEvaluator.evaluate_candidate``.
"""

from __future__ import annotations

import asyncio
import logging
from typing import List, Optional

from slopguard.core.signals import Finding
from slopguard.detectors.base import Detector, PackageContext, load_all_detectors

logger = logging.getLogger("slopguard.detectors.engine")

_DEFAULT_PER_DETECTOR_TIMEOUT = 10.0


class DetectionEngine:
    def __init__(
        self,
        detectors: Optional[List[Detector]] = None,
        *,
        per_detector_timeout: float = _DEFAULT_PER_DETECTOR_TIMEOUT,
    ):
        # Cache the discovered detector list on the instance; callers that want a
        # fresh scan can pass an explicit list.
        self.detectors: List[Detector] = detectors if detectors is not None else load_all_detectors()
        self.per_detector_timeout = per_detector_timeout

    async def run(self, ctx: PackageContext) -> List[Finding]:
        findings: List[Finding] = []
        for det in self.detectors:
            try:
                if not det.applies(ctx):
                    continue
            except Exception as e:  # pragma: no cover - defensive
                logger.error("detector %s .applies() raised: %s", det.name, e)
                continue
            try:
                result = await asyncio.wait_for(det.analyze(ctx), timeout=self.per_detector_timeout)
            except asyncio.TimeoutError:
                logger.warning("detector %s timed out on %s", det.name, ctx.package_name)
                continue
            except Exception as e:
                logger.error("detector %s failed on %s: %s", det.name, ctx.package_name, e)
                continue
            for f in result or []:
                if isinstance(f, Finding):
                    if f.detector == "unknown":
                        f.detector = det.name
                    findings.append(f)
        return findings


_SHARED_ENGINE: Optional[DetectionEngine] = None


def get_shared_engine() -> DetectionEngine:
    """Process-wide engine so detector discovery only happens once."""
    global _SHARED_ENGINE
    if _SHARED_ENGINE is None:
        _SHARED_ENGINE = DetectionEngine()
    return _SHARED_ENGINE
