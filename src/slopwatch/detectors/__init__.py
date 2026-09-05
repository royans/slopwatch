"""
Sentinel detector plugins.

Drop a new module in this package, decorate a ``Detector`` subclass with
``@register_detector``, and it is discovered and run automatically — no changes
to the scorer, the database schema, the downstream syncer, or the web UI. See
``docs/internal/DETECTION_ENGINE_DESIGN.md``.
"""

from slopwatch.detectors.base import (
    Detector,
    PackageContext,
    Stage,
    load_all_detectors,
    register_detector,
    registered_detector_names,
)
from slopwatch.detectors.engine import DetectionEngine, get_shared_engine

__all__ = [
    "Detector",
    "PackageContext",
    "Stage",
    "DetectionEngine",
    "get_shared_engine",
    "load_all_detectors",
    "register_detector",
    "registered_detector_names",
]
