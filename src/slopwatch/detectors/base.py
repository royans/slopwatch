"""
Sentinel — Detector plugin framework.

A **detector** is a self-contained unit that inspects one package and emits
``Finding`` objects. Detectors live in ``slopwatch.detectors.*`` and register
themselves with ``@register_detector``; ``load_all_detectors()`` discovers every
module in this package automatically, so adding a new signal is a one-file change
with no edits to the scorer, the DB layer, the syncer, or the UI.

Detectors must be cheap and defensive: ``DetectionEngine`` runs them behind a
per-detector try/except and a timeout, so a broken or slow plugin can never take
down a crawl cycle.
"""

from __future__ import annotations

import asyncio
import importlib
import inspect
import logging
import pkgutil
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Set, Type

from slopwatch.core.dto import (
    ASTSecurityReport,
    Ecosystem,
    EvidenceSignal,
    PackageMetadata,
    WatchlistCandidate,
)
from slopwatch.core.signals import Finding

logger = logging.getLogger("slopwatch.detectors")


class Stage(str):
    NAME_ONLY = "NAME_ONLY"        # needs only the package name / candidate tokens
    METADATA = "METADATA"          # needs registry metadata
    PAYLOAD = "PAYLOAD"            # needs the downloaded/inspected payload
    CROSS_PACKAGE = "CROSS_PACKAGE"  # needs corpus-level context (author history, ...)


@dataclass
class PackageContext:
    """Everything a detector may need about one package, loaded lazily upstream."""
    ecosystem: Ecosystem
    package_name: str
    candidate: Optional[WatchlistCandidate] = None
    metadata: Optional[PackageMetadata] = None
    ast_report: Optional[ASTSecurityReport] = None
    # Signals already produced by the progressive scorer this run (read-only).
    existing_signals: List[EvidenceSignal] = field(default_factory=list)
    # Free-form scratch space shared across detectors in one run.
    shared: Dict[str, Any] = field(default_factory=dict)

    @property
    def available_stages(self) -> Set[str]:
        s = {Stage.NAME_ONLY}
        if self.metadata is not None:
            s.add(Stage.METADATA)
        if self.ast_report is not None:
            s.add(Stage.PAYLOAD)
        return s

    @property
    def flags(self) -> List[str]:
        return list(self.ast_report.flags) if self.ast_report else []


class Detector:
    """Base class. Subclass, set the class attributes, implement ``analyze``."""
    name: str = "unnamed"
    version: str = "1"
    stage: str = Stage.METADATA
    applies_to: Set[str] = frozenset({"*"})   # ecosystem values or "*"
    enabled_by_default: bool = True

    def applies(self, ctx: PackageContext) -> bool:
        if "*" not in self.applies_to and ctx.ecosystem.value not in self.applies_to:
            return False
        return self.stage in ctx.available_stages or self.stage == Stage.NAME_ONLY

    async def analyze(self, ctx: PackageContext) -> List[Finding]:  # pragma: no cover - interface
        raise NotImplementedError

    def __repr__(self) -> str:  # pragma: no cover - cosmetic
        return f"<Detector {self.name}@{self.version}>"


# ==================== Registry & discovery ====================

_REGISTRY: "Dict[str, Type[Detector]]" = {}


def register_detector(cls: "Type[Detector]") -> "Type[Detector]":
    """Class decorator — add a detector to the auto-run registry."""
    if not (inspect.isclass(cls) and issubclass(cls, Detector)):
        raise TypeError(f"{cls!r} is not a Detector subclass")
    key = getattr(cls, "name", None) or cls.__name__
    if key in _REGISTRY and _REGISTRY[key] is not cls:
        logger.warning("Detector name %r already registered; overwriting.", key)
    _REGISTRY[key] = cls
    return cls


def _discover_modules() -> None:
    """Import every submodule of ``slopwatch.detectors`` so decorators run."""
    import slopwatch.detectors as pkg

    for mod in pkgutil.iter_modules(pkg.__path__):
        if mod.name in ("base", "engine") or mod.name.startswith("_"):
            continue
        try:
            importlib.import_module(f"slopwatch.detectors.{mod.name}")
        except Exception as e:  # a broken plugin module must not break discovery
            logger.error("Failed to import detector module %r: %s", mod.name, e)


def _config_disabled_detectors() -> Set[str]:
    """Read an optional ``config/detectors.yaml`` ``disabled:`` list."""
    import os

    candidates = [
        os.getenv("SLOPWATCH_DETECTORS_CONFIG"),
        "config/detectors.yaml",
    ]
    for path in candidates:
        if not path:
            continue
        p = __import__("pathlib").Path(path)
        if not p.exists():
            continue
        try:
            import yaml
            data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
            return {str(x) for x in data.get("disabled", []) or []}
        except Exception as e:  # pragma: no cover - defensive
            logger.warning("could not parse detectors config %s: %s", path, e)
    return set()


def load_all_detectors(
    *,
    disabled: Optional[Iterable[str]] = None,
    include_disabled_by_default: bool = False,
) -> List[Detector]:
    """
    Instantiate every registered detector. ``disabled`` is a set of detector
    names to skip; when not given it is read from ``config/detectors.yaml``.
    """
    _discover_modules()
    skip = set(disabled) if disabled is not None else _config_disabled_detectors()
    out: List[Detector] = []
    for name, cls in sorted(_REGISTRY.items()):
        if name in skip:
            continue
        if not cls.enabled_by_default and not include_disabled_by_default:
            continue
        try:
            out.append(cls())
        except Exception as e:  # pragma: no cover - defensive
            logger.error("Failed to instantiate detector %r: %s", name, e)
    return out


def registered_detector_names() -> List[str]:
    _discover_modules()
    return sorted(_REGISTRY)
