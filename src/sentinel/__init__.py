"""
FlagThis Sentinel (Project SpectreCatch)
Zero-LLM Multi-Ecosystem Long-Tail AI Package Squatting Detection Engine.
"""

from sentinel.core.dto import (
    Ecosystem,
    WatchlistState,
    ThreatVerdict,
    RegisteredPackage,
    WatchlistCandidate,
    SquatDetection,
    ASTSecurityReport,
    PackageMetadata,
)
from sentinel.db.engine import DatabaseManager
from sentinel.db.repository import SentinelRepository
from sentinel.adapters import get_adapter
from sentinel.matrix.generator import generate_ecosystem_candidates, filter_unregistered_candidates
from sentinel.sentinel.monitor import InboundTripwireMonitor
from sentinel.linter.lockfile import DependencyLinter
from sentinel.exporter.flagthis import FlagThisExporter

__version__ = "0.2.0"

__all__ = [
    "Ecosystem",
    "WatchlistState",
    "ThreatVerdict",
    "RegisteredPackage",
    "WatchlistCandidate",
    "SquatDetection",
    "ASTSecurityReport",
    "PackageMetadata",
    "DatabaseManager",
    "SentinelRepository",
    "get_adapter",
    "generate_ecosystem_candidates",
    "filter_unregistered_candidates",
    "InboundTripwireMonitor",
    "DependencyLinter",
    "FlagThisExporter",
]
