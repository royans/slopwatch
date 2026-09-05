"""
SlopGuard: Zero-LLM AI Package Hallucination & Supply Chain Threat Auditor.
"""

from slopguard.core.dto import (
    Ecosystem,
    WatchlistState,
    ThreatVerdict,
    RegisteredPackage,
    WatchlistCandidate,
    SquatDetection,
    ASTSecurityReport,
    PackageMetadata,
)
from slopguard.db.engine import DatabaseManager
from slopguard.db.repository import SentinelRepository, SlopGuardRepository
from slopguard.adapters import get_adapter
from slopguard.matrix.generator import generate_ecosystem_candidates, filter_unregistered_candidates
from slopguard.monitor import InboundTripwireMonitor
from slopguard.linter.lockfile import DependencyLinter
from slopguard.exporter.dossier import DossierExporter

# Direct public API exports
from slopguard.assessor.yara_engine import YaraPatternScanner
from slopguard.assessor.python_ast import (
    inspect_python_code_ast,
    analyze_python_package_tarball,
    PythonASTAssessor,
)
from slopguard.assessor.scorer import ProgressiveThreatEvaluator

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
    "SlopGuardRepository",
    "get_adapter",
    "generate_ecosystem_candidates",
    "filter_unregistered_candidates",
    "InboundTripwireMonitor",
    "DependencyLinter",
    "DossierExporter",
    "YaraPatternScanner",
    "inspect_python_code_ast",
    "analyze_python_package_tarball",
    "ProgressiveThreatEvaluator",
    "PythonASTAssessor",
]
