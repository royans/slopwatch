"""
SlopWatch: Zero-LLM AI Package Hallucination & Supply Chain Threat Auditor.
"""

from slopwatch.core.dto import (
    Ecosystem,
    WatchlistState,
    ThreatVerdict,
    RegisteredPackage,
    WatchlistCandidate,
    SquatDetection,
    ASTSecurityReport,
    PackageMetadata,
)
from slopwatch.db.engine import DatabaseManager
from slopwatch.db.repository import SentinelRepository, SlopWatchRepository
from slopwatch.adapters import get_adapter
from slopwatch.matrix.generator import generate_ecosystem_candidates, filter_unregistered_candidates
from slopwatch.linter.lockfile import DependencyLinter

# Direct public API exports
from slopwatch.assessor.yara_engine import YaraPatternScanner
from slopwatch.assessor.python_ast import (
    inspect_python_code_ast,
    analyze_python_package_tarball,
    PythonASTAssessor,
)
from slopwatch.assessor.scorer import ProgressiveThreatEvaluator

__version__ = "0.1.0"

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
    "SlopWatchRepository",
    "get_adapter",
    "generate_ecosystem_candidates",
    "filter_unregistered_candidates",
    "DependencyLinter",
    "YaraPatternScanner",
    "inspect_python_code_ast",
    "analyze_python_package_tarball",
    "ProgressiveThreatEvaluator",
    "PythonASTAssessor",
]
