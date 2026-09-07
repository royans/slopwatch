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

# Fallback for running straight from a source tree with no install; kept in sync
# with pyproject.toml by scripts/release.py. The installed metadata wins below.
_FALLBACK_VERSION = "0.3.0"


def _resolve_version() -> str:
    """Single-source the version from installed package metadata (pyproject.toml)."""
    from importlib.metadata import PackageNotFoundError, version

    try:
        return version("slopwatch")
    except PackageNotFoundError:
        return _FALLBACK_VERSION


__version__ = _resolve_version()

_LAZY_EXPORTS = {
    "DatabaseManager": ("slopwatch.db.engine", "DatabaseManager"),
    "SlopWatchRepository": ("slopwatch.db.repository", "SlopWatchRepository"),
    "SentinelRepository": ("slopwatch.db.repository", "SentinelRepository"),
}

def __getattr__(name: str):
    if name in _LAZY_EXPORTS:
        module_name, attr_name = _LAZY_EXPORTS[name]
        import importlib
        mod = importlib.import_module(module_name)
        val = getattr(mod, attr_name)
        globals()[name] = val
        return val
    raise AttributeError(f"module '{__name__}' has no attribute '{name}'")

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
