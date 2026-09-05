"""
SlopGuard: Zero-LLM AI Package Hallucination & Supply Chain Threat Auditor.
"""

import sys
import importlib

import sentinel
from sentinel import *

# Direct public API exports
from sentinel.assessor.yara_engine import YaraPatternScanner
from sentinel.assessor.python_ast import (
    inspect_python_code_ast,
    analyze_python_package_tarball,
    ASTSecurityReport,
    PythonASTAssessor,
)
from sentinel.assessor.scorer import ProgressiveThreatEvaluator
from sentinel.linter.lockfile import DependencyLinter
from sentinel.core.dto import Ecosystem, ThreatVerdict, SquatDetection

__version__ = sentinel.__version__
__all__ = list(sentinel.__all__) + [
    "YaraPatternScanner",
    "inspect_python_code_ast",
    "analyze_python_package_tarball",
    "ProgressiveThreatEvaluator",
    "PythonASTAssessor",
]

from importlib.machinery import ModuleSpec

class _AliasLoader:
    def __init__(self, target_module):
        self.target_module = target_module

    def create_module(self, spec):
        return self.target_module

    def exec_module(self, module):
        pass

class _SlopGuardAliasFinder:
    def find_spec(self, fullname, path, target=None):
        if fullname.startswith("slopguard."):
            sentinel_name = "sentinel." + fullname[len("slopguard."):]
            try:
                mod = importlib.import_module(sentinel_name)
                is_pkg = hasattr(mod, "__path__")
                spec = ModuleSpec(fullname, _AliasLoader(mod), is_package=is_pkg)
                if is_pkg:
                    spec.submodule_search_locations = list(mod.__path__)
                return spec
            except ModuleNotFoundError:
                return None
        return None

if not any(isinstance(f, _SlopGuardAliasFinder) for f in sys.meta_path):
    sys.meta_path.insert(0, _SlopGuardAliasFinder())
