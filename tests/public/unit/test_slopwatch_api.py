"""Unit tests verifying public slopwatch package exports, API usability, and CLI."""

import tempfile
from pathlib import Path
from click.testing import CliRunner

import slopwatch
from slopwatch import (
    YaraPatternScanner,
    PythonASTAssessor,
    inspect_python_code_ast,
    analyze_python_package_tarball,
    ProgressiveThreatEvaluator,
    DependencyLinter,
    Ecosystem,
    ThreatVerdict,
    SquatDetection,
)
from slopwatch.cli import cli


def test_slopwatch_exports():
    """Verify that all core classes and enums are exported directly from slopwatch."""
    assert YaraPatternScanner is not None
    assert PythonASTAssessor is not None
    assert inspect_python_code_ast is not None
    assert analyze_python_package_tarball is not None
    assert ProgressiveThreatEvaluator is not None
    assert DependencyLinter is not None
    assert Ecosystem is not None
    assert ThreatVerdict is not None
    assert SquatDetection is not None
    assert slopwatch.__version__ == "0.1.0"


def test_slopwatch_submodule_aliasing():
    """Verify that submodule imports under slopwatch.* resolve dynamically."""
    from slopwatch.assessor.yara_engine import YaraPatternScanner as SubYPS
    from slopwatch.core.dto import ThreatVerdict as SubTV

    assert SubYPS is YaraPatternScanner
    assert SubTV is ThreatVerdict


def test_yara_scanner_scan_text():
    """Verify scan_text convenience method on YaraPatternScanner."""
    scanner = YaraPatternScanner()
    clean_findings = scanner.scan_text("def add(a, b):\n    return a + b\n")
    assert len(clean_findings) == 0

    suspicious_code = (
        "import socket, subprocess, os\n"
        "s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
        "s.connect(('127.0.0.1', 4444))\n"
        "os.dup2(s.fileno(), 0)\n"
    )
    findings = scanner.scan_text(suspicious_code, filename="setup.py")
    assert len(findings) > 0
    assert any("rule" in f and "detail" in f for f in findings)


def test_python_ast_assessor():
    """Verify PythonASTAssessor analyze_source method."""
    assessor = PythonASTAssessor()
    clean_res = assessor.analyze_source("def calculate():\n    return 100\n")
    assert clean_res.verdict == ThreatVerdict.BENIGN_COMMUNITY

    malicious_code = "import os; os.system('id')\n"
    mal_res = assessor.analyze_source(malicious_code, filename="setup.py")
    assert mal_res.verdict == ThreatVerdict.MALICIOUS
    assert any("INSTALL_TIME_EXECUTION" in flag for flag in mal_res.flags)


def test_cli_info_command():
    """Verify slopwatch info command displays banner and status."""
    runner = CliRunner()
    result = runner.invoke(cli, ["info"])
    assert result.exit_code == 0
    assert "SlopWatch Threat Engine" in result.output
    assert "Zero-LLM" in result.output


def test_cli_scan_command_clean_and_flagged():
    """Verify slopwatch scan command outputs respectful and humble messages."""
    runner = CliRunner()
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        clean_file = tmp_path / "clean.py"
        clean_file.write_text("x = 10 + 20\n")

        res_clean = runner.invoke(cli, ["scan", str(clean_file)])
        assert res_clean.exit_code == 0
        assert "SCAN COMPLETE" in res_clean.output
        assert "Zero matched heuristic threat patterns" in res_clean.output

        flagged_file = tmp_path / "hook.py"
        flagged_file.write_text(
            "import socket, os\ns = socket.socket()\nos.dup2(s.fileno(), 0)\n"
        )
        res_flagged = runner.invoke(cli, ["scan", str(flagged_file)])
        assert res_flagged.exit_code == 1
        assert "PATTERNS FLAGGED" in res_flagged.output
        assert "Heuristics flagged potential risk areas" in res_flagged.output
