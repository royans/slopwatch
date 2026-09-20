import importlib.util
from pathlib import Path

_spec = importlib.util.spec_from_file_location(
    "rule_scorecard", Path(__file__).resolve().parents[3] / "scripts" / "rule_scorecard.py"
)
rs = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(rs)


def test_scan_finds_a_rule_and_compare_flags_new_and_grown(tmp_path):
    pkg = tmp_path / "somepkg"
    pkg.mkdir()
    (pkg / "a.py").write_text("import os\nx = os.environ['HOME']\nos.system('ls')\n")
    result = rs.scan([tmp_path])
    assert result["packages_scanned"] == 1 and result["rules"]

    assert rs.compare(result, result, 0.10) == []
    assert any(p.startswith("NEW") for p in rs.compare(result, {"rules": {}}, 0.10))
    key = next(iter(result["rules"]))
    grown = {"rules": {key: {"packages": 0, "files": 0, "example": ""}}}
    assert any(p.startswith("GREW") for p in rs.compare({"rules": {key: {**result["rules"][key], "packages": 5}}}, grown, 0.10))
