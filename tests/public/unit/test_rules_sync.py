"""config/rules/ must mirror the packaged rules that are actually loaded (src/slopwatch/rules/)."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]


def test_config_rules_mirror_packaged_rules():
    packaged = ROOT / "src" / "slopwatch" / "rules"
    mirror = ROOT / "config" / "rules"
    for f in sorted(packaged.glob("*.yar")):
        assert (mirror / f.name).read_text() == f.read_text(), (
            f"config/rules/{f.name} drifted from src/slopwatch/rules/{f.name}; edit the packaged copy and re-copy"
        )
