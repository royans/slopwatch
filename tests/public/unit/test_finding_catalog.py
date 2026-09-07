import pytest
from pathlib import Path

from slopwatch.core.finding_catalog import (
    FINDING_CATALOG,
    code_for_reason,
    resolve_ignore_token,
)
from slopwatch.linter.lockfile import DependencyLinter, load_project_config


def test_catalog_codes_are_well_formed():
    for code, fc in FINDING_CATALOG.items():
        assert code.startswith("SLOP-")
        assert fc.code == code
        assert fc.default_severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
        assert fc.title and fc.description


def test_code_for_reason_exact_and_family():
    assert code_for_reason("UNREGISTERED_OR_HALLUCINATED_PACKAGE") == "SLOP-0001"
    assert code_for_reason("MATCHES_UNREGISTERED_SLOPSQUAT_WATCHLIST") == "SLOP-0002"
    assert code_for_reason("DIRECT_VCS_OR_RAW_URL_DEPENDENCY") == "SLOP-0004"
    # dynamic typosquat family resolves to one stable code
    assert code_for_reason("SUSPICIOUS_TYPOSQUAT_OF_REQUESTS") == "SLOP-0003"
    assert code_for_reason("SUSPICIOUS_TYPOSQUAT_OF_LODASH") == "SLOP-0003"
    assert code_for_reason("") is None
    assert code_for_reason("NOT_A_REAL_REASON") is None


def test_resolve_ignore_token_accepts_code_or_reason():
    assert resolve_ignore_token("SLOP-0003") == "SLOP-0003"
    assert resolve_ignore_token("slop-0003") == "SLOP-0003"
    assert resolve_ignore_token("suspicious_typosquat_of_requests") == "SLOP-0003"
    assert resolve_ignore_token("bogus") is None


@pytest.mark.asyncio
async def test_flagged_items_carry_stable_codes(tmp_path: Path):
    req_file = tmp_path / "requirements.txt"
    req_file.write_text("reqeusts==2.31.0\n")

    linter = DependencyLinter(repository=None, offline=True)
    result = await linter.audit_file(req_file)

    assert result["flagged_count"] == 1
    assert result["flagged_dependencies"][0]["code"] == "SLOP-0003"


@pytest.mark.asyncio
async def test_ignore_codes_move_finding_to_suppression_ledger(tmp_path: Path):
    req_file = tmp_path / "requirements.txt"
    req_file.write_text("reqeusts==2.31.0\n")

    linter = DependencyLinter(repository=None, offline=True, ignore_codes={"SLOP-0003"})
    result = await linter.audit_file(req_file)

    assert result["flagged_count"] == 0
    assert result["is_clean"] is True
    assert result["suppressed_count"] == 1
    supp = result["suppressed_dependencies"][0]
    assert supp["kind"] == "ignore"
    assert supp["code"] == "SLOP-0003"


@pytest.mark.asyncio
async def test_allowlist_reason_flows_into_suppression_ledger(tmp_path: Path):
    cfg_file = tmp_path / ".slopwatch.yaml"
    cfg_file.write_text(
        "allowlist:\n"
        "  - name: my-internal-sdk\n"
        '    reason: "approved 2026-09 (SEC-412)"\n'
    )
    req_file = tmp_path / "requirements.txt"
    req_file.write_text("my-internal-sdk==1.0.0\n")

    cfg = load_project_config(tmp_path)
    linter = DependencyLinter(repository=None, offline=True, config=cfg)
    result = await linter.audit_file(req_file)

    assert result["is_clean"] is True
    assert result["suppressed_count"] == 1
    supp = result["suppressed_dependencies"][0]
    assert supp["kind"] == "allowlist"
    assert supp["reason"] == "approved 2026-09 (SEC-412)"


@pytest.mark.asyncio
async def test_ignore_list_in_config_is_honored(tmp_path: Path):
    cfg_file = tmp_path / ".slopwatch.yaml"
    cfg_file.write_text("ignore:\n  - SLOP-0003\n")
    req_file = tmp_path / "requirements.txt"
    req_file.write_text("reqeusts==2.31.0\n")

    cfg = load_project_config(tmp_path)
    assert "SLOP-0003" in cfg["ignore"]

    linter = DependencyLinter(repository=None, offline=True, config=cfg)
    result = await linter.audit_file(req_file)
    assert result["is_clean"] is True
    assert result["suppressed_count"] == 1
