"""Contract + behaviour tests for the unified signal model & catalog."""

import pytest

from slopguard.core.dto import EvidenceSignal
from slopguard.core.signals import (
    SIGNAL_CATALOG,
    CODE_EXECUTION_CODES,
    CONFIRMED_DANGEROUS_CODES,
    Finding,
    build_findings,
    catalog_as_rows,
    findings_from_analysis_details,
    findings_to_legacy_facets,
    flag_code,
    severity_rank,
)


def test_catalog_codes_are_unique_and_well_formed():
    rows = catalog_as_rows()
    codes = [r["signal_code"] for r in rows]
    assert len(codes) == len(set(codes))
    for r in rows:
        assert r["title"]
        assert r["severity"] in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
        assert r["severity_rank"] == severity_rank(r["severity"])
        # a signal that gates MALICIOUS should also be code-execution classified
        if r["gates_malicious"]:
            assert r["is_code_execution"], r["signal_code"]


def test_scorer_prefix_tuples_stay_in_sync_with_catalog():
    """The scorer's hand-maintained prefix tuples must be a subset of the catalog's
    derived classification — this is the guard that stops the two drifting apart."""
    from slopguard.assessor.scorer import (
        CODE_EXECUTION_FLAG_PREFIXES,
        CONFIRMED_DANGEROUS_FLAG_PREFIXES,
    )

    missing_exec = [p for p in CODE_EXECUTION_FLAG_PREFIXES if p not in CODE_EXECUTION_CODES]
    assert not missing_exec, f"scorer code-exec prefixes absent from catalog: {missing_exec}"

    missing_dang = [
        p for p in CONFIRMED_DANGEROUS_FLAG_PREFIXES
        if p not in CONFIRMED_DANGEROUS_CODES
    ]
    assert not missing_dang, f"scorer dangerous prefixes absent from catalog: {missing_dang}"


@pytest.mark.parametrize("flag,expected", [
    ("INSTALL_TIME_EXECUTION: 'exec' at top-level in setup.py:12", "INSTALL_TIME_EXECUTION"),
    ("MISSING_SOURCE_REPOSITORY_URL", "MISSING_SOURCE_REPOSITORY_URL"),
    ("SYNTAX_ERROR_IN_setup.py: invalid syntax", "SYNTAX_ERROR"),
    ("EXFILTRATION_DESTINATION_DETECTED: Discord Webhook in a.js:3 (+2 more occurrence(s) elsewhere)",
     "EXFILTRATION_DESTINATION_DETECTED"),
])
def test_flag_code_extraction(flag, expected):
    assert flag_code(flag) == expected


def test_flag_strings_never_change_score_on_rederivation():
    """Re-deriving findings from stored flag strings must contribute 0 points so a
    backfill can never move an existing threat_score."""
    fs = build_findings([], [
        "LIFECYCLE_SCRIPT: 'postinstall' -> 'curl x | bash'",
        "INSTALL_TIME_EXECUTION: 'exec' in setup.py:1",
    ])
    assert all(f.score == 0 for f in fs)
    assert {f.code for f in fs} == {"LIFECYCLE_SCRIPT", "INSTALL_TIME_EXECUTION"}


def test_structured_signal_wins_over_flag_on_dedup():
    sig = EvidenceSignal(
        signal_id="SIGNAL_INFLATED_MAJOR_VERSION_CONFUSION",
        category="VERSIONING_ANOMALY", severity="MEDIUM", score_impact=25,
        rule_code="RULE_INFLATED_MAJOR_VERSION", human_description="v99 on new pkg",
    )
    fs = build_findings([sig], ["SIGNAL_INFLATED_MAJOR_VERSION_CONFUSION: dupe"])
    match = [f for f in fs if f.code == "SIGNAL_INFLATED_MAJOR_VERSION_CONFUSION"]
    assert len(match) == 1
    assert match[0].score == 25  # kept the structured one


def test_legacy_facets_projection_matches_known_expectations():
    fs = build_findings([], [
        "LIFECYCLE_SCRIPT: x",
        "SOURCE_CODE_ENV_VARS_ACCESS: process.env in a.js:2",
        "CREDENTIAL_PATH_HARVESTING: ~/.aws in b.js:9",
    ])
    facets = findings_to_legacy_facets(fs)
    assert facets["has_install_hook"] is True
    assert facets["has_env_vars_access"] is True
    assert facets["has_credential_harvesting"] is True
    assert facets["has_pth_execution"] is False
    assert facets["has_confirmed_dangerous_execution"] is False


def test_gates_malicious_flags_are_detected():
    fs = build_findings([], ["PYTHON_PTH_CODE_EXECUTION: dangerous import os in x.pth"])
    assert any(f.gates_malicious for f in fs)
    facets = findings_to_legacy_facets(fs)
    assert facets["has_confirmed_dangerous_execution"] is True


def test_findings_from_analysis_details_prefers_stored_findings():
    stored = Finding.from_spec("SIGNAL_HIGH_VALUE_BRAND_TARGET", detector="scorer", score=15)
    details = {
        "findings": [stored.model_dump(mode="json")],
        "flags": ["LIFECYCLE_SCRIPT: x"],  # must be ignored when findings present
    }
    fs = findings_from_analysis_details(details)
    assert [f.code for f in fs] == ["SIGNAL_HIGH_VALUE_BRAND_TARGET"]


def test_findings_from_analysis_details_falls_back_to_legacy_shape():
    details = {
        "signals": [{
            "signal_id": "SIGNAL_COMBINATORIAL_GRAMMAR_MATCH", "category": "NAMING_HEURISTIC",
            "severity": "MEDIUM", "score_impact": 25, "rule_code": "RULE_GRAMMAR_TRIPLET_MATCH",
            "human_description": "matches template",
        }],
        "flags": ["EXFILTRATION_DESTINATION_DETECTED: Discord in a.js:1"],
    }
    fs = findings_from_analysis_details(details)
    codes = {f.code for f in fs}
    assert "SIGNAL_COMBINATORIAL_GRAMMAR_MATCH" in codes
    assert "EXFILTRATION_DESTINATION_DETECTED" in codes


def test_finding_roundtrips_through_evidence_signal():
    f = Finding.from_spec("SIGNAL_UNVERIFIED_AUTHOR_DOMAIN", detector="scorer", score=25)
    ev = f.to_evidence_signal()
    assert ev.signal_id == "SIGNAL_UNVERIFIED_AUTHOR_DOMAIN"
    assert ev.score_impact == 25
    f2 = Finding.from_evidence_signal(ev)
    assert f2.code == f.code
    assert f2.score == f.score
