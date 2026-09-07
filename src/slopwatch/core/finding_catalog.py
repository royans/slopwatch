"""
Stable finding-code catalog for SlopWatch's dependency gate.

Every finding that `slopwatch check` / `slopwatch audit` can raise on a
dependency manifest has a stable ``SLOP-XXXX`` identifier. Codes never change
meaning and are never reused, so they are safe to cite in issues, pull
requests, and CI logs, and to suppress precisely with ``--ignore SLOP-0003``
(or an ``ignore:`` list in ``.slopwatch.yaml``).

Deep-inspection findings from ``slopwatch inspect`` additionally carry a
``RULE_*`` evidence identifier emitted by the scoring engine; those are
documented in ``docs/FINDINGS.md`` and are not part of this catalog.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional


@dataclass(frozen=True)
class FindingCode:
    """One stable, documented finding SlopWatch's manifest gate can raise."""

    code: str
    reason: str  # canonical linter reason string, or a reason-family prefix
    title: str
    default_severity: str  # CRITICAL | HIGH | MEDIUM | LOW
    category: str  # hallucination | slopsquat | typosquat | unpinned
    description: str


FINDING_CATALOG: Dict[str, FindingCode] = {
    "SLOP-0001": FindingCode(
        code="SLOP-0001",
        reason="UNREGISTERED_OR_HALLUCINATED_PACKAGE",
        title="Unregistered / hallucinated package",
        default_severity="HIGH",
        category="hallucination",
        description=(
            "The dependency name does not resolve on the public registry "
            "(HTTP 404). Typically an LLM-invented ('hallucinated') package "
            "name, or a real name an attacker has not parked yet."
        ),
    ),
    "SLOP-0002": FindingCode(
        code="SLOP-0002",
        reason="MATCHES_UNREGISTERED_SLOPSQUAT_WATCHLIST",
        title="Name matches an active slopsquat watchlist entry",
        default_severity="CRITICAL",
        category="slopsquat",
        description=(
            "The dependency name matches a candidate on SlopWatch's "
            "slopsquat watchlist — a plausible hallucination target that is "
            "being actively monitored for adversarial registration."
        ),
    ),
    "SLOP-0003": FindingCode(
        code="SLOP-0003",
        reason="SUSPICIOUS_TYPOSQUAT_OF",
        title="Typosquat of a popular package",
        default_severity="HIGH",
        category="typosquat",
        description=(
            "The dependency name is within edit distance 1 of a well-known "
            "package. Common attack pattern for tricking a human or an agent "
            "that misremembers a real dependency name."
        ),
    ),
    "SLOP-0004": FindingCode(
        code="SLOP-0004",
        reason="DIRECT_VCS_OR_RAW_URL_DEPENDENCY",
        title="Direct VCS or raw-URL dependency",
        default_severity="MEDIUM",
        category="unpinned",
        description=(
            "The dependency is pulled directly from a VCS ref or a raw URL "
            "rather than a registry release, bypassing registry-level "
            "verification and (usually) version pinning."
        ),
    ),
}

# Longest reason keys first so a specific reason wins over a family prefix.
_REASON_TO_CODE = {
    fc.reason: code
    for code, fc in sorted(
        FINDING_CATALOG.items(), key=lambda kv: len(kv[1].reason), reverse=True
    )
}


def code_for_reason(reason: Optional[str]) -> Optional[str]:
    """Map a linter ``reason`` string to its stable ``SLOP-XXXX`` code."""
    if not reason:
        return None
    if reason in _REASON_TO_CODE:
        return _REASON_TO_CODE[reason]
    for family, code in _REASON_TO_CODE.items():
        if reason.startswith(family):
            return code
    return None


def resolve_ignore_token(token: str) -> Optional[str]:
    """Resolve a user-supplied ``--ignore`` token to a catalog code.

    Accepts a code (``SLOP-0003`` / ``slop-0003``) or a reason string
    (``SUSPICIOUS_TYPOSQUAT_OF_REQUESTS``). Returns ``None`` if unknown.
    """
    if not token:
        return None
    t = token.strip().upper()
    if t in FINDING_CATALOG:
        return t
    return code_for_reason(t)
