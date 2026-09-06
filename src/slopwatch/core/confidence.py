"""
Confidence-weighted evidence combination for the UNVERIFIED_HIGH_SIGNAL gate.

Background: the point-based scorer treats every fired signal as an
independent flat addition. That has no way to express that a hardcoded
Discord webhook and "this file reads an environment variable" carry wildly
different evidentiary weight — five ubiquitous, individually-common signals
(eval, network call, env access, base64 decode — every one of which a real
browser-automation or build tool has entirely legitimate reasons to use) can
stack past the same threshold as one genuinely rare, hard-to-explain-away
signal. That's exactly how two real, legitimate, unambiguous packages
(`playwright`, `agentdiscover`) got mislabeled SUSPICIOUS / "POTENTIALLY
MALICIOUS" this session — see flagthis_sentinel task.md for the full writeup.

This module does NOT change the existing point-based score (used for
ranking/severity, calibrated by ~100 existing tests) — it adds a second,
independent check that gates the *verdict label*: if the combined evidence
isn't actually strong enough to justify confidently saying MALICIOUS or
SUSPICIOUS, report ThreatVerdict.UNVERIFIED_HIGH_SIGNAL instead — same score
(so severity/ranking is unaffected), an honest label.

How rules are rated (`confidence` meta on a YARA rule, or the hardcoded
`AST_FLAG_CONFIDENCE` table below for AST-derived flags that don't come from
YARA at all):

    HIGH   - a bare match of this pattern, on its own, has few or no
             legitimate explanations in real-world code (a live Discord
             webhook, a reverse-shell primitive, a PowerShell download
             cradle).
    MEDIUM - genuinely tilts toward malice, but real legitimate uses exist
             (disabling TLS verification, a named-secret env read that a
             legitimate CI-integration tool would also do).
    LOW    - close to uninformative on its own (eval(), a network call, env
             access, base64 decode) — near-universal in complex, entirely
             legitimate software; only meaningful in combination or when
             paired with something more specific.

These tiers are currently *estimates*, assigned by reasoning about each
rule's real-world false-positive risk (the same reasoning documented inline
in each .yar file's confidence comment) — not yet measured from labeled
data. The natural path to calibrating them for real: once the malware-corpus
ledger (flagthis_sentinel's corpus/ingestor.py) covers a representative
slice of confirmed-malicious samples AND a "golden negative" benchmark of
confirmed-legitimate packages exists (task.md Phase 13), each rule's actual
precision — P(malicious | rule fired) — becomes directly measurable, and the
LIKELIHOOD_RATIOS below should be replaced with real numbers derived from
that. Until then, these are deliberately conservative (biased toward NOT
demoting a real MALICIOUS/SUSPICIOUS call) educated priors, documented as
such rather than dressed up as measured probabilities they aren't.
"""

from typing import Dict, List, Optional

# Likelihood ratio: P(this signal fires | package is malicious) / P(this
# signal fires | package is benign). >1 means the signal is evidence FOR
# malice; the further above 1, the stronger that evidence, independent of
# how bad the signal would be if true (that's severity, a separate axis).
CONFIDENCE_LIKELIHOOD_RATIOS: Dict[str, float] = {
    "HIGH": 18.0,
    "MEDIUM": 3.0,
    "LOW": 1.3,
}

# A rule with no `confidence` meta yet (most of the 73 YARA rules — this is a
# started, not finished, audit; see task.md) defaults here: neither silently
# trusted as HIGH nor unfairly suppressed as LOW.
DEFAULT_CONFIDENCE = "MEDIUM"

# Confidence for flags generated directly by the AST visitor (python_ast.py),
# which never go through YARA and so have no rule `meta` to read from. All of
# these are narrow, specific, install/import-time execution primitives —
# verified empirically this session (55 real high-download legitimate
# packages, zero false positives) for MODULE_TOPLEVEL_EXECUTION specifically.
AST_FLAG_CONFIDENCE: Dict[str, str] = {
    "INSTALL_TIME_EXECUTION": "HIGH",
    "INSTALL_TIME_CMDCLASS_OVERRIDE": "HIGH",
    "INSTALL_TIME_NETWORK_SOCKET": "HIGH",
    "MODULE_TOPLEVEL_EXECUTION": "HIGH",
    "OBFUSCATED_DYNAMIC_ACCESS": "HIGH",
    "PYTHON_PTH_CODE_EXECUTION": "HIGH",
    "PYTHON_PTH_STARTUP_HOOK": "MEDIUM",
    "CUSTOM_BUILD_BACKEND_UNVERIFIED": "MEDIUM",
    "BUNDLED_NATIVE_BINARY": "LOW",
    # Composite proximity heuristics (yara_engine.py's own Python code, not a
    # YARA rule match) — each REQUIRES two independently-detected signal
    # categories within COMPOSITE_PROXIMITY_WINDOW_CHARS of each other in the
    # same file (e.g. an exfiltration destination *and* credential/env
    # harvesting close together). That joint condition is genuinely rare and
    # specific even though the underlying LOW-confidence primitives
    # (network call, env access) are individually ubiquitous — HIGH.
    "SOURCE_CODE_DYNAMIC_CODE_LOADER": "HIGH",
    "SOURCE_CODE_CONFIRMED_STEALER": "HIGH",
    "SOURCE_CODE_PERSISTENT_BACKDOOR": "HIGH",
    "SOURCE_CODE_EVASIVE_PAYLOAD": "HIGH",
    # npm_source.py's own hardcoded binding.gyp sandbox-escape/execution
    # pattern match (not a YARA rule) — a node-gyp Python sandbox escape or
    # direct command execution in a build config has no legitimate purpose.
    "GYP_WEAPONIZED_EXECUTION": "HIGH",
    # npm_manifest.py: a bare lifecycle hook (preinstall/install/postinstall)
    # EXISTING is ubiquitous for any native-addon npm package (confirmed:
    # node-sass, esbuild both do this legitimately) — the specific dangerous
    # SHELL PATTERN found inside one, if any, is a separate, much stronger
    # flag (SUSPICIOUS_SHELL_COMMAND) not covered by this entry.
    "LIFECYCLE_SCRIPT": "LOW",
    # A specific dangerous shell pattern (curl|bash, etc.) actually MATCHED
    # inside a lifecycle script, not just the script existing — real case:
    # "52471254zqdl55"'s preinstall curl-exfil dropper.
    "SUSPICIOUS_SHELL_COMMAND": "HIGH",
    # Plenty of legitimate small/internal/scoped npm packages omit this
    # optional metadata field.
    "MISSING_SOURCE_REPOSITORY_URL": "LOW",
}

# Assumed base rate: fraction of packages reaching AST/YARA analysis that are
# genuinely malicious. A rough prior pending real measurement — deliberately
# conservative (low), which is the direction that makes the confidence gate
# HARDER to satisfy, not easier (i.e. biased toward flagging UNVERIFIED
# rather than confidently asserting malice on thin evidence).
DEFAULT_PRIOR_MALICIOUS = 0.02

# Below this estimated posterior probability, a would-be SUSPICIOUS/MALICIOUS
# verdict built from LOW/MEDIUM signals only is downgraded to
# UNVERIFIED_HIGH_SIGNAL instead.
UNVERIFIED_GATE_PROBABILITY_THRESHOLD = 0.5


def combined_likelihood_ratio(confidences: List[str]) -> float:
    """Multiply the likelihood ratios of every fired signal, treating them as
    conditionally independent. A standard, imperfect, practical simplifying
    assumption (the same one a Naive Bayes classifier makes) — real signals
    are rarely perfectly independent, but modeling their true joint
    correlation isn't tractable here and this is a large improvement over
    today's flat addition regardless."""
    lr = 1.0
    for c in confidences:
        lr *= CONFIDENCE_LIKELIHOOD_RATIOS.get(c, CONFIDENCE_LIKELIHOOD_RATIOS[DEFAULT_CONFIDENCE])
    return lr


def estimated_probability_malicious(
    confidences: List[str], prior: float = DEFAULT_PRIOR_MALICIOUS
) -> float:
    """Bayesian combination: posterior_odds = prior_odds * combined LR,
    converted back to a probability. Returns `prior` unchanged if no signals
    fired at all."""
    if not confidences:
        return prior
    prior_odds = prior / (1 - prior)
    posterior_odds = prior_odds * combined_likelihood_ratio(confidences)
    return posterior_odds / (1 + posterior_odds)


def passes_confidence_gate(confidences: List[str], prior: float = DEFAULT_PRIOR_MALICIOUS) -> bool:
    """
    True => the evidence justifies confidently reporting MALICIOUS/SUSPICIOUS
    as computed by the point-based scorer.
    False => real signal fired and the point score crossed the threshold,
    but nothing in the evidence is actually strong enough to be confident
    about — the caller should report UNVERIFIED_HIGH_SIGNAL instead.

    Rule: a single HIGH-confidence signal is trusted outright — that's what
    HIGH means by construction, no aggregate math needed. Otherwise, the
    combined likelihood ratio of every LOW/MEDIUM signal present must itself
    clear UNVERIFIED_GATE_PROBABILITY_THRESHOLD.
    """
    if not confidences:
        return False
    if any(c == "HIGH" for c in confidences):
        return True
    return estimated_probability_malicious(confidences, prior) >= UNVERIFIED_GATE_PROBABILITY_THRESHOLD


def _resolve_signature_and_confidence(flag_text: str, yara_scanner) -> "tuple[str, str]":
    """
    Match a rendered flag against the scanner's known (prefix, label) rules
    via `startswith`, NOT a "stop at the first quote" regex: several real
    rule labels contain their OWN internal single quotes (e.g.
    "require('child_process')", "Buffer.from(..., 'base64')"), which
    silently truncates a naive regex match and was a real bug found while
    building this (playwright's `require('child_process')` hit fell through
    to DEFAULT_CONFIDENCE instead of its authored LOW). Falls back to
    AST_FLAG_CONFIDENCE by bare prefix for flags with no YARA rule behind
    them at all (AST-visitor and composite-heuristic flags — these
    legitimately need only prefix-level resolution, since every flag under
    one such prefix shares the same confidence by design).

    Returns (signature, confidence) — `signature` is prefix:label when a
    specific rule matched (for cross-file dedup in
    distinct_signal_confidences), else just the bare prefix.
    """
    prefix = flag_text.split(":", 1)[0]
    if yara_scanner is not None:
        for dedup_key, confidence in yara_scanner.confidence_index.items():
            key_prefix, _, label = dedup_key.partition(":")
            if key_prefix == prefix and flag_text.startswith(f"{prefix}: '{label}'"):
                return dedup_key, confidence
    return prefix, AST_FLAG_CONFIDENCE.get(prefix, DEFAULT_CONFIDENCE)


def flag_confidence(flag_text: str, yara_scanner) -> str:
    """Resolve one rendered flag's confidence tier. Shared by both language
    analyzers (python_ast.py, npm_source.py) so a rule rated once applies
    consistently everywhere its prefix can appear."""
    return _resolve_signature_and_confidence(flag_text, yara_scanner)[1]


def distinct_signal_confidences(flags: List[str], yara_scanner) -> List[str]:
    """
    One confidence value per DISTINCT signal type present, not one per raw
    occurrence. Without this, a large codebase where the same generic,
    LOW-confidence pattern (e.g. "reads an env var") repeats across dozens of
    files compounds its likelihood ratio dozens of times over — rewarding
    codebase SIZE with apparent confidence, which is backwards. This exactly
    mirrors how the point scorer itself already dedupes ("each distinct flag
    category contributes once"). Real case this fixes: `agentdiscover`'s ~20
    repeated LOW-confidence flags across many files falsely cleared the gate
    before this dedup was added.
    """
    seen_signatures = set()
    confidences = []
    for f in flags:
        signature, confidence = _resolve_signature_and_confidence(f, yara_scanner)
        if signature in seen_signatures:
            continue
        seen_signatures.add(signature)
        confidences.append(confidence)
    return confidences
