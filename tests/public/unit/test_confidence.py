"""
Unit tests for core.confidence's Bayesian evidence combination — decoupled
from the full scoring pipeline so the math itself is verified independently
of any particular rule's point-scoring calibration.
"""

from slopwatch.core.confidence import (
    combined_likelihood_ratio,
    estimated_probability_malicious,
    passes_confidence_gate,
)


def test_no_signals_returns_prior():
    assert estimated_probability_malicious([]) == 0.02


def test_single_high_confidence_passes_gate_regardless_of_math():
    """HIGH means HIGH by construction — no aggregate math needed, and this
    must hold even if the probability math alone wouldn't clear the bar."""
    assert passes_confidence_gate(["HIGH"]) is True
    assert passes_confidence_gate(["HIGH", "LOW", "LOW", "LOW"]) is True


def test_single_low_or_medium_signal_fails_gate():
    assert passes_confidence_gate(["LOW"]) is False
    assert passes_confidence_gate(["MEDIUM"]) is False


def test_many_low_confidence_signals_still_fail_gate():
    """The core property this whole module exists for: weak signals stacking
    should NOT compound into false confidence the way flat point-addition
    does. Five LOW-confidence hits together should still be far short of the
    gate — real case this protects: `playwright`, `agentdiscover`."""
    assert passes_confidence_gate(["LOW"] * 5) is False
    assert estimated_probability_malicious(["LOW"] * 5) < 0.3


def test_enough_medium_confidence_signals_can_pass_gate():
    """Unlike LOW, several genuinely MEDIUM signals compounding is allowed to
    eventually justify confidence — MEDIUM means real, if imperfect, evidence."""
    assert passes_confidence_gate(["MEDIUM"] * 2) is False
    assert passes_confidence_gate(["MEDIUM"] * 4) is True


def test_combined_likelihood_ratio_multiplies():
    assert combined_likelihood_ratio(["HIGH", "HIGH"]) == 18.0 * 18.0
    assert combined_likelihood_ratio([]) == 1.0


def test_unknown_confidence_label_defaults_to_medium_weight():
    from slopwatch.core.confidence import CONFIDENCE_LIKELIHOOD_RATIOS, DEFAULT_CONFIDENCE
    assert combined_likelihood_ratio(["NOT_A_REAL_TIER"]) == CONFIDENCE_LIKELIHOOD_RATIOS[DEFAULT_CONFIDENCE]
