"""
Unit tests for Counterfactual Latency Diagnosis Engine.
Validates pure verdict function, bootstrap confidence intervals,
and causal confirmation/refutation logic.
"""

from engine.counterfactual_engine import CounterfactualDiagnosisEngine


def test_verdict_pure_function():
    # Case 1: CONFIRMED (Median >= delta and CI lower > 0)
    v1 = CounterfactualDiagnosisEngine.evaluate_verdict(
        median_effect=0.75, ci_lower=0.55, ci_upper=0.85, delta=0.30
    )
    assert v1 == "CONFIRMED"

    # Case 2: REFUTED (CI upper < delta)
    v2 = CounterfactualDiagnosisEngine.evaluate_verdict(
        median_effect=0.08, ci_lower=-0.05, ci_upper=0.18, delta=0.30
    )
    assert v2 == "REFUTED"

    # Case 3: INCONCLUSIVE (Overlapping delta, or negative lower bound)
    v3 = CounterfactualDiagnosisEngine.evaluate_verdict(
        median_effect=0.32, ci_lower=-0.10, ci_upper=0.55, delta=0.30
    )
    assert v3 == "INCONCLUSIVE"


def test_counterfactual_experiment_cpu_contention_confirmed():
    engine = CounterfactualDiagnosisEngine(delta_threshold=0.30)
    result = engine.run_counterfactual_experiment("CPU_CONTENTION", n_pairs=10, base_seed=123)
    
    assert result.verdict == "CONFIRMED"
    assert result.median_effect > 0.50
    assert result.ci_lower > 0.0


def test_counterfactual_experiment_decoy_refuted():
    engine = CounterfactualDiagnosisEngine(delta_threshold=0.30)
    # Decoy scenario: Innocent background task blamed for latency
    result = engine.run_counterfactual_experiment("DECOY_BACKGROUND", n_pairs=10, base_seed=456)
    
    # Must be REFUTED by the counterfactual rerun!
    assert result.verdict == "REFUTED"
    assert result.ci_upper < 0.30


def test_counterfactual_experiment_noisy_inconclusive():
    engine = CounterfactualDiagnosisEngine(delta_threshold=0.40)
    result = engine.run_counterfactual_experiment("NOISY_UNSTABLE", n_pairs=8, base_seed=789)
    assert result.verdict == "INCONCLUSIVE"
