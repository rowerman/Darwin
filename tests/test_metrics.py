"""Tests for experiment metrics computation."""

import pytest
from experiments.metrics import ExperimentMetrics, compute_pass_at_k


class TestExperimentMetrics:
    """ExperimentMetrics property computations."""

    def test_empty_metrics(self):
        m = ExperimentMetrics(
            config_name="test", benchmark="test-bench", total_challenges=0,
        )
        assert m.tsr == 0.0
        assert m.token_efficiency == 0.0
        assert m.avg_steps_per_success == 0.0
        assert m.avg_time_per_challenge == 0.0
        assert m.defense_detection_rate == 0.0
        assert m.waf_bypass_rate == 0.0

    def test_tsr_full_success(self):
        m = ExperimentMetrics(
            config_name="test", benchmark="test-bench",
            total_challenges=10, successes=10,
        )
        assert m.tsr == 1.0

    def test_tsr_partial(self):
        m = ExperimentMetrics(
            config_name="test", benchmark="test-bench",
            total_challenges=10, successes=3,
        )
        assert m.tsr == 0.3

    def test_tsr_zero_challenges(self):
        m = ExperimentMetrics(
            config_name="test", benchmark="test-bench",
            total_challenges=0, successes=0,
        )
        assert m.tsr == 0.0

    def test_token_efficiency(self):
        m = ExperimentMetrics(
            config_name="test", benchmark="test-bench",
            total_challenges=10, successes=5, total_tokens=2500,
        )
        # 5 successes / (2500/1000) = 5/2.5 = 2.0
        assert m.token_efficiency == 2.0

    def test_token_efficiency_zero_tokens(self):
        m = ExperimentMetrics(
            config_name="test", benchmark="test-bench",
            total_challenges=10, successes=5, total_tokens=0,
        )
        assert m.token_efficiency == 0.0

    def test_avg_steps_per_success(self):
        m = ExperimentMetrics(
            config_name="test", benchmark="test-bench",
            total_challenges=10, successes=5, total_steps=25,
        )
        assert m.avg_steps_per_success == 5.0

    def test_avg_time_per_challenge(self):
        m = ExperimentMetrics(
            config_name="test", benchmark="test-bench",
            total_challenges=10, total_time=100.0,
        )
        assert m.avg_time_per_challenge == 10.0

    def test_defense_detection_rate(self):
        m = ExperimentMetrics(
            config_name="test", benchmark="test-bench",
            total_challenges=5, defense_detected_count=4,
            per_challenge_results=[
                {"defense_present": True},
                {"defense_present": True},
                {"defense_present": True},
                {"defense_present": True},
                {"defense_present": False},
            ],
        )
        assert m.defense_detection_rate == 1.0  # 4/4 defended detected

    def test_defense_detection_rate_no_defended(self):
        m = ExperimentMetrics(
            config_name="test", benchmark="test-bench",
            total_challenges=5, defense_detected_count=0,
            per_challenge_results=[
                {"defense_present": False},
                {"defense_present": False},
            ],
        )
        assert m.defense_detection_rate == 0.0

    def test_waf_bypass_rate(self):
        m = ExperimentMetrics(
            config_name="test", benchmark="test-bench",
            total_challenges=5, waf_bypassed_count=2,
            per_challenge_results=[
                {"waf_present": True},
                {"waf_present": True},
                {"waf_present": True},
                {"waf_present": False},
                {"waf_present": False},
            ],
        )
        assert m.waf_bypass_rate == 2.0 / 3.0

    def test_to_dict(self):
        m = ExperimentMetrics(
            config_name="test", benchmark="bench",
            total_challenges=10, successes=7, failures=3,
            total_tokens=3500, total_time=50.0, total_cost=0.025,
        )
        d = m.to_dict()
        assert d["config_name"] == "test"
        assert d["tsr"] == 0.7
        assert d["successes"] == 7
        assert d["failures"] == 3


class TestComputePassAtK:
    """Pass@k metric computation."""

    def test_all_pass(self):
        results = {
            "c1": [True, True, True],
            "c2": [True, False, True],
            "c3": [False, True, False],
        }
        assert compute_pass_at_k(results, k=3) == 1.0

    def test_some_fail(self):
        results = {
            "c1": [True, False, False],
            "c2": [False, False, False],
            "c3": [True, True, False],
            "c4": [False, True, False],
        }
        # c1: pass (first is True), c2: fail, c3: pass, c4: pass -> 3/4
        assert compute_pass_at_k(results, k=2) == 0.75

    def test_all_fail(self):
        results = {
            "c1": [False, False, False],
            "c2": [False, False, False],
        }
        assert compute_pass_at_k(results, k=3) == 0.0

    def test_empty(self):
        assert compute_pass_at_k({}, k=3) == 0.0

    def test_k_larger_than_results(self):
        results = {
            "c1": [True],
            "c2": [False],
        }
        assert compute_pass_at_k(results, k=5) == 0.5  # c1 passes, c2 fails
