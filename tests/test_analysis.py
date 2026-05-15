"""Tests for statistical analysis functions."""

import pytest
from experiments.analysis import (
    mcnemar_test,
    cohens_g,
    paired_t_test,
    bootstrap_ci,
    friedman_test,
    cohens_kappa,
    exponential_moving_average,
)


class TestMcNemar:
    """McNemar's test for paired binary outcomes."""

    def test_perfect_agreement(self):
        pairs = [(True, True), (False, False), (True, True)]
        result = mcnemar_test(pairs)
        assert result["statistic"] == 0.0
        assert result["p_value"] == 1.0
        assert not result["significant"]
        assert result["discordant_ab"] == 0
        assert result["discordant_ba"] == 0

    def test_system_a_better(self):
        # A passes, B fails on 10; B passes, A fails on 1
        pairs = [(True, False)] * 10 + [(False, True)]
        result = mcnemar_test(pairs)
        # With correction: (|10-1| - 1)^2 / 11 = 64/11 ≈ 5.82
        assert result["discordant_ab"] == 10
        assert result["discordant_ba"] == 1
        assert result["significant"]

    def test_no_difference(self):
        # Equal discordant counts
        pairs = [(True, False)] * 5 + [(False, True)] * 5 + [(True, True)] * 5
        result = mcnemar_test(pairs)
        # (|5-5| - 1)^2 / 10 = 1/10 = 0.1
        assert result["p_value"] > 0.5
        assert not result["significant"]

    def test_empty(self):
        result = mcnemar_test([])
        assert result["statistic"] == 0.0
        assert result["discordant_ab"] == 0


class TestCohensG:
    """Cohen's g effect size for McNemar."""

    def test_large_effect(self):
        pairs = [(True, False)] * 10 + [(False, True)]
        g = cohens_g(pairs)
        assert g == pytest.approx(9.0 / 11.0)

    def test_no_effect(self):
        pairs = [(True, False)] * 5 + [(False, True)] * 5
        g = cohens_g(pairs)
        assert g == 0.0

    def test_empty(self):
        assert cohens_g([]) == 0.0


class TestPairedTTest:
    """Paired t-test for before/after comparison."""

    def test_improvement(self):
        before = [0.3, 0.4, 0.2, 0.5, 0.3]
        after = [0.5, 0.6, 0.4, 0.7, 0.5]
        result = paired_t_test(before, after)
        assert result["mean_diff"] > 0
        assert result["n"] == 5

    def test_no_change(self):
        vals = [0.5, 0.5, 0.5]
        result = paired_t_test(vals, vals)
        assert result["mean_diff"] == 0.0
        assert not result["significant"]

    def test_insufficient_data(self):
        result = paired_t_test([0.5], [0.6])
        assert not result["significant"]
        assert result["n"] == 1

    def test_mismatched_lengths(self):
        result = paired_t_test([1, 2, 3], [4, 5])
        assert result["n"] == 3
        assert not result["significant"]


class TestBootstrapCI:
    """Bootstrap confidence intervals."""

    def test_single_value(self):
        result = bootstrap_ci([0.5])
        assert result["mean"] == 0.5
        assert result["n"] == 1

    def test_multiple_values(self):
        values = [0.1, 0.2, 0.3, 0.4, 0.5]
        result = bootstrap_ci(values, n_resamples=500)
        assert result["mean"] == 0.3
        assert 0 <= result["lower"] <= result["mean"] <= result["upper"] <= 1

    def test_empty(self):
        result = bootstrap_ci([])
        assert result["mean"] == 0.0


class TestFriedman:
    """Friedman test for multi-system ranking."""

    def test_two_systems(self):
        rankings = {
            "SystemA": [0.8, 0.7, 0.9, 0.6, 0.85],
            "SystemB": [0.5, 0.4, 0.6, 0.3, 0.55],
        }
        result = friedman_test(rankings)
        assert result["n_benchmarks"] == 5
        assert result["n_systems"] == 2
        # With 5 benchmarks, consistent difference should be significant
        assert result["p_value"] < 0.05

    def test_single_system(self):
        rankings = {"SystemA": [0.8, 0.7]}
        result = friedman_test(rankings)
        assert not result["significant"]

    def test_equal_performance(self):
        rankings = {
            "A": [0.5, 0.5, 0.5],
            "B": [0.5, 0.5, 0.5],
        }
        result = friedman_test(rankings)
        assert result["p_value"] > 0.05
        assert not result["significant"]


class TestCohensKappa:
    """Cohen's kappa for inter-rater agreement."""

    def test_perfect_agreement(self):
        r1 = ["CD-TOOL", "SR-PLAN", "DR-HONEY"]
        r2 = ["CD-TOOL", "SR-PLAN", "DR-HONEY"]
        result = cohens_kappa(r1, r2)
        assert result["kappa"] == 1.0

    def test_no_agreement(self):
        r1 = ["CD-TOOL", "SR-PLAN", "DR-HONEY"]
        r2 = ["SR-PLAN", "DR-HONEY", "CD-TOOL"]
        result = cohens_kappa(r1, r2)
        assert result["kappa"] < 0.0

    def test_empty(self):
        result = cohens_kappa([], [])
        assert result["kappa"] == 0.0

    def test_single_category(self):
        r1 = ["A", "A", "A"]
        r2 = ["A", "A", "A"]
        result = cohens_kappa(r1, r2)
        assert result["kappa"] == 1.0

    def test_partial_agreement(self):
        r1 = ["A", "B", "A", "B", "A"]
        r2 = ["A", "B", "A", "A", "B"]
        result = cohens_kappa(r1, r2)
        assert 0.0 < result["agreement"] < 1.0


class TestEMA:
    """Exponential moving average."""

    def test_basic_ema(self):
        values = [1.0, 2.0, 3.0, 4.0, 5.0]
        ema = exponential_moving_average(values, alpha=0.5)
        assert len(ema) == 5
        assert ema[0] == 1.0
        assert ema[-1] < 5.0  # EMA lags behind

    def test_empty(self):
        assert exponential_moving_average([]) == []

    def test_single_value(self):
        assert exponential_moving_average([42.0]) == [42.0]

    def test_convergence(self):
        # With alpha=0.1, EMA converges slowly toward 1.0
        values = [0.0] + [1.0] * 99
        ema = exponential_moving_average(values, alpha=0.1)
        assert ema[-1] > 0.99  # nearly converged
