"""Statistical analysis for experiment results.

Methods:
  - McNemar's test (paired binary data — per-challenge TSR comparison)
  - Cohen's g (effect size for McNemar)
  - Friedman test + Nemenyi post-hoc (multi-system ranking)
  - Paired t-test (before/after comparison, e.g., CTEG learning curve)
  - Bootstrap confidence intervals
  - Cohen's κ (inter-rater agreement for failure coding)
"""

from __future__ import annotations

import math
from collections import defaultdict
from typing import Any, Dict, List, Optional, Tuple


# ── McNemar's Test (paired binary outcomes) ─────────────────────

def mcnemar_test(
    paired_results: List[Tuple[bool, bool]],
    continuity_correction: bool = True,
) -> Dict[str, Any]:
    """McNemar's test for paired binary data.

    Used to compare two systems on the same set of challenges.
    Each pair is (system_a_pass, system_b_pass).

    Returns:
        {"statistic": chi2, "p_value": p, "significant": True/False,
         "discordant_ab": count, "discordant_ba": count}

    Reference: McNemar, Q. (1947). Note on the sampling error of the
    difference between correlated proportions or percentages.
    """
    # Count discordant pairs
    n_ab = sum(1 for a, b in paired_results if a and not b)  # A pass, B fail
    n_ba = sum(1 for a, b in paired_results if not a and b)   # A fail, B pass

    if n_ab + n_ba == 0:
        return {
            "statistic": 0.0, "p_value": 1.0, "significant": False,
            "discordant_ab": 0, "discordant_ba": 0,
        }

    if continuity_correction:
        chi2 = (abs(n_ab - n_ba) - 1) ** 2 / (n_ab + n_ba)
    else:
        chi2 = (n_ab - n_ba) ** 2 / (n_ab + n_ba)

    # Chi-square with 1 df → p-value approximation
    p_value = 1.0 - _chi2_cdf(chi2, 1)

    return {
        "statistic": chi2,
        "p_value": p_value,
        "significant": p_value < 0.05,
        "discordant_ab": n_ab,
        "discordant_ba": n_ba,
        "n_pairs": len(paired_results),
    }


def cohens_g(paired_results: List[Tuple[bool, bool]]) -> float:
    """Cohen's g effect size for McNemar test.

    g = |n_ab - n_ba| / n
    Values: small=0.05, medium=0.15, large=0.25
    """
    n_ab = sum(1 for a, b in paired_results if a and not b)
    n_ba = sum(1 for a, b in paired_results if not a and b)
    n = len(paired_results)
    if n == 0:
        return 0.0
    return abs(n_ab - n_ba) / n


# ── Paired t-test ──────────────────────────────────────────────────

def paired_t_test(
    before_values: List[float],
    after_values: List[float],
) -> Dict[str, Any]:
    """Paired t-test for before/after comparison.

    Used for CTEG learning curve analysis (first N vs last N tasks).

    Returns:
        {"statistic": t, "p_value": p, "significant": True/False,
         "mean_diff": mean_difference, "n": n}
    """
    n = len(before_values)
    if n < 2 or n != len(after_values):
        return {"statistic": 0, "p_value": 1.0, "significant": False, "n": n}

    diffs = [a - b for a, b in zip(after_values, before_values)]
    mean_diff = sum(diffs) / n
    if n == 1:
        return {"statistic": 0, "p_value": 1.0, "significant": False,
                "mean_diff": mean_diff, "n": n}

    sd_diff = math.sqrt(sum((d - mean_diff) ** 2 for d in diffs) / (n - 1))

    if sd_diff == 0:
        return {"statistic": 0, "p_value": 1.0, "significant": False,
                "mean_diff": mean_diff, "n": n}

    t = mean_diff / (sd_diff / math.sqrt(n))
    df = n - 1
    p_value = 2 * (1.0 - _t_cdf(abs(t), df))

    return {
        "statistic": t,
        "p_value": p_value,
        "significant": p_value < 0.05,
        "mean_diff": mean_diff,
        "sd_diff": sd_diff,
        "n": n,
        "df": df,
    }


# ── Bootstrap CI ──────────────────────────────────────────────────

def bootstrap_ci(
    values: List[float],
    n_resamples: int = 1000,
    confidence: float = 0.95,
) -> Dict[str, float]:
    """Bootstrap confidence interval for a metric.

    Returns:
        {"mean": mean, "lower": lower_bound, "upper": upper_bound, "n": n}
    """
    import random
    random.seed(42)

    n = len(values)
    if n < 2:
        return {"mean": sum(values) / max(n, 1), "lower": 0, "upper": 0, "n": n}

    means = []
    for _ in range(n_resamples):
        sample = [random.choice(values) for _ in range(n)]
        means.append(sum(sample) / n)

    means.sort()
    alpha = (1 - confidence) / 2
    lower_idx = int(alpha * n_resamples)
    upper_idx = int((1 - alpha) * n_resamples)

    return {
        "mean": sum(values) / n,
        "lower": means[lower_idx],
        "upper": means[min(upper_idx, n_resamples - 1)],
        "n": n,
    }


# ── Friedman + Nemenyi ────────────────────────────────────────────

def friedman_test(
    rankings: Dict[str, List[float]],
) -> Dict[str, Any]:
    """Friedman test for multi-system comparison.

    Args:
        rankings: {system_name: [rank_or_score_per_benchmark, ...]}

    Returns:
        {"statistic": F, "p_value": p, "significant": True/False}
    """
    systems = list(rankings.keys())
    if len(systems) < 2:
        return {"statistic": 0, "p_value": 1.0, "significant": False}

    n = len(rankings[systems[0]])  # number of benchmarks/groups
    k = len(systems)

    # Convert scores to ranks per benchmark
    ranks = {s: [] for s in systems}
    for i in range(n):
        benchmark_scores = [(s, rankings[s][i]) for s in systems]
        benchmark_scores.sort(key=lambda x: x[1], reverse=True)
        for rank, (system, _) in enumerate(benchmark_scores, 1):
            ranks[system].append(rank)

    # Compute rank sums
    R = {s: sum(ranks[s]) for s in systems}

    # Friedman statistic
    term = sum(r ** 2 for r in R.values())
    chi2 = (12 / (n * k * (k + 1))) * term - 3 * n * (k + 1)

    df = k - 1
    p_value = 1.0 - _chi2_cdf(chi2, df)

    return {
        "statistic": chi2,
        "p_value": p_value,
        "significant": p_value < 0.05,
        "df": df,
        "n_benchmarks": n,
        "n_systems": k,
    }


# ── Cohen's κ (inter-rater agreement) ────────────────────────────

def cohens_kappa(
    rater1: List[str],
    rater2: List[str],
) -> Dict[str, float]:
    """Cohen's kappa for inter-rater agreement.

    Used for failure mode coding consistency check (RQ6).

    Returns:
        {"kappa": kappa, "agreement": p_o, "chance_agreement": p_e}
    """
    n = len(rater1)
    if n != len(rater2) or n == 0:
        return {"kappa": 0.0, "agreement": 0.0, "chance_agreement": 0.0}

    # Get all unique categories
    categories = sorted(set(rater1 + rater2))
    cat_to_idx = {c: i for i, c in enumerate(categories)}

    # Observed agreement
    agreements = sum(1 for a, b in zip(rater1, rater2) if a == b)
    p_o = agreements / n

    # Expected (chance) agreement
    counts1 = defaultdict(int)
    counts2 = defaultdict(int)
    for a, b in zip(rater1, rater2):
        counts1[a] += 1
        counts2[b] += 1

    p_e = sum(
        (counts1[c] / n) * (counts2[c] / n)
        for c in categories
    )

    if p_e == 1.0:
        return {"kappa": 1.0, "agreement": p_o, "chance_agreement": p_e}

    kappa = (p_o - p_e) / (1.0 - p_e)
    return {"kappa": kappa, "agreement": p_o, "chance_agreement": p_e}


# ── Helper: Exponential Moving Average ────────────────────────────

def exponential_moving_average(values: List[float], alpha: float = 0.1) -> List[float]:
    """Compute EMA for learning curve visualization."""
    if not values:
        return []
    ema = [values[0]]
    for v in values[1:]:
        ema.append(alpha * v + (1 - alpha) * ema[-1])
    return ema


# ── Internal CDF approximations ───────────────────────────────────

def _chi2_cdf(x: float, df: int) -> float:
    """Approximate chi-square CDF using gamma regularized."""
    if x <= 0:
        return 0.0
    if df <= 0:
        return 1.0
    # Wilson-Hilferty approximation for chi2 → normal
    z = ((x / df) ** (1 / 3) - 1 + 2 / (9 * df)) / math.sqrt(2 / (9 * df))
    return _normal_cdf(z)


def _t_cdf(t: float, df: int) -> float:
    """Approximate t-distribution CDF using normal for large df."""
    if df > 30:
        return _normal_cdf(t)
    # Rough approximation for small df
    return _normal_cdf(t * (1 - 1 / (4 * df)) / math.sqrt(1 + t * t / (2 * df)))


def _normal_cdf(x: float) -> float:
    """Standard normal CDF approximation."""
    a1, a2, a3, a4, a5 = 0.254829592, -0.284496736, 1.421413741, -1.453152027, 1.061405429
    p = 0.3275911
    sign = 1 if x >= 0 else -1
    x = abs(x) / math.sqrt(2)
    t = 1 / (1 + p * x)
    y = 1 - (((((a5 * t + a4) * t) + a3) * t + a2) * t + a1) * t * math.exp(-x * x)
    return 0.5 * (1 + sign * y)
