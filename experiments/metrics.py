"""Experiment metrics — TSR, Pass@k, token efficiency, defense detection rates."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass
class ExperimentMetrics:
    """Aggregated metrics for a single experiment configuration."""
    config_name: str
    benchmark: str
    total_challenges: int
    successes: int = 0
    failures: int = 0
    total_steps: int = 0
    total_tokens: int = 0
    total_time: float = 0.0
    total_cost: float = 0.0
    defense_detected_count: int = 0
    waf_bypassed_count: int = 0
    flag_hallucinations: int = 0
    per_challenge_results: List[Dict[str, Any]] = field(default_factory=list)

    @property
    def tsr(self) -> float:
        """Task Success Rate."""
        if self.total_challenges == 0:
            return 0.0
        return self.successes / self.total_challenges

    @property
    def token_efficiency(self) -> float:
        """TSR per 1000 tokens."""
        if self.total_tokens == 0:
            return 0.0
        return self.successes / (self.total_tokens / 1000)

    @property
    def avg_steps_per_success(self) -> float:
        """Average steps per successful challenge."""
        if self.successes == 0:
            return 0.0
        return self.total_steps / self.successes

    @property
    def avg_time_per_challenge(self) -> float:
        """Average time in seconds per challenge."""
        if self.total_challenges == 0:
            return 0.0
        return self.total_time / self.total_challenges

    @property
    def defense_detection_rate(self) -> float:
        """Rate of defense detection on defended challenges."""
        defended = sum(
            1 for r in self.per_challenge_results if r.get("defense_present", False)
        )
        if defended == 0:
            return 0.0
        return self.defense_detected_count / defended

    @property
    def waf_bypass_rate(self) -> float:
        """Rate of WAF bypass on WAF challenges."""
        waf_challenges = sum(
            1 for r in self.per_challenge_results if r.get("waf_present", False)
        )
        if waf_challenges == 0:
            return 0.0
        return self.waf_bypassed_count / waf_challenges

    def summary(self) -> str:
        """Human-readable metrics summary."""
        return (
            f"{self.config_name} on {self.benchmark}: "
            f"TSR={self.tsr:.1%} ({self.successes}/{self.total_challenges}), "
            f"token_eff={self.token_efficiency:.3f}, "
            f"defense_detect={self.defense_detection_rate:.1%}, "
            f"waf_bypass={self.waf_bypass_rate:.1%}"
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dict for JSON serialization."""
        return {
            "config_name": self.config_name,
            "benchmark": self.benchmark,
            "total_challenges": self.total_challenges,
            "successes": self.successes,
            "failures": self.failures,
            "tsr": self.tsr,
            "token_efficiency": self.token_efficiency,
            "avg_steps_per_success": self.avg_steps_per_success,
            "avg_time_per_challenge": self.avg_time_per_challenge,
            "total_cost": self.total_cost,
            "defense_detection_rate": self.defense_detection_rate,
            "waf_bypass_rate": self.waf_bypass_rate,
            "flag_hallucinations": self.flag_hallucinations,
        }


def compute_pass_at_k(
    per_challenge_runs: Dict[str, List[bool]], k: int = 3
) -> float:
    """Compute Pass@k metric.

    Args:
        per_challenge_runs: challenge_id -> [True/False for each run]
        k: number of attempts to consider

    Returns:
        Pass@k score (0.0-1.0)
    """
    passed = 0
    total = 0
    for challenge_id, results in per_challenge_runs.items():
        total += 1
        if any(results[:k]):
            passed += 1
    return passed / total if total > 0 else 0.0
