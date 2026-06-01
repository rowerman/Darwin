"""Result aggregator — collects, classifies, and reports experiment results."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any


# ── Failure classification ───────────────────────────────────────────

FAILURE_CATEGORIES = {
    "STARTUP_FAILURE": "Scenario infrastructure failed to start",
    "STARTUP_TIMEOUT": "Scenario did not become ready within timeout",
    "ORCHESTRATOR_ERROR": "Orchestrator raised an unhandled exception",
    "TARGET_UNREACHABLE": "Target host/port not reachable after startup",
    "NMAP_FAILURE": "Nmap scan failed or returned no open ports",
    "TOOL_MISSING": "Required external tool not found",
    "LLM_API_ERROR": "LLM API call failed (rate limit, auth, timeout)",
    "TOKEN_EXHAUSTION": "Token budget exhausted before finding flag",
    "TIME_EXHAUSTION": "Time budget exhausted before finding flag",
    "FLAG_NOT_FOUND": "Orchestrator completed but found no flag",
    "FLAG_MISMATCH": "Flag found but does not match expected pattern",
    "HALLUCINATION": "Flag reported but does not match ground truth",
    "TEARDOWN_FAILURE": "Scenario cleanup failed (non-fatal)",
    "UNKNOWN": "Uncategorized failure",
}


# ── Data classes ──────────────────────────────────────────────────────

@dataclass
class AttemptResult:
    attempt: int
    success: bool
    flag: str = ""
    steps: int = 0
    tokens_used: int = 0
    time_elapsed: float = 0.0
    defense_detected: bool = False
    waf_bypassed: bool = False
    waf_type: str = ""
    error: str = ""


@dataclass
class ScenarioResult:
    scenario_id: str
    category: str
    difficulty: str
    group: str  # "docker" | "k8s"

    passed: bool = False
    attempts: list[dict] = field(default_factory=list)

    # Aggregate metrics
    total_time_seconds: float = 0.0
    total_tokens: int = 0
    total_steps: int = 0

    # Lifecycle errors
    has_startup_error: bool = False
    startup_error: str = ""
    has_teardown_error: bool = False
    teardown_error: str = ""

    # Failure classification (only set when not passed and no startup error)
    failure_category: str = ""
    failure_detail: str = ""

    # Extra metadata
    expected_flag: str = ""
    scenario_name: str = ""
    cve: str = ""


@dataclass
class RunSummary:
    """Top-level summary of an experiment run."""
    run_id: str = ""
    timestamp: str = ""
    config: dict = field(default_factory=dict)

    total_scenarios: int = 0
    available_scenarios: int = 0
    blocked_scenarios: int = 0
    passed: int = 0
    failed: int = 0
    startup_failures: int = 0

    overall_tsr: float = 0.0
    total_time_seconds: float = 0.0
    total_tokens: int = 0

    by_group: dict[str, dict] = field(default_factory=dict)
    by_category: dict[str, dict] = field(default_factory=dict)
    failures: list[dict] = field(default_factory=list)
    blocked: list[dict] = field(default_factory=list)


# ── Failure classifier ────────────────────────────────────────────────

def classify_failure(result: ScenarioResult) -> str:
    """Classify a failed scenario result into a failure category.

    Heuristic priority:
    1. If startup_error is set → STARTUP_FAILURE
    2. If orchestrator error message contains keywords → specific category
    3. Otherwise → UNKNOWN
    """
    if result.has_startup_error:
        msg = result.startup_error.lower()
        if "timeout" in msg or "timed out" in msg:
            return "STARTUP_TIMEOUT"
        return "STARTUP_FAILURE"

    # Check error messages from attempts
    errors = []
    for a in result.attempts:
        if a.get("error"):
            errors.append(a["error"].lower())

    combined = " ".join(errors)

    if not combined:
        # No explicit error but still failed — likely flag not found
        return "FLAG_NOT_FOUND"

    if any(kw in combined for kw in ("rate limit", "rate_limit", "429", "api key", "auth", "unauthorized")):
        return "LLM_API_ERROR"
    if any(kw in combined for kw in ("token", "context length", "max_tokens")):
        return "TOKEN_EXHAUSTION"
    if any(kw in combined for kw in ("time", "timeout", "timed out", "budget")):
        return "TIME_EXHAUSTION"
    if any(kw in combined for kw in ("nmap", "port scan", "no open ports")):
        return "NMAP_FAILURE"
    if any(kw in combined for kw in ("tool", "not found", "missing", "command not found")):
        return "TOOL_MISSING"
    if any(kw in combined for kw in ("connection refused", "unreachable", "no route")):
        return "TARGET_UNREACHABLE"
    if any(kw in combined for kw in ("hallucin", "flag mismatch", "wrong flag")):
        return "FLAG_MISMATCH"

    return "UNKNOWN"


# ── Summary report builder ────────────────────────────────────────────

def build_summary(
    results: list[ScenarioResult],
    blocked: list[dict],
    config: dict,
    run_id: str = "",
) -> RunSummary:
    """Build a summary report from all scenario results."""
    available = [r for r in results if not r.has_startup_error or r.passed]
    passed = [r for r in results if r.passed]

    summary = RunSummary(
        run_id=run_id,
        timestamp=time.strftime("%Y-%m-%dT%H:%M:%S"),
        config=config,
        total_scenarios=len(results),
        available_scenarios=len(results),
        blocked_scenarios=len(blocked),
        passed=len(passed),
        failed=len(available) - len(passed),
        startup_failures=sum(1 for r in results if r.has_startup_error and not r.passed),
        overall_tsr=len(passed) / max(len(available), 1),
        total_time_seconds=sum(r.total_time_seconds for r in results),
        total_tokens=sum(r.total_tokens for r in results),
        blocked=blocked,
    )

    # Per-group stats
    for group_name in ["docker", "k8s"]:
        group_results = [r for r in results if r.group == group_name]
        group_passed = [r for r in group_results if r.passed]
        group_available = [r for r in group_results if not r.has_startup_error or r.passed]
        summary.by_group[group_name] = {
            "total": len(group_results),
            "available": len(group_available),
            "passed": len(group_passed),
            "failed": len(group_available) - len(group_passed),
            "startup_failures": sum(1 for r in group_results if r.has_startup_error and not r.passed),
            "tsr": len(group_passed) / max(len(group_available), 1),
            "total_time_minutes": round(sum(r.total_time_seconds for r in group_results) / 60, 1),
            "total_tokens": sum(r.total_tokens for r in group_results),
        }

    # Per-category stats
    for cat in ["web", "db", "linux", "k8s", "defense"]:
        cat_results = [r for r in results if r.category == cat]
        if not cat_results:
            continue
        cat_passed = [r for r in cat_results if r.passed]
        cat_available = [r for r in cat_results if not r.has_startup_error or r.passed]
        summary.by_category[cat] = {
            "total": len(cat_results),
            "passed": len(cat_passed),
            "tsr": len(cat_passed) / max(len(cat_available), 1),
        }

    # Failure list (only failed scenarios)
    for r in results:
        if r.passed:
            continue
        failure_info = {
            "scenario_id": r.scenario_id,
            "name": r.scenario_name,
            "category": r.category,
            "difficulty": r.difficulty,
            "group": r.group,
            "failure_category": r.failure_category,
            "failure_detail": r.failure_detail,
            "startup_error": r.startup_error,
            "attempt_errors": [a.get("error", "") for a in r.attempts if a.get("error")],
        }
        summary.failures.append(failure_info)

    return summary


# ── Serialization helpers ─────────────────────────────────────────────

def save_scenario_result(result: ScenarioResult, path: Path) -> None:
    """Save a single scenario result to JSON."""
    path.parent.mkdir(parents=True, exist_ok=True)
    data = {
        "scenario_id": result.scenario_id,
        "scenario_name": result.scenario_name,
        "category": result.category,
        "difficulty": result.difficulty,
        "group": result.group,
        "cve": result.cve,
        "passed": result.passed,
        "expected_flag": result.expected_flag,
        "attempts": result.attempts,
        "total_time_seconds": result.total_time_seconds,
        "total_tokens": result.total_tokens,
        "total_steps": result.total_steps,
        "has_startup_error": result.has_startup_error,
        "startup_error": result.startup_error,
        "has_teardown_error": result.has_teardown_error,
        "teardown_error": result.teardown_error,
        "failure_category": result.failure_category,
        "failure_detail": result.failure_detail,
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, default=str)


def save_summary(summary: RunSummary, path: Path) -> None:
    """Save the run summary to JSON."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(asdict(summary), fh, indent=2, default=str)


def print_summary(summary: RunSummary) -> None:
    """Print a human-readable summary to stdout."""
    print()
    print("=" * 60)
    print("EXPERIMENT RESULTS")
    print("=" * 60)
    print(f"Run: {summary.run_id}")
    print(f"Scenarios: {summary.total_scenarios} total, "
          f"{summary.blocked_scenarios} blocked")
    print(f"Passed: {summary.passed}/{summary.available_scenarios} "
          f"(TSR: {summary.overall_tsr:.1%})")
    print(f"Startup failures: {summary.startup_failures}")
    print(f"Total time: {summary.total_time_seconds / 60:.1f} min")
    print(f"Total tokens: {summary.total_tokens:,}")

    for group_name, stats in summary.by_group.items():
        print(f"\n--- {group_name.upper()} ---")
        print(f"  Scenarios: {stats['total']} ({stats['startup_failures']} startup failures)")
        print(f"  Passed: {stats['passed']}/{stats['available']} (TSR: {stats['tsr']:.1%})")
        print(f"  Time: {stats['total_time_minutes']:.1f} min")
        print(f"  Tokens: {stats['total_tokens']:,}")

    # Failure breakdown
    if summary.failures:
        print(f"\n--- FAILURES ({len(summary.failures)}) ---")
        by_cat: dict[str, list] = {}
        for f in summary.failures:
            cat = f["failure_category"]
            by_cat.setdefault(cat, []).append(f["scenario_id"])

        for cat, ids in sorted(by_cat.items()):
            desc = FAILURE_CATEGORIES.get(cat, cat)
            print(f"  {cat} ({len(ids)}): {desc}")
            for sid in ids:
                print(f"    - {sid}")

    # Blocked scenarios
    if summary.blocked:
        print(f"\n--- BLOCKED ({len(summary.blocked)}) ---")
        for b in summary.blocked:
            print(f"  - {b['id']}: {b.get('reason', 'Unknown')}")

    print("=" * 60)


# ── Failure suggestions ───────────────────────────────────────────────

def generate_suggestions(failures: list[dict]) -> list[dict]:
    """Generate actionable suggestions based on failure categories."""
    suggestions = []
    for f in failures:
        cat = f["failure_category"]
        sid = f["scenario_id"]

        if cat == "TOKEN_EXHAUSTION":
            suggestions.append({
                "scenario": sid,
                "suggestion": "Increase token_budget (currently 200000). "
                              "Complex multi-step scenarios may need more tokens.",
            })
        elif cat == "TIME_EXHAUSTION":
            suggestions.append({
                "scenario": sid,
                "suggestion": "Increase time_budget (currently 600s). "
                              "Docker/K8s startup time may eat into exploit budget.",
            })
        elif cat == "STARTUP_FAILURE":
            suggestions.append({
                "scenario": sid,
                "suggestion": f"Check scenario infrastructure manually. "
                              f"Error: {f.get('startup_error', '')[:200]}",
            })
        elif cat == "FLAG_NOT_FOUND":
            suggestions.append({
                "scenario": sid,
                "suggestion": "Orchestrator completed recon/exploit but did not "
                              "extract flag. Review DKG trajectory and DAVE verification.",
            })
        elif cat == "LLM_API_ERROR":
            suggestions.append({
                "scenario": sid,
                "suggestion": "Check LLM API key, rate limits, and quota. "
                              "Consider adding exponential backoff retry.",
            })
        elif cat == "NMAP_FAILURE":
            suggestions.append({
                "scenario": sid,
                "suggestion": "Check if target port is actually open. "
                              "Verify nmap is installed and has proper permissions.",
            })
        elif cat == "TARGET_UNREACHABLE":
            suggestions.append({
                "scenario": sid,
                "suggestion": "Target port not responding. "
                              "Check if Docker container / KIND cluster is actually running.",
            })

    return suggestions
