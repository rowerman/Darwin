"""Parallel experiment runner — run Docker and K8s benchmark scenarios.

Groups scenarios by infrastructure type, runs each group with configurable
parallelism, and produces a structured failure analysis report.

Usage:
    # Dry-run — list all scenarios without executing
    python experiments/parallel_runner.py --dry-run

    # Single scenario test
    python experiments/parallel_runner.py --scenario WEB-01

    # Two scenarios in parallel (verify no cross-contamination)
    python experiments/parallel_runner.py --scenario WEB-01 --scenario WEB-02 --parallelism 2

    # Full Docker + K8s run
    python experiments/parallel_runner.py --parallelism 4

    # Docker group only
    python experiments/parallel_runner.py --group docker --parallelism 4

    # K8s group only
    python experiments/parallel_runner.py --group k8s --parallelism 4
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any

from darwin.orchestrator import Orchestrator, TaskResult
from darwin.utils.llm import LLMSession

from experiments.scenario_loader import (
    ScenarioDef,
    ROOT_DIR,
    get_blocked_scenarios,
    group_scenarios,
    load_scenarios,
)
from experiments.lifecycle_manager import (
    start_scenario,
    stop_scenario,
)
from experiments.result_aggregator import (
    AttemptResult,
    ScenarioResult,
    RunSummary,
    build_summary,
    classify_failure,
    generate_suggestions,
    print_summary,
    save_scenario_result,
    save_summary,
)

# ── Logging ───────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("parallel_runner")


# ── Defaults ──────────────────────────────────────────────────────────

DEFAULT_PARALLELISM = 4
DEFAULT_TIME_BUDGET = 600
DEFAULT_TOKEN_BUDGET = 200000
DEFAULT_PASS_AT_K = 1  # Diagnostic mode


# ── Main entry point ──────────────────────────────────────────────────

async def main():
    args = _parse_args()
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    run_id = f"parallel_run_{timestamp}"
    output_dir = Path(args.output_dir) / run_id
    output_dir.mkdir(parents=True, exist_ok=True)

    # 1. Load scenarios
    all_scenarios = load_scenarios(include_ad=False)
    blocked = get_blocked_scenarios(all_scenarios)
    available = [s for s in all_scenarios if s.is_available]

    # 2. Filter by CLI args
    available = _filter_scenarios(available, args)

    # 3. Group
    groups = group_scenarios(available)

    # Filter groups if --group specified
    if args.group:
        groups = {k: v for k, v in groups.items() if k == args.group}
        if not groups:
            logger.error(f"No scenarios in group '{args.group}'. "
                         f"Available: {list(group_scenarios(available).keys())}")
            sys.exit(1)

    # 4. Dry-run mode
    if args.dry_run:
        _dry_run(groups, blocked, args)
        return

    # 5. Save run config
    config = {
        "parallelism": args.parallelism,
        "time_budget": args.time_budget,
        "token_budget": args.token_budget,
        "pass_at_k": args.pass_at_k,
        "groups": list(groups.keys()),
    }
    _save_json(config, output_dir / "run_config.json")

    # 6. Execute groups sequentially (docker → k8s)
    all_results: list[ScenarioResult] = []

    try:
        for group_name in ["docker", "k8s"]:
            if group_name not in groups:
                continue
            scenarios = groups[group_name]
            parallel = True  # Both groups support parallelism

            logger.info(f"{'='*60}")
            logger.info(f"Group: {group_name} ({len(scenarios)} scenarios, "
                        f"parallelism={args.parallelism if parallel else 1})")
            logger.info(f"{'='*60}")

            group_results = await _run_group(
                scenarios=scenarios,
                group_name=group_name,
                parallel=parallel,
                args=args,
                output_dir=output_dir,
            )
            all_results.extend(group_results)

    except KeyboardInterrupt:
        logger.warning("Interrupted by user. Saving partial results...")
    finally:
        # 7. Build and save summary
        if all_results:
            summary = build_summary(all_results, blocked, config, run_id)
            save_summary(summary, output_dir / "overview.json")
            print_summary(summary)

            # Generate suggestions
            suggestions = generate_suggestions(summary.failures)
            if suggestions:
                _save_json(suggestions, output_dir / "failure_suggestions.json")

        logger.info(f"Results saved to {output_dir}")


# ── Group execution ───────────────────────────────────────────────────

async def _run_group(
    scenarios: list[ScenarioDef],
    group_name: str,
    parallel: bool,
    args: argparse.Namespace,
    output_dir: Path,
) -> list[ScenarioResult]:
    """Run all scenarios in a group, respecting parallelism.

    Scenarios sharing the same target_port are serialized to avoid
    port conflicts (e.g., WEB-01 and WEB-01-WAF both use port 10101).
    """
    concurrency = max(args.parallelism if parallel else 1, 1)

    # For Docker scenarios, detect host port conflicts and serialize them.
    # K8s scenarios each have their own KIND cluster with isolated networks,
    # so port conflicts don't apply.
    port_locks: dict[int, asyncio.Lock] = {}
    if group_name == "docker":
        port_groups: dict[int, list[ScenarioDef]] = {}
        for s in scenarios:
            port_groups.setdefault(s.target_port, []).append(s)
        for port, group in port_groups.items():
            if len(group) > 1 and port > 0:
                ids = [s.id for s in group]
                logger.warning(f"Port conflict on {port}: {ids} — will serialize")
            port_locks[port] = asyncio.Lock()

    global_sem = asyncio.Semaphore(concurrency)

    async def bounded_run(scenario: ScenarioDef) -> ScenarioResult:
        # For Docker: acquire port lock first (serializes same-port scenarios)
        lock = port_locks.get(scenario.target_port)
        if lock:
            async with lock:
                async with global_sem:
                    return await _run_one_scenario(scenario, group_name, args, output_dir)
        else:
            async with global_sem:
                return await _run_one_scenario(scenario, group_name, args, output_dir)

    tasks = [asyncio.create_task(bounded_run(s)) for s in scenarios]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    # Unwrap exceptions
    wrapped: list[ScenarioResult] = []
    for i, r in enumerate(results):
        if isinstance(r, Exception):
            logger.error(f"Unhandled error in task for {scenarios[i].id}: {r}")
        else:
            wrapped.append(r)

    return wrapped


# ── Single scenario execution ─────────────────────────────────────────

async def _run_one_scenario(
    scenario: ScenarioDef,
    group_name: str,
    args: argparse.Namespace,
    output_dir: Path,
) -> ScenarioResult:
    """Execute one scenario: start → run(pass@k) → stop → collect."""
    result = ScenarioResult(
        scenario_id=scenario.id,
        category=scenario.category,
        difficulty=scenario.difficulty,
        group=group_name,
        scenario_name=scenario.name,
        cve=scenario.cve,
    )
    t_start = time.monotonic()

    # ── Phase 1: Start ───────────────────────────────────────────
    start_info: dict[str, Any] = {}
    try:
        start_info = await start_scenario(scenario)
        result.expected_flag = start_info.get("flag", "unknown")
    except Exception as exc:
        logger.error(f"[{scenario.id}] STARTUP FAILURE: {exc}")
        result.has_startup_error = True
        result.startup_error = str(exc)[:1000]
        result.failure_category = classify_failure(result)
        result.failure_detail = str(exc)[:2000]
        result.total_time_seconds = time.monotonic() - t_start

        _save_scenario_result(result, output_dir)
        return result

    # ── Phase 2: Run (pass@k) ────────────────────────────────────
    for attempt in range(args.pass_at_k):
        logger.info(f"[{scenario.id}] Attempt {attempt + 1}/{args.pass_at_k} "
                     f"target={scenario.target_url} port_range={scenario.port_range}")

        att = await _run_attempt(scenario, attempt + 1, args)
        result.attempts.append({
            "attempt": att.attempt,
            "success": att.success,
            "flag": att.flag,
            "steps": att.steps,
            "tokens_used": att.tokens_used,
            "time_elapsed": att.time_elapsed,
            "defense_detected": att.defense_detected,
            "waf_bypassed": att.waf_bypassed,
            "waf_type": att.waf_type,
            "error": att.error,
        })
        result.total_tokens += att.tokens_used

        if att.success:
            result.passed = True
            result.total_steps = att.steps
            break  # Early exit on success

    # ── Phase 3: Stop ────────────────────────────────────────────
    try:
        await stop_scenario(scenario)
    except Exception as exc:
        logger.warning(f"[{scenario.id}] Teardown warning: {exc}")
        result.has_teardown_error = True
        result.teardown_error = str(exc)[:500]

    result.total_time_seconds = time.monotonic() - t_start

    # ── Classify failure if needed ───────────────────────────────
    if not result.passed and not result.has_startup_error:
        result.failure_category = classify_failure(result)
        result.failure_detail = _build_failure_detail(result)

    status = "PASS" if result.passed else f"FAIL ({result.failure_category})"
    logger.info(f"[{scenario.id}] {status} "
                 f"({result.total_time_seconds:.0f}s, {result.total_tokens} tokens)")

    _save_scenario_result(result, output_dir)
    return result


async def _run_attempt(
    scenario: ScenarioDef,
    attempt_num: int,
    args: argparse.Namespace,
) -> AttemptResult:
    """Run a single DARWIN orchestrator attempt."""
    att = AttemptResult(attempt=attempt_num, success=False)
    t0 = time.monotonic()

    try:
        llm = LLMSession.from_config(profile="default", config_path="config/llm.yaml")

        orch = Orchestrator(
            llm_session=llm,
            time_budget=args.time_budget,
            token_budget=args.token_budget,
        )

        task_result: TaskResult = await orch.run(
            task_description=scenario.description,
            target_url=scenario.target_url,
            port_range=scenario.port_range,
        )

        att.success = task_result.success
        att.flag = task_result.flag or ""
        att.steps = task_result.steps
        att.tokens_used = task_result.tokens_used
        att.defense_detected = task_result.defense_detected
        att.waf_bypassed = task_result.waf_bypassed
        att.waf_type = task_result.waf_type or ""
        att.error = task_result.error or ""

        if not att.success and not att.error:
            att.error = "Orchestrator completed without capturing flag"

    except Exception as exc:
        att.success = False
        att.error = f"{type(exc).__name__}: {exc}"
        logger.debug(f"[{scenario.id}] Attempt {attempt_num} exception: {exc}", exc_info=True)

    att.time_elapsed = time.monotonic() - t0
    return att


# ── CLI ───────────────────────────────────────────────────────────────

def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="DARWIN Parallel Experiment Runner — Docker + K8s benchmark",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --dry-run                     List scenarios without executing
  %(prog)s --scenario WEB-01             Run a single scenario
  %(prog)s --group docker -p 4           Run all Docker scenarios with 4 workers
  %(prog)s --group k8s -p 2              Run all K8s scenarios with 2 workers
  %(prog)s -p 4                          Run all Docker + K8s scenarios
        """,
    )
    parser.add_argument(
        "--parallelism", "-p", type=int, default=DEFAULT_PARALLELISM,
        help=f"Max concurrent scenarios within a group (default: {DEFAULT_PARALLELISM})",
    )
    parser.add_argument(
        "--time-budget", type=int, default=DEFAULT_TIME_BUDGET,
        help=f"Time budget per scenario in seconds (default: {DEFAULT_TIME_BUDGET})",
    )
    parser.add_argument(
        "--token-budget", type=int, default=DEFAULT_TOKEN_BUDGET,
        help=f"Token budget per scenario (default: {DEFAULT_TOKEN_BUDGET})",
    )
    parser.add_argument(
        "--pass-at-k", type=int, default=DEFAULT_PASS_AT_K,
        help=f"Attempts per scenario (default: {DEFAULT_PASS_AT_K} for diagnostic)",
    )
    parser.add_argument(
        "--output-dir", default="experiment_results",
        help="Base directory for results (default: experiment_results)",
    )
    parser.add_argument(
        "--group", "-g", choices=["docker", "k8s"], default=None,
        help="Run only the specified group (default: all)",
    )
    parser.add_argument(
        "--scenario", "-s", action="append", default=None,
        help="Run specific scenario(s) only (can be repeated, e.g. -s WEB-01 -s WEB-02)",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="List all scenarios and exit without executing",
    )
    return parser.parse_args()


# ── Helpers ───────────────────────────────────────────────────────────

def _filter_scenarios(
    scenarios: list[ScenarioDef], args: argparse.Namespace,
) -> list[ScenarioDef]:
    """Apply CLI filters to scenario list."""
    if args.scenario:
        selected = set(args.scenario)
        filtered = [s for s in scenarios if s.id in selected]
        missing = selected - {s.id for s in filtered}
        if missing:
            logger.warning(f"Scenarios not found: {missing}")
        return filtered
    return scenarios


def _dry_run(
    groups: dict[str, list[ScenarioDef]],
    blocked: list[dict],
    args: argparse.Namespace,
) -> None:
    """Print scenario listing without executing."""
    print(f"\nDARWIN Parallel Experiment Runner — DRY RUN")
    print(f"Config: parallelism={args.parallelism}, "
          f"time_budget={args.time_budget}s, "
          f"pass@k={args.pass_at_k}")
    print()

    total = 0
    for group_name in ["docker", "k8s"]:
        if group_name not in groups:
            continue
        scenarios = groups[group_name]
        total += len(scenarios)
        parallel_mark = f"parallel ({args.parallelism} workers)" if True else "sequential"
        print(f"── {group_name.upper()} ({len(scenarios)} scenarios, {parallel_mark}) ──")
        for s in scenarios:
            port_info = f"port={s.target_port}" if s.target_port else "no-port"
            print(f"  {s.id:12s} {s.difficulty:3s}  {s.target_url:30s}  {port_info}  range={s.port_range}")
        print()

    if blocked:
        print(f"── BLOCKED ({len(blocked)}) ──")
        for b in blocked:
            print(f"  {b['id']:12s} {b.get('reason', '?')}")
        print()

    print(f"Total available: {total}")
    print(f"Estimated time: ~{total / args.parallelism * args.time_budget / 60:.0f} min "
          f"(assuming {args.parallelism}x parallelism)\n")


def _save_scenario_result(result: ScenarioResult, output_dir: Path) -> None:
    """Save a single scenario result to its group subdirectory."""
    group_dir = output_dir / "results" / result.group
    save_scenario_result(result, group_dir / f"{result.scenario_id}.json")


def _save_json(data: object, path: Path) -> None:
    """Save data as JSON."""
    import json
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, default=str)


def _build_failure_detail(result: ScenarioResult) -> str:
    """Build a human-readable failure detail string."""
    parts = []
    for i, att in enumerate(result.attempts):
        if att.get("error"):
            parts.append(f"Attempt {i + 1}: {att['error'][:300]}")
        elif att.get("success") is False:
            parts.append(f"Attempt {i + 1}: No flag captured, no error reported")
    return " | ".join(parts) if parts else "No details available"


# ── Entry point ───────────────────────────────────────────────────────

if __name__ == "__main__":
    asyncio.run(main())
