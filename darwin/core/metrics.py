"""Metrics aggregation for the v2 success criteria (P19).

Consumes the orchestrator's structured task log (M0 traces) plus the
Replanner's duplicate stats, and produces the five v2 metrics from the
architecture plan section 21:

    - plan adherence rate      (tool_result.adherence)
    - invalid tool invocation  (task_evaluated failure_type:
                                invalid_argument / precondition_missing)
    - recovery rate            (same task: at least one failed execution
                                followed by a successful execution)
    - replan novelty           (Replanner proposed vs rejected duplicates;
                                falls back to replan_requested traces when
                                no Replanner object is supplied)
    - duplicate action rate    (1 - replan novelty)

All rates are None when the denominator is zero (nothing to judge).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


INVALID_FAILURE_TYPES = frozenset(
    {"invalid_argument", "precondition_missing"}
)


@dataclass
class MetricsReport:
    """Aggregated v2 success metrics for one run."""

    total_executions: int = 0
    adherence_count: int = 0
    adherence_rate: float | None = None
    invalid_invocations: int = 0
    invalid_tool_invocation_rate: float | None = None
    recovery_rate: float | None = None
    replan_novelty: float | None = None
    duplicate_action_rate: float | None = None
    failure_type_counts: dict[str, int] = field(default_factory=dict)
    outcome_counts: dict[str, int] = field(default_factory=dict)
    replan_action_counts: dict[str, int] = field(default_factory=dict)


class MetricsCalculator:
    """Pure aggregation over task-log traces and optional Replanner stats."""

    def calculate(
        self, task_log: list[dict], replanner: Any | None = None
    ) -> MetricsReport:
        report = MetricsReport()
        tool_results: list[dict] = []
        evaluated: list[dict] = []
        replans: list[dict] = []

        for event in task_log or []:
            if not isinstance(event, dict):
                continue
            name = event.get("event")
            if name == "tool_result":
                tool_results.append(event)
            elif name == "task_evaluated":
                evaluated.append(event)
            elif name == "replan_requested":
                replans.append(event)

        # ── Plan adherence ──────────────────────────────────────
        report.total_executions = len(tool_results)
        report.adherence_count = sum(
            1 for e in tool_results if bool(e.get("adherence"))
        )
        if tool_results:
            report.adherence_rate = report.adherence_count / len(tool_results)

        # ── Invalid tool invocation ─────────────────────────────
        invalid = [
            e
            for e in evaluated
            if (e.get("failure_type") or "") in INVALID_FAILURE_TYPES
        ]
        report.invalid_invocations = len(invalid)
        if tool_results:
            report.invalid_tool_invocation_rate = (
                report.invalid_invocations / len(tool_results)
            )

        # ── Recovery: failure -> later success on the same task ─
        by_task: dict[str, list[bool]] = {}
        for e in tool_results:
            by_task.setdefault(str(e.get("task_id", "")), []).append(
                bool(e.get("success"))
            )
        failed_tasks = {
            tid for tid, results in by_task.items() if any(not r for r in results)
        }
        recovered_tasks = {
            tid
            for tid, results in by_task.items()
            if any(not r for r in results) and any(r for r in results)
        }
        if failed_tasks:
            report.recovery_rate = len(recovered_tasks) / len(failed_tasks)

        # ── Replan novelty / duplicate actions ──────────────────
        if replanner is not None and hasattr(replanner, "novelty_ratio"):
            report.replan_novelty = replanner.novelty_ratio
        elif replans:
            rejected = sum(1 for e in replans if bool(e.get("rejected_duplicate")))
            report.replan_novelty = 1.0 - (rejected / len(replans))
        if report.replan_novelty is not None:
            report.duplicate_action_rate = 1.0 - report.replan_novelty

        # ── Distributions ───────────────────────────────────────
        for e in evaluated:
            failure_type = e.get("failure_type")
            if failure_type:
                key = str(failure_type)
                report.failure_type_counts[key] = report.failure_type_counts.get(key, 0) + 1
            outcome = e.get("outcome")
            if outcome:
                key = str(outcome)
                report.outcome_counts[key] = report.outcome_counts.get(key, 0) + 1
        for e in replans:
            action = str(e.get("action") or "unknown")
            report.replan_action_counts[action] = (
                report.replan_action_counts.get(action, 0) + 1
            )

        return report
