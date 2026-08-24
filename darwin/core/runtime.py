"""Thin runtime loop (P15, stage 2c).

The v2 end state is a control loop that owns no vulnerability-, tool-,
or prompt-specific logic:

    while not runtime.finished():
        plan       = planner.plan(state, objective, memory)
        graph.update(plan)
        task       = scheduler.next_ready(graph, budget)
        result     = executor.execute(task)
        evaluation = evaluator.evaluate(task, result, state)
        memory.apply(evaluation)
        graph.apply(evaluation)

Stage 2c: this loop is executable and verified against mock components
(tests/test_core_runtime.py); the orchestrator is NOT wired to it yet.
Migration stages after 2c (each gated by behavior-parity checks):
  2b — orchestrator delegates its outer loop control to Runtime.run()
       (post-processing stays in an orchestrator-supplied callback);
  2d — post-processing is extracted into lifecycle hooks;
  3   — orchestrator becomes a thin composition root calling Runtime.run().
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from darwin.core.contracts import (
    Budget,
    Evaluator,
    Executor,
    Objective,
    Planner,
    ReplanRecommendation,
    Scheduler,
    TaskOutcome,
    TaskStatus,
    WorldState,
)
from darwin.core.evaluator import Evaluation
from darwin.core.task_graph import TaskGraph


# Evaluation used to ask the Planner for a fresh look when the graph has
# no ready tasks (the thin-loop equivalent of runtime.handle_stall()).
_STALL_EVALUATION = Evaluation(
    task_id="",
    outcome=TaskOutcome.INCONCLUSIVE,
    replan=ReplanRecommendation.GLOBAL,
)

_OUTCOME_TO_STATUS = {
    TaskOutcome.SUCCESS: TaskStatus.SUCCESS,
    TaskOutcome.FAILED: TaskStatus.FAILED,
    TaskOutcome.BLOCKED: TaskStatus.BLOCKED,
    TaskOutcome.INCONCLUSIVE: TaskStatus.NEEDS_REPLAN,
    TaskOutcome.ABANDONED: TaskStatus.ABANDONED,
}


@dataclass
class RuntimeOutcome:
    """Summary of one Runtime.run() execution."""

    iterations: int = 0
    executed_tasks: list[str] = field(default_factory=list)
    replan_count: int = 0
    stopped_reason: str = ""  # "max_loops" | "budget_exceeded" | "plan_exhausted"


class Runtime:
    """Thin control loop: plan -> schedule -> execute -> evaluate -> replan.

    Owns no vulnerability-, tool-, or prompt-specific logic. Components
    are injected through the P2 Protocols; memory is optional.
    """

    def __init__(
        self,
        planner: Planner,
        scheduler: Scheduler,
        executor: Executor,
        evaluator: Evaluator,
        memory=None,
        state_provider=None,
    ) -> None:
        self.planner = planner
        self.scheduler = scheduler
        self.executor = executor
        self.evaluator = evaluator
        self.memory = memory
        self.state_provider = state_provider

    def _current_state(self, fallback: WorldState) -> WorldState:
        """Refresh working state when the composition root supplies a provider."""
        if callable(self.state_provider):
            try:
                refreshed = self.state_provider()
                if refreshed is not None:
                    return refreshed
            except Exception:
                pass
        return fallback

    @staticmethod
    def _scheduler_world(state: WorldState) -> dict:
        topology = getattr(state, "topology", None)
        paths = getattr(topology, "attack_paths", []) if topology is not None else []
        return {
            "attack_paths": [
                {
                    "path_id": str(getattr(path, "path_id", "")),
                    "status": str(getattr(path, "status", "active")),
                }
                for path in paths
                if getattr(path, "path_id", "")
            ]
        }

    async def run(
        self,
        state: WorldState,
        objective: Objective,
        budget: Budget,
    ) -> RuntimeOutcome:
        """Drive one run to exhaustion (max loops, time budget, or stall)."""
        outcome = RuntimeOutcome()
        graph: TaskGraph | None = None
        started = time.monotonic()
        stall_tried = False
        current_state = self._current_state(state)

        for iteration in range(1, budget.max_loops + 1):
            if time.monotonic() - started > budget.time_budget_seconds:
                outcome.stopped_reason = "budget_exceeded"
                break

            if graph is None:
                graph = await self.planner.plan(current_state, objective, self.memory)

            scheduler_world = self._scheduler_world(current_state)
            try:
                task = self.scheduler.next_ready(graph, budget, scheduler_world)
            except TypeError:
                # Preserve compatibility with injected legacy schedulers.
                task = self.scheduler.next_ready(graph, budget)
            if task is None:
                if stall_tried:
                    outcome.stopped_reason = "plan_exhausted"
                    break
                stall_tried = True
                current_state = self._current_state(current_state)
                graph = await self.planner.replan(
                    current_state, graph, _STALL_EVALUATION, self.memory
                ) or graph
                outcome.replan_count += 1
                continue

            graph.transition(task.id, TaskStatus.RUNNING)
            result = await self.executor.execute(task)
            current_state = self._current_state(current_state)
            evaluation = await self.evaluator.evaluate(task, result, current_state)
            if self.memory is not None:
                self.memory.record_task(task)
                self.memory.record_execution(
                    result,
                    failure_type=(
                        evaluation.failure_type.value
                        if evaluation.failure_type is not None
                        else None
                    ),
                )
            graph.transition(task.id, _OUTCOME_TO_STATUS[evaluation.outcome])
            outcome.iterations = iteration
            outcome.executed_tasks.append(task.id)

            if evaluation.replan is not ReplanRecommendation.NONE:
                current_state = self._current_state(current_state)
                graph = await self.planner.replan(
                    current_state, graph, evaluation, self.memory
                ) or graph
                outcome.replan_count += 1
                stall_tried = False

        if not outcome.stopped_reason:
            outcome.stopped_reason = "max_loops"
        return outcome
