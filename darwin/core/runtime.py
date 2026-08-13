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
    ) -> None:
        self.planner = planner
        self.scheduler = scheduler
        self.executor = executor
        self.evaluator = evaluator
        self.memory = memory

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

        for iteration in range(1, budget.max_loops + 1):
            if time.monotonic() - started > budget.time_budget_seconds:
                outcome.stopped_reason = "budget_exceeded"
                break

            if graph is None:
                graph = await self.planner.plan(state, objective, self.memory)

            task = self.scheduler.next_ready(graph, budget)
            if task is None:
                if stall_tried:
                    outcome.stopped_reason = "plan_exhausted"
                    break
                stall_tried = True
                graph = await self.planner.replan(
                    state, graph, _STALL_EVALUATION, self.memory
                ) or graph
                outcome.replan_count += 1
                continue

            graph.transition(task.id, TaskStatus.RUNNING)
            result = await self.executor.execute(task)
            evaluation = await self.evaluator.evaluate(task, result, state)
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
                graph = await self.planner.replan(
                    state, graph, evaluation, self.memory
                ) or graph
                outcome.replan_count += 1
                stall_tried = False

        if not outcome.stopped_reason:
            outcome.stopped_reason = "max_loops"
        return outcome
