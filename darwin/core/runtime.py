"""Thin runtime skeleton (P2).

The v2 end state is a thin control loop that owns no vulnerability-,
tool-, or prompt-specific logic:

    while not runtime.finished():
        plan       = planner.plan(state, objective, memory)
        graph.update(plan)
        task       = scheduler.next_ready(graph, budget)
        result     = executor.execute(task)
        evaluation = evaluator.evaluate(task, result, state)
        memory.apply(evaluation)
        graph.apply(evaluation)

P15 migrates the orchestrator's main loop onto this skeleton. Nothing here
is wired into the orchestrator yet.
"""

from __future__ import annotations

from darwin.core.contracts import (
    Budget,
    Evaluator,
    Executor,
    Objective,
    Planner,
    Scheduler,
    WorldState,
)


class Runtime:
    """Placeholder control loop. Not wired until P15."""

    def __init__(
        self,
        planner: Planner,
        scheduler: Scheduler,
        executor: Executor,
        evaluator: Evaluator,
    ) -> None:
        self.planner = planner
        self.scheduler = scheduler
        self.executor = executor
        self.evaluator = evaluator

    async def run(self, state: WorldState, objective: Objective, budget: Budget) -> None:
        """See module docstring for the target loop; not implemented yet."""
        raise NotImplementedError("Runtime loop lands in P15.")
