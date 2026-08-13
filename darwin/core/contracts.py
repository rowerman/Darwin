"""P2 interface contracts for the DARWIN v2 control plane.

These Protocols define the *contracts* between components, not their
implementations. The orchestrator remains the implementation owner during
migration and delegates to real components in later milestones.

Design rules (agreed in P2):
- Planner decides WHAT to do; it never executes tools.
- Scheduler picks the next ready Task; it never changes strategy.
- Executor executes an existing Task; it never replans.
- Evaluator interprets results into evidence; it never executes.
- Memory is the intended single write path for state (gradual goal).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Protocol

from darwin.data_model import PipelineState


class TaskStatus(str, Enum):
    """Task lifecycle status.

    P2 keeps the statuses the current runtime already uses; P4 replaces
    this with the full v2 state machine (CREATED / READY / RUNNING /
    SUCCESS / FAILED / BLOCKED / INVALIDATED / NEEDS_REPLAN / ABANDONED).
    """

    PENDING = "pending"
    DONE = "done"
    FAILED = "failed"
    SKIPPED = "skipped"
    EXHAUSTED = "exhausted"


class TaskOutcome(str, Enum):
    """Evaluator verdict for one Task execution. P6 refines this together
    with the failure taxonomy."""

    SUCCESS = "success"
    FAILED = "failed"
    BLOCKED = "blocked"
    INCONCLUSIVE = "inconclusive"
    ABANDONED = "abandoned"


class ReplanRecommendation(str, Enum):
    """Scope of the replan requested by the Evaluator."""

    NONE = "none"
    LOCAL = "local"  # replace one Task / a small branch
    GLOBAL = "global"  # rebuild the plan


WorldState = PipelineState
"""Typed snapshot of the world (DKG) consumed by Planner/Evaluator.
Reuses darwin.data_model.PipelineState instead of inventing a second type."""


@dataclass(frozen=True)
class Budget:
    """Execution budgets consumed by Scheduler and the Runtime loop."""

    time_budget_seconds: int = 1200
    token_budget: int = 200000
    max_loops: int = 30


@dataclass(frozen=True)
class Objective:
    """Top-level goal plus execution budgets (what run() was called for)."""

    task_description: str
    budgets: Budget = field(default_factory=Budget)


class Task(Protocol):
    """The single unit Planner produces, Scheduler orders, Executor
    executes, and Evaluator judges. The full field set lands in P3."""

    id: str
    type: str
    goal: str
    status: TaskStatus


class TaskGraph(Protocol):
    """Task collection plus dependency semantics (finalized in P4)."""

    tasks: list[Task]


class PlanMemory(Protocol):
    """Why each Task exists and what it depends on (P10)."""


class WorkingMemory(Protocol):
    """World model — implemented by the DKG (P10)."""


class ExecutionMemory(Protocol):
    """What actually happened: tool calls and normalized results (P10/P14)."""


class ExperienceMemory(Protocol):
    """Cross-task experience — implemented by CTEG (P10/P13)."""


class ExecutionResult(Protocol):
    """Normalized outcome of executing one Task.

    P14 extends this into the full ExecutionRecord (params, timestamps,
    normalized result, error type, retry count, ...).
    """

    task_id: str
    tool: str
    success: bool
    stdout: str
    stderr: str
    exit_code: int
    elapsed_ms: float
    normalized: dict


class Evaluation(Protocol):
    """Evaluator output: verdict + evidence + replan signal (P6)."""

    task_id: str
    outcome: TaskOutcome
    failure_type: str | None
    evidence: list[str]
    confidence_delta: float
    replan: ReplanRecommendation


class Planner(Protocol):
    """Decides what to do. Never executes tools."""

    async def plan(
        self, state: WorldState, objective: Objective, memory: PlanMemory
    ) -> TaskGraph: ...

    async def replan(
        self,
        state: WorldState,
        graph: TaskGraph,
        evaluation: Evaluation,
        memory: PlanMemory,
    ) -> TaskGraph: ...


class Scheduler(Protocol):
    """Picks the next ready Task from the graph."""

    def next_ready(self, graph: TaskGraph, budget: Budget) -> Task | None: ...


class Executor(Protocol):
    """Executes an existing Task. Never replans."""

    async def execute(self, task: Task, capabilities: Any) -> ExecutionResult: ...


class Evaluator(Protocol):
    """Interprets an execution result into verdict + evidence. Never executes."""

    async def evaluate(
        self, task: Task, result: ExecutionResult, state: WorldState
    ) -> Evaluation: ...
