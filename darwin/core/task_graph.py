"""TaskGraph — dependency semantics and task state machine (P4).

Owns:
- task storage (add / update / get),
- state transitions (enforced against an allowed-transition table),
- readiness computation (CREATED/BLOCKED -> READY when dependencies hold).

It does NOT pick the next task to run — that is the Scheduler's job
(see contracts.Scheduler). Dependency semantics agreed in P4:

- dependencies are structured dicts with a ``type`` from DependencyType;
- ``requires_task_success`` edges also define the graph ordering;
- ``requires_evidence/credential/access/capability`` gate readiness against
  the current world state and never cascade-fail their dependents.
"""

from __future__ import annotations

from collections import deque
from enum import Enum
from typing import Any, Iterable

from darwin.core.contracts import TaskStatus
from darwin.core.task import Task


class DependencyType(str, Enum):
    """Structured dependency kinds (P4)."""

    REQUIRES_TASK_SUCCESS = "requires_task_success"
    REQUIRES_EVIDENCE = "requires_evidence"
    REQUIRES_CREDENTIAL = "requires_credential"
    REQUIRES_ACCESS = "requires_access"
    REQUIRES_CAPABILITY = "requires_capability"


def dependency_task_ids(task: Task) -> list[str]:
    """Task-ID edges used for ordering (requires_task_success + legacy strings)."""
    ids: list[str] = []
    for d in task.dependencies:
        if isinstance(d, dict):
            if (
                d.get("type") == DependencyType.REQUIRES_TASK_SUCCESS
                and d.get("task_id")
            ):
                ids.append(str(d["task_id"]))
        elif d:
            ids.append(str(d))
    return ids


class TaskGraph:
    """Task collection with state transitions and readiness computation."""

    _ALLOWED_TRANSITIONS: dict[TaskStatus, set[TaskStatus]] = {
        TaskStatus.CREATED: {
            TaskStatus.READY,
            TaskStatus.INVALIDATED,
            TaskStatus.ABANDONED,
        },
        TaskStatus.READY: {
            TaskStatus.RUNNING,
            TaskStatus.BLOCKED,
            TaskStatus.INVALIDATED,
            TaskStatus.ABANDONED,
        },
        TaskStatus.RUNNING: {
            TaskStatus.SUCCESS,
            TaskStatus.FAILED,
            TaskStatus.NEEDS_REPLAN,
            TaskStatus.BLOCKED,
        },
        TaskStatus.BLOCKED: {
            TaskStatus.READY,
            TaskStatus.INVALIDATED,
            TaskStatus.ABANDONED,
            TaskStatus.NEEDS_REPLAN,
        },
        TaskStatus.SUCCESS: {TaskStatus.INVALIDATED},
        TaskStatus.FAILED: {
            TaskStatus.NEEDS_REPLAN,
            TaskStatus.ABANDONED,
            TaskStatus.BLOCKED,
        },
        TaskStatus.NEEDS_REPLAN: {
            TaskStatus.READY,
            TaskStatus.ABANDONED,
            TaskStatus.INVALIDATED,
        },
        TaskStatus.INVALIDATED: set(),
        TaskStatus.ABANDONED: set(),
    }

    def __init__(self, tasks: Iterable[Task] | None = None) -> None:
        self._tasks: dict[str, Task] = {}
        for t in tasks or []:
            self._tasks[t.id] = t

    @property
    def tasks(self) -> list[Task]:
        return list(self._tasks.values())

    def get(self, task_id: str) -> Task | None:
        return self._tasks.get(task_id)

    def add(self, task: Task) -> None:
        if task.id in self._tasks:
            raise ValueError(f"duplicate task id: {task.id}")
        self._tasks[task.id] = task

    def update(self, task: Task) -> None:
        """Replace a task (used after Planner/Evaluator revise it)."""
        self._tasks[task.id] = task

    def transition(self, task_id: str, new_status: TaskStatus) -> Task:
        """Apply an explicit state transition, enforcing the allowed table."""
        task = self._tasks.get(task_id)
        if task is None:
            raise KeyError(f"unknown task id: {task_id}")
        allowed = self._ALLOWED_TRANSITIONS.get(task.status, set())
        if new_status not in allowed:
            raise ValueError(
                f"illegal transition {task.status.value} -> {new_status.value} "
                f"for task {task_id}"
            )
        task.status = new_status
        return task

    @staticmethod
    def _dependency_satisfied(dep: dict, world: dict) -> bool:
        kind = dep.get("type", DependencyType.REQUIRES_TASK_SUCCESS)
        if kind == DependencyType.REQUIRES_TASK_SUCCESS:
            return False  # requires graph lookup; handled by refresh_states
        if kind == DependencyType.REQUIRES_EVIDENCE:
            key = dep.get("evidence")
            return bool(key and key in (world.get("evidence") or set()))
        if kind == DependencyType.REQUIRES_CREDENTIAL:
            key = dep.get("credential_type") or dep.get("credential")
            return bool(key and key in (world.get("credentials") or set()))
        if kind == DependencyType.REQUIRES_ACCESS:
            key = dep.get("access")
            return bool(key and key in (world.get("access") or set()))
        if kind == DependencyType.REQUIRES_CAPABILITY:
            key = dep.get("capability")
            return bool(key and key in (world.get("capabilities") or set()))
        return False

    def refresh_states(self, world: dict | None = None) -> None:
        """Derive READY/BLOCKED from dependency satisfaction.

        ``world`` provides sets for semantic checks:
        {"evidence": set, "credentials": set, "access": set, "capabilities": set}.
        Unknown dependency kinds count as unmet. Tasks whose dependencies
        hold move to READY; tasks with unmet preconditions move to BLOCKED
        (and may become READY again later — no cascade failure).
        """
        world = world or {}
        for task in list(self._tasks.values()):
            if task.status not in (
                TaskStatus.CREATED,
                TaskStatus.READY,
                TaskStatus.BLOCKED,
            ):
                continue
            deps = task.dependencies or []
            if not deps:
                if task.status == TaskStatus.CREATED:
                    task.status = TaskStatus.READY
                continue

            satisfied = True
            for d in deps:
                if isinstance(d, dict):
                    if (
                        d.get("type", DependencyType.REQUIRES_TASK_SUCCESS)
                        == DependencyType.REQUIRES_TASK_SUCCESS
                    ):
                        tid = d.get("task_id")
                        dep_task = self._tasks.get(str(tid)) if tid else None
                        satisfied = (
                            satisfied
                            and dep_task is not None
                            and dep_task.status == TaskStatus.SUCCESS
                        )
                    else:
                        satisfied = satisfied and self._dependency_satisfied(d, world)
                elif d:  # legacy plain-string Task-ID dependency
                    dep_task = self._tasks.get(str(d))
                    satisfied = (
                        satisfied
                        and dep_task is not None
                        and dep_task.status == TaskStatus.SUCCESS
                    )
            task.status = TaskStatus.READY if satisfied else TaskStatus.BLOCKED

    def ready_tasks(self, world: dict | None = None) -> list[Task]:
        """Return tasks currently in READY state."""
        self.refresh_states(world)
        return [t for t in self._tasks.values() if t.status == TaskStatus.READY]

    def topological_order(self) -> list[Task]:
        """Order tasks by their Task-ID dependency edges (Kahn's algorithm)."""
        ids = list(self._tasks)
        in_deg = {tid: 0 for tid in ids}
        adj: dict[str, list[str]] = {tid: [] for tid in ids}
        for tid in ids:
            for dep_id in dependency_task_ids(self._tasks[tid]):
                if dep_id in self._tasks:
                    adj[dep_id].append(tid)
                    in_deg[tid] += 1
        queue = deque(tid for tid, deg in in_deg.items() if deg == 0)
        result: list[Task] = []
        seen: set[str] = set()
        while queue:
            tid = queue.popleft()
            seen.add(tid)
            result.append(self._tasks[tid])
            for nxt in adj[tid]:
                in_deg[nxt] -= 1
                if in_deg[nxt] == 0:
                    queue.append(nxt)
        result.extend(self._tasks[tid] for tid in ids if tid not in seen)
        return result
