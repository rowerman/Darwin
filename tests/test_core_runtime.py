"""P15 stage-2c tests: the thin Runtime loop works end to end with mock
components (Planner / Scheduler / Executor / Evaluator)."""

import pytest

from darwin.core.contracts import (
    Budget,
    Objective,
    ReplanRecommendation,
    TaskOutcome,
)
from darwin.core.evaluator import Evaluation, FailureType
from darwin.core.executor import ExecutionResult
from darwin.core.memory import MemoryManager
from darwin.core.runtime import Runtime
from darwin.core.task import Task
from darwin.core.task_graph import TaskGraph


def task(tid, tool="curl_get"):
    return Task(
        id=tid,
        type="task",
        goal=f"goal {tid}",
        action={"tool": tool, "target": "http://x", "params": {"url": "http://x"}},
    )


def result_for(task_id, success=True):
    return ExecutionResult(
        task_id=task_id,
        tool="curl_get",
        planned_tool="curl_get",
        adherence=True,
        success=success,
        stdout="ok",
        stderr="",
        exit_code=0 if success else 1,
        elapsed_ms=5.0,
    )


class FakePlanner:
    def __init__(self, initial_tasks, replan_adds=None):
        self.initial_tasks = list(initial_tasks)
        self.replan_adds = list(replan_adds or [])
        self.plan_calls = 0
        self.replan_calls = 0
        self.last_evaluation = None

    async def plan(self, state, objective, memory):
        self.plan_calls += 1
        return TaskGraph(list(self.initial_tasks))

    async def replan(self, state, graph, evaluation, memory):
        self.replan_calls += 1
        self.last_evaluation = evaluation
        for extra in self.replan_adds:
            if graph.get(extra.id) is None:
                graph.add(extra)
        return graph


class FakeScheduler:
    def next_ready(self, graph, budget):
        for ready in graph.ready_tasks():
            return ready
        return None


class FakeExecutor:
    def __init__(self, results=None):
        self.results = results or {}
        self.calls = []

    async def execute(self, task):
        self.calls.append(task.id)
        res = self.results.get(task.id)
        if res is None:
            res = result_for(task.id)
        return res


class FakeEvaluator:
    def __init__(self, evaluations=None):
        self.evaluations = evaluations or {}
        self.calls = []

    async def evaluate(self, task, result, state):
        self.calls.append(task.id)
        ev = self.evaluations.get(task.id)
        if ev is None:
            ev = Evaluation(
                task_id=task.id,
                outcome=TaskOutcome.SUCCESS,
                replan=ReplanRecommendation.NONE,
            )
        return ev


def make_runtime(planner, executor=None, evaluator=None, memory=None):
    return Runtime(
        planner=planner,
        scheduler=FakeScheduler(),
        executor=executor or FakeExecutor(),
        evaluator=evaluator or FakeEvaluator(),
        memory=memory,
    )


def objective():
    return Objective(task_description="smoke", budgets=Budget(max_loops=10))


@pytest.mark.asyncio
async def test_runs_all_planned_tasks_to_exhaustion():
    runtime = make_runtime(FakePlanner([task("t1"), task("t2")]))

    outcome = await runtime.run(None, objective(), Budget(max_loops=10))

    assert outcome.executed_tasks == ["t1", "t2"]
    assert outcome.stopped_reason == "plan_exhausted"


@pytest.mark.asyncio
async def test_failure_triggers_replan_and_replacement_runs():
    replacement = task("t1-alt")
    planner = FakePlanner([task("t1")], replan_adds=[replacement])
    evaluations = {
        "t1": Evaluation(
            task_id="t1",
            outcome=TaskOutcome.FAILED,
            failure_type=FailureType.DEFENSE_BLOCKED,
            replan=ReplanRecommendation.LOCAL,
        )
    }
    runtime = make_runtime(planner, evaluator=FakeEvaluator(evaluations))

    outcome = await runtime.run(None, objective(), Budget(max_loops=10))

    assert planner.replan_calls >= 1
    assert outcome.replan_count >= 1
    assert "t1" in outcome.executed_tasks
    assert "t1-alt" in outcome.executed_tasks


@pytest.mark.asyncio
async def test_max_loops_budget_stops_loop():
    runtime = make_runtime(FakePlanner([task("t1"), task("t2")]))

    outcome = await runtime.run(None, objective(), Budget(max_loops=1))

    assert outcome.executed_tasks == ["t1"]
    assert outcome.stopped_reason == "max_loops"


@pytest.mark.asyncio
async def test_failure_without_replan_exhausts_plan():
    planner = FakePlanner([task("t1")])
    evaluations = {
        "t1": Evaluation(
            task_id="t1",
            outcome=TaskOutcome.FAILED,
            failure_type=FailureType.HYPOTHESIS_REJECTED,
            replan=ReplanRecommendation.NONE,
        )
    }
    runtime = make_runtime(planner, evaluator=FakeEvaluator(evaluations))

    outcome = await runtime.run(None, objective(), Budget(max_loops=10))

    assert outcome.executed_tasks == ["t1"]
    assert outcome.stopped_reason == "plan_exhausted"
    assert outcome.replan_count == 1  # one stall replan, nothing new


@pytest.mark.asyncio
async def test_memory_records_tasks_and_executions_with_failure_type():
    memory = MemoryManager()
    evaluations = {
        "t1": Evaluation(
            task_id="t1",
            outcome=TaskOutcome.FAILED,
            failure_type=FailureType.TOOL_ERROR,
            replan=ReplanRecommendation.NONE,
        )
    }
    executor = FakeExecutor(results={"t1": result_for("t1", success=False)})
    runtime = make_runtime(
        FakePlanner([task("t1")]),
        executor=executor,
        evaluator=FakeEvaluator(evaluations),
        memory=memory,
    )

    await runtime.run(None, objective(), Budget(max_loops=10))

    assert memory.plan.get("t1") is not None
    items = memory.execution.for_task("t1")
    assert len(items) == 1
    assert items[0].record.success is False
    assert items[0].record.failure_type == "tool_error"


@pytest.mark.asyncio
async def test_scheduler_picks_ready_tasks_in_dependency_order():
    t1 = task("t1")
    t2 = task("t2")
    t2.dependencies = [{"type": "requires_task_success", "task_id": "t1"}]
    runtime = make_runtime(FakePlanner([t1, t2]))

    outcome = await runtime.run(None, objective(), Budget(max_loops=10))

    assert outcome.executed_tasks == ["t1", "t2"]


@pytest.mark.asyncio
async def test_executor_called_for_each_ready_task_in_order():
    """Each READY task is handed to the executor exactly once."""
    executor = FakeExecutor()
    runtime = make_runtime(FakePlanner([task("t1"), task("t2")]), executor=executor)

    await runtime.run(None, objective(), Budget(max_loops=10))

    assert executor.calls == ["t1", "t2"]
