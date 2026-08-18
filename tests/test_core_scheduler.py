"""Stage C: ParityScheduler ordering + Runtime plan-exhausted stall."""

import pytest

from darwin.core.contracts import TaskStatus
from darwin.core.scheduler import ParityScheduler
from darwin.core.task import Task, deps_from_task_ids
from darwin.core.task_graph import TaskGraph


def _task(tid, tool="curl_get", instruction="", deps=None, source="", status=None):
    return Task(
        id=tid,
        type="task",
        goal=instruction or f"goal {tid}",
        instruction=instruction or f"Run {tool}",
        action={"tool": tool, "target": "", "params": {}},
        dependencies=deps_from_task_ids(deps or []),
        status=status or TaskStatus.READY,
        source=source,
    )


def _graph(tasks):
    return TaskGraph(tasks)


def _finish(graph, tid, status):
    graph.transition(tid, TaskStatus.RUNNING)
    graph.transition(tid, status)


def test_dependency_order_first():
    t1 = _task("t1")
    t2 = _task("t2", deps=["t1"])
    graph = _graph([t2, t1])
    scheduler = ParityScheduler()

    assert scheduler.next_ready(graph).id == "t1"
    _finish(graph, "t1", TaskStatus.SUCCESS)
    assert scheduler.next_ready(graph).id == "t2"


def test_exploit_task_wins_over_probe():
    probe = _task("p", tool="curl_get")
    exploit = _task("e", tool="sqlmap_test")
    graph = _graph([probe, exploit])
    scheduler = ParityScheduler()

    assert scheduler.next_ready(graph).id == "e"


def test_all_deps_failed_abandons_dependent():
    t1 = _task("t1")
    t2 = _task("t2", deps=["t1"])
    graph = _graph([t1, t2])
    _finish(graph, "t1", TaskStatus.FAILED)
    scheduler = ParityScheduler()

    assert scheduler.next_ready(graph) is None
    assert graph.get("t2").status is TaskStatus.ABANDONED


def test_exhausted_ids_skipped():
    t1 = _task("t1", tool="sqlmap_test")
    graph = _graph([t1])
    scheduler = ParityScheduler(exhausted_ids={"t1"})

    assert scheduler.next_ready(graph) is None


def test_low_priority_last():
    probe = _task("p", tool="curl_get")
    low = _task("l", tool="hydra_http_brute")
    graph = _graph([probe, low])
    scheduler = ParityScheduler()

    assert scheduler.next_ready(graph).id == "p"
    _finish(graph, "p", TaskStatus.SUCCESS)
    assert scheduler.next_ready(graph).id == "l"


def test_exploit_keyword_semantics_priority():
    probe = _task("p", tool="curl_get", instruction="probe the page")
    semantic = _task("s", tool="curl_get", instruction="exploit the token")
    graph = _graph([probe, semantic])
    scheduler = ParityScheduler()

    assert scheduler.next_ready(graph).id == "s"


def test_credential_hint_source_priority():
    probe = _task("p", tool="curl_get")
    hint = _task("h", tool="ssh_exec", source="credential-hint")
    graph = _graph([probe, hint])
    scheduler = ParityScheduler()

    assert scheduler.next_ready(graph).id == "h"


def test_abandoned_tasks_skipped():
    done = _task("d")
    abandoned = _task("a")
    abandoned.status = TaskStatus.ABANDONED
    graph = _graph([done, abandoned])
    scheduler = ParityScheduler()

    assert scheduler.next_ready(graph).id == "d"


@pytest.mark.asyncio
async def test_runtime_stall_runs_plan_exhaustion_review(
    fake_llm, fake_gateway, make_orchestrator
):
    """Runtime stall (no ready task) triggers the legacy exhaustion review."""
    llm = fake_llm(content="[]")
    orch = make_orchestrator(llm, fake_gateway({}), fake_gateway({}))
    failed = _task("t-fail", tool="curl_get")
    failed.status = TaskStatus.FAILED
    from darwin.data_model import ExploitationPlan
    orch.exploitation_plan = ExploitationPlan(
        plan_id="exhaust", phase="exploit", goal="g", tasks=[failed]
    )

    result = await orch._run_with_runtime("http://target:8000/")

    assert result is None
    assert orch._plan_review_exhausted is True
    # The exhaustion review went through the planner LLM call and carried
    # the legacy [RECONSIDER] summary.
    generates = [c for c in llm.calls if c[0] == "generate"]
    assert generates
    assert any("[RECONSIDER]" in str(c[1]) for c in generates)
