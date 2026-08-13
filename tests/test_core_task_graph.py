"""Unit tests for the P4 TaskGraph (state machine + dependency semantics)."""

import pytest

from darwin.core.contracts import TaskStatus
from darwin.core.task import Task
from darwin.core.task_graph import DependencyType, TaskGraph


def make_task(tid: str, deps: list | None = None) -> Task:
    return Task(id=tid, type="exploit", goal=f"goal {tid}", dependencies=deps or [])


def success(graph: TaskGraph, tid: str) -> None:
    if graph.get(tid).status is TaskStatus.CREATED:
        graph.transition(tid, TaskStatus.READY)
    graph.transition(tid, TaskStatus.RUNNING)
    graph.transition(tid, TaskStatus.SUCCESS)


def test_status_enum_has_full_state_machine():
    assert len(TaskStatus) == 9
    for name in (
        "CREATED",
        "READY",
        "RUNNING",
        "SUCCESS",
        "FAILED",
        "BLOCKED",
        "INVALIDATED",
        "NEEDS_REPLAN",
        "ABANDONED",
    ):
        assert hasattr(TaskStatus, name)


def test_no_dependencies_are_ready():
    g = TaskGraph([make_task("a"), make_task("b")])
    ready = {t.id for t in g.ready_tasks()}
    assert ready == {"a", "b"}


def test_requires_task_success_gates_ready():
    g = TaskGraph(
        [
            make_task("a"),
            make_task(
                "b",
                [{"type": "requires_task_success", "task_id": "a"}],
            ),
        ]
    )
    g.refresh_states()
    assert g.get("a").status == TaskStatus.READY
    assert g.get("b").status == TaskStatus.BLOCKED
    success(g, "a")
    # 'a' is SUCCESS (not READY); only 'b' becomes ready.
    assert {t.id for t in g.ready_tasks()} == {"b"}


def test_failed_dependency_blocks_not_cascades():
    g = TaskGraph(
        [
            make_task("a"),
            make_task(
                "b",
                [{"type": "requires_task_success", "task_id": "a"}],
            ),
        ]
    )
    g.transition("a", TaskStatus.READY)
    g.transition("a", TaskStatus.RUNNING)
    g.transition("a", TaskStatus.FAILED)
    ready = {t.id for t in g.ready_tasks()}
    assert "b" not in ready
    assert g.get("b").status == TaskStatus.BLOCKED


@pytest.mark.parametrize(
    "dep,world,ready",
    [
        (
            {"type": "requires_evidence", "evidence": "sql_error"},
            {},
            False,
        ),
        (
            {"type": "requires_evidence", "evidence": "sql_error"},
            {"evidence": {"sql_error"}},
            True,
        ),
        (
            {"type": "requires_credential", "credential_type": "mssql"},
            {"credentials": {"mssql"}},
            True,
        ),
        (
            {"type": "requires_access", "access": "shell"},
            {"access": {"shell"}},
            True,
        ),
        (
            {"type": "requires_capability", "capability": "verify_sql_injection"},
            {"capabilities": {"verify_sql_injection"}},
            True,
        ),
    ],
)
def test_semantic_dependencies_gate_on_world(dep, world, ready):
    g = TaskGraph([make_task("t", [dep])])
    tasks = g.ready_tasks(world)
    assert ("t" in {x.id for x in tasks}) is ready
    if not ready:
        assert g.get("t").status == TaskStatus.BLOCKED


def test_unknown_dependency_kind_counts_as_unmet():
    g = TaskGraph([make_task("t", [{"type": "requires_magic"}])])
    assert g.ready_tasks() == []
    assert g.get("t").status == TaskStatus.BLOCKED


def test_legal_transition_path_and_invalidation():
    g = TaskGraph([make_task("a")])
    g.transition("a", TaskStatus.READY)
    g.transition("a", TaskStatus.RUNNING)
    g.transition("a", TaskStatus.SUCCESS)
    g.transition("a", TaskStatus.INVALIDATED)
    assert g.get("a").status is TaskStatus.INVALIDATED


def test_illegal_transition_raises():
    g = TaskGraph([make_task("a")])
    with pytest.raises(ValueError):
        g.transition("a", TaskStatus.SUCCESS)  # CREATED -> SUCCESS not allowed
    g.transition("a", TaskStatus.READY)
    g.transition("a", TaskStatus.RUNNING)
    g.transition("a", TaskStatus.SUCCESS)
    with pytest.raises(ValueError):
        g.transition("a", TaskStatus.CREATED)  # SUCCESS -> CREATED not allowed


def test_terminal_states_are_terminal():
    g = TaskGraph([make_task("a"), make_task("b")])
    g.transition("a", TaskStatus.READY)
    g.transition("a", TaskStatus.RUNNING)
    g.transition("a", TaskStatus.FAILED)
    g.transition("a", TaskStatus.ABANDONED)
    with pytest.raises(ValueError):
        g.transition("a", TaskStatus.READY)
    g.transition("b", TaskStatus.INVALIDATED)
    with pytest.raises(ValueError):
        g.transition("b", TaskStatus.READY)


def test_unknown_task_transition_raises():
    g = TaskGraph([])
    with pytest.raises(KeyError):
        g.transition("nope", TaskStatus.READY)


def test_duplicate_add_raises():
    g = TaskGraph([make_task("a")])
    with pytest.raises(ValueError):
        g.add(make_task("a"))


def test_topological_order_respects_edges():
    g = TaskGraph(
        [
            make_task("c", [{"type": "requires_task_success", "task_id": "b"}]),
            make_task("a"),
            make_task("b", [{"type": "requires_task_success", "task_id": "a"}]),
        ]
    )
    order = [t.id for t in g.topological_order()]
    assert order.index("a") < order.index("b") < order.index("c")


def test_blocked_can_become_ready_again():
    g = TaskGraph(
        [
            make_task("a"),
            make_task(
                "b",
                [{"type": "requires_task_success", "task_id": "a"}],
            ),
        ]
    )
    g.transition("a", TaskStatus.READY)
    g.transition("a", TaskStatus.RUNNING)
    g.transition("a", TaskStatus.FAILED)
    g.refresh_states()
    assert g.get("b").status == TaskStatus.BLOCKED
    # evidence arrives -> a is replanned and succeeds -> b unblocks
    g.update(make_task("a"))
    success(g, "a")
    assert {t.id for t in g.ready_tasks()} == {"b"}


def test_dependency_type_values():
    assert DependencyType.REQUIRES_TASK_SUCCESS.value == "requires_task_success"
    assert DependencyType.REQUIRES_EVIDENCE.value == "requires_evidence"
