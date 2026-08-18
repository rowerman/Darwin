"""Unit tests for the P3 Task data model (darwin.core.task)."""

import pytest

from darwin.core.contracts import TaskStatus
from darwin.core.task import Task, deps_from_task_ids


def test_required_fields_only():
    """Only id/type/goal are required; everything else has a default."""
    t = Task(id="t1", type="exploit", goal="Verify SQLi")
    assert t.status is TaskStatus.CREATED
    assert t.attempt_count == 0
    assert t.priority == 0.5
    assert t.confidence == 0.5
    assert t.action == {}
    assert t.failure_policy == {"retry": 1, "replan_on_failure": True}
    assert t.created_at


def test_missing_required_raises():
    with pytest.raises(TypeError):
        Task()  # noqa


def test_failure_policy_not_shared():
    """Default failure_policy must be a fresh dict per instance."""
    a = Task(id="a", type="t", goal="g")
    b = Task(id="b", type="t", goal="g")
    a.failure_policy["retry"] = 5
    assert b.failure_policy["retry"] == 1


def test_deps_from_task_ids_structured():
    deps = deps_from_task_ids(["a", "b"])
    assert deps == [
        {"type": "requires_task_success", "task_id": "a"},
        {"type": "requires_task_success", "task_id": "b"},
    ]


def test_deps_from_task_ids_preserves_structured_entries():
    structured = {"type": "requires_evidence", "evidence": "quote-error"}
    deps = deps_from_task_ids([structured])
    assert deps == [structured]


def test_summary_compact():
    t = Task(id="x", type="exploit", goal="Capture the flag on the login form")
    s = t.summary()
    assert s.startswith("x: [created]")
    assert "Capture" in s
