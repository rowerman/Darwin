"""Unit tests for the P3 Task data model (darwin.core.task)."""

import pytest

from darwin.core.contracts import TaskStatus
from darwin.core.task import Task


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


def test_legacy_roundtrip_preserves_key_fields():
    legacy = {
        "id": "sql_001",
        "instruction": "Test SQL injection on /login",
        "tool": "sqlmap_test",
        "params": {"url": "http://x/login", "param": "username"},
        "dependent_task_ids": ["recon_001"],
        "status": "pending",
        "attempts": 2,
        "result_summary": "ok",
    }
    t = Task.from_legacy_dict(legacy)
    assert t.id == "sql_001"
    assert t.type == "task"
    assert t.goal == legacy["instruction"]
    assert t.action["tool"] == "sqlmap_test"
    assert t.action["params"] == legacy["params"]
    assert t.dependencies == [
        {"type": "requires_task_success", "task_id": "recon_001"}
    ]
    assert t.attempt_count == 2

    out = t.to_legacy_dict()
    assert out["id"] == "sql_001"
    assert out["tool"] == "sqlmap_test"
    assert out["params"] == legacy["params"]
    assert out["dependent_task_ids"] == ["recon_001"]
    assert out["status"] == "pending"
    assert out["attempts"] == 2
    assert out["result_summary"] == "ok"


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("pending", TaskStatus.READY),
        ("done", TaskStatus.SUCCESS),
        ("failed", TaskStatus.FAILED),
        ("skipped", TaskStatus.ABANDONED),
        ("exhausted", TaskStatus.ABANDONED),
        ("blocked", TaskStatus.BLOCKED),
        ("unknown_status", TaskStatus.CREATED),
    ],
)
def test_legacy_status_mapping(raw, expected):
    t = Task.from_legacy_dict({"id": "x", "type": "t", "goal": "g", "status": raw})
    assert t.status is expected


def test_params_json_string_normalized():
    t = Task.from_legacy_dict(
        {
            "id": "x",
            "type": "t",
            "goal": "g",
            "params": '{"url": "http://x"}',
        }
    )
    assert t.action["params"] == {"url": "http://x"}


def test_goal_falls_back_to_instruction():
    t = Task.from_legacy_dict(
        {"id": "x", "type": "t", "instruction": "Do the thing", "tool": "curl_get"}
    )
    assert t.goal == "Do the thing"


def test_endpoint_used_as_target():
    t = Task.from_legacy_dict(
        {"id": "x", "type": "t", "goal": "g", "endpoint": "http://x/login"}
    )
    assert t.action["target"] == "http://x/login"


def test_summary_compact():
    t = Task(id="x", type="exploit", goal="Capture the flag on the login form")
    s = t.summary()
    assert s.startswith("x: [created]")
    assert "Capture" in s
