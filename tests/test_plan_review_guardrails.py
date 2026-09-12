"""Plan review must be paid for by executions and must not undo write tasks.

Two failure modes observed in a live run:
  * the review regenerated the whole plan after almost every task, spending
    most of the exploit budget on rewrites that were never tested;
  * a review replaced a blocked write task (``http_method_probe`` with
    ``method=PUT``) with a POST-only tool, making the write unreachable.
"""

from __future__ import annotations

from darwin.core.contracts import TaskStatus
from darwin.core.task import Task
from darwin.orchestration.planning import (
    PlanCoordinator,
    _MIN_EXECUTIONS_BETWEEN_REVIEWS,
)


def _coordinator() -> PlanCoordinator:
    coord = PlanCoordinator.__new__(PlanCoordinator)
    object.__setattr__(coord, "_orch", type("Orch", (), {})())
    return coord


def _task(task_id: str, tool: str, params: dict | None = None) -> Task:
    return Task(
        id=task_id,
        type="task",
        goal="g",
        instruction="i",
        action={"tool": tool, "target": "", "params": dict(params or {})},
        status=TaskStatus.READY,
    )


def test_first_review_is_always_allowed():
    coord = _coordinator()
    assert coord._review_skip_reason(_task("t-1", "curl_get", {"url": "x"})) == ""


def test_second_review_waits_for_executions():
    coord = _coordinator()
    coord._review_done_this_cycle = True
    coord._executions_since_review = _MIN_EXECUTIONS_BETWEEN_REVIEWS - 1
    reason = coord._review_skip_reason(_task("t-2", "curl_get", {"url": "x"}))
    assert "Skipping plan review" in reason

    coord._executions_since_review = _MIN_EXECUTIONS_BETWEEN_REVIEWS
    assert coord._review_skip_reason(_task("t-3", "curl_get", {"url": "x"})) == ""


def test_forced_review_bypasses_the_cadence():
    coord = _coordinator()
    coord._review_done_this_cycle = True
    coord._executions_since_review = 0
    assert coord._review_skip_reason(
        _task("t-4", "curl_get", {"url": "x"}), force=True
    ) == ""


def test_empty_stall_review_is_not_repeated():
    coord = _coordinator()
    coord._review_done_this_cycle = True
    coord._executions_since_review = 0
    stall = _task("plan-exhausted", "", {})

    assert coord._review_skip_reason(stall) == ""  # first stall review runs
    reason = coord._review_skip_reason(stall)      # second one does not
    assert "repeated stall review" in reason


def test_write_task_downgraded_by_review_is_reverted():
    coord = _coordinator()
    original = _task("t-5", "http_method_probe", {
        "url": "http://h:1/packages", "method": "PUT", "data": "payload",
    })
    downgraded = _task("t-5", "http_post", {
        "url": "http://h:1/packages", "data": "payload",
    })

    reverted = coord._enforce_write_intent(
        [downgraded], {"t-5": ("http_method_probe", dict(original.action["params"]))}
    )

    assert reverted == ["t-5"]
    assert downgraded.action["tool"] == "http_method_probe"
    assert downgraded.action["params"]["method"] == "PUT"


def test_write_task_upgraded_to_a_write_capable_tool_is_kept():
    coord = _coordinator()
    replacement = _task("t-6", "http_post", {
        "url": "http://h:1/packages", "method": "PUT", "data": "payload",
    })

    reverted = coord._enforce_write_intent(
        [replacement],
        {"t-6": ("http_method_probe", {"url": "http://h:1/packages",
                                       "method": "PUT", "data": "payload"})},
    )

    assert reverted == []
    assert replacement.action["tool"] == "http_post"


def test_read_task_replacement_is_untouched():
    coord = _coordinator()
    task = _task("t-7", "curl_get", {"url": "http://h:1/x"})

    reverted = coord._enforce_write_intent(
        [task], {"t-7": ("curl_get", {"url": "http://h:1/x"})}
    )

    assert reverted == []
    assert task.action["tool"] == "curl_get"
