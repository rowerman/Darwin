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
    _LLM_MIN_REMAINING_SECONDS,
    PlanCoordinator,
    _MIN_EXECUTIONS_BETWEEN_REVIEWS,
    _REVIEW_MIN_REMAINING_SECONDS,
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


# ── Review triggers ──────────────────────────────────────────────────

def test_review_is_skipped_when_the_budget_is_almost_spent():
    """A late rewrite costs more than it can return."""
    coord = _coordinator()
    object.__setattr__(
        coord, "_orch",
        type("Orch", (), {"_remaining_budget": lambda self: 30.0})(),
    )
    reason = coord._review_skip_reason(_task("t-8", "curl_get", {"url": "x"}))
    assert "budget" in reason


def test_new_evidence_triggers_a_review_before_the_execution_floor():
    """A freshly discovered route is exactly what a review exists for."""
    coord = _coordinator()
    object.__setattr__(
        coord, "_orch",
        type("Orch", (), {"_remaining_budget": lambda self: 600.0})(),
    )
    coord._review_done_this_cycle = True
    coord._executions_since_review = 1
    assert coord._review_skip_reason(_task("t-9", "curl_get", {"url": "x"})) != ""
    coord._evidence_since_review = True
    assert coord._review_skip_reason(_task("t-9", "curl_get", {"url": "x"})) == ""


def test_plan_wrong_failures_trigger_a_review():
    coord = _coordinator()
    object.__setattr__(
        coord, "_orch",
        type("Orch", (), {"_remaining_budget": lambda self: 600.0})(),
    )
    coord._review_done_this_cycle = True
    coord._executions_since_review = 1
    coord._last_failure_type = "invalid_argument"
    assert coord._review_skip_reason(_task("t-10", "curl_get", {"url": "x"})) == ""


# ── Plan cap ─────────────────────────────────────────────────────────

def test_cap_keeps_tasks_that_cover_a_documented_but_untested_route():
    coord = _coordinator()
    object.__setattr__(
        coord, "_orch",
        type("Orch", (), {
            "_untested_documented_routes": lambda self: [
                ("http://h:1/workflows", "POST"),
            ],
        })(),
    )
    coverage = _task("t-cov", "http_post", {"url": "http://h:1/workflows"})
    filler = [_task(f"t-{i}", "curl_get", {"url": f"http://h:1/x{i}"})
              for i in range(30)]
    kept = coord._cap_pending_tasks([coverage] + filler, max_total=5)
    assert "t-cov" in {t.id for t in kept}


def test_cap_prefers_tasks_that_have_not_already_run():
    coord = _coordinator()
    object.__setattr__(
        coord, "_orch",
        type("Orch", (), {"_untested_documented_routes": lambda self: []})(),
    )
    coord._executed_signatures = {("curl_get", "http://h:1/done")}
    repeat = _task("t-done", "curl_get", {"url": "http://h:1/done"})
    fresh = _task("t-new", "curl_get", {"url": "http://h:1/new"})
    kept = coord._cap_pending_tasks([repeat, fresh], max_total=1)
    assert [t.id for t in kept] == ["t-new"]


def test_forced_review_still_respects_the_llm_budget_floor():
    """`force=True` means "as soon as cadence allows", not "with 12s left"."""
    coord = _coordinator()
    coord.time_budget = 600.0
    coord._remaining_budget = lambda: _LLM_MIN_REMAINING_SECONDS - 12.0

    reason = coord._review_skip_reason(_task("t-1", "curl_get"), force=True)

    assert "budget" in reason


def test_forced_review_runs_when_the_budget_can_afford_it():
    coord = _coordinator()
    coord._remaining_budget = lambda: 600.0
    coord._review_done_this_cycle = True
    coord._evidence_since_review = False
    coord._executions_since_review = 0

    assert coord._review_skip_reason(_task("t-1", "curl_get"), force=True) == ""


def test_unusable_tool_is_remembered_and_reused_as_a_skip_reason():
    coord = _coordinator()

    coord._remember_unusable("aws_cli", "binary not installed")
    coord._remember_unusable("aws_cli", "binary not installed again")

    assert coord._unusable_tools() == {"aws_cli": "binary not installed"}
    assert "aws_cli (binary not installed)" in coord._unusable_tools_note()


def test_plan_sanitizer_skips_a_remembered_tool_without_repeating_the_note():
    """A tool the run already proved unusable is not re-planned every review."""
    coord = _coordinator()
    object.__setattr__(
        coord, "_orch",
        type("Orch", (), {
            "_BLACKLISTED_TOOLS": {},
            "_absent_services": set(),
            "attack_gateway": None,
            "recon_gateway": None,
            "dkg": type("DKK", (), {
                "query_nodes": lambda self, *a, **k: [],
            })(),
        })(),
    )
    coord._remember_unusable("aws_cli", "binary not installed")
    tasks = [_task("t-aws", "aws_cli", {"service": "s3", "action": "ls"})]

    coord._sanitize_plan_tools(tasks)
    coord._sanitize_plan_tools(tasks)

    assert tasks[0].status is TaskStatus.ABANDONED
    assert tasks[0].instruction.count("[skipped: aws_cli") == 1
