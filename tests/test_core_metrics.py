"""Unit tests for the P19 metrics aggregation (darwin.core.metrics)."""

import pytest

from darwin.core.metrics import MetricsCalculator, MetricsReport


def tool_result(task_id, adherence=True, success=True):
    return {
        "event": "tool_result",
        "task_id": task_id,
        "tool": "x",
        "planned_tool": "x",
        "adherence": adherence,
        "success": success,
        "exit_code": 0,
        "elapsed_ms": 1.0,
    }


def evaluated(task_id, failure_type=None, outcome="failed"):
    return {
        "event": "task_evaluated",
        "task_id": task_id,
        "failure_type": failure_type,
        "outcome": outcome,
        "replan": "none",
    }


def replan(task_id, action="replace", rejected_duplicate=False):
    return {
        "event": "replan_requested",
        "task_id": task_id,
        "action": action,
        "rejected_duplicate": rejected_duplicate,
    }


class FakeReplanner:
    def __init__(self, proposed=10, rejected=2):
        self.proposed_count = proposed
        self.rejected_count = rejected
        self.novelty_ratio = (
            1.0 - rejected / proposed if proposed else None
        )


def test_empty_log_returns_zeroed_report():
    report = MetricsCalculator().calculate([])
    assert isinstance(report, MetricsReport)
    assert report.total_executions == 0
    assert report.adherence_rate is None
    assert report.invalid_tool_invocation_rate is None
    assert report.recovery_rate is None
    assert report.replan_novelty is None
    assert report.duplicate_action_rate is None
    assert report.failure_type_counts == {}


def test_plan_adherence_rate():
    log = [
        tool_result("t1", adherence=True),
        tool_result("t2", adherence=True),
        tool_result("t3", adherence=False),
    ]
    report = MetricsCalculator().calculate(log)
    assert report.total_executions == 3
    assert report.adherence_count == 2
    assert report.adherence_rate == pytest.approx(2 / 3)


def test_invalid_tool_invocation_rate_and_failure_distribution():
    log = [
        tool_result("t1"),
        tool_result("t2"),
        tool_result("t3"),
        tool_result("t4"),
        evaluated("t1", failure_type="invalid_argument"),
        evaluated("t2", failure_type="precondition_missing"),
        evaluated("t3", failure_type="tool_error"),
    ]
    report = MetricsCalculator().calculate(log)
    assert report.invalid_invocations == 2
    assert report.invalid_tool_invocation_rate == pytest.approx(2 / 4)
    assert report.failure_type_counts == {
        "invalid_argument": 1,
        "precondition_missing": 1,
        "tool_error": 1,
    }
    assert report.outcome_counts["failed"] == 3


def test_recovery_rate_from_execution_history():
    log = [
        tool_result("t1", success=False),
        tool_result("t1", success=True),
        tool_result("t2", success=False),
        tool_result("t3", success=True),
    ]
    report = MetricsCalculator().calculate(log)
    assert report.recovery_rate == pytest.approx(0.5)  # t1 recovered, t2 not


def test_replan_novelty_from_replanner_stats():
    report = MetricsCalculator().calculate([], FakeReplanner(proposed=10, rejected=2))
    assert report.replan_novelty == pytest.approx(0.8)
    assert report.duplicate_action_rate == pytest.approx(0.2)


def test_replan_novelty_falls_back_to_trace():
    log = [
        replan("t1", rejected_duplicate=True),
        replan("t2", rejected_duplicate=False),
        replan("t3", rejected_duplicate=False),
    ]
    report = MetricsCalculator().calculate(log)
    assert report.replan_novelty == pytest.approx(2 / 3)
    assert report.duplicate_action_rate == pytest.approx(1 / 3)
    assert report.replan_action_counts == {"replace": 3}


def test_replanner_with_zero_proposals_yields_no_novelty():
    report = MetricsCalculator().calculate([], FakeReplanner(proposed=0, rejected=0))
    assert report.replan_novelty is None
    assert report.duplicate_action_rate is None


def test_metrics_ignore_unrelated_events():
    log = [{"event": "plan_generated", "plan_id": "p1"}, {"event": "run_started"}]
    report = MetricsCalculator().calculate(log)
    assert report.total_executions == 0
    assert report.replan_novelty is None
