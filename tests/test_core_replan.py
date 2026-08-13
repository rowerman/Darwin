"""Unit tests for the P7 Replanner (local-first replanning)."""

from darwin.core.contracts import ReplanRecommendation, TaskOutcome
from darwin.core.evaluator import Evaluation, FailureType
from darwin.core.replan import Replanner
from darwin.core.task import Task


def task(tool="sqlmap_test", params=None, tid="t1"):
    return Task(
        id=tid,
        type="exploit",
        goal="g",
        action={
            "tool": tool,
            "target": "http://x",
            "params": params or {"url": "http://x"},
        },
    )


def evaluation(failure_type):
    return Evaluation(
        task_id="t1",
        outcome=(
            TaskOutcome.SUCCESS if failure_type is None else TaskOutcome.FAILED
        ),
        failure_type=failure_type,
        evidence=[],
        confidence_delta=0.0,
        replan=ReplanRecommendation.NONE,
    )


def test_record_failure_and_duplicate_detection():
    r = Replanner()
    t = task()
    r.record_failure(t)
    assert r.is_duplicate(task())
    assert r.is_duplicate(task(params={"url": "http://other"})) is False


def test_invalid_argument_is_retry_not_replace():
    r = Replanner()
    repair = r.local_repair(task(), evaluation(FailureType.INVALID_ARGUMENT))
    assert repair.action == "retry"
    assert repair.replacement is None


def test_budget_exceeded_global_stop():
    r = Replanner()
    repair = r.local_repair(task(), evaluation(FailureType.BUDGET_EXCEEDED))
    assert repair.action == "global_stop"


def test_target_unreachable_invalidates_branch():
    r = Replanner()
    repair = r.local_repair(task(), evaluation(FailureType.TARGET_UNREACHABLE))
    assert repair.action == "invalidate"


def test_hypothesis_rejected_uses_alternative_tool():
    r = Replanner()
    repair = r.local_repair(task(), evaluation(FailureType.HYPOTHESIS_REJECTED))
    assert repair.action == "replace"
    assert repair.replacement is not None
    assert repair.replacement.action["tool"] == "http_post"  # alt for sqlmap_test


def test_repeated_failure_of_replacement_is_rejected():
    r = Replanner()
    t = task()
    repair1 = r.local_repair(t, evaluation(FailureType.HYPOTHESIS_REJECTED))
    assert repair1.replacement is not None
    r.record_failure(repair1.replacement)  # replacement also failed
    repair2 = r.local_repair(t, evaluation(FailureType.HYPOTHESIS_REJECTED))
    assert repair2.action == "abandon"
    assert repair2.rejected_duplicate is True


def test_defense_blocked_creates_encoded_variant():
    r = Replanner()
    repair = r.local_repair(task(), evaluation(FailureType.DEFENSE_BLOCKED))
    assert repair.action == "replace"
    assert repair.replacement is not None
    assert repair.replacement.action["params"].get("encode_type") == "url_double"


def test_auth_failure_abandons_for_planner():
    r = Replanner()
    repair = r.local_repair(task(), evaluation(FailureType.AUTH_FAILURE))
    assert repair.action == "abandon"


def test_inconclusive_tweaks_evidence_source():
    r = Replanner()
    repair = r.local_repair(task(), evaluation(FailureType.INCONCLUSIVE))
    assert repair.action == "replace"
    assert "tweak_hint" in repair.replacement.action["params"]


def test_no_failure_means_no_repair():
    r = Replanner()
    repair = r.local_repair(task(), evaluation(None))
    assert repair.action == "none"


def test_novelty_ratio_metrics():
    r = Replanner()
    t = task()
    repair1 = r.local_repair(t, evaluation(FailureType.HYPOTHESIS_REJECTED))
    assert repair1.replacement is not None
    r.record_failure(repair1.replacement)
    r.local_repair(t, evaluation(FailureType.HYPOTHESIS_REJECTED))
    assert r.proposed_count == 2
    assert r.rejected_count == 1
    assert r.novelty_ratio == 0.5
