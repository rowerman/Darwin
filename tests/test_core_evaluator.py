"""Unit tests for the P6 Evaluator / FailureAnalyzer."""

import pytest

from darwin.core.contracts import ReplanRecommendation, TaskOutcome
from darwin.core.evaluator import Evaluation, Evaluator, FailureAnalyzer, FailureType
from darwin.core.executor import ExecutionResult
from darwin.core.task import Task


def result(output="", stderr="", exit_code=0, success=False, tool="sqlmap_test"):
    return ExecutionResult(
        task_id="t1",
        tool=tool,
        planned_tool=tool,
        adherence=True,
        success=success,
        stdout=output,
        stderr=stderr,
        exit_code=exit_code,
        elapsed_ms=1.0,
    )


def task():
    return Task(id="t1", type="exploit", goal="g")


@pytest.mark.parametrize(
    "output,stderr,exit_code,tool,expected",
    [
        ("budget exceeded", "", 0, "curl_get", FailureType.BUDGET_EXCEEDED),
        (
            "",
            "unexpected keyword argument 'foo'",
            1,
            "curl_get",
            FailureType.INVALID_ARGUMENT,
        ),
        ("", "command not found: sqlmap", 127, "sqlmap_test", FailureType.ENVIRONMENT_ERROR),
        ("connection refused", "", 7, "curl_get", FailureType.TARGET_UNREACHABLE),
        ("", "", 7, "curl_get", FailureType.TARGET_UNREACHABLE),
        ("authentication failed", "", 1, "test_credential", FailureType.AUTH_FAILURE),
        ("403 Forbidden - ModSecurity blocked", "", 403, "send_payload", FailureType.DEFENSE_BLOCKED),
        ("not vulnerable to SQL injection", "", 0, "sqlmap_test", FailureType.HYPOTHESIS_REJECTED),
        ("Traceback (most recent call last)", "", 1, "shell_exec", FailureType.TOOL_ERROR),
        ("no tool available for this service", "", 1, "curl_get", FailureType.PRECONDITION_MISSING),
        ("", "", 3, "shell_exec", FailureType.TOOL_ERROR),
        ("weird opaque failure", "", 0, "curl_get", FailureType.INCONCLUSIVE),
    ],
)
def test_failure_classification(output, stderr, exit_code, tool, expected):
    analyzer = FailureAnalyzer()
    cls = analyzer.classify(result(output, stderr, exit_code, tool=tool))
    assert cls.failure_type is expected


def test_successful_exploratory_tool_without_evidence_is_inconclusive():
    analyzer = FailureAnalyzer()
    cls = analyzer.classify(result("nothing found", success=True, tool="dirb_scan"))
    assert cls.failure_type is FailureType.INCONCLUSIVE


def test_successful_tool_that_rejects_hypothesis():
    analyzer = FailureAnalyzer()
    cls = analyzer.classify(result("no vulnerability detected", success=True, tool="sqlmap_test"))
    assert cls.failure_type is FailureType.HYPOTHESIS_REJECTED


async def test_success_evaluation():
    ev = await Evaluator().evaluate(task(), result("flag{ok}", success=True))
    assert isinstance(ev, Evaluation)
    assert ev.outcome is TaskOutcome.SUCCESS
    assert ev.failure_type is None
    assert ev.replan is ReplanRecommendation.NONE


async def test_hypothesis_rejected_evaluation():
    ev = await Evaluator().evaluate(task(), result("not vulnerable", exit_code=0))
    assert ev.outcome is TaskOutcome.FAILED
    assert ev.failure_type is FailureType.HYPOTHESIS_REJECTED
    assert ev.confidence_delta == -0.5
    assert ev.replan is ReplanRecommendation.LOCAL
    assert ev.evidence


async def test_defense_blocked_raises_confidence():
    ev = await Evaluator().evaluate(task(), result("ModSecurity blocked", exit_code=403))
    assert ev.failure_type is FailureType.DEFENSE_BLOCKED
    assert ev.confidence_delta == 0.1


async def test_precondition_missing_blocks():
    ev = await Evaluator().evaluate(task(), result("no tool available"))
    assert ev.outcome is TaskOutcome.BLOCKED
    assert ev.replan is ReplanRecommendation.NONE


async def test_budget_exceeded_global_replan():
    ev = await Evaluator().evaluate(task(), result("time budget exceeded"))
    assert ev.failure_type is FailureType.BUDGET_EXCEEDED
    assert ev.replan is ReplanRecommendation.GLOBAL
