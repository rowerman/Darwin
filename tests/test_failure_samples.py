"""P18 failure-sample regression tests (architecture plan section 4.3).

Each test reproduces a real failure mode observed in Darwin v1 and pins
the v2 mechanism that detects or prevents it. All are marked ``acceptance``
so milestone acceptance can be run as a group (``pytest -m acceptance``).
"""

import pytest

from darwin.core.capabilities import Capability, CapabilityRegistry
from darwin.core.contracts import TaskOutcome
from darwin.core.evaluator import Evaluation, FailureAnalyzer, FailureType
from darwin.core.executor import ToolExecutor
from darwin.core.replan import Replanner
from darwin.core.task import Task
from darwin.data_model import ExploitationPlan
from darwin.tools.mcp_gateway import ToolResult


FLAG = "flag{failure-sample-ok}"


def plan_task(tool, params):
    return {
        "id": f"t-{tool}",
        "instruction": f"Run {tool}",
        "tool": tool,
        "params": params,
        "status": "pending",
        "dependent_task_ids": [],
        "attempts": 0,
        "result_summary": "",
    }


def make_plan(task):
    return ExploitationPlan(plan_id="fail-sample", phase="exploit", goal="g", tasks=[task])


@pytest.mark.acceptance
@pytest.mark.asyncio
async def test_m2_plan_adherence_detects_execution_deviation(
    fake_llm, fake_gateway, make_orchestrator
):
    """Real failure: plan said sqlmap_test, but execution drifted to curl_get.

    v2 mechanism: tool_result.adherence records planned vs executed tool;
    P19 aggregates it into plan adherence rate.
    """
    recon_gw = fake_gateway(
        {
            "curl_get": ToolResult(
                tool_name="curl_get",
                success=True,
                stdout=f"page\n{FLAG}\n",
                stderr="",
                exit_code=0,
                elapsed_ms=1.0,
            )
        }
    )
    attack_gw = fake_gateway({})
    llm = fake_llm(
        tool_calls=[
            {
                "name": "curl_get",
                "arguments": {"url": "http://target:8000/"},
                "id": "tc-1",
            }
        ]
    )

    orch = make_orchestrator(llm, recon_gw, attack_gw)
    orch.exploitation_plan = make_plan(
        plan_task("sqlmap_test", {"url": "http://target:8000/", "param": "user"})
    )

    result = await orch._unified_llm_loop("http://target:8000/")

    assert result is not None and result.success is True
    report = orch.metrics_report()
    assert report.total_executions == 1
    assert report.adherence_rate == 0.0  # deviation detected


@pytest.mark.acceptance
@pytest.mark.asyncio
async def test_m5_invalid_parameter_caught_before_execution(fake_gateway):
    """Real failure: LLM built a call with missing/incorrect tool params.

    v2 mechanism: P9 pre-execution schema validation turns it into
    INVALID_ARGUMENT without invoking the tool.
    """
    gw = fake_gateway(
        {},
        schemas={
            "sqlmap_test": {
                "url": {"type": "string"},
                "param": {"type": "string"},
            }
        },
    )
    cap = Capability(
        name="custom-sqli",
        description="",
        required_context=[],
        supported_tools=["sqlmap_test"],
        default_tool="sqlmap_test",
    )
    reg = CapabilityRegistry()
    reg.register(cap)
    ex = ToolExecutor(attack_gateway=gw, capability_registry=reg)

    task = Task(
        id="t-bad-params",
        type="exploit",
        goal="verify sqli",
        action={"capability": "custom-sqli", "target": "", "params": {}},
    )
    res = await ex.execute(task)

    assert gw.calls == []  # tool never invoked
    assert res.success is False
    assert "invalid argument" in res.stderr
    cls = FailureAnalyzer().classify(res)
    assert cls.failure_type == FailureType.INVALID_ARGUMENT


@pytest.mark.acceptance
def test_m7_replan_novelty_drops_when_variant_repeats():
    """Real failure: after a variant fails, replan re-proposes the same variant.

    v2 mechanism: Replanner failed-signature registry rejects the duplicate
    and the novelty_ratio drops below 1.
    """
    task = Task(
        id="t1",
        type="exploit",
        goal="g",
        action={"tool": "curl_get", "target": "http://x", "params": {"url": "http://x"}},
    )
    evaluation = Evaluation(
        task_id="t1",
        outcome=TaskOutcome.FAILED,
        failure_type=FailureType.DEFENSE_BLOCKED,
    )
    replanner = Replanner()

    first = replanner.local_repair(task, evaluation)
    assert first.action == "replace"
    assert first.replacement is not None
    # The variant also failed in reality — record it.
    replanner.record_failure(first.replacement)

    second = replanner.local_repair(task, evaluation)
    assert second.rejected_duplicate is True
    assert second.action == "defer"
    assert replanner.novelty_ratio is not None
    assert replanner.novelty_ratio < 1.0


@pytest.mark.acceptance
def test_duplicate_action_identical_failed_path_detected():
    """Real failure: the exact same tool+params keeps being retried.

    v2 mechanism: Replanner.is_duplicate flags an identical failed
    signature; a different parameter set is not flagged.
    """
    replanner = Replanner()
    task = Task(
        id="t1",
        type="exploit",
        goal="g",
        action={
            "tool": "sqlmap_test",
            "target": "http://x/login",
            "params": {"url": "http://x/login", "param": "user"},
        },
    )
    replanner.record_failure(task)

    assert replanner.is_duplicate(task) is True

    different = Task(
        id="t2",
        type="exploit",
        goal="g",
        action={
            "tool": "sqlmap_test",
            "target": "http://x/login",
            "params": {"url": "http://x/login", "param": "password"},
        },
    )
    assert replanner.is_duplicate(different) is False
