import pytest

from darwin.data_model import TaskResult
from darwin.dpm import DefenseCategory, DefenseStateVector
from darwin.core.task import Task
from darwin.core.contracts import TaskStatus
from darwin.data_model import ExploitationPlan


@pytest.mark.asyncio
async def test_final_result_projects_defense_snapshot(make_orchestrator, fake_llm, fake_gateway):
    orch = make_orchestrator(fake_llm(content="[]"), fake_gateway({}), fake_gateway({}))
    orch.defense_state = DefenseStateVector(
        waf_type="cloudflare",
        defense_category=DefenseCategory.CLOAK,
        defense_complexity=0.65,
        bypass_successes=1,
    )
    result = TaskResult(success=True)

    orch.lifecycle._apply_final_defense_state(result)

    assert result.defense_detected is True
    assert result.waf_type == "cloudflare"
    assert result.defense_complexity == 0.65
    assert result.waf_bypassed is True


@pytest.mark.asyncio
async def test_final_result_does_not_treat_unknown_state_as_defense(
    make_orchestrator, fake_llm, fake_gateway
):
    orch = make_orchestrator(fake_llm(content="[]"), fake_gateway({}), fake_gateway({}))
    result = TaskResult(success=False)

    orch.lifecycle._apply_final_defense_state(result)

    assert result.defense_detected is False
    assert result.waf_type == ""
    assert result.defense_complexity == 0.0


@pytest.mark.asyncio
async def test_systematic_inconclusive_task_remains_runnable(
    make_orchestrator, fake_llm, fake_gateway
):
    orch = make_orchestrator(fake_llm(content="[]"), fake_gateway({}), fake_gateway({}))
    task = Task(
        id="t1", type="exploit", goal="test SSRF", instruction="test",
        action={"tool": "ssrf_probe", "params": {
            "ssrf_url": "http://target/fetch", "url_param": "url"
        }}, status=TaskStatus.READY,
    )
    orch.exploitation_plan = ExploitationPlan(
        plan_id="p1", phase="exploit", goal="test", tasks=[task]
    )
    # Systematic results are intentionally scoped to that pass. An
    # inconclusive probe must remain available to Runtime for a second,
    # potentially different parameter strategy.
    assert task.status is TaskStatus.READY
    assert task.id not in orch._exhausted_task_ids
