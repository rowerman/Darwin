import pytest

from darwin.data_model import TaskResult
from darwin.dpm import DefenseCategory, DefenseStateVector


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
