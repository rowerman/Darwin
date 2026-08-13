"""P16 tests: role prompts exist, are cut correctly, and the testable
wiring points use them."""

import pytest

from darwin.prompts.evaluator import SYSTEM_PROMPT_EVALUATOR
from darwin.prompts.memory import SYSTEM_PROMPT_MEMORY
from darwin.prompts.planner import SYSTEM_PROMPT_PLANNER
from darwin.prompts.research import SYSTEM_PROMPT_RESEARCH
from darwin.data_model import ExploitationPlan


# ── Structural assertions ────────────────────────────────────────────


def test_planner_prompt_has_planning_responsibilities():
    assert "Tool Selection Rules" in SYSTEM_PROMPT_PLANNER
    assert "Multi-step attacks" in SYSTEM_PROMPT_PLANNER
    assert "Recognize exhaustion" in SYSTEM_PROMPT_PLANNER
    assert "dependent_task_ids" in SYSTEM_PROMPT_PLANNER


def test_research_prompt_has_research_guidance():
    assert "knowledge_search" in SYSTEM_PROMPT_RESEARCH
    assert "Research(!!)" in SYSTEM_PROMPT_RESEARCH
    assert "MANDATORY" in SYSTEM_PROMPT_RESEARCH


def test_evaluator_prompt_has_classification_schema():
    assert "fixable" in SYSTEM_PROMPT_EVALUATOR
    assert "partial_success" in SYSTEM_PROMPT_EVALUATOR
    assert "not_fixable" in SYSTEM_PROMPT_EVALUATOR
    assert "corrected_params" in SYSTEM_PROMPT_EVALUATOR


def test_memory_prompt_preserves_decision_facts():
    assert "Preserve ALL" in SYSTEM_PROMPT_MEMORY
    assert "Failed Attempts" in SYSTEM_PROMPT_MEMORY
    assert "Intermediate Artifacts" in SYSTEM_PROMPT_MEMORY


# ── Wiring assertions (the testable接入点) ───────────────────────────


def test_memory_prompt_wired_into_llm_by_identity():
    from darwin.utils import llm

    assert llm.SYSTEM_PROMPT_COMPRESS == SYSTEM_PROMPT_MEMORY


def _plan_with(task):
    return ExploitationPlan(plan_id="p16", phase="exploit", goal="g", tasks=[task])


@pytest.mark.asyncio
async def test_review_plan_uses_planner_prompt(
    fake_llm, fake_gateway, make_orchestrator
):
    llm = fake_llm(content="[]")
    orch = make_orchestrator(llm, fake_gateway({}), fake_gateway({}))
    orch.exploitation_plan = _plan_with(
        {
            "id": "t1",
            "instruction": "x",
            "tool": "curl_get",
            "params": {"url": "http://x"},
            "status": "pending",
            "dependent_task_ids": [],
        }
    )

    await orch._review_and_update_plan(
        {"id": "t1", "instruction": "x", "tool": "curl_get"},
        False,
        "failed",
    )

    generates = [c for c in llm.calls if c[0] == "generate"]
    assert generates
    assert generates[0][2] == SYSTEM_PROMPT_PLANNER


@pytest.mark.asyncio
async def test_fix_analysis_uses_evaluator_prompt(
    fake_llm, fake_gateway, make_orchestrator
):
    llm = fake_llm(
        content=(
            '{"fixable": true, "corrected_params": {"url": "http://x"}, '
            '"reason": "wrong url"}'
        )
    )
    orch = make_orchestrator(llm, fake_gateway({}), fake_gateway({}))

    fix = await orch._analyze_and_fix_task(
        {"id": "t1", "instruction": "fetch", "tool": "curl_get", "params": {"url": "bad"}},
        "missing required argument",
    )

    assert fix is not None
    assert fix["fixable"] is True
    generates = [c for c in llm.calls if c[0] == "generate"]
    assert generates
    assert generates[0][2] == SYSTEM_PROMPT_EVALUATOR
