"""P16 tests: role prompts exist, are cut correctly, and the testable
wiring points use them."""

import pytest

from darwin.prompts.evaluator import SYSTEM_PROMPT_EVALUATOR
from darwin.prompts.memory import SYSTEM_PROMPT_MEMORY
from darwin.prompts.orchestrator import (
    SYSTEM_PROMPT_ANALYZE,
    SYSTEM_PROMPT_ORCHESTRATOR_UNIFIED,
)
from darwin.prompts.planner import SYSTEM_PROMPT_PLANNER
from darwin.prompts.research import SYSTEM_PROMPT_RESEARCH
from darwin.core.contracts import TaskStatus
from darwin.core.task import Task, deps_from_task_ids
from darwin.data_model import ExploitationPlan, VulnerabilityHypothesis


# ── Structural assertions ────────────────────────────────────────────


def test_planner_prompt_has_planning_responsibilities():
    assert "Tool Selection Rules" in SYSTEM_PROMPT_PLANNER
    assert "Multi-step attacks" in SYSTEM_PROMPT_PLANNER
    assert "Recognize exhaustion" in SYSTEM_PROMPT_PLANNER
    assert "dependent_task_ids" in SYSTEM_PROMPT_PLANNER


def test_unified_prompt_uses_registry_instead_of_static_catalog():
    assert "tool_registry_list" in SYSTEM_PROMPT_ORCHESTRATOR_UNIFIED
    assert "tool_registry_get" in SYSTEM_PROMPT_ORCHESTRATOR_UNIFIED
    assert "scenario-based categories" not in SYSTEM_PROMPT_ORCHESTRATOR_UNIFIED
    assert "file:///PATH" not in SYSTEM_PROMPT_ORCHESTRATOR_UNIFIED


def test_planner_prompt_uses_registry_instead_of_static_catalog():
    assert "tool_registry_list" in SYSTEM_PROMPT_PLANNER
    assert "tool_registry_get" in SYSTEM_PROMPT_PLANNER
    assert "scenario-based categories" not in SYSTEM_PROMPT_PLANNER


def test_analyze_prompt_uses_registry_instead_of_static_catalog():
    assert "tool_registry_list" in SYSTEM_PROMPT_ANALYZE
    assert "tool_registry_get" in SYSTEM_PROMPT_ANALYZE
    assert "{attack_tools}" not in SYSTEM_PROMPT_ANALYZE
    assert "{recon_tools}" not in SYSTEM_PROMPT_ANALYZE


def test_unified_prompt_flag_hunt_is_target_side_only():
    # shell_exec runs on the DARWIN host; the prompt must never teach the LLM
    # to hunt target flags with it (those flags are rejected by _verify_flag).
    assert "shell_exec runs on the DARWIN host" in SYSTEM_PROMPT_ORCHESTRATOR_UNIFIED
    assert "NEVER use shell_exec" in SYSTEM_PROMPT_ORCHESTRATOR_UNIFIED


def test_planner_prompt_flag_hunt_is_target_side_only():
    assert "shell_exec runs on the DARWIN host" in SYSTEM_PROMPT_PLANNER
    assert "Never use shell_exec" in SYSTEM_PROMPT_PLANNER


def test_research_prompt_has_research_guidance():
    assert "knowledge_search" in SYSTEM_PROMPT_RESEARCH
    assert "darwin.research_evidence.v1" in SYSTEM_PROMPT_RESEARCH
    assert "research specialist" in SYSTEM_PROMPT_RESEARCH
    assert "MANDATORY" in SYSTEM_PROMPT_RESEARCH
    assert "Output ONLY valid JSON" in SYSTEM_PROMPT_RESEARCH


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


def _task_from_dict(d):
    return Task(
        id=str(d["id"]),
        type="task",
        goal=d.get("goal", "") or d.get("instruction", ""),
        instruction=d.get("instruction", ""),
        action={
            "tool": d.get("tool", ""),
            "target": d.get("endpoint", ""),
            "params": dict(d.get("params") or {}),
        },
        dependencies=deps_from_task_ids(
            d.get("dependent_task_ids") or d.get("dependencies") or []
        ),
        status=TaskStatus.READY,
    )


@pytest.mark.asyncio
async def test_review_plan_uses_planner_prompt(
    fake_llm, fake_gateway, make_orchestrator
):
    llm = fake_llm(content="[]")
    orch = make_orchestrator(llm, fake_gateway({}), fake_gateway({}))
    orch.exploitation_plan = _plan_with(
        _task_from_dict({
            "id": "t1",
            "instruction": "x",
            "tool": "curl_get",
            "params": {"url": "http://x"},
            "dependent_task_ids": [],
        })
    )

    await orch._review_and_update_plan(
        _task_from_dict({"id": "t1", "instruction": "x", "tool": "curl_get"}),
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
        _task_from_dict(
            {"id": "t1", "instruction": "fetch", "tool": "curl_get", "params": {"url": "bad"}}
        ),
        "missing required argument",
    )

    assert fix is not None
    assert fix["fixable"] is True
    generates = [c for c in llm.calls if c[0] == "generate"]
    assert generates
    assert generates[0][2] == SYSTEM_PROMPT_EVALUATOR


@pytest.mark.asyncio
async def test_review_plan_injects_provenance(
    fake_llm, fake_gateway, make_orchestrator
):
    """P15 G2: the replan prompt carries DKG provenance."""
    llm = fake_llm(content="[]")
    orch = make_orchestrator(llm, fake_gateway({}), fake_gateway({}))
    orch.exploitation_plan = _plan_with(
        _task_from_dict({
            "id": "t1",
            "instruction": "x",
            "tool": "curl_get",
            "params": {"url": "http://x"},
            "dependent_task_ids": [],
        })
    )
    orch.dkg.add_node(
        "Vulnerability",
        "v1",
        {"vuln_type": "sqli", "endpoint": "http://x/login"},
        source="sqlmap_test",
        evidence="error-based injection",
    )

    await orch._review_and_update_plan(
        _task_from_dict({"id": "t1", "instruction": "x", "tool": "curl_get"}),
        False,
        "failed",
    )

    prompts = [c[1] for c in llm.calls if c[0] == "generate"]
    assert prompts
    assert "World State Provenance" in prompts[0]
    assert "source: sqlmap_test" in prompts[0]


def _research_gateway(fake_gateway):
    """Attack gateway exposing the research tool set."""
    return fake_gateway(
        {
            "knowledge_search": None,
            "cve_lookup": None,
            "metasploit_search": None,
            "searchsploit_search": None,
            "go_exploitdb_search": None,
            "ddg_web_search": None,
            "curl_get": None,
        },
        schemas={
            "knowledge_search": {"query": {"type": "string"}},
            "cve_lookup": {"cve_id": {"type": "string"}},
            "metasploit_search": {"query": {"type": "string"}},
            "searchsploit_search": {"query": {"type": "string"}},
            "go_exploitdb_search": {"query": {"type": "string"}},
            "ddg_web_search": {"query": {"type": "string"}},
            "curl_get": {"url": {"type": "string"}},
        },
    )


@pytest.mark.asyncio
async def test_research_phase_uses_research_prompt(
    fake_llm, fake_gateway, make_orchestrator
):
    """P15 G4: the vulnerability research phase runs with the research role."""
    llm = fake_llm(content="[]")
    orch = make_orchestrator(llm, _research_gateway(fake_gateway), fake_gateway({}))
    orch.vulnerabilities = [
        VulnerabilityHypothesis(
            vuln_type="sqli",
            endpoint="http://x/login",
            param="user",
            confidence=0.7,
            evidence="quote error observed",
            suggested_tool="sqlmap_test",
            tool_args={"url": "http://x/login", "param": "user"},
        )
    ]

    await orch._research_phase()

    generates = [c for c in llm.calls if c[0] == "generate"]
    assert generates
    assert any(c[2] == SYSTEM_PROMPT_RESEARCH for c in generates)


@pytest.mark.asyncio
async def test_active_service_research_uses_research_prompt(
    fake_llm, fake_gateway, make_orchestrator
):
    """P15 G4: service research also runs with the research role."""
    llm = fake_llm(content="[]")
    orch = make_orchestrator(llm, _research_gateway(fake_gateway), fake_gateway({}))
    orch.dkg.add_node(
        "Service", "svc-1", {"port": 80, "protocol": "tcp", "version": "Apache/2.4.41"}
    )

    await orch._active_service_research()

    generates = [c for c in llm.calls if c[0] == "generate"]
    assert generates
    assert any(c[2] == SYSTEM_PROMPT_RESEARCH for c in generates)
