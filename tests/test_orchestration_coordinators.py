"""Coordination wiring tests for the orchestrator decoupling (final refactor).

Verifies the shared-context composition contract:
- the five phase coordinators share the owning Orchestrator instance;
- every legacy method name still resolves on ``Orchestrator`` and routes to
  the coordinator that owns it;
- coordinator attribute writes land on the Orchestrator (shared state);
- ``_call_tool`` routes attack/recon tools to the correct gateway and returns
  a failure ToolResult for unknown tools.
"""

import asyncio

import pytest

from darwin.orchestrator import Orchestrator
from darwin.orchestration import (
    ExecutionCoordinator,
    LifecycleCoordinator,
    PlanCoordinator,
    ReconCoordinator,
    ResearchCoordinator,
)
from darwin.orchestration.ports import GatewayToolCallPort
from darwin.tools.mcp_gateway import ToolResult


# Legacy method name -> owning coordinator attribute on the Orchestrator.
METHOD_OWNER = {
    "lifecycle": [
        "run", "_should_terminate", "_detect_chain_topology",
        "_count_unexploited_services", "_get_state", "_belief_context",
        "_check_response_for_flag", "_print_plan_status", "_task_log_event",
        "metrics_report", "provenance_summary", "_task_log_write",
        "_checkpoint_path", "_check_tool_dependencies", "_time_exceeded",
        "_tokens_exceeded", "_maybe_compress", "_build_truncation_context",
        "_extract_json_array", "_extract_json",
    ],
    "recon": [
        "_bootstrap_scan", "_k8s_cluster_discovery", "_deep_recon",
        "_detect_defenses", "_verify_flag",
    ],
    "research": [
        "_analyze_phase", "_augment_from_dkg", "_cloud_discovery_hint",
        "_service_research", "_research_phase", "_active_service_research",
        "_probe_endpoints", "_format_vulnerability_summary",
        "_format_vulnerability_summary_short",
    ],
    "planning": [
        "_sanitize_plan_tools", "_generate_structured",
        "_generate_exploitation_plan", "_guess_tool", "_task_from_llm_dict",
        "_topological_sort", "_detect_cycle", "_break_cycle",
        "_select_next_plan_task", "_extract_recent_artifacts",
        "_build_defense_evasion_context", "_summarize_task_result",
        "_format_plan_status", "_build_cycle_summary", "_analyze_and_fix_task",
        "_extract_credentials_from_task", "_is_duplicate_task",
        "_cap_pending_tasks", "_review_and_update_plan", "_persist_plan",
        "_generate_phase_summary",
    ],
    "execution": [
        "_find_vuln_dkg_id", "_apply_vulnerability_feedback",
        "_format_parse_summary", "_format_tool_feedback", "_probe_for_defense",
        "_execute_task_with_policies", "_run_with_runtime",
        "_build_plan_exhaustion_context", "_execute_privesc",
        "_try_db_default_credentials", "_systematic_exploit_pass",
    ],
}

COORDINATOR_TYPES = {
    "lifecycle": LifecycleCoordinator,
    "recon": ReconCoordinator,
    "research": ResearchCoordinator,
    "planning": PlanCoordinator,
    "execution": ExecutionCoordinator,
}


@pytest.fixture
async def orch(make_orchestrator, fake_llm, fake_gateway):
    return make_orchestrator(fake_llm(), fake_gateway({}), fake_gateway({}))


def test_coordinators_share_the_same_orchestrator(orch):
    for name in ("recon", "research", "planning", "execution", "lifecycle"):
        coord = getattr(orch, name)
        assert coord._orch is orch
        assert isinstance(coord, COORDINATOR_TYPES[name])
    assert orch._tool_port._attack_gateway is orch.attack_gateway
    assert orch._tool_port._recon_gateway is orch.recon_gateway


def test_all_legacy_methods_resolve_on_orchestrator(orch):
    for owner, names in METHOD_OWNER.items():
        coord = getattr(orch, owner)
        for name in names:
            assert callable(getattr(orch, name)), name
            assert callable(getattr(coord, name)), name


def test_coordinator_owns_its_methods(orch):
    # The facade keeps one delegate per method; the coordinator that owns a
    # method exposes it directly (class-level), not via the shared context.
    for owner, names in METHOD_OWNER.items():
        coord = getattr(orch, owner)
        for name in names:
            if name in ("_extract_json_array", "_extract_json"):
                continue  # static helpers live on the coordinator class
            assert name in type(coord).__dict__, (owner, name)


def test_facade_delegates_sync_method_to_coordinator(orch, monkeypatch):
    called = []

    def fake_sanitize(tasks):
        called.append(tasks)
        return None

    monkeypatch.setattr(orch.planning, "_sanitize_plan_tools", fake_sanitize)
    orch._sanitize_plan_tools(["task"])
    assert called == [["task"]]


def test_facade_delegates_async_method_to_coordinator(orch, monkeypatch):
    called = []

    async def fake_verify(target_url):
        called.append(target_url)
        return None

    monkeypatch.setattr(orch.recon, "_verify_flag", fake_verify)
    result = orch._verify_flag("http://target:8000/")
    assert asyncio.run(result) is None
    assert called == ["http://target:8000/"]


def test_facade_run_delegates_to_lifecycle(orch, monkeypatch):
    called = []

    async def fake_run(task_description, target_url, username=None,
                       password=None, port_range=None):
        called.append((task_description, target_url, username, password, port_range))
        return None

    monkeypatch.setattr(orch.lifecycle, "run", fake_run)
    assert asyncio.run(orch.run("task", "http://target:8000/", username="u")) is None
    assert called == [("task", "http://target:8000/", "u", None, None)]


def test_coordinator_state_writes_land_on_orchestrator(orch):
    orch.recon.target_host = "example.test"
    assert orch.target_host == "example.test"
    orch.planning.some_marker = {"a": 1}
    assert orch.some_marker == {"a": 1}


def test_coordinator_reads_orchestrator_state(orch):
    orch.phase = "ANALYZE"
    assert orch.research.phase == "ANALYZE"


def test_call_tool_routes_to_attack_and_recon_gateways():
    attack = _RecordingGateway({"attack_tool"})
    recon = _RecordingGateway({"recon_tool"})
    port = GatewayToolCallPort(attack, recon)

    assert asyncio.run(port.call("attack_tool", {"x": 1})).success is True
    assert asyncio.run(port.call("recon_tool", {"y": 2})).success is True
    assert attack.calls == [("attack_tool", {"x": 1})]
    assert recon.calls == [("recon_tool", {"y": 2})]


def test_call_tool_unknown_tool_returns_failure(orch):
    result = asyncio.run(orch._tool_port.call("no_such_tool", {}))
    assert result.success is False
    assert result.exit_code == -1


def test_coordinator_call_tool_uses_injected_port(orch, monkeypatch):
    async def fake_call(name, params):
        return ToolResult(
            tool_name=name, success=True, stdout="ok", stderr="",
            exit_code=0, elapsed_ms=0.0,
        )

    monkeypatch.setattr(orch._tool_port, "call", fake_call)
    result = asyncio.run(orch.recon._call_tool("nmap_port_range", {"target": "x"}))
    assert result.success is True


def test_static_helpers_still_reachable_from_orchestrator():
    assert Orchestrator._extract_json_array("[1, 2]") == [1, 2]
    assert Orchestrator._extract_json('{"a": 1}') == {"a": 1}


class _RecordingGateway:
    """Minimal gateway stand-in recording calls."""

    def __init__(self, tool_names):
        self._names = set(tool_names)
        self.calls = []

    def get_tool_names(self):
        return set(self._names)

    async def call(self, name, params):
        self.calls.append((name, params))
        return ToolResult(
            tool_name=name, success=True, stdout="ok", stderr="",
            exit_code=0, elapsed_ms=0.0,
        )
