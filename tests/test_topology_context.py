"""Focused coverage for DKG topology snapshots and planner context."""

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from darwin.core.belief import render_belief_snapshot
from darwin.core.task import Task
from darwin.data_model import ExploitationPlan, normalize_dkg_state
from darwin.dkg import DKG
from darwin.tools.mcp_gateway import ToolResult


def test_dkg_topology_snapshot_and_diff_are_bounded_and_stable():
    dkg = DKG()
    dkg.add_node("Host", "host-a", {"ip": "10.0.0.1"})
    dkg.add_node("Service", "svc-a", {"port": 8080, "version": "nginx"})
    dkg.add_node("Endpoint", "ep-a", {"url": "http://target/"})
    dkg.add_edge("host-a", "svc-a", "host_has_service")

    before = dkg.topology_snapshot(anchor_ids=["host-a"], max_hops=1, max_nodes=2)
    assert before["anchors"] == ["host-a"]
    assert [node["id"] for node in before["nodes"]] == ["host-a", "svc-a"]
    assert before["edges"][0]["type"] == "host_has_service"

    dkg.add_node("Session", "session-a", {"host": "10.0.0.1", "user": "root"})
    dkg.add_edge("session-a", "host-a", "session_on_host")
    after = dkg.topology_snapshot(anchor_ids=["host-a"], max_hops=1)
    diff = dkg.topology_diff(before, after)
    assert diff["to_revision"] > diff["from_revision"]
    assert any(row["id"] == "session-a" for row in diff["added_nodes"])
    assert any(row["type"] == "session_on_host" for row in diff["added_edges"])


def test_normalize_dkg_state_exposes_edges_and_full_credentials():
    dkg = DKG()
    dkg.add_node("Host", "host-a", {"ip": "10.0.0.1"})
    dkg.add_node("Credential", "cred-a", {
        "username": "admin", "password": "secret", "source_host": "10.0.0.1",
    })
    dkg.add_edge("cred-a", "host-a", "credential_for")

    state = normalize_dkg_state(dkg)
    assert state.topology.nodes
    assert any(edge.edge_type == "credential_for" for edge in state.topology.edges)
    text = render_belief_snapshot(state)
    assert "credential_for" in text
    assert "password=secret" in text


def test_topology_renderer_includes_attack_path_summary():
    state = normalize_dkg_state(DKG())
    state.topology.attack_paths.append(SimpleNamespace(
        path_id="p1", category="lateral_move", description="session to pod",
        confidence=0.8, prerequisites=["session"],
        recommended_tools=["kubectl_exec"], steps=[{"action": "exec", "tool": "kubectl_exec", "target": "pod/a"}],
    ))
    text = render_belief_snapshot(state)
    assert "Attack paths:" in text
    assert "kubectl_exec" in text


def test_topology_snapshot_dedupes_parallel_edges_and_diff_reports_real_adds():
    dkg = DKG()
    dkg.add_node("Host", "host-a", {})
    dkg.add_node("Service", "svc-b", {})
    dkg.add_node("Service", "svc-c", {})
    dkg.add_edge("host-a", "svc-b", "host_has_service")
    dkg.add_edge("host-a", "svc-b", "host_has_service")
    before = dkg.topology_snapshot(anchor_ids=["host-a"])
    assert len(before["edges"]) == 1

    dkg.add_edge("host-a", "svc-c", "host_has_service")
    after = dkg.topology_snapshot(anchor_ids=["host-a"])
    assert len(after["edges"]) == 2
    diff = dkg.topology_diff(before, after)
    assert [e["to"] for e in diff["added_edges"]] == ["svc-c"]
    assert diff["to_revision"] > diff["from_revision"]


def test_dkg_revision_persists_and_legacy_checkpoint_loads_with_zero(tmp_path):
    dkg = DKG()
    dkg.add_node("Host", "host-a", {"ip": "10.0.0.1"})
    dkg.add_node("Service", "svc-a", {"port": 80})
    dkg.add_edge("host-a", "svc-a", "host_has_service")
    path = str(tmp_path / "dkg.json")
    dkg.save(path)

    loaded = DKG.load(path)
    assert loaded.revision == dkg.revision == 3

    # Old checkpoints serialized before the revision field must still load.
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    data.pop("revision", None)
    legacy_path = str(tmp_path / "legacy.json")
    Path(legacy_path).write_text(json.dumps(data), encoding="utf-8")
    legacy = DKG.load(legacy_path)
    assert legacy.revision == 0
    assert any(n["id"] == "host-a" for n in legacy.topology_snapshot()["nodes"])


def test_attack_path_summary_gate_and_revision_cache(monkeypatch):
    import darwin.cloud_attack_path as cloud_attack_path

    calls = {"n": 0}

    def fake_compute(dkg):
        calls["n"] += 1
        return cloud_attack_path.AttackPathReport(paths=[])

    monkeypatch.setattr(cloud_attack_path, "compute_attack_paths", fake_compute)
    dkg = DKG()
    dkg.add_node("Host", "host-a", {})
    assert dkg.attack_path_summary() == []
    assert calls["n"] == 0  # gated: no cloud/K8s node types present

    dkg.add_node("IAMRole", "role-a", {"name": "dev"})
    dkg.add_node("IAMRole", "role-b", {"name": "admin"})
    dkg.add_edge("role-a", "role-b", "role_can_assume")
    dkg.attack_path_summary()
    dkg.attack_path_summary()
    assert calls["n"] == 1  # cached within the same revision

    dkg.add_node("IAMRole", "role-c", {"name": "audit"})
    dkg.attack_path_summary()
    assert calls["n"] == 2  # recomputed after a revision bump


def test_cloud_relations_enter_topology_with_attack_paths():
    dkg = DKG()
    dkg.add_node("IAMRole", "role-a", {"name": "dev-role"})
    dkg.add_node("IAMRole", "role-b", {"name": "admin-role"})
    dkg.add_edge("role-a", "role-b", "role_can_assume")

    state = normalize_dkg_state(dkg)
    assert any(n.node_type == "IAMRole" for n in state.topology.nodes)
    assert any(e.edge_type == "role_can_assume" for e in state.topology.edges)
    assert state.topology.attack_paths
    assert state.topology.attack_paths[0].category == "privilege_escalation"


def test_topology_render_survives_non_numeric_confidence():
    dkg = DKG()
    dkg.add_node("Host", "host-a", {"ip": "10.0.0.1", "confidence": "high"})
    dkg.add_node("Service", "svc-a", {"port": 80, "confidence": "unknown"})
    dkg.add_edge("host-a", "svc-a", "host_has_service", confidence="high")

    text = render_belief_snapshot(normalize_dkg_state(dkg))
    assert "Topology (revision=" in text
    assert "Host:host-a" in text
    assert "host_has_service" in text


def test_topology_snapshot_max_hops_zero_returns_only_anchors():
    dkg = DKG()
    dkg.add_node("Host", "host-a", {})
    dkg.add_node("Service", "svc-a", {})
    dkg.add_edge("host-a", "svc-a", "host_has_service")

    snapshot = dkg.topology_snapshot(
        anchor_ids=["host-a"], max_hops=0, max_nodes=2, max_edges=1
    )
    assert [n["id"] for n in snapshot["nodes"]] == ["host-a"]
    assert snapshot["edges"] == []


@pytest.mark.asyncio
async def test_execution_to_review_prompt_contains_topology_diff(
    make_orchestrator, fake_llm, fake_gateway, monkeypatch
):
    """A task that adds DKG nodes must surface them in the next plan review."""
    llm = fake_llm(content="[]")
    imds_stdout = (
        '{"AccessKeyId":"AKIAEXAMPLE123","SecretAccessKey":"secretkey123",'
        '"Token":"tok123"}'
    )
    attack_gw = fake_gateway(
        {
            "shell_exec": ToolResult(
                tool_name="shell_exec", success=True, stdout=imds_stdout,
                stderr="", exit_code=0, elapsed_ms=1.0,
            ),
        },
        schemas={"shell_exec": {"command": {"type": "string"}}},
    )
    orch = make_orchestrator(llm, fake_gateway({}), attack_gw)
    monkeypatch.setattr(orch, "_persist_plan", lambda phase="exploit": None)
    orch._exploit_chain = []

    task = Task(
        id="t-cred",
        type="exploit",
        goal="discover credentials",
        instruction="fetch cloud metadata",
        action={"tool": "shell_exec", "params": {"command": "curl imds"}},
    )
    orch.exploitation_plan = ExploitationPlan(
        plan_id="p1", phase="exploit", goal="g", tasks=[task]
    )

    execution = await orch._execute_task_with_policies(task, tool_defs=[])
    assert execution.success is True
    assert any(
        "cred-aws-" in n["id"]
        for n in orch.dkg.query_nodes("Credential")
    )

    await orch._review_and_update_plan(task, True, execution.result_text)
    diff_prompts = [
        str(p) for kind, p, *_ in llm.calls
        if kind == "generate" and "Topology Changes This Task" in str(p)
    ]
    assert diff_prompts
    assert "cred-aws-" in diff_prompts[0]
    assert "revision " in diff_prompts[0]

    # A review without a per-task baseline (e.g. plan-exhausted stall) must
    # not misreport the whole graph as newly added.
    stall_task = Task(
        id="t-stall", type="review", goal="plan exhausted",
        instruction="plan exhausted", action={"tool": "", "params": {}},
    )
    await orch._review_and_update_plan(stall_task, True, "no ready tasks")
    stall_diff_prompts = [
        str(p) for kind, p, *_ in llm.calls
        if kind == "generate" and "Topology Changes This Task" in str(p)
    ]
    assert len(stall_diff_prompts) == 1  # only the real per-task review


@pytest.mark.asyncio
async def test_runtime_state_provider_refreshes_before_replan():
    from darwin.core.contracts import Budget, Objective, ReplanRecommendation, TaskOutcome
    from darwin.core.evaluator import Evaluation
    from darwin.core.executor import ExecutionResult
    from darwin.core.runtime import Runtime
    from darwin.core.task import Task
    from darwin.core.task_graph import TaskGraph

    task = Task(id="t1", type="task", goal="x", instruction="x")

    class Planner:
        def __init__(self):
            self.states = []

        async def plan(self, state, objective, memory):
            self.states.append(state)
            return TaskGraph([task])

        async def replan(self, state, graph, evaluation, memory):
            self.states.append(state)
            return graph

    class Scheduler:
        def next_ready(self, graph, budget):
            return next(iter(graph.ready_tasks()), None)

    class Executor:
        async def execute(self, task):
            return ExecutionResult(task_id=task.id, tool="x", planned_tool="x", adherence=True, success=True, stdout="", stderr="", exit_code=0, elapsed_ms=0)

    class Evaluator:
        async def evaluate(self, task, result, state):
            return Evaluation(task_id=task.id, outcome=TaskOutcome.SUCCESS, replan=ReplanRecommendation.GLOBAL)

    first = SimpleNamespace(revision=1)
    second = SimpleNamespace(revision=2)
    current = [first]
    planner = Planner()
    runtime = Runtime(planner, Scheduler(), Executor(), Evaluator(), state_provider=lambda: current[0])
    current[0] = second
    await runtime.run(first, Objective(task_description="x", budgets=Budget(max_loops=1)), Budget(max_loops=1))
    assert planner.states[0] is second
    assert planner.states[-1] is second
    assert len(planner.states) >= 2
