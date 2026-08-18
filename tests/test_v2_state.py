"""Stage B: typed plan state, canonical DKG fields, working-memory wiring."""

import json

import pytest

from darwin.core.contracts import TaskStatus
from darwin.core.memory import MemoryManager
from darwin.core.task import Task, deps_from_task_ids
from darwin.data_model import ExploitationPlan, PipelineState
from darwin.data_model import VulnerabilityHypothesis
from darwin.dkg import DKG


# ── Task serialization round-trip ───────────────────────────────────


def test_task_to_dict_from_dict_roundtrip():
    task = Task(
        id="t-1",
        type="task",
        goal="g",
        instruction="Run sqlmap",
        hypothesis="SQLI on id",
        rationale="quote error",
        evidence=["error-based"],
        confidence=0.8,
        action={"tool": "sqlmap_test", "target": "http://x", "params": {"url": "http://x", "param": "id"}},
        dependencies=deps_from_task_ids(["t-0"]),
        priority=0.9,
        status=TaskStatus.FAILED,
        attempt_count=2,
        result_summary="not injectable",
        source="credential-hint",
        vuln_type="SQLi",
    )

    restored = Task.from_dict(task.to_dict())

    assert restored.id == "t-1"
    assert restored.status is TaskStatus.FAILED
    assert restored.attempt_count == 2
    assert restored.result_summary == "not injectable"
    assert restored.source == "credential-hint"
    assert restored.vuln_type == "SQLi"
    assert restored.action == task.action
    assert restored.dependencies == [{"type": "requires_task_success", "task_id": "t-0"}]
    assert restored.confidence == 0.8
    assert restored.priority == 0.9


def test_task_to_dict_keeps_structured_dependencies_and_status_value():
    task = Task(
        id="t-1",
        type="task",
        goal="g",
        instruction="i",
        dependencies=[{"type": "requires_evidence", "evidence": "quote-error"}],
        status=TaskStatus.NEEDS_REPLAN,
    )
    d = task.to_dict()
    assert d["status"] == "needs_replan"  # canonical enum value, not legacy "failed"
    assert d["dependencies"] == [{"type": "requires_evidence", "evidence": "quote-error"}]


# ── MemoryManager working-memory wiring ─────────────────────────────


def test_memory_manager_working_snapshot_returns_pipeline_state():
    dkg = DKG()
    dkg.add_node("Host", "h1", {"ip": "10.0.0.1"})
    dkg.add_node("Endpoint", "ep1", {"url": "http://10.0.0.1:8080/", "method": "GET"})
    dkg.add_node("Credential", "c1", {"user": "admin", "password": "x", "source_host": "10.0.0.1"})

    manager = MemoryManager(working=dkg)
    snapshot = manager.working_snapshot()

    assert isinstance(snapshot, PipelineState)
    assert len(snapshot.endpoints) == 1
    assert snapshot.endpoints[0].url == "http://10.0.0.1:8080/"
    assert len(snapshot.credentials) == 1
    assert snapshot.credentials[0].username == "admin"  # alias canonicalized


def test_memory_manager_working_snapshot_none_without_dkg():
    manager = MemoryManager()
    assert manager.working_snapshot() is None


def test_memory_manager_working_snapshot_never_raises_on_bad_dkg():
    class BadDKG:
        def query_nodes(self, *a, **k):
            raise RuntimeError("boom")

    manager = MemoryManager(working=BadDKG())
    assert manager.working_snapshot() is None


# ── DKG canonical field normalization ───────────────────────────────


def test_dkg_canonicalizes_vulnerability_param_alias():
    dkg = DKG()
    dkg.add_node("Vulnerability", "v1", {
        "vuln_type": "SQLi", "endpoint": "http://x", "param": "id",
    })
    node = dkg.get_node("v1")
    assert node["parameter"] == "id"
    assert "param" not in node


def test_dkg_canonicalizes_credential_user_alias():
    dkg = DKG()
    dkg.add_node("Credential", "c1", {"user": "admin", "password": "pw"})
    node = dkg.get_node("c1")
    assert node["username"] == "admin"
    assert "user" not in node


def test_dkg_endpoint_params_list_joined_to_string():
    dkg = DKG()
    dkg.add_node("Endpoint", "ep1", {"url": "http://x", "params": ["id", "q"]})
    node = dkg.get_node("ep1")
    assert node["params"] == "id, q"


def test_dkg_keeps_unknown_properties():
    dkg = DKG()
    dkg.add_node("Vulnerability", "v1", {"vuln_type": "XSS", "custom_flag": 1})
    node = dkg.get_node("v1")
    assert node["custom_flag"] == 1


def test_dkg_host_remains_free_form():
    dkg = DKG()
    dkg.add_node("Host", "h1", {"ip": "1.1.1.1", "k8s_labels": {"app": "x"}})
    node = dkg.get_node("h1")
    assert node["k8s_labels"] == {"app": "x"}


# ── Plan persistence round-trip ─────────────────────────────────────


@pytest.mark.asyncio
async def test_plan_persist_roundtrip(make_orchestrator, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    orch = make_orchestrator(
        _FakeLLM(), _FakeGateway({}), _FakeGateway({})
    )
    orch.target_url = "http://target:8080/"
    plan = ExploitationPlan(
        plan_id="plan-1",
        phase="exploit",
        goal="capture",
        tasks=[
            Task(
                id="t1",
                type="task",
                goal="run",
                instruction="Run curl",
                action={"tool": "curl_get", "target": "http://x", "params": {"url": "http://x"}},
                status=TaskStatus.SUCCESS,
                attempt_count=1,
                result_summary="ok",
            ),
            Task(
                id="t2",
                type="task",
                goal="run2",
                instruction="Run send_payload",
                action={"tool": "send_payload", "target": "http://x", "params": {"url": "http://x"}},
                dependencies=deps_from_task_ids(["t1"]),
                status=TaskStatus.READY,
            ),
        ],
    )
    orch.exploitation_plan = plan

    orch._persist_plan("test_phase")

    plan_dir = tmp_path / "checkpoints"
    matches = list(plan_dir.glob("plan_*_test_phase.json"))
    assert matches, f"no plan checkpoint in {plan_dir}"
    path = matches[0]
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["plan_id"] == "plan-1"
    assert len(data["tasks"]) == 2
    restored = Task.from_dict(data["tasks"][1])
    assert restored.status is TaskStatus.READY
    assert restored.dependencies == [{"type": "requires_task_success", "task_id": "t1"}]


# ── Orchestrator typed-plan helpers ─────────────────────────────────


@pytest.mark.asyncio
async def test_generate_plan_fallback_builds_typed_tasks(
    make_orchestrator, tmp_path, monkeypatch
):
    monkeypatch.chdir(tmp_path)
    orch = make_orchestrator(_FakeLLM(content="not json"), _FakeGateway({}), _FakeGateway({}))
    orch.target_url = "http://t:8080/"
    orch.vulnerabilities.append(
        VulnerabilityHypothesis(
            vuln_type="SQLi",
            endpoint="http://t/login",
            param="user",
            confidence=0.8,
            evidence="quote error",
        )
    )

    plan = await orch._generate_exploitation_plan("http://t:8080/")

    assert plan.tasks
    assert all(isinstance(t, Task) for t in plan.tasks)
    assert plan.tasks[0].status is TaskStatus.READY
    assert plan.tasks[0].action["tool"] == "sqlmap_test"
    assert plan.tasks[0].action["params"]["url"] == "http://t/login"


@pytest.mark.asyncio
async def test_sanitize_plan_tools_replaces_blacklisted_tool(
    make_orchestrator,
):
    orch = make_orchestrator(_FakeLLM(), _FakeGateway({}), _FakeGateway({}))
    orch._BLACKLISTED_TOOLS["curl_get"] = "http_post"
    task = Task(
        id="t1",
        type="task",
        goal="g",
        instruction="fetch",
        action={"tool": "curl_get", "target": "", "params": {}},
        status=TaskStatus.READY,
    )

    orch._sanitize_plan_tools([task])

    assert task.action["tool"] == "http_post"
    assert "authenticate" in task.instruction or task.instruction == "fetch"


@pytest.mark.asyncio
async def test_sanitize_plan_tools_abandons_unfixable_tool(
    make_orchestrator,
):
    orch = make_orchestrator(_FakeLLM(), _FakeGateway({}), _FakeGateway({}))
    orch._BLACKLISTED_TOOLS["broken_tool"] = ""
    task = Task(
        id="t1",
        type="task",
        goal="g",
        instruction="x",
        action={"tool": "broken_tool", "target": "", "params": {}},
        status=TaskStatus.READY,
    )

    orch._sanitize_plan_tools([task])

    assert task.status is TaskStatus.ABANDONED


@pytest.mark.asyncio
async def test_sanitize_plan_tools_appends_credential_hint(
    make_orchestrator,
):
    orch = make_orchestrator(_FakeLLM(), _FakeGateway({}), _FakeGateway({}))
    orch.dkg.add_node("Credential", "c1", {
        "username": "root", "password": "pw", "host": "h",
        "port": 22, "cred_type": "ssh",
    })
    probe = Task(
        id="p1",
        type="task",
        goal="g",
        instruction="probe",
        action={"tool": "curl_get", "target": "", "params": {}},
        status=TaskStatus.READY,
    )

    tasks = [probe]
    orch._sanitize_plan_tools(tasks)

    assert any(t.source == "credential-hint" for t in tasks)


def test_task_from_llm_dict_normalizes_params_deps_status():
    from darwin.orchestrator import Orchestrator

    task = Orchestrator._task_from_llm_dict({
        "id": "t1",
        "instruction": "x",
        "tool": "curl_get",
        "params": '{"url": "http://x"}',
        "dependent_task_ids": ["t0"],
        "status": "done",
    })
    assert task.status is TaskStatus.SUCCESS
    assert task.action["params"] == {"url": "http://x"}
    assert task.dependencies == [{"type": "requires_task_success", "task_id": "t0"}]


def test_task_from_llm_dict_unknown_status_is_created():
    from darwin.orchestrator import Orchestrator

    task = Orchestrator._task_from_llm_dict({
        "id": "t1", "instruction": "x", "status": "bogus",
    })
    assert task.status is TaskStatus.CREATED


# ── Minimal stand-ins ───────────────────────────────────────────────


class _FakeLLM:
    def __init__(self, tool_calls=None, content="[]"):
        self.tool_calls = tool_calls or []
        self.content = content
        self.token_count = 100
        self.context_load = 0.0
        self.calls = []

    def replace_system_prompt(self, prompt):
        self.calls.append(("replace_system_prompt", prompt))

    def add_context_message(self, content, role="user"):
        self.calls.append(("add_context_message", content))

    def add_tool_result(self, tool_call_id, result):
        self.calls.append(("add_tool_result", tool_call_id, result))

    def generate(self, prompt, system_prompt=None, tools=None, temperature=None, timeout=180.0, stage=None):
        self.calls.append(("generate", prompt, system_prompt))
        return self.content, [dict(tc) for tc in self.tool_calls]

    def compress(self, **kwargs):
        return 0


class _FakeGateway:
    def __init__(self, responses, schemas=None):
        self.responses = responses
        self.schemas = schemas or {}
        self.calls = []

    def get_tool_names(self):
        return list(set(self.responses) | set(self.schemas))

    def get_tool_definitions(self):
        return []

    async def call(self, name, params):
        self.calls.append((name, params))
        return self.responses.get(name)
