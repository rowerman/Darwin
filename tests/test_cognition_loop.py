"""Orchestrator-level tests for the cognition optimization (O1/O2).

Verifies:
    - the plan-review prompt includes the unified snapshot AND the
      per-task discovery diff (O1.2/O1.3);
    - the task-execution prompt includes the snapshot (O1.3);
    - task outcomes update vulnerability confidence + DKG status (O2.1);
    - PlanMemory status stays in sync without losing rationale (O2.2);
    - truncation context reuses the snapshot (O3.4).
"""

from darwin.core.belief import SNAPSHOT_MARKER, node_ids_by_type
from darwin.data_model import ExploitationPlan, VulnerabilityHypothesis
from darwin.tools.mcp_gateway import ToolResult

import pytest


def _plan_with(task):
    return ExploitationPlan(
        plan_id="cog-plan",
        phase="exploit",
        goal="cognition",
        tasks=[task],
    )


def _task(tool, params, **extra):
    base = {
        "id": f"t-{tool}",
        "instruction": f"Run {tool}",
        "tool": tool,
        "params": params,
        "status": "pending",
        "dependent_task_ids": [],
        "attempts": 0,
        "result_summary": "",
    }
    base.update(extra)
    return base


class TestReviewPrompt:
    async def test_review_prompt_includes_snapshot_and_diff(
        self, make_orchestrator
    ):
        orch = make_orchestrator(
            _FakeLLM(), _FakeGateway({}), _FakeGateway({})
        )
        task = _task("curl_get", {"url": "http://t/"})
        orch.exploitation_plan = _plan_with(task)
        orch.vulnerabilities.append(
            VulnerabilityHypothesis(
                vuln_type="SQLI",
                endpoint="http://t/login",
                param="user",
                confidence=0.6,
                evidence="quote error",
            )
        )
        orch.dkg.add_node("Endpoint", "ep-before", {"url": "http://t/old"})
        orch._cognition_before = node_ids_by_type(orch.dkg)
        orch.dkg.add_node("Endpoint", "ep-new", {"url": "http://t/new"})
        orch.dkg.add_node("Vulnerability", "vuln-new", {
            "vuln_type": "SQLI", "endpoint": "http://t/login", "parameter": "user",
        })

        await orch._review_and_update_plan(task, True, "found login form")

        prompts = [c[1] for c in orch.llm.calls if c[0] == "generate"]
        assert prompts
        prompt = prompts[0]
        assert "Current Cognition" in prompt
        assert SNAPSHOT_MARKER in prompt
        assert "[SQLI] http://t/login param=user conf=60%" in prompt
        assert "New This Task" in prompt
        assert "http://t/new" in prompt

    async def test_review_fallback_without_baseline(self, make_orchestrator):
        orch = make_orchestrator(_FakeLLM(), _FakeGateway({}), _FakeGateway({}))
        task = _task("curl_get", {"url": "http://t/"})
        orch.exploitation_plan = _plan_with(task)
        orch.dkg.add_node("Endpoint", "ep-1", {"url": "http://t/latest"})

        await orch._review_and_update_plan(task, True, "ok")

        prompts = [c[1] for c in orch.llm.calls if c[0] == "generate"]
        assert "Latest Discoveries" in prompts[0]


class TestTaskExecutionPrompt:
    async def test_task_prompt_includes_snapshot(self, make_orchestrator):
        recon_gw = _FakeGateway({})
        attack_gw = _FakeGateway({})
        llm = _FakeLLM(
            tool_calls=[
                {
                    "name": "curl_get",
                    "arguments": {"url": "http://t/"},
                    "id": "tc-1",
                }
            ]
        )
        orch = make_orchestrator(llm, recon_gw, attack_gw)
        orch._exploit_chain = []
        orch.vulnerabilities.append(
            VulnerabilityHypothesis(
                vuln_type="SQLI",
                endpoint="http://t/login",
                param="user",
                confidence=0.6,
                evidence="quote error",
            )
        )

        await orch._execute_task_with_policies(
            _task("curl_get", {"url": "http://t/"}), []
        )

        prompts = [c[1] for c in llm.calls if c[0] == "generate"]
        assert prompts
        assert "Current Cognition" in prompts[0]
        assert "[SQLI] http://t/login" in prompts[0]


class TestConfidenceFeedback:
    async def _orch_with_vuln(self, make_orchestrator):
        orch = make_orchestrator(_FakeLLM(), _FakeGateway({}), _FakeGateway({}))
        orch.vulnerabilities.append(
            VulnerabilityHypothesis(
                vuln_type="SQLI",
                endpoint="http://t/login",
                param="user",
                confidence=0.7,
                evidence="quote error",
            )
        )
        orch.dkg.add_node("Vulnerability", "vuln-1", {
            "vuln_type": "SQLI", "endpoint": "http://t/login",
            "parameter": "user", "confidence": 0.7,
        })
        return orch

    async def test_hypothesis_rejected_lowers_confidence(self, make_orchestrator):
        orch = await self._orch_with_vuln(make_orchestrator)
        orch._apply_vulnerability_feedback(
            {"endpoint": "http://t/login", "params": {"url": "http://t/login"}},
            success=False,
            failure_type="hypothesis_rejected",
            delta=-0.5,
        )
        assert orch.vulnerabilities[0].confidence == pytest.approx(0.2)
        assert orch.vulnerabilities[0].status == "rejected"
        node = orch.dkg.get_node("vuln-1")
        assert node["status"] == "rejected"
        assert node["confidence"] == pytest.approx(0.2)

    async def test_success_raises_confidence(self, make_orchestrator):
        orch = await self._orch_with_vuln(make_orchestrator)
        orch._apply_vulnerability_feedback(
            {"endpoint": "http://t/login", "params": {"url": "http://t/login"}},
            success=True,
        )
        assert orch.vulnerabilities[0].confidence == pytest.approx(0.75)
        assert orch.vulnerabilities[0].status == "tested"

    async def test_tool_error_keeps_confidence(self, make_orchestrator):
        orch = await self._orch_with_vuln(make_orchestrator)
        orch._apply_vulnerability_feedback(
            {"endpoint": "http://t/login", "params": {"url": "http://t/login"}},
            success=False,
            failure_type="tool_error",
            delta=0.0,
        )
        assert orch.vulnerabilities[0].confidence == pytest.approx(0.7)
        assert orch.vulnerabilities[0].status == ""

    async def test_no_matching_endpoint_is_noop(self, make_orchestrator):
        orch = await self._orch_with_vuln(make_orchestrator)
        orch._apply_vulnerability_feedback(
            {"endpoint": "http://other/", "params": {}},
            success=True,
        )
        assert orch.vulnerabilities[0].confidence == pytest.approx(0.7)


class TestPlanMemorySync:
    async def test_review_updates_status_and_keeps_rationale(
        self, make_orchestrator
    ):
        orch = make_orchestrator(_FakeLLM(), _FakeGateway({}), _FakeGateway({}))
        full_task = _task(
            "curl_get", {"url": "http://t/"},
            rationale="ssh creds found in prior run",
            hypothesis="SQLI on user",
            evidence=["quote error"],
        )
        orch.exploitation_plan = _plan_with(full_task)
        orch.memory.record_task(full_task)

        slim_task = _task("curl_get", {"url": "http://t/"})
        await orch._review_and_update_plan(slim_task, True, "ok")

        entry = orch.memory.plan.get("t-curl_get")
        assert entry.status == "success"
        assert entry.rationale == "ssh creds found in prior run"
        assert entry.hypothesis == "SQLI on user"


class TestTruncationContext:
    async def test_reuses_belief_snapshot(self, make_orchestrator):
        orch = make_orchestrator(_FakeLLM(), _FakeGateway({}), _FakeGateway({}))
        orch.dkg.add_node("Endpoint", "ep-1", {"url": "http://t/"})
        orch.vulnerabilities.append(
            VulnerabilityHypothesis(
                vuln_type="SQLI",
                endpoint="http://t/login",
                param="user",
                confidence=0.6,
                evidence="quote error",
            )
        )
        ctx = orch._build_truncation_context()
        assert SNAPSHOT_MARKER in ctx
        assert "[SQLI] http://t/login" in ctx


# ── Minimal stand-ins (local copies to avoid conftest coupling) ────


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
    def __init__(self, responses):
        self.responses = responses
        self.calls = []

    def get_tool_names(self):
        return set(self.responses)

    def get_tool_definitions(self):
        return [
            {
                "type": "function",
                "function": {
                    "name": name,
                    "description": "",
                    "parameters": {
                        "type": "object",
                        "properties": {"url": {"type": "string"}},
                        "required": [],
                    },
                },
            }
            for name in self.responses
        ]

    async def call(self, name, params):
        self.calls.append((name, params))
        return self.responses.get(
            name,
            ToolResult(tool_name=name, success=True, stdout="ok", stderr="", exit_code=0, elapsed_ms=1.0),
        )
