"""Smoke tests for the orchestrator main loop (P5c).

These drive the real ``_unified_llm_loop`` with a fake LLM and fake tool
gateways to verify the strict Task-consumption contract end to end:

    - the loop consumes plan tasks through ``Task.from_legacy_dict`` and
      ``executor.execute`` (no direct gateway calls in the execution path);
    - post-processing (flag verification) still works on the normalized
      ExecutionResult;
    - direct-execution tasks bypass the LLM entirely.
"""

import time

import pytest

from darwin.data_model import ExploitationPlan
from darwin.orchestrator import Orchestrator
from darwin.tools.mcp_gateway import ToolResult


FLAG = "flag{smoke-test-42}"


class FakeLLM:
    """Minimal LLMSession stand-in for the main loop."""

    def __init__(self, tool_calls=None, fail_on_generate=False, content="ok"):
        self.tool_calls = tool_calls or []
        self.fail_on_generate = fail_on_generate
        self.content = content
        self.token_count = 100
        self._compressed_count = 0
        self.calls = []

    @property
    def context_load(self):
        return 0.0

    def replace_system_prompt(self, prompt):
        self.calls.append(("replace_system_prompt", prompt))

    def add_context_message(self, content, role="user"):
        self.calls.append(("add_context_message", content))

    def add_tool_result(self, tool_call_id, result):
        self.calls.append(("add_tool_result", tool_call_id, result))

    def generate(self, prompt, system_prompt=None, tools=None, temperature=None, timeout=180.0, stage=None):
        if self.fail_on_generate:
            raise AssertionError("generate() must not be called on the direct path")
        self.calls.append(("generate", prompt))
        return self.content, [dict(tc) for tc in self.tool_calls]

    def compress(self, **kwargs):
        return 0


class FakeGateway:
    """Tool gateway stand-in (names + OpenAI-style definitions + call)."""

    def __init__(self, responses):
        self.responses = responses  # tool name -> ToolResult
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
                        "properties": {"url": {"type": "string"}, "command": {"type": "string"}},
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


class FakeMCPPool:
    def get_tool_names(self):
        return set()

    def get_tool_definitions(self):
        return []

    async def call_tool(self, name, params):
        return {"isError": True, "content": []}


class FakeCTEG:
    """No-op CTEG stand-in so smoke tests never touch cteg_state.json."""

    def __init__(self, storage_path="cteg_state.json"):
        self.storage_path = storage_path

    def add_credential(self, **kwargs):
        pass

    def commit_task(self, *args, **kwargs):
        pass

    def get_credentials(self, *args, **kwargs):
        return []

    def get_suggestions(self, *args, **kwargs):
        return []


def _plan_with(task):
    return ExploitationPlan(
        plan_id="smoke-plan",
        phase="exploit",
        goal="smoke",
        tasks=[task],
    )


def _task(tool, params):
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


def _make_orchestrator(llm, recon_gw, attack_gw, monkeypatch):
    monkeypatch.setattr("darwin.orchestrator.create_recon_gateway", lambda: recon_gw)
    monkeypatch.setattr("darwin.orchestrator.create_attack_gateway", lambda: attack_gw)
    monkeypatch.setattr("darwin.orchestrator.MCPClientPool", lambda: FakeMCPPool())
    monkeypatch.setattr("darwin.orchestrator.CTEG", FakeCTEG)

    orch = Orchestrator(llm_session=llm, time_budget=1200)
    orch.start_time = time.time()  # loop checks _time_exceeded() immediately
    # Normally set by run() before the loop; needed for direct entry here.
    orch._solo_cycle_context_injected = False
    return orch


def _spy_executor(orch):
    """Wrap executor.execute to prove the main loop consumes Tasks."""
    executed = []
    real_execute = orch.executor.execute

    async def spy(task):
        executed.append(task)
        return await real_execute(task)

    orch.executor.execute = spy
    return executed


@pytest.mark.asyncio
async def test_llm_driven_task_executes_via_executor_and_finds_flag(monkeypatch):
    recon_gw = FakeGateway(
        {
            "curl_get": ToolResult(
                tool_name="curl_get",
                success=True,
                stdout=f"page content\n{FLAG}\n",
                stderr="",
                exit_code=0,
                elapsed_ms=1.0,
            )
        }
    )
    attack_gw = FakeGateway({})
    llm = FakeLLM(
        tool_calls=[
            {
                "name": "curl_get",
                "arguments": {"url": "http://target:8000/"},
                "id": "tc-1",
            }
        ]
    )

    orch = _make_orchestrator(llm, recon_gw, attack_gw, monkeypatch)
    orch.exploitation_plan = _plan_with(
        _task("curl_get", {"url": "http://target:8000/"})
    )
    executed = _spy_executor(orch)

    result = await orch._unified_llm_loop("http://target:8000/")

    assert result is not None
    assert result.success is True
    assert result.flag == FLAG
    # The loop executed a Task through the Executor, not a direct gateway call.
    assert len(executed) == 1
    assert executed[0].action["tool"] == "curl_get"
    assert executed[0].action["params"] == {"url": "http://target:8000/"}
    assert recon_gw.calls == [("curl_get", {"url": "http://target:8000/"})]
    # P10/P11: the loop persisted plan rationale + execution history.
    assert orch.memory.plan.get("t-curl_get") is not None
    assert len(orch.memory.execution.for_task("t-curl_get")) == 1
    assert orch.memory.execution.for_task("t-curl_get")[0].record.tool == "curl_get"
    # P19: metrics aggregate from the run's traces.
    report = orch.metrics_report()
    assert report.total_executions == 1
    assert report.adherence_rate == 1.0


@pytest.mark.asyncio
async def test_direct_task_skips_llm_and_executes_via_executor(monkeypatch):
    recon_gw = FakeGateway({})
    attack_gw = FakeGateway(
        {
            "shell_exec": ToolResult(
                tool_name="shell_exec",
                success=True,
                stdout=FLAG,
                stderr="",
                exit_code=0,
                elapsed_ms=1.0,
            )
        }
    )
    # shell_exec is in the direct-execution set: the LLM must not be called.
    llm = FakeLLM(fail_on_generate=True)

    orch = _make_orchestrator(llm, recon_gw, attack_gw, monkeypatch)
    orch.exploitation_plan = _plan_with(
        _task("shell_exec", {"command": f"echo {FLAG}"})
    )
    executed = _spy_executor(orch)

    result = await orch._unified_llm_loop("http://target:8000/")

    assert result is not None
    assert result.success is True
    assert result.flag == FLAG
    assert all(c[0] != "generate" for c in llm.calls)  # direct path never called generate()
    assert len(executed) == 1
    assert executed[0].action["tool"] == "shell_exec"
    assert attack_gw.calls == [("shell_exec", {"command": f"echo {FLAG}"})]
    assert len(orch.memory.execution.for_task("t-shell_exec")) == 1


@pytest.mark.asyncio
async def test_review_plan_injects_preserved_memory(monkeypatch):
    recon_gw = FakeGateway({})
    attack_gw = FakeGateway({})
    llm = FakeLLM(content="[]")

    orch = _make_orchestrator(llm, recon_gw, attack_gw, monkeypatch)
    orch.exploitation_plan = _plan_with(_task("curl_get", {"url": "http://target:8000/"}))
    orch.memory.record_task(
        {
            "id": "t-curl_get",
            "instruction": "Fetch the target page",
            "rationale": "ssh creds found in prior run",
            "tool": "curl_get",
            "params": {"url": "http://target:8000/"},
            "status": "pending",
            "dependent_task_ids": [],
        }
    )
    orch.memory.record_execution(
        ToolResult(
            tool_name="curl_get",
            success=False,
            stdout="",
            stderr="connection refused",
            exit_code=7,
            elapsed_ms=800.0,
        )
    )

    await orch._review_and_update_plan(
        {"id": "t-curl_get", "instruction": "Fetch the target page", "tool": "curl_get"},
        False,
        "connection refused",
    )

    prompts = [c[1] for c in llm.calls if c[0] == "generate"]
    assert prompts
    assert "Preserved Memory" in prompts[0]
    assert "ssh creds found in prior run" in prompts[0]
