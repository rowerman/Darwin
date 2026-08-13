"""Shared test fixtures (P18).

Factories and stand-ins reused across test files. New tests should use
these; existing test files keep their local fakes to preserve history.
"""

import time

import pytest

from darwin.orchestrator import Orchestrator
from darwin.tools.mcp_gateway import ToolResult


class FakeLLM:
    """Minimal LLMSession stand-in for orchestrator-loop tests."""

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

    def generate(self, prompt, system_prompt=None, tools=None, temperature=None, timeout=180.0):
        if self.fail_on_generate:
            raise AssertionError("generate() must not be called on the direct path")
        self.calls.append(("generate", prompt, system_prompt))
        return self.content, [dict(tc) for tc in self.tool_calls]

    def compress(self, **kwargs):
        return 0


class FakeGateway:
    """Tool gateway stand-in (names + schemas + call)."""

    def __init__(self, responses, schemas=None):
        self.responses = responses  # tool name -> ToolResult
        self.schemas = schemas or {}
        self.calls = []

    def get_tool_names(self):
        return set(self.responses) | set(self.schemas)

    def get_tool_definitions(self):
        all_props = dict(self.schemas)
        for name in self.responses:
            all_props.setdefault(name, {"url": {"type": "string"}})
        return [
            {
                "type": "function",
                "function": {
                    "name": name,
                    "description": "",
                    "parameters": {
                        "type": "object",
                        "properties": props,
                        "required": [
                            k for k, v in props.items() if "default" not in v
                        ],
                    },
                },
            }
            for name, props in all_props.items()
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
    """No-op CTEG stand-in so tests never touch cteg_state.json."""

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


@pytest.fixture
def fake_llm():
    """Factory: fake_llm(tool_calls=[...], content='[]') -> FakeLLM."""
    return FakeLLM


@pytest.fixture
def fake_gateway():
    """Factory: fake_gateway({tool: ToolResult}, schemas={...}) -> FakeGateway."""
    return FakeGateway


@pytest.fixture
def fake_mcp_pool():
    return FakeMCPPool()


@pytest.fixture
def fake_cteg():
    return FakeCTEG()


@pytest.fixture
def make_orchestrator(monkeypatch):
    """Factory: make_orchestrator(llm, recon_gw, attack_gw) -> Orchestrator."""

    def _make(llm, recon_gw, attack_gw):
        monkeypatch.setattr("darwin.orchestrator.create_recon_gateway", lambda: recon_gw)
        monkeypatch.setattr("darwin.orchestrator.create_attack_gateway", lambda: attack_gw)
        monkeypatch.setattr("darwin.orchestrator.MCPClientPool", lambda: FakeMCPPool())
        monkeypatch.setattr("darwin.orchestrator.CTEG", FakeCTEG)
        orch = Orchestrator(llm_session=llm, time_budget=1200)
        orch.start_time = time.time()
        orch._solo_cycle_context_injected = False
        return orch

    return _make
