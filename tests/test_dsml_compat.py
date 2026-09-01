"""DeepSeek DSML tool-call compatibility tests.

Covers the DSML ``invoke``/``parameter`` parser in ``darwin.utils.llm`` and the
registry-lookup loop in ``PlanCoordinator`` that must converge to a final JSON
after DSML-formatted tool calls.
"""

import json
from types import SimpleNamespace

import pytest

from darwin.orchestrator import Orchestrator
from darwin.tools.mcp_gateway import ToolResult
from darwin.utils.llm import LLMSession


class TestDSMLParser:
    def test_single_call(self):
        content = (
            '<invoke name="curl_get">'
            '<parameter name="url">http://target:8000/</parameter>'
            "</invoke>"
        )
        calls = LLMSession._parse_dsml_tool_calls(content)
        assert calls is not None
        assert len(calls) == 1
        assert calls[0]["name"] == "curl_get"
        assert calls[0]["arguments"] == {"url": "http://target:8000/"}
        assert calls[0]["id"].startswith("dsml-")

    def test_multiple_calls(self):
        content = (
            '<invoke name="tool_registry_list">'
            '<parameter name="keyword">curl</parameter>'
            "</invoke>"
            '<invoke name="tool_registry_get">'
            '<parameter name="name">curl_get</parameter>'
            "</invoke>"
        )
        calls = LLMSession._parse_dsml_tool_calls(content)
        assert calls is not None
        assert [c["name"] for c in calls] == [
            "tool_registry_list", "tool_registry_get",
        ]
        assert calls[0]["arguments"] == {"keyword": "curl"}
        assert calls[1]["arguments"] == {"name": "curl_get"}

    def test_production_wrapped_dsml(self):
        content = (
            '<｜｜DSML｜｜tool_calls>'
            '<｜｜DSML｜｜invoke name="tool_registry_list">'
            '<｜｜DSML｜｜parameter name="keyword" string="true">curl'
            '</｜｜DSML｜｜parameter>'
            '</｜｜DSML｜｜invoke>'
            '</｜｜DSML｜｜tool_calls>'
        )
        calls = LLMSession._parse_dsml_tool_calls(content)
        assert calls is not None
        assert calls[0]["name"] == "tool_registry_list"
        assert calls[0]["arguments"] == {"keyword": "curl"}

    def test_escaped_parameter_value(self):
        content = (
            '<invoke name="send_payload">'
            '<parameter name="payload">&lt;script&gt;alert(1)&lt;/script&gt;</parameter>'
            '<parameter name="method">POST</parameter>'
            "</invoke>"
        )
        calls = LLMSession._parse_dsml_tool_calls(content)
        assert calls is not None
        assert calls[0]["arguments"]["payload"] == "<script>alert(1)</script>"
        assert calls[0]["arguments"]["method"] == "POST"

    def test_json_parameter_value(self):
        content = (
            '<invoke name="http_method_probe">'
            '<parameter name="params">{"a": 1, "b": [1, 2]}</parameter>'
            "</invoke>"
        )
        calls = LLMSession._parse_dsml_tool_calls(content)
        assert calls is not None
        assert calls[0]["arguments"]["params"] == {"a": 1, "b": [1, 2]}

    def test_tool_name_attribute_alias(self):
        content = (
            '<invoke tool_name="response_parse">'
            '<parameter name="data">{"x": 1}</parameter>'
            "</invoke>"
        )
        calls = LLMSession._parse_dsml_tool_calls(content)
        assert calls is not None
        assert calls[0]["name"] == "response_parse"

    def test_invalid_dsml_returns_none(self):
        # Missing closing tag / incomplete structure must NOT be treated as calls.
        assert LLMSession._parse_dsml_tool_calls(
            '<invoke name="curl_get"> no close'
        ) is None
        assert LLMSession._parse_dsml_tool_calls("plain text") is None
        assert LLMSession._parse_dsml_tool_calls("") is None


def _fake_completion(content="ok", tool_calls=None):
    def _completion(**kwargs):
        message = SimpleNamespace(
            content=content,
            reasoning_content=None,
            reasoning=None,
            tool_calls=tool_calls,
        )
        return SimpleNamespace(choices=[SimpleNamespace(message=message)])

    return _completion


class TestDSMLGeneratePath:
    def test_generate_returns_dsml_calls(self, monkeypatch):
        dsml = (
            '<invoke name="tool_registry_get">'
            '<parameter name="name">curl_get</parameter>'
            "</invoke>"
        )
        monkeypatch.setattr(
            "darwin.utils.llm.litellm.completion",
            _fake_completion(content=dsml, tool_calls=None),
        )
        llm = LLMSession(model="deepseek/deepseek-v4-pro")
        content, tool_calls = llm.generate("Query the registry", stage="plan")
        assert tool_calls is not None
        assert tool_calls[0]["name"] == "tool_registry_get"
        assert tool_calls[0]["arguments"] == {"name": "curl_get"}
        # assistant message carries normalized tool_calls so add_tool_result works
        assert llm.conversation_history[-1]["tool_calls"][0]["id"] == tool_calls[0]["id"]

    def test_standard_openai_tool_calls_take_priority(self, monkeypatch):
        dsml_in_content = (
            '<invoke name="tool_registry_get">'
            '<parameter name="name">curl_get</parameter>'
            "</invoke>"
        )
        tc = SimpleNamespace(
            id="oa-1", type="function",
            function=SimpleNamespace(
                name="tool_registry_list",
                arguments=json.dumps({"domain": "web"}),
            ),
        )
        monkeypatch.setattr(
            "darwin.utils.llm.litellm.completion",
            _fake_completion(content=dsml_in_content, tool_calls=[tc]),
        )
        llm = LLMSession()
        _, tool_calls = llm.generate("p", stage="plan")
        assert tool_calls[0]["id"] == "oa-1"
        assert tool_calls[0]["name"] == "tool_registry_list"


class _RegistryDSMLLLM:
    """Fake LLM: first emits a DSML registry query, then a final JSON plan."""

    def __init__(self, dsml_markup, final_json):
        self.calls = []
        self.step = 0
        self.dsml_markup = dsml_markup
        self.final_json = final_json
        self.token_count = 100
        self._compressed_count = 0
        self.context_load = 0.0

    def replace_system_prompt(self, prompt):
        self.calls.append(("replace_system_prompt", prompt))

    def add_context_message(self, content, role="user"):
        self.calls.append(("add_context_message", content))

    def add_tool_result(self, tool_call_id, result):
        self.calls.append(("add_tool_result", tool_call_id, result))

    def generate(self, prompt, system_prompt=None, tools=None,
                 temperature=None, timeout=180.0, stage=None):
        self.calls.append(("generate", stage))
        if self.step == 0:
            self.step += 1
            return self.dsml_markup, [
                {"id": "dsml-1", "name": "tool_registry_get",
                 "arguments": {"name": "curl_get"}},
            ]
        self.step += 1
        return self.final_json, None

    def compress(self, **kwargs):
        return 0


def _make_orchestrator(llm, monkeypatch):
    from darwin.tools.mcp_client import MCPClientPool

    class _FakeMCP:
        def get_tool_names(self):
            return set()

        def get_tool_definitions(self):
            return []

    class _FakeCTEG:
        def __init__(self, storage_path="cteg_state.json"):
            self.storage_path = storage_path

        def add_credential(self, **kwargs):
            pass

        def commit_task(self, *args, **kwargs):
            pass

        def get_credentials(self, *args, **kwargs):
            return []

        def get_suggestions(self, *args, **kwargs):
            return {}

    recon_gw = _RegistryGateway()
    attack_gw = _RegistryGateway()
    monkeypatch.setattr("darwin.orchestrator.create_recon_gateway",
                        lambda: recon_gw)
    monkeypatch.setattr("darwin.orchestrator.create_attack_gateway",
                        lambda: attack_gw)
    monkeypatch.setattr("darwin.orchestrator.MCPClientPool", _FakeMCP)
    monkeypatch.setattr("darwin.orchestrator.CTEG", _FakeCTEG)
    orch = Orchestrator(llm_session=llm, time_budget=1200)
    return orch, recon_gw, attack_gw


class _RegistryGateway:
    """Minimal gateway exposing the two registry meta tools."""

    def __init__(self):
        self.calls = []

    def get_tool_names(self):
        return {"tool_registry_list", "tool_registry_get"}

    def get_tool_definitions(self):
        return [
            {
                "type": "function",
                "function": {
                    "name": name,
                    "description": "",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "name": {"type": "string"},
                            "domain": {"type": "string"},
                            "keyword": {"type": "string"},
                        },
                        "required": [],
                    },
                },
            }
            for name in ("tool_registry_list", "tool_registry_get")
        ]

    async def call(self, name, params):
        self.calls.append((name, params))
        return ToolResult(
            tool_name=name, success=True,
            stdout=json.dumps({"name": "curl_get", "params": {"url": "string"}}),
            stderr="", exit_code=0, elapsed_ms=1.0,
            parsed_output={"name": "curl_get"},
        )


@pytest.mark.asyncio
async def test_registry_lookup_dsml_query_converges_to_final_json(monkeypatch):
    """DSML registry query is executed, then a final JSON plan is requested."""
    dsml = (
        '<invoke name="tool_registry_get">'
        '<parameter name="name">curl_get</parameter>'
        "</invoke>"
    )
    final_plan = json.dumps([
        {"id": "task-1", "dependent_task_ids": [],
         "instruction": "Fetch the target page", "tool": "curl_get",
         "params": {"url": "http://target:8000/"}, "reason": "recon"}
    ])
    llm = _RegistryDSMLLLM(dsml, final_plan)
    orch, recon_gw, attack_gw = _make_orchestrator(llm, monkeypatch)

    content, tool_calls, registry_used = await orch.planning._generate_with_registry_lookup(
        prompt="Generate a plan", stage="plan",
    )

    assert registry_used is True
    assert tool_calls is None
    assert json.loads(content) == json.loads(final_plan)
    # the DSML tool call id reached add_tool_result
    assert any(
        item[0] == "add_tool_result" and item[1] == "dsml-1"
        for item in llm.calls
    )
    assert ("tool_registry_get", {"name": "curl_get"}) in attack_gw.calls
    # final JSON was validated: the loop did NOT issue a second registry call
    assert len(attack_gw.calls) == 1


@pytest.mark.asyncio
async def test_registry_lookup_rejects_non_registry_tool(monkeypatch):
    class _UnexpectedToolLLM(_RegistryDSMLLLM):
        def generate(self, prompt, system_prompt=None, tools=None,
                     temperature=None, timeout=180.0, stage=None):
            self.calls.append(("generate", stage))
            if self.step == 0:
                self.step += 1
                return "", [{"id": "bad-1", "name": "send_payload", "arguments": {}}]
            self.step += 1
            return "[]", None

    llm = _UnexpectedToolLLM("", "[]")
    orch, recon_gw, attack_gw = _make_orchestrator(llm, monkeypatch)
    content, _, _ = await orch.planning._generate_with_registry_lookup(
        prompt="Generate a plan", stage="plan",
    )
    assert content == "[]"
    assert attack_gw.calls == []
    assert any(item[0] == "add_tool_result" and item[1] == "bad-1" for item in llm.calls)
