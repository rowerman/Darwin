"""Tool registry introspection tests (registry meta tools).

Covers:
- the two registry tools are registered on the attack gateway and present
  in the committed manifest;
- tool_registry_list filtering (domain/capability/keyword);
- tool_registry_get returns the full ToolSpec contract with correct
  required/optional semantics (defaulted params are optional);
- the orchestrator's registry query loop executes registry tool calls and
  degrades to a plain generation when no registry tools are exposed.
"""

import pytest

from darwin.tools.attack_server import create_attack_gateway
from darwin.tools.mcp_gateway import MCPGateway, ToolResult
from darwin.tools.manifest import load_manifest


def _fake_gateway_with_tools() -> MCPGateway:
    gw = MCPGateway()

    async def _echo(**kwargs):
        return ToolResult("echo", True, "ok", "", 0, 1.0)

    gw.register(
        "shell_exec", _echo, "run a shell command locally",
        {"command": {"type": "string"}}, domain="ad",
    )
    gw.register(
        "curl_get", _echo, "fetch a URL",
        {"url": {"type": "string"},
         "cookie": {"type": "string", "description": "session cookie", "default": ""}},
    )
    # Mirror production: registry meta tools are registered on the gateway.
    gw.register(
        "tool_registry_list", gw.tool_registry_list,
        "list tools", {"domain": {"type": "string", "default": ""},
                       "capability": {"type": "string", "default": ""},
                       "keyword": {"type": "string", "default": ""}},
    )
    gw.register(
        "tool_registry_get", gw.tool_registry_get,
        "get one tool contract", {"name": {"type": "string"}},
    )
    return gw


def test_attack_gateway_registers_registry_tools():
    gw = create_attack_gateway()
    names = gw.get_tool_names()
    assert "tool_registry_list" in names
    assert "tool_registry_get" in names


def test_registry_tools_are_in_committed_manifest():
    manifest = load_manifest("tools_manifest.json")
    names = {t["name"] for t in manifest["tools"]}
    assert "tool_registry_list" in names
    assert "tool_registry_get" in names


@pytest.mark.asyncio
async def test_registry_list_filters():
    gw = _fake_gateway_with_tools()

    all_tools = await gw.call("tool_registry_list", {})
    assert all_tools.success is True
    assert all_tools.parsed_output["count"] == 4

    by_keyword = await gw.call("tool_registry_list", {"keyword": "curl"})
    assert [t["name"] for t in by_keyword.parsed_output["tools"]] == ["curl_get"]

    by_domain = await gw.call("tool_registry_list", {"domain": "ad"})
    assert [t["name"] for t in by_domain.parsed_output["tools"]] == ["shell_exec"]

    no_match = await gw.call("tool_registry_list", {"keyword": "zzz-no-such"})
    assert no_match.parsed_output["count"] == 0


@pytest.mark.asyncio
async def test_registry_get_returns_full_contract():
    gw = _fake_gateway_with_tools()

    result = await gw.call("tool_registry_get", {"name": "shell_exec"})
    assert result.success is True
    assert result.parsed_output["required"] == ["command"]
    assert "command" in result.parsed_output["parameters"]
    assert result.parsed_output["domains"] == ["ad"]

    optional = await gw.call("tool_registry_get", {"name": "curl_get"})
    assert optional.parsed_output["required"] == ["url"]
    assert "cookie" in optional.parsed_output["parameters"]

    missing = await gw.call("tool_registry_get", {"name": "no-such-tool"})
    assert missing.success is False
    assert "not found" in missing.stderr


class _RegistryGateway:
    """Fake gateway exposing only the registry meta tools."""

    def __init__(self):
        self.calls = []

    def get_tool_names(self):
        return {"tool_registry_get"}

    def get_tool_definitions(self):
        return [{
            "type": "function",
            "function": {
                "name": "tool_registry_get",
                "description": "get one tool contract",
                "parameters": {
                    "type": "object",
                    "properties": {"name": {"type": "string"}},
                    "required": ["name"],
                },
            },
        }]

    async def call(self, name, params):
        self.calls.append((name, params))
        return ToolResult(
            tool_name=name, success=True,
            stdout='{"name": "shell_exec", "required": ["command"]}',
            stderr="", exit_code=0, elapsed_ms=1.0,
        )


class _RoundFakeLLM:
    """Returns scripted (content, tool_calls) rounds; records calls."""

    def __init__(self, rounds):
        self.rounds = list(rounds)
        self.calls = []
        self.token_count = 100

    def generate(self, prompt, system_prompt=None, tools=None,
                 temperature=None, timeout=180.0, stage=None):
        self.calls.append(("generate", prompt, system_prompt, stage))
        if self.rounds:
            return self.rounds.pop(0)
        return "[]", None

    def add_tool_result(self, tool_call_id, result):
        self.calls.append(("add_tool_result", tool_call_id))

    def replace_system_prompt(self, prompt):
        self.calls.append(("replace_system_prompt", prompt))

    def add_context_message(self, content, role="user"):
        self.calls.append(("add_context_message", content))

    def compress(self, **kwargs):
        return 0


@pytest.mark.asyncio
async def test_registry_lookup_loop_executes_registry_calls(
    make_orchestrator,
):
    llm = _RoundFakeLLM([
        ("", [{"name": "tool_registry_get",
               "arguments": {"name": "shell_exec"},
               "id": "reg-1"}]),
        ('[{"id": "t1", "instruction": "x", "tool": "shell_exec", '
         '"params": {"command": "echo hi"}, "dependent_task_ids": []}]', None),
    ])
    gw = _RegistryGateway()
    orch = make_orchestrator(llm, gw, gw)

    content, tool_calls, registry_used = await orch._generate_with_registry_lookup(
        prompt="plan", system_prompt="sys", stage="plan"
    )

    assert registry_used is True
    assert content.startswith("[")
    assert tool_calls is None
    assert gw.calls == [("tool_registry_get", {"name": "shell_exec"})]
    assert any(c[0] == "add_tool_result" for c in llm.calls)


@pytest.mark.asyncio
async def test_registry_lookup_loop_degrades_without_registry_tools(
    fake_llm, fake_gateway, make_orchestrator,
):
    llm = fake_llm(content="[1,2]")
    gw = fake_gateway({})  # no tool definitions at all
    orch = make_orchestrator(llm, gw, gw)

    content, tool_calls, registry_used = await orch._generate_with_registry_lookup(
        prompt="p", system_prompt="s", stage="plan_review"
    )

    assert registry_used is False
    assert content == "[1,2]"
    assert not tool_calls
    generates = [c for c in llm.calls if c[0] == "generate"]
    assert len(generates) == 1
