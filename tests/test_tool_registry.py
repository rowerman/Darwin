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


class _ScriptedLLM:
    """Returns scripted plain contents; records whether tools were exposed."""

    def __init__(self, contents):
        self.contents = list(contents)
        self.calls = []
        self.token_count = 100

    def generate(self, prompt, system_prompt=None, tools=None,
                 temperature=None, timeout=180.0, stage=None):
        self.calls.append((stage, prompt, tools is not None))
        if self.contents:
            return self.contents.pop(0), None
        return "", None

    def add_tool_result(self, tool_call_id, result):
        self.calls.append(("add_tool_result", tool_call_id))

    def replace_system_prompt(self, prompt):
        self.calls.append(("replace_system_prompt", prompt))

    def add_context_message(self, content, role="user"):
        self.calls.append(("add_context_message", content))

    def compress(self, **kwargs):
        return 0


@pytest.mark.asyncio
async def test_generate_structured_never_exposes_registry_tools(
    make_orchestrator,
):
    from darwin.core.schemas import parse_analyze_output

    llm = _ScriptedLLM(['{"application_understanding": "x", "vulnerabilities": []}'])
    gw = _RegistryGateway()  # registry meta tools exist but must NOT be offered
    orch = make_orchestrator(llm, gw, gw)

    content, parsed, err = await orch.planning._generate_structured(
        stage="analyze", prompt="p", validator=parse_analyze_output,
        system_prompt="sys",
    )

    assert parsed is not None
    assert err == ""
    assert len(llm.calls) == 1
    assert llm.calls[0][2] is False  # tools were not exposed
    assert gw.calls == []


@pytest.mark.asyncio
async def test_generate_structured_repairs_schema_error(make_orchestrator):
    from darwin.core.schemas import parse_analyze_output

    bad = '{"vulnerabilities": [{"name": "x", "affected_endpoint": "/api"}]}'
    good = (
        '{"application_understanding": "y", "vulnerabilities": ['
        '{"vuln_type": "IDOR", "endpoint": "http://t/a", "confidence": 0.4}]}'
    )
    llm = _ScriptedLLM([bad, good])
    orch = make_orchestrator(llm, _RegistryGateway(), _RegistryGateway())

    content, parsed, err = await orch.planning._generate_structured(
        stage="analyze", prompt="p", validator=parse_analyze_output,
        system_prompt="sys", schema_example="{}",
    )

    assert parsed is not None
    assert err == ""
    assert len(llm.calls) == 2
    assert "SCHEMA REPAIR ATTEMPT" in llm.calls[1][1]
    assert "Validation errors" in llm.calls[1][1]


@pytest.mark.asyncio
async def test_generate_structured_exhausts_attempts_and_prints(
    make_orchestrator, capsys,
):
    from darwin.core.schemas import parse_plan_tasks

    llm = _ScriptedLLM(["not json", "also not json"])
    orch = make_orchestrator(llm, _RegistryGateway(), _RegistryGateway())

    content, parsed, err = await orch.planning._generate_structured(
        stage="plan", prompt="p", validator=parse_plan_tasks,
        max_attempts=2,
    )

    assert parsed is None
    assert err
    assert len(llm.calls) == 2
    assert "[SCHEMA] plan:" in capsys.readouterr().out
