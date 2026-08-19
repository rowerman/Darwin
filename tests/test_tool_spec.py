"""Phase 1 tool-contract tests: ToolSpec, manifest, shell-argv executor."""

import sys

import pytest

from darwin.tools.attack_server import create_attack_gateway
from darwin.tools.manifest import build_manifest, load_manifest, verify_manifest, write_manifest
from darwin.tools.mcp_gateway import MCPGateway
from darwin.tools.recon_server import create_recon_gateway
from darwin.tools.spec import (
    EXECUTOR_SHELL,
    EXECUTOR_SHELL_ARGV,
    ToolSpec,
    auto_spec,
    check_all_specs,
    validate_spec,
)


def _all_specs():
    attack = create_attack_gateway()
    recon = create_recon_gateway()
    return {**attack.get_tool_specs(), **recon.get_tool_specs()}


def test_every_registered_tool_has_a_valid_spec():
    specs = _all_specs()
    # 130 attack/recon tools + 2 registry meta tools (tool_registry_list,
    # tool_registry_get) registered on the attack gateway.
    assert len(specs) == 132
    assert check_all_specs(specs) == []


def test_manifest_roundtrip_is_in_sync(tmp_path):
    specs = _all_specs()
    manifest = build_manifest(specs, source="test")
    path = tmp_path / "tools_manifest.json"
    write_manifest(manifest, path)
    recorded = load_manifest(path)
    assert verify_manifest(recorded, specs) == []
    assert recorded["tool_count"] == len(specs)
    assert recorded["schema_version"] == "1.0.0"


def test_manifest_detects_drift(tmp_path):
    specs = _all_specs()
    manifest = build_manifest(specs, source="test")
    # Simulate a contract change (a tool's parameter set changed).
    manifest["tools"][0]["parameters"]["bogus"] = {"type": "string"}
    assert verify_manifest(manifest, specs)


@pytest.mark.asyncio
async def test_shell_argv_tool_runs_without_shell():
    gw = MCPGateway()
    gw.register_shell_argv_tool(
        name="demo_argv",
        shell_args=[sys.executable, "-c", "{code}"],
        description="demo argv tool",
        parameters={"code": {"type": "string", "description": "python code"}},
    )
    result = await gw.call("demo_argv", {"code": "print('hello argv')"})
    assert result.success is True
    assert "hello argv" in result.stdout
    spec = gw.get_tool_specs()["demo_argv"]
    assert spec.executor == EXECUTOR_SHELL_ARGV
    assert spec.split_params == []


@pytest.mark.asyncio
async def test_shell_argv_tool_splits_free_form_param():
    gw = MCPGateway()
    gw.register_shell_argv_tool(
        name="demo_split",
        shell_args=["cmd", "/c", "{cmdline}"],
        split_params=["cmdline"],
        description="demo split tool",
        parameters={"cmdline": {"type": "string", "description": "cmd line"}},
    )
    result = await gw.call("demo_split", {"cmdline": "echo a b"})
    assert result.success is True
    assert "a b" in result.stdout
    spec = gw.get_tool_specs()["demo_split"]
    assert spec.split_params == ["cmdline"]


def test_tuple_command_template_coerced():
    gw = MCPGateway()
    gw.register_shell_tool(
        name="tuple_tool",
        command_template=("echo ", "{msg}"),
        description="tuple template tool",
        parameters={"msg": {"type": "string", "description": "message"}},
    )
    spec = gw.get_tool_specs()["tuple_tool"]
    assert isinstance(spec.command_template, str)
    assert spec.command_template == "echo {msg}"
    assert spec.executor == EXECUTOR_SHELL


@pytest.mark.asyncio
async def test_spec_aliases_are_applied_during_normalization():
    gw = MCPGateway()
    spec = ToolSpec(
        name="alias_tool",
        description="alias tool",
        parameters={"target": {"type": "string"}, "port": {"type": "integer"}},
        aliases={"host": ["target"]},
        executor=EXECUTOR_SHELL,
        command_template="echo {target}:{port}",
    )

    async def _fake(**kwargs):
        from darwin.tools.mcp_gateway import ToolResult
        return ToolResult(
            tool_name="alias_tool", success=True,
            stdout=str(kwargs), stderr="", exit_code=0, elapsed_ms=0,
        )

    gw.register("alias_tool", _fake, spec=spec, description="alias tool",
                parameters=spec.parameters)
    result = await gw.call("alias_tool", {"host": "h", "port": 1})
    assert result.success is True


def test_validate_spec_reports_unbound_placeholder():
    spec = ToolSpec(
        name="bad",
        description="bad",
        parameters={"a": {"type": "string"}},
        executor=EXECUTOR_SHELL,
        command_template="echo {b}",
    )
    issues = validate_spec(spec)
    assert any("placeholder '{b}'" in issue for issue in issues)
    assert any("required parameter 'a'" in issue for issue in issues)


def test_auto_spec_marks_domain_and_executor():
    spec = auto_spec(
        name="x", description="x", parameters={},
        domain="k8s", executor=EXECUTOR_SHELL, command_template="kubectl get pods",
    )
    assert spec.domains == ["k8s"]
    assert spec.auto is True
    assert spec.executor == EXECUTOR_SHELL
