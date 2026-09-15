"""Parameter normalization must be explicit, never silently lossy.

An undeclared argument (``json``) or a missing required one used to travel
to the tool and fail there with an opaque Python error. The gateway now
aliases what it can, reports what it drops, and refuses a call whose
required parameters are absent.
"""

from __future__ import annotations

import logging

import pytest

from darwin.orchestration.execution import ExecutionCoordinator
from darwin.orchestration.planning import PlanCoordinator
from darwin.tools.attack_server import create_attack_gateway
from darwin.tools.contracts import apply_explicit_contracts
from darwin.tools.mcp_gateway import MCPGateway, ToolResult
from darwin.tools.recon_server import create_recon_gateway


def _gateway_with_echo() -> MCPGateway:
    gateway = MCPGateway()

    async def _echo(url: str, data: str = "", headers: str = "") -> ToolResult:
        return ToolResult(tool_name="echo_tool", success=True, stdout="ok",
                          stderr="", exit_code=0, elapsed_ms=0.0)

    gateway.register(
        name="echo_tool", func=_echo, description="d",
        parameters={
            "url": {"type": "string", "description": "u"},
            "data": {"type": "string", "description": "d", "default": ""},
            "headers": {"type": "string", "description": "h", "default": ""},
        },
    )
    # Real registries get their alias table at the server boundary; mirror it
    # so the alias behaviour under test matches the production gateway.
    apply_explicit_contracts(gateway)
    return gateway


def test_gateway_aliases_json_body_to_data():
    gateway = _gateway_with_echo()
    normalized = gateway.normalize_params("echo_tool", {
        "url": "http://x", "json": {"a": 1},
    })
    assert normalized["data"] == {"a": 1}
    assert "json" not in normalized


def test_gateway_reports_dropped_parameters(caplog):
    gateway = _gateway_with_echo()
    with caplog.at_level(logging.WARNING):
        normalized = gateway.normalize_params("echo_tool", {
            "url": "http://x", "bogus_key": 1,
        })

    assert normalized == {"url": "http://x"}
    assert any("bogus_key" in record.getMessage() for record in caplog.records)


def test_gateway_does_not_report_applied_aliases(caplog):
    gateway = _gateway_with_echo()
    with caplog.at_level(logging.WARNING):
        gateway.normalize_params("echo_tool", {"url": "http://x", "json": {"a": 1}})
    assert not caplog.records


@pytest.mark.asyncio
async def test_missing_required_parameter_never_reaches_the_tool():
    calls: list[dict] = []
    gateway = MCPGateway()

    async def _needs_url(url: str) -> ToolResult:
        calls.append({"url": url})
        return ToolResult(tool_name="needs_url", success=True, stdout="",
                          stderr="", exit_code=0, elapsed_ms=0.0)

    gateway.register(
        name="needs_url", func=_needs_url, description="d",
        parameters={"url": {"type": "string", "description": "u"}},
    )

    result = await gateway.call("needs_url", {"headers": "A: 1"})

    assert calls == []
    assert result.success is False
    assert "missing required parameter" in result.stderr
    assert "url" in result.stderr


def _coordinator():
    gateway = _gateway_with_echo()
    orch = type("Orch", (), {
        "attack_gateway": gateway,
        "recon_gateway": MCPGateway(),
    })()
    coord = ExecutionCoordinator.__new__(ExecutionCoordinator)
    object.__setattr__(coord, "_orch", orch)
    return coord


def _plan_coordinator():
    gateway = _gateway_with_echo()
    orch = type("Orch", (), {
        "attack_gateway": gateway,
        "recon_gateway": MCPGateway(),
    })()
    coord = PlanCoordinator.__new__(PlanCoordinator)
    object.__setattr__(coord, "_orch", orch)
    return coord


def test_corrected_params_are_filtered_against_the_tool_contract():
    coord = _coordinator()
    normalized, dropped = coord._normalized_tool_args("echo_tool", {
        "data": "body", "json": {"a": 1}, "made_up": 2,
    })

    assert normalized.get("data") == "body"
    assert dropped == ["made_up"]


def test_render_tool_params_marks_required_and_defaults():
    rendered = _plan_coordinator()._render_tool_params("echo_tool")

    assert "url: string (REQUIRED)" in rendered
    assert "data: string (optional" in rendered


@pytest.mark.asyncio
async def test_container_value_in_string_slot_is_serialized_not_crashed():
    """`credentials: [...]` migrated onto curl_get.cookie must not raise."""
    gateway = create_recon_gateway()

    result = await gateway.call("curl_get", {
        "url": "http://127.0.0.1:1/",
        "credentials": ["admin:admin", "root:root"],
    })

    assert result.params_coerced == ["cookie"]
    # The call reached curl (which cannot connect) instead of dying in Python.
    assert "has no attribute" not in result.stderr


@pytest.mark.asyncio
async def test_body_container_is_not_rewritten_by_coercion(monkeypatch):
    """A dict body keeps its JSON form: the tool, not the gateway, encodes it."""
    gateway = create_recon_gateway()
    captured: dict = {}

    def _fake_urlopen(req, timeout=30, context=None):
        captured["body"] = req.data
        captured["content_type"] = req.headers.get("Content-type")

        class _Resp:
            status = 200
            headers: dict = {}

            def read(self):
                return b'{"ok":1}'

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

        return _Resp()

    monkeypatch.setattr("urllib.request.urlopen", _fake_urlopen)

    result = await gateway.call("http_post", {
        "url": "http://127.0.0.1:1/workflows",
        "json": {"workspace": "tenant-a", "dataset_ref": "../tenant-b/secret.txt"},
    })

    assert result.params_coerced == []
    assert captured["body"] == b'{"workspace": "tenant-a", "dataset_ref": "../tenant-b/secret.txt"}'
    assert captured["content_type"] == "application/json"
