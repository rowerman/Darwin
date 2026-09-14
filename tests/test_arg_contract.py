"""Shared argument contract: producers and the gateway speak one language."""

from __future__ import annotations

import pytest

from darwin.core.task import Task, realign_success_condition
from darwin.tools.arg_contract import is_placeholder, project_args
from darwin.tools.mcp_gateway import MCPGateway, ToolResult


def _declared(*params):
    return {name: {"type": "string"} for name in params}


def test_content_migrates_to_the_body_slot():
    projected, migrated, dropped, unmappable = project_args(
        _declared("data", "content_type"), {"content": "<html/>"},
    )
    assert projected == {"data": "<html/>"}
    assert migrated == {"content": "data"}
    assert dropped == [] and unmappable == []


def test_payload_and_body_format_migrate_to_declared_slots():
    projected, migrated, _dropped, _unmappable = project_args(
        _declared("data", "content_type"),
        {"payload": "1' OR 1=1", "body_format": "json"},
    )
    assert projected == {"data": "1' OR 1=1", "content_type": "json"}
    assert set(migrated) == {"payload", "body_format"}


def test_credentials_migrate_to_the_cookie_slot():
    projected, migrated, _dropped, _unmappable = project_args(
        _declared("cookie"), {"credentials": "session=abc"},
    )
    assert projected == {"cookie": "session=abc"}
    assert migrated == {"credentials": "cookie"}


def test_domain_param_name_is_unmappable_not_guessed():
    """`param` is a target property; a tool without such a slot cannot take it."""
    projected, migrated, dropped, unmappable = project_args(
        _declared("url", "data"), {"url": "http://t/workflows", "param": "workspace"},
    )
    assert projected == {"url": "http://t/workflows"}
    assert migrated == {} and dropped == []
    assert unmappable == ["param"]


def test_empty_and_template_values_are_dropped_placeholders():
    projected, _migrated, dropped, unmappable = project_args(
        _declared("url"), {"url": "http://t", "empty": "", "slot": "<tenant>"},
    )
    assert projected == {"url": "http://t"}
    assert dropped == ["empty", "slot"]
    assert unmappable == []


@pytest.mark.parametrize("value", ["default", "<html>body</html>", "a<b"])
def test_real_values_are_never_treated_as_placeholders(value):
    """`workspace=default` is a real name, and HTML payloads start with '<'."""
    assert is_placeholder(value) is False


@pytest.mark.parametrize("value", [None, "", "   ", "<tenant>", "{{id}}", [], {}])
def test_placeholder_values(value):
    assert is_placeholder(value) is True


@pytest.mark.asyncio
async def test_gateway_refusal_names_the_declared_slots_and_a_replacement():
    gateway = MCPGateway()

    async def _post(url: str, data: str = "") -> ToolResult:
        return ToolResult("http_post", True, "", "", 0, 0.0)

    async def _inject(url: str, param: str) -> ToolResult:
        return ToolResult("command_injection_test", True, "", "", 0, 0.0)

    gateway.register(
        name="http_post", func=_post, description="d",
        parameters={
            "url": {"type": "string"},
            "data": {"type": "string", "default": ""},
        },
    )
    gateway.register(
        name="command_injection_test", func=_inject, description="d",
        parameters=_declared("url", "param"),
    )

    result = await gateway.call("http_post", {"url": "http://t", "param": "workspace"})

    assert result.success is False
    assert "unknown parameter" in result.stderr
    assert "command_injection_test" in result.stderr


@pytest.mark.asyncio
async def test_gateway_reports_placeholder_drops_in_the_result():
    gateway = MCPGateway()

    async def _post(url: str, data: str = "") -> ToolResult:
        return ToolResult("http_post", True, url, "", 0, 0.0)

    gateway.register(
        name="http_post", func=_post, description="d",
        parameters={
            "url": {"type": "string"},
            "data": {"type": "string", "default": ""},
        },
    )

    result = await gateway.call("http_post", {"url": "http://t", "note": ""})

    assert result.success is True
    assert result.params_dropped == ["note"]


def test_realign_success_condition_repoints_a_pinned_tool():
    condition = {"type": "tool_success", "tool": "ssrf_probe"}

    assert realign_success_condition(condition, "http_post") is True
    assert condition["tool"] == "http_post"
    # Already aligned / different condition shapes stay untouched.
    assert realign_success_condition(condition, "http_post") is False
    assert realign_success_condition({"type": "http_status_in"}, "http_post") is False
    assert realign_success_condition(None, "http_post") is False


def test_task_condition_survives_a_tool_switch():
    task = Task(
        id="t1", type="exploit", goal="g", instruction="i",
        success_condition={"type": "tool_success", "tool": "curl_get"},
    )
    realign_success_condition(task.success_condition, "http_post")
    assert task.success_condition["tool"] == "http_post"
