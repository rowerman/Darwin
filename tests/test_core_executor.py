"""Unit tests for the P5 ToolExecutor (Task-based execution)."""

import pytest

from darwin.core.executor import ExecutionResult, ToolExecutor
from darwin.core.task import Task


class FakeResult:
    def __init__(
        self,
        success=True,
        stdout="out",
        stderr="",
        exit_code=0,
        elapsed_ms=5.0,
        parsed_output=None,
    ):
        self.success = success
        self.stdout = stdout
        self.stderr = stderr
        self.exit_code = exit_code
        self.elapsed_ms = elapsed_ms
        self.parsed_output = parsed_output or {}


class FakeGateway:
    def __init__(self, tools, result=None):
        self._tools = set(tools)
        self.result = result or FakeResult()
        self.calls = []

    def get_tool_names(self):
        return set(self._tools)

    async def call(self, name, params):
        self.calls.append((name, params))
        return self.result


class FakeMcpPool:
    def __init__(self, tools, raw):
        self._tools = set(tools)
        self.raw = raw

    def get_tool_names(self):
        return set(self._tools)

    async def call_tool(self, name, params):
        return self.raw


def task_with(tool, params=None, tid="t1"):
    return Task(
        id=tid,
        type="exploit",
        goal="g",
        action={"tool": tool, "target": "http://x", "params": params or {}},
    )


@pytest.mark.asyncio
async def test_attack_gateway_dispatch():
    gw = FakeGateway(["sqlmap_test"])
    ex = ToolExecutor(attack_gateway=gw)
    res = await ex.execute(task_with("sqlmap_test", {"url": "http://x"}))
    assert gw.calls == [("sqlmap_test", {"url": "http://x"})]
    assert isinstance(res, ExecutionResult)
    assert res.success is True
    assert res.tool == "sqlmap_test"
    assert res.planned_tool == "sqlmap_test"
    assert res.adherence is True
    assert res.stdout == "out"
    assert res.elapsed_ms == 5.0


@pytest.mark.asyncio
async def test_recon_gateway_dispatch():
    gw = FakeGateway(["curl_get"])
    ex = ToolExecutor(recon_gateway=gw)
    res = await ex.execute(task_with("curl_get"))
    assert gw.calls == [("curl_get", {})]
    assert res.success is True


@pytest.mark.asyncio
async def test_mcp_dispatch_success():
    pool = FakeMcpPool(
        ["nvd_search_cves"],
        {"isError": False, "content": [{"type": "text", "text": "cve found"}]},
    )
    ex = ToolExecutor(mcp_pool=pool)
    res = await ex.execute(task_with("nvd_search_cves"))
    assert res.success is True
    assert res.stdout == "cve found"


@pytest.mark.asyncio
async def test_mcp_dispatch_error():
    pool = FakeMcpPool(
        ["nvd_search_cves"],
        {"isError": True, "content": [{"type": "text", "text": "boom"}]},
    )
    ex = ToolExecutor(mcp_pool=pool)
    res = await ex.execute(task_with("nvd_search_cves"))
    assert res.success is False
    assert "boom" in res.stderr
    assert res.exit_code == 1


@pytest.mark.asyncio
async def test_unknown_tool():
    ex = ToolExecutor()
    res = await ex.execute(task_with("no_such_tool"))
    assert res.success is False
    assert "Unknown tool" in res.stderr
    assert res.exit_code == 1


@pytest.mark.asyncio
async def test_params_json_string_normalized():
    gw = FakeGateway(["curl_get"])
    ex = ToolExecutor(recon_gateway=gw)
    t = Task(
        id="t1",
        type="recon",
        goal="g",
        action={"tool": "curl_get", "params": '{"url": "http://x"}'},
    )
    await ex.execute(t)
    assert gw.calls == [("curl_get", {"url": "http://x"})]


@pytest.mark.asyncio
async def test_failure_result_carried_through():
    gw = FakeGateway(
        ["curl_get"],
        result=FakeResult(success=False, stdout="", stderr="refused", exit_code=7),
    )
    ex = ToolExecutor(recon_gateway=gw)
    res = await ex.execute(task_with("curl_get"))
    assert res.success is False
    assert res.stderr == "refused"
    assert res.exit_code == 7


@pytest.mark.asyncio
async def test_elapsed_ms_fallback_measured():
    gw = FakeGateway(["curl_get"], result=FakeResult(elapsed_ms=0.0))
    ex = ToolExecutor(recon_gateway=gw)
    res = await ex.execute(task_with("curl_get"))
    assert res.elapsed_ms >= 0
