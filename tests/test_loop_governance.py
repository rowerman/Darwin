"""Loop governance: no repeated identical verdicts, no silent zero-work sweeps."""

from __future__ import annotations

import pytest

from darwin.core.contracts import TaskStatus
from darwin.core.task import Task
from darwin.orchestration.execution import ExecutionCoordinator
from darwin.tools.mcp_gateway import ToolResult


class _RecordingExecutor:
    """Executor double: counts calls and replays one canned HTTP verdict."""

    def __init__(self, stdout: str):
        self.calls: list[str] = []
        self._stdout = stdout

    async def execute(self, task: Task):
        tool = str((task.action or {}).get("tool", ""))
        self.calls.append(tool)
        return ToolResult(
            tool_name=tool, success=False, stdout=self._stdout,
            stderr="", exit_code=1, elapsed_ms=1.0,
        )


def _coordinator(executor) -> ExecutionCoordinator:
    coord = ExecutionCoordinator.__new__(ExecutionCoordinator)
    object.__setattr__(coord, "_orch", type("Orch", (), {"executor": executor})())
    return coord


def _task(tool: str, params: dict) -> Task:
    return Task(
        id="t1", type="task", goal="g", instruction="i",
        action={"tool": tool, "params": params}, status=TaskStatus.RUNNING,
    )


def test_terminal_http_status_only_accepts_route_level_failures():
    def _result(stdout=""):
        return ToolResult("x", False, stdout, "", 1, 0.0)

    assert ExecutionCoordinator._terminal_http_status(
        _result("HTTP/1.1 404 NOT FOUND")
    ) == 404
    assert ExecutionCoordinator._terminal_http_status(
        _result("HTTP 405 Method Not Allowed")
    ) == 405
    # Transient failures may answer differently after another step.
    assert ExecutionCoordinator._terminal_http_status(
        _result("connection refused")
    ) == 0
    assert ExecutionCoordinator._terminal_http_status(_result("HTTP 500")) == 0


@pytest.mark.asyncio
async def test_identical_404_call_is_not_issued_twice():
    executor = _RecordingExecutor("HTTP/1.1 404 NOT FOUND")
    coord = _coordinator(executor)
    task = _task("curl_get", {"url": "http://t/workflows", "method": "POST"})

    first = await coord._execute_tool_call(
        task, "curl_get", {"url": "http://t/workflows", "method": "POST"}, "c1", "i",
    )
    second = await coord._execute_tool_call(
        task, "curl_get", {"url": "http://t/workflows", "method": "POST"}, "c1", "i",
    )

    assert executor.calls == ["curl_get"], "the second identical call is cached"
    assert first.exit_code == 1
    assert second.exit_code == 404
    assert "dedup" in second.stderr
    assert coord._redundant_calls == 1


@pytest.mark.asyncio
async def test_different_arguments_are_not_cached():
    executor = _RecordingExecutor("HTTP/1.1 404 NOT FOUND")
    coord = _coordinator(executor)
    task = _task("curl_get", {"url": "http://t/a"})

    await coord._execute_tool_call(task, "curl_get", {"url": "http://t/a"}, "c1", "i")
    await coord._execute_tool_call(task, "curl_get", {"url": "http://t/b"}, "c2", "i")

    assert executor.calls == ["curl_get", "curl_get"]
