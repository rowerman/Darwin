"""Shared context for orchestrator coordinators.

Every coordinator receives the owning :class:`darwin.orchestrator.Orchestrator`
instance and forwards unknown attribute reads, writes and method calls to it.
State therefore stays on the Orchestrator (single source of truth) while each
coordinator owns a domain slice of behavior. Tool calls go through the
injected tool port (``orch._tool_port``) so coordinators never touch gateways
directly.
"""
from __future__ import annotations

from darwin.tools.mcp_gateway import ToolResult
import asyncio


class CoordinatorContext:
    """Mixin-free shared-context base for phase coordinators.

    - ``self.<attr>`` reads/writes fall through to the owning Orchestrator.
    - ``self.<method>`` calls resolve locally first, then fall through to the
      Orchestrator (which routes cross-coordinator calls through thin
      delegates).
    - ``_call_tool()`` is the only sanctioned way to invoke external tools.
    """

    def __init__(self, orch):
        object.__setattr__(self, "_orch", orch)

    def __getattr__(self, name):
        return getattr(object.__getattribute__(self, "_orch"), name)

    def __setattr__(self, name, value):
        if name == "_orch":
            object.__setattr__(self, name, value)
        else:
            setattr(object.__getattribute__(self, "_orch"), name, value)

    async def _call_tool(self, name: str, params: dict) -> ToolResult:
        # A tool call must never outlive the active run/phase deadline.
        remaining = self._orch._remaining_budget()
        if remaining <= 0:
            return ToolResult(tool_name=name, success=False, stdout="",
                              stderr="time budget exceeded", exit_code=-1,
                              elapsed_ms=0)
        try:
            return await asyncio.wait_for(
                self._orch._tool_port.call(name, params), timeout=remaining
            )
        except asyncio.TimeoutError:
            return ToolResult(tool_name=name, success=False, stdout="",
                              stderr=f"tool timeout after {remaining:.1f}s",
                              exit_code=-1, elapsed_ms=remaining * 1000)
