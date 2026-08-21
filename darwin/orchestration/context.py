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
        return await self._orch._tool_port.call(name, params)
