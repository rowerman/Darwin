"""Tool call port — the only sanctioned way coordinators invoke tools.

Coordinators call ``ctx._call_tool(name, params)``; the Orchestrator injects a
:class:`GatewayToolCallPort` bound to the attack and recon gateways. Routing is
identical to ``ToolExecutor``: attack gateway first, then recon gateway, by
``get_tool_names()`` membership. Tool names never overlap between the two
gateways, so this is behavior-identical to the original direct gateway calls.
"""
from __future__ import annotations

from typing import Protocol

from darwin.tools.mcp_gateway import ToolResult


class ToolCallPort(Protocol):
    """Minimal port contract for invoking a registered tool by name."""

    async def call(self, name: str, params: dict) -> ToolResult:
        ...


class GatewayToolCallPort:
    """Routes tool calls to the attack/recon gateways (mirrors ToolExecutor)."""

    def __init__(self, attack_gateway, recon_gateway):
        self._attack_gateway = attack_gateway
        self._recon_gateway = recon_gateway

    async def call(self, name: str, params: dict) -> ToolResult:
        if name in self._attack_gateway.get_tool_names():
            return await self._attack_gateway.call(name, params)
        if name in self._recon_gateway.get_tool_names():
            return await self._recon_gateway.call(name, params)
        return ToolResult(
            tool_name=name,
            success=False,
            stdout="",
            stderr=f"Tool '{name}' not found",
            exit_code=-1,
            elapsed_ms=0,
        )
