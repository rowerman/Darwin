"""MCP-style tool gateway for standardized tool invocation.

Reference:
  - Cochise common.py — LLMFunctionMapping auto-conversion
  - CPA spoke/grpc/ — gRPC tool registry pattern
"""

from __future__ import annotations

import asyncio
import subprocess
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional


@dataclass
class ToolResult:
    """Standardized tool execution result."""
    tool_name: str
    success: bool
    stdout: str
    stderr: str
    exit_code: int
    elapsed_ms: float
    parsed_output: Dict[str, Any] = field(default_factory=dict)


class MCPGateway:
    """Tool gateway with registration and standardized execution.

    All tools are registered with input/output schemas,
    enabling LLM tool_choice integration.
    """

    def __init__(self):
        self._registry: Dict[str, _ToolEntry] = {}
        self._execution_log: List[ToolResult] = []

    def register(
        self,
        name: str,
        func: Callable,
        description: str,
        parameters: Dict[str, Any],
    ) -> None:
        """Register a tool with its schema."""
        self._registry[name] = _ToolEntry(
            name=name,
            func=func,
            description=description,
            parameters=parameters,
        )

    def register_shell_tool(
        self, name: str, command_template: str, description: str,
        parameters: Dict[str, Any], parser: Callable | None = None,
    ) -> None:
        """Register a shell command as a tool.

        Args:
            name: Tool name
            command_template: Shell command with {param} placeholders
            description: Tool description for LLM
            parameters: Parameter schema for LLM
            parser: Optional output parser function
        """
        async def _execute(**kwargs) -> ToolResult:
            cmd = command_template.format(**kwargs)
            start = time.perf_counter()
            try:
                proc = await asyncio.create_subprocess_shell(
                    cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(), timeout=60
                )
                stdout_s = stdout.decode("utf-8", errors="replace")
                stderr_s = stderr.decode("utf-8", errors="replace")
                elapsed = (time.perf_counter() - start) * 1000

                parsed = {}
                if parser:
                    try:
                        parsed = parser(stdout_s)
                    except Exception:
                        pass

                result = ToolResult(
                    tool_name=name,
                    success=proc.returncode == 0,
                    stdout=stdout_s,
                    stderr=stderr_s,
                    exit_code=proc.returncode or 0,
                    elapsed_ms=elapsed,
                    parsed_output=parsed,
                )
            except asyncio.TimeoutError:
                elapsed = (time.perf_counter() - start) * 1000
                result = ToolResult(
                    tool_name=name,
                    success=False,
                    stdout="",
                    stderr="Command timed out after 60s",
                    exit_code=-1,
                    elapsed_ms=elapsed,
                )

            self._execution_log.append(result)
            return result

        self._registry[name] = _ToolEntry(
            name=name, func=_execute, description=description, parameters=parameters,
        )

    async def call(self, name: str, params: Dict[str, Any]) -> ToolResult:
        """Execute a registered tool."""
        if name not in self._registry:
            return ToolResult(
                tool_name=name, success=False, stdout="", stderr=f"Tool '{name}' not found",
                exit_code=-1, elapsed_ms=0,
            )
        entry = self._registry[name]
        try:
            if asyncio.iscoroutinefunction(entry.func):
                result = await entry.func(**params)
            else:
                result = entry.func(**params)
            if not isinstance(result, ToolResult):
                result = ToolResult(
                    tool_name=name, success=True, stdout=str(result),
                    stderr="", exit_code=0, elapsed_ms=0,
                )
            self._execution_log.append(result)
            return result
        except Exception as e:
            return ToolResult(
                tool_name=name, success=False, stdout="", stderr=str(e),
                exit_code=-1, elapsed_ms=0,
            )

    def get_tool_definitions(self) -> List[Dict[str, Any]]:
        """Get all registered tools as OpenAI function calling format."""
        definitions = []
        for name, entry in self._registry.items():
            definitions.append({
                "type": "function",
                "function": {
                    "name": name,
                    "description": entry.description,
                    "parameters": {
                        "type": "object",
                        "properties": entry.parameters,
                        "required": list(entry.parameters.keys()),
                    },
                },
            })
        return definitions

    def get_tool_names(self) -> List[str]:
        """List all registered tool names."""
        return list(self._registry.keys())

    def get_execution_log(self) -> List[ToolResult]:
        """Get all tool execution results."""
        return self._execution_log


class _ToolEntry:
    """Internal registry entry for a tool."""
    def __init__(self, name: str, func: Callable, description: str, parameters: Dict[str, Any]):
        self.name = name
        self.func = func
        self.description = description
        self.parameters = parameters
