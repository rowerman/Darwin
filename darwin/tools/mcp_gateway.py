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
        timeout: int = 60, retries: int = 1,
    ) -> None:
        """Register a shell command as a tool.

        Args:
            name: Tool name
            command_template: Shell command with {param} placeholders
            description: Tool description for LLM
            parameters: Parameter schema for LLM
            parser: Optional output parser function
            timeout: Per-attempt timeout in seconds (default 60)
            retries: Number of retries after timeout (default 1, timeout multiplier 1.5x)
        """
        import logging
        _log = logging.getLogger(__name__)

        # Collect defaults from parameter schema
        _defaults = {k: v["default"] for k, v in parameters.items() if isinstance(v, dict) and "default" in v}

        async def _execute(**kwargs) -> ToolResult:
            try:
                # Fill missing params from defaults
                for k, v in _defaults.items():
                    kwargs.setdefault(k, v)
                # Explicit parameter name aliases for common LLM naming patterns
                # that the substring auto-correction below cannot handle
                # (e.g. "url" → "target_url" fails the 50% length threshold: 3 < 5)
                _PARAM_ALIASES = {
                    "url": "target_url",    # LLMs commonly use 'url' instead of 'target_url'
                    "host": "target",       # LLMs use 'host'+'port' instead of 'target'
                }
                for _alias, _canonical in _PARAM_ALIASES.items():
                    if _canonical not in kwargs and _alias in kwargs:
                        _val = kwargs[_alias]
                        # Compose host:port → target when both are provided
                        if _alias == "host" and "port" in kwargs:
                            _val = f"{_val}:{kwargs['port']}"
                        kwargs[_canonical] = _val
                # Handle 'anonymous' flag: set empty credentials for anonymous auth
                if kwargs.pop("anonymous", None) is True:
                    kwargs.setdefault("user", "")
                    kwargs.setdefault("password", "")
                # Auto-correct parameter name variations
                # Handles both directions:
                #   LLM "username" → template "user"  (kwargs key contains template var)
                #   LLM "target"  → template "target_url" (template var contains kwargs key)
                import string as _string
                _template_vars = {
                    fv[1] for fv in _string.Formatter().parse(command_template)
                    if fv[1] is not None
                }
                for _tv in _template_vars:
                    if _tv not in kwargs:
                        # Direction 1: template var is substring of kwargs key
                        _candidates = [
                            k for k in kwargs if _tv in k and k != _tv
                        ]
                        if not _candidates:
                            # Direction 2: kwargs key is substring of template var
                            # Only match non-trivial substrings (≥3 chars, ≥50% of template var length)
                            _candidates = [
                                k for k in kwargs
                                if k in _tv and k != _tv
                                and len(k) >= 3 and len(k) >= len(_tv) * 0.5
                            ]
                        if len(_candidates) == 1:
                            kwargs[_tv] = kwargs[_candidates[0]]
                cmd = command_template.format(**kwargs)
            except (ValueError, KeyError) as e:
                _err_msg = f"Template format error: {e} | template={command_template[:200]} | kwargs={kwargs}"
                return ToolResult(
                    tool_name=name, success=False,
                    stdout=_err_msg,  # Write to stdout so orchestrator fix LLM sees it
                    stderr=_err_msg,
                    exit_code=1, elapsed_ms=0,
                )
            start = time.perf_counter()
            last_stderr = ""

            max_attempts = 1 + retries
            for attempt in range(max_attempts):
                current_timeout = timeout * (1.5 ** attempt)
                proc = None
                try:
                    # Prevent psql/mysql from blocking on interactive password prompts
                    no_prompt_env = {**__import__("os").environ, "PGPASSWORD": ""}
                    proc = await asyncio.create_subprocess_shell(
                        cmd,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                        env=no_prompt_env,
                    )
                    stdout, stderr = await asyncio.wait_for(
                        proc.communicate(), timeout=current_timeout
                    )
                    stdout_s = stdout.decode("utf-8", errors="replace")
                    stderr_s = stderr.decode("utf-8", errors="replace")
                    elapsed = (time.perf_counter() - start) * 1000

                    parsed = {}
                    if parser:
                        try:
                            parsed = parser(stdout_s)
                        except Exception as e:
                            _log.warning(
                                "MCPGateway: parser function failed for tool '%s': %s", name, e
                            )

                    result = ToolResult(
                        tool_name=name,
                        success=proc.returncode == 0,
                        stdout=stdout_s,
                        stderr=stderr_s,
                        exit_code=proc.returncode or 0,
                        elapsed_ms=elapsed,
                        parsed_output=parsed,
                    )
                    return result

                except asyncio.TimeoutError:
                    last_stderr = f"Command timed out after {current_timeout}s"
                    if attempt < max_attempts - 1:
                        _log.warning(
                            "Tool '%s' timed out after %ds (attempt %d/%d), retrying",
                            name, current_timeout, attempt + 1, max_attempts,
                        )
                    try:
                        if proc is not None:
                            proc.kill()
                    except Exception:
                        pass

            elapsed = (time.perf_counter() - start) * 1000
            result = ToolResult(
                tool_name=name,
                success=False,
                stdout="",
                stderr=last_stderr,
                exit_code=-1,
                elapsed_ms=elapsed,
            )
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
                    tool_name=name, success=True, stdout=str(result) if result is not None else "",
                    stderr="", exit_code=0, elapsed_ms=0,
                )
            self._execution_log.append(result)
            return result
        except Exception as e:
            import traceback
            _tb = traceback.format_exc()[-800:]
            return ToolResult(
                tool_name=name, success=False,
                stdout=f"Tool error: {e}\n{_tb}",
                stderr=str(e),
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
                        "required": [k for k, v in entry.parameters.items()
                                    if isinstance(v, dict) and "default" not in v],
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
