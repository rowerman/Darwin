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


# ── Semantic parameter alias table ────────────────────────────────────
# Maps LLM-preferred parameter names to tool-declared canonical names.
# Aliases are DIRECTIONAL: "alias": "canonical" means "if LLM provides
# 'alias' but the tool expects 'canonical', remap it."
# An alias is ONLY applied when the canonical name exists in the tool's
# declared parameter schema, preventing false matches (e.g. command→query
# on ssh_exec, which legitimately expects 'command').
_PARAM_ALIASES: Dict[str, list[str]] = {
    # URL / target concept — 4 LLM names for the same thing.
    # Each alias maps to a PRIORITY-ORDERED list — first canonical
    # that exists in the tool's declared parameters wins.
    "url":        ["target_url", "file_path"],
    "ssrf_url":   ["target_url"],
    "endpoint":   ["target_url"],

    # Host / target concept
    "host":       ["target"],
    "server":     ["host"],
    "hostname":   ["host"],
    "dc_ip":      ["target"],

    # Username concept
    "username":   ["user"],
    "login":      ["user"],

    # Password concept
    "pass":       ["password"],
    "passwd":     ["password"],
    "pwd":        ["password"],

    # Request body / data
    "body":       ["data"],
    "post_data":  ["data"],
    "json_body":  ["data"],
}

# Substring auto-correction thresholds
_SUBSTRING_MIN_LEN = 3         # minimum chars for a substring to match
_SUBSTRING_MIN_RATIO = 0.4     # minimum ratio of substring / declared-param length


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

                # Extract template variables — only pass what the
                # command template actually uses to format()
                import string as _string
                _template_vars = {
                    fv[1] for fv in _string.Formatter().parse(command_template)
                    if fv[1] is not None
                }
                kwargs = {k: v for k, v in kwargs.items() if k in _template_vars}
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

    def _normalize_params(
        self, name: str, params: Dict[str, Any], entry: "_ToolEntry",
    ) -> Dict[str, Any]:
        """Normalize LLM-provided parameters to match tool-declared names.

        Applies four phases:
          1. Explicit alias table (_PARAM_ALIASES)
          2. 'anonymous' flag → empty credentials
          3. Substring fuzzy matching for close-but-not-exact names
          4. Drop params not in the tool's declared schema

        Aliases are only applied when the canonical name exists in the tool's
        parameters schema — this prevents false matches like command→query on
        ssh_exec, which legitimately expects 'command'.
        """
        normalized = dict(params)
        tool_params = entry.parameters  # declared parameter schema dict

        # Phase 1: apply explicit aliases
        for alias, canonical_list in _PARAM_ALIASES.items():
            if alias not in normalized:
                continue
            # Try each canonical name in priority order — first one
            # that exists in the tool's declared parameters wins.
            for canonical in canonical_list:
                if (
                    canonical in tool_params
                    and canonical not in normalized
                ):
                    val = normalized[alias]
                    # Compose host:port → target when both are provided
                    if alias == "host" and "port" in normalized:
                        val = f"{val}:{normalized['port']}"
                    normalized[canonical] = val
                    break  # only apply the first matching canonical

        # Phase 2: handle 'anonymous' flag — set empty credentials
        if normalized.pop("anonymous", None) is True:
            normalized.setdefault("user", "")
            normalized.setdefault("password", "")

        # Phase 3: substring fuzzy matching
        # Handles both directions:
        #   Direction 1: declared param is substring of provided key
        #     e.g.  declared "url"  ←  provided "target_url"
        #   Direction 2: provided key is substring of declared param
        #     e.g.  provided "url"  →  declared "target_url"
        #     (only when key ≥ _SUBSTRING_MIN_LEN chars AND
        #      key ≥ _SUBSTRING_MIN_RATIO of declared param length)
        #
        # CRITICAL: skip candidates that are themselves declared params
        # of this tool.  Otherwise "key" (etcd key path) matches "tls_key"
        # (TLS key file path) and corrupts the etcd call.
        for declared_param in list(tool_params.keys()):
            if declared_param not in normalized:
                # Direction 1: declared param is substring of provided key
                candidates = [
                    k for k in normalized
                    if declared_param in k and k != declared_param
                    and k not in tool_params
                ]
                # Direction 2: provided key is substring of declared param
                if not candidates:
                    candidates = [
                        k for k in normalized
                        if k in declared_param and k != declared_param
                        and k not in tool_params
                        and len(k) >= _SUBSTRING_MIN_LEN
                        and len(k) >= len(declared_param) * _SUBSTRING_MIN_RATIO
                    ]
                if len(candidates) == 1:
                    normalized[declared_param] = normalized[candidates[0]]

        # Phase 4: drop params not in the tool's declared schema.
        # This prevents "unexpected keyword argument" errors in Python
        # function tools and Template format errors in shell tools.
        # Keep alias-source keys as well — they'll be dropped later if
        # the template doesn't need them (shell path) or ignored via
        # the strip below.
        normalized = {
            k: v for k, v in normalized.items()
            if k in tool_params
        }

        return normalized

    async def call(self, name: str, params: Dict[str, Any]) -> ToolResult:
        """Execute a registered tool."""
        if name not in self._registry:
            return ToolResult(
                tool_name=name, success=False, stdout="", stderr=f"Tool '{name}' not found",
                exit_code=-1, elapsed_ms=0,
            )
        entry = self._registry[name]

        # Normalize LLM-provided parameters before dispatch.
        # This single call site covers BOTH register() Python functions
        # AND register_shell_tool() shell commands.
        params = self._normalize_params(name, params, entry)

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
