"""MCP-style tool gateway for standardized tool invocation.

Reference:
  - Cochise common.py — LLMFunctionMapping auto-conversion
  - CPA spoke/grpc/ — gRPC tool registry pattern

Phase 1 (tool contract): every registration carries (or auto-derives) a
ToolSpec. The gateway exposes ``get_tool_specs()`` for the manifest and
coverage tooling, and provides a shell-argv executor that runs external
commands without a shell (``register_shell_argv_tool``).
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import subprocess
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from darwin.tools.spec import (
    EXECUTOR_MCP,
    EXECUTOR_PYTHON,
    EXECUTOR_SHELL,
    EXECUTOR_SHELL_ARGV,
    ToolSpec,
    auto_spec,
    shlex_split_value,
)


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


async def _kill_and_reap(proc: asyncio.subprocess.Process) -> None:
    """Terminate a timed-out child and drain its pipes before returning."""
    try:
        proc.kill()
    except (ProcessLookupError, OSError):
        pass
    try:
        await asyncio.wait_for(proc.communicate(), timeout=2.0)
    except (asyncio.TimeoutError, ProcessLookupError, OSError):
        try:
            await asyncio.wait_for(proc.wait(), timeout=0.5)
        except (asyncio.TimeoutError, ProcessLookupError, OSError):
            pass


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
        self._enabled_domains: set[str] | None = None  # None = all domains enabled
        self._log = logging.getLogger(__name__)

    def set_enabled_domains(self, domains: set[str] | None) -> None:
        """Set which tool domains are enabled. None = all domains enabled.

        When set, tools with a domain not in the set are silently skipped
        during registration. Tools without a domain (domain=None) are
        always registered regardless of the filter.
        """
        self._enabled_domains = domains

    def register(
        self,
        name: str,
        func: Callable,
        description: str,
        parameters: Dict[str, Any],
        domain: str | None = None,
        spec: ToolSpec | None = None,
    ) -> None:
        """Register a tool with its schema.

        Args:
            domain: Optional domain tag for filtering (e.g. 'web', 'k8s', 'cloud', 'ad').
                    Tools without a domain are always registered.
            spec: Optional explicit ToolSpec. When omitted, an auto spec is
                    derived from the registration fields (Phase 1 contract).
        """
        # Domain filter: skip if domain is set and not in enabled_domains
        if domain is not None and self._enabled_domains is not None:
            if domain not in self._enabled_domains:
                return  # silently skip

        tool_spec = spec or auto_spec(
            name=name,
            description=description,
            parameters=parameters,
            domain=domain,
            executor=EXECUTOR_PYTHON,
        )
        self._registry[name] = _ToolEntry(
            name=name,
            func=func,
            description=description,
            parameters=parameters,
            domain=domain,
            spec=tool_spec,
        )

    def register_shell_tool(
        self, name: str, command_template: str, description: str,
        parameters: Dict[str, Any], parser: Callable | None = None,
        timeout: int = 60, retries: int = 1,
        domain: str | None = None,
        spec: ToolSpec | None = None,
        prepare: Callable[[], None] | None = None,
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
            domain: Optional domain tag for filtering (e.g. 'web', 'k8s', 'cloud', 'ad').
                    Tools without a domain are always registered.
            spec: Optional explicit ToolSpec.
            prepare: Optional best-effort callable run once before the command
                    starts (e.g. lazy environment setup). Failures are logged
                    and do not block execution.
        """
        # Domain filter: skip if domain is set and not in enabled_domains
        if domain is not None and self._enabled_domains is not None:
            if domain not in self._enabled_domains:
                return  # silently skip
        # Some registrations pass parenthesized adjacent string literals as a
        # tuple (e.g. ``command_template=("python3 -c \\"", "import ...")``).
        # Coerce to a single string so both format() and spec validation work.
        if isinstance(command_template, (list, tuple)):
            command_template = "".join(command_template)
        _log = self._log

        # Collect defaults from parameter schema
        _defaults = {k: v["default"] for k, v in parameters.items() if isinstance(v, dict) and "default" in v}

        async def _execute(**kwargs) -> ToolResult:
            if prepare is not None:
                try:
                    prepare()
                except Exception as e:
                    _log.warning(
                        "MCPGateway: prepare hook failed for tool '%s': %s", name, e
                    )
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
                            await _kill_and_reap(proc)
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

        tool_spec = spec or auto_spec(
            name=name,
            description=description,
            parameters=parameters,
            domain=domain,
            executor=EXECUTOR_SHELL,
            command_template=command_template,
        )
        self._registry[name] = _ToolEntry(
            name=name, func=_execute, description=description, parameters=parameters,
            domain=domain, spec=tool_spec,
        )

    def register_shell_argv_tool(
        self,
        name: str,
        shell_args: List[str],
        description: str,
        parameters: Dict[str, Any],
        split_params: List[str] | None = None,
        parser: Callable | None = None,
        timeout: int = 60,
        retries: int = 1,
        domain: str | None = None,
        spec: ToolSpec | None = None,
    ) -> None:
        """Register a shell tool that runs WITHOUT a shell (argv list).

        Args:
            name: Tool name.
            shell_args: argv template; each element may contain ``{param}``
                placeholders. Elements that are exactly ``{param}`` and whose
                param is listed in ``split_params`` are shlex-split and spliced
                (preserving the old shell word-splitting behaviour for
                free-form ``command`` parameters).
            description: Tool description for the LLM.
            parameters: Parameter schema (OpenAI property format).
            split_params: params to word-split when injected as a standalone
                argv element.
            parser: Optional output parser.
            timeout: Per-attempt timeout in seconds.
            retries: Retries after timeout (1.5x multiplier per attempt).
            domain: Optional domain tag.
            spec: Optional explicit ToolSpec.
        """
        if domain is not None and self._enabled_domains is not None:
            if domain not in self._enabled_domains:
                return
        _log = self._log
        split_params = list(split_params or [])
        _defaults = {
            k: v["default"]
            for k, v in parameters.items()
            if isinstance(v, dict) and "default" in v
        }

        async def _execute(**kwargs: Any) -> ToolResult:
            try:
                for k, v in _defaults.items():
                    kwargs.setdefault(k, v)
                argv: List[str] = []
                raw_cmdline: str | None = None
                for element in shell_args:
                    match = re.fullmatch(r"\{(\w+)\}", element)
                    if match and match.group(1) in split_params:
                        value = kwargs.get(match.group(1))
                        # Keep the original command for POSIX emulation of
                        # the Windows ``cmd /c {cmdline}`` convention.
                        if (
                            len(shell_args) == 3
                            and shell_args[0].lower() == "cmd"
                            and shell_args[1].lower() == "/c"
                            and element == shell_args[2]
                        ):
                            raw_cmdline = str(value or "")
                        argv.extend(shlex_split_value(value))
                    else:
                        argv.append(element.format(**kwargs))
                if raw_cmdline is not None and os.name != "nt":
                    argv = ["/bin/sh", "-c", raw_cmdline]
            except (ValueError, KeyError) as e:
                _err_msg = (
                    f"argv format error: {e} | argv={shell_args[:4]} | kwargs={kwargs}"
                )
                return ToolResult(
                    tool_name=name, success=False,
                    stdout=_err_msg, stderr=_err_msg,
                    exit_code=1, elapsed_ms=0,
                )

            start = time.perf_counter()
            last_stderr = ""
            max_attempts = 1 + retries
            for attempt in range(max_attempts):
                current_timeout = timeout * (1.5 ** attempt)
                proc = None
                try:
                    no_prompt_env = {**os.environ, "PGPASSWORD": ""}
                    proc = await asyncio.create_subprocess_exec(
                        *argv,
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
                                "MCPGateway: parser failed for '%s': %s", name, e
                            )
                    return ToolResult(
                        tool_name=name,
                        success=proc.returncode == 0,
                        stdout=stdout_s,
                        stderr=stderr_s,
                        exit_code=proc.returncode or 0,
                        elapsed_ms=elapsed,
                        parsed_output=parsed,
                    )
                except asyncio.TimeoutError:
                    last_stderr = f"Command timed out after {current_timeout}s"
                    if attempt < max_attempts - 1:
                        _log.warning(
                            "Tool '%s' timed out after %ds (attempt %d/%d), retrying",
                            name, current_timeout, attempt + 1, max_attempts,
                        )
                    try:
                        if proc is not None:
                            await _kill_and_reap(proc)
                    except Exception:
                        pass

            elapsed = (time.perf_counter() - start) * 1000
            return ToolResult(
                tool_name=name, success=False,
                stdout="", stderr=last_stderr,
                exit_code=-1, elapsed_ms=elapsed,
            )

        tool_spec = spec or auto_spec(
            name=name,
            description=description,
            parameters=parameters,
            domain=domain,
            executor=EXECUTOR_SHELL_ARGV,
            shell_args=shell_args,
            split_params=split_params,
        )
        self._registry[name] = _ToolEntry(
            name=name, func=_execute, description=description,
            parameters=parameters, domain=domain, spec=tool_spec,
        )

    def _normalize_params(
        self, name: str, params: Dict[str, Any], entry: "_ToolEntry",
    ) -> Dict[str, Any]:
        """Normalize LLM-provided parameters to match tool-declared names.

        Applies four phases:
          1. Explicit aliases: spec.aliases first, then _PARAM_ALIASES
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
        spec_aliases: Dict[str, list[str]] = {}
        if entry.spec is not None:
            spec_aliases = dict(entry.spec.aliases)
        alias_table: Dict[str, list[str]] = {}
        alias_table.update(_PARAM_ALIASES)
        alias_table.update(spec_aliases)  # spec aliases take precedence
        for alias, canonical_list in alias_table.items():
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

    def get_tool_specs(self) -> Dict[str, ToolSpec]:
        """Return {tool_name: ToolSpec} for every registered tool.

        Auto-derives a spec for any entry registered before the Phase 1
        contract landed, so the manifest covers the full registry.
        """
        specs: Dict[str, ToolSpec] = {}
        for name, entry in self._registry.items():
            if entry.spec is None:
                entry.spec = auto_spec(
                    name=name,
                    description=entry.description,
                    parameters=entry.parameters,
                    domain=entry.domain,
                    executor=EXECUTOR_PYTHON,
                )
            specs[name] = entry.spec
        return specs

    def ensure_specs(self) -> Dict[str, ToolSpec]:
        """Idempotent wrapper over :meth:`get_tool_specs` (naming clarity)."""
        return self.get_tool_specs()

    def get_execution_log(self) -> List[ToolResult]:
        """Get all tool execution results."""
        return self._execution_log

    # ── Tool registry introspection (meta tools) ──────────────────
    def tool_registry_list(
        self,
        domain: str = "",
        capability: str = "",
        keyword: str = "",
    ) -> ToolResult:
        """List registered tools as compact entries for LLM tool discovery.

        Filters are optional and ANDed: domain matches one of the tool's
        declared domains, capability must match exactly, keyword is a
        case-insensitive substring of the tool name or description.
        """
        try:
            specs = self.get_tool_specs()
        except Exception as e:  # pragma: no cover - defensive
            return ToolResult(
                tool_name="tool_registry_list", success=False,
                stdout="", stderr=f"failed to collect specs: {e}",
                exit_code=1, elapsed_ms=0,
            )
        items = []
        for name in sorted(specs):
            spec = specs[name]
            if domain and domain not in spec.domains:
                continue
            if capability and spec.capability != capability:
                continue
            if keyword and keyword.lower() not in name.lower() \
                    and keyword.lower() not in spec.description.lower():
                continue
            items.append({
                "name": name,
                "description": spec.description[:200],
                "domains": list(spec.domains),
                "capability": spec.capability,
                "executor": spec.executor,
            })
        payload = {"count": len(items), "tools": items}
        return ToolResult(
            tool_name="tool_registry_list", success=True,
            stdout=json.dumps(payload, ensure_ascii=False, indent=1),
            stderr="", exit_code=0, elapsed_ms=0,
            parsed_output=payload,
        )

    def tool_registry_get(self, name: str) -> ToolResult:
        """Return the full ToolSpec contract (parameters, required, aliases,
        executor, dependencies) for one registered tool."""
        try:
            specs = self.get_tool_specs()
        except Exception as e:  # pragma: no cover - defensive
            return ToolResult(
                tool_name="tool_registry_get", success=False,
                stdout="", stderr=f"failed to collect specs: {e}",
                exit_code=1, elapsed_ms=0,
            )
        spec = specs.get(name)
        if spec is None:
            return ToolResult(
                tool_name="tool_registry_get", success=False,
                stdout="", stderr=f"tool '{name}' not found in registry",
                exit_code=1, elapsed_ms=0,
            )
        data = spec.to_dict()
        return ToolResult(
            tool_name="tool_registry_get", success=True,
            stdout=json.dumps(data, ensure_ascii=False, indent=1),
            stderr="", exit_code=0, elapsed_ms=0,
            parsed_output=data,
        )


class _ToolEntry:
    """Internal registry entry for a tool."""
    def __init__(self, name: str, func: Callable, description: str, parameters: Dict[str, Any],
                 domain: str | None = None, spec: ToolSpec | None = None):
        self.name = name
        self.func = func
        self.description = description
        self.parameters = parameters
        self.domain = domain
        self.spec = spec
