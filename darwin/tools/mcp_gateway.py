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
from darwin.tools.paths import tool_path_env
from darwin.tools.arg_contract import PARAM_ALIASES, coerce_string_params, project_args

log = logging.getLogger(__name__)

# Pipefail-capable shell.  ``create_subprocess_shell`` passes the command to
# ``<executable> -c <cmd>``; without an explicit prefix, a trailing
# ``| head`` would mask a failing command's exit status.
_PIPEFAIL_SHELL = "/bin/bash"
_PIPEFAIL_PREFIX = "set -o pipefail; "


def _pipeline_returncode(returncode: int | None, stdout: str) -> int:
    """Normalize a shell pipeline's exit status for tool reporting.

    With ``pipefail`` enabled a reader that closes early (``... | head``)
    makes the producer die on SIGPIPE (141) even though the command worked
    and produced output; that must not be reported as a failure.
    """
    rc = returncode or 0
    if rc == 141 and stdout.strip():
        return 0
    return rc


# ── Semantic parameter aliases ────────────────────────────────────────
# The shared table lives in :mod:`darwin.tools.arg_contract` so producers
# bind and the gateway projects through the same rules.  ``_PARAM_ALIASES``
# mirrors it for callers that only need the name pairs.
_PARAM_ALIASES: Dict[str, list[str]] = {
    alias: list(targets) for alias, targets in PARAM_ALIASES.items()
}


async def _kill_and_reap(proc: asyncio.subprocess.Process) -> None:
    """Terminate a timed-out child and drain its pipes before returning."""
    try:
        proc.kill()
    except (ProcessLookupError, OSError) as exc:
        log.debug("swallowed exception: %s", exc, exc_info=True)
    try:
        await asyncio.wait_for(proc.communicate(), timeout=2.0)
    except (asyncio.TimeoutError, ProcessLookupError, OSError):
        try:
            await asyncio.wait_for(proc.wait(), timeout=0.5)
        except (asyncio.TimeoutError, ProcessLookupError, OSError) as exc:
            log.debug("swallowed exception: %s", exc, exc_info=True)


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
    #: Parameter keys the gateway redirected to a declared parameter before
    #: dispatch (explicit alias migration). A non-empty list means the
    #: call did not receive the exact arguments the caller planned, so a
    #: negative verdict drawn from it is not trustworthy evidence.
    params_repaired: List[str] = field(default_factory=list)
    #: Parameter keys dropped before dispatch because their value carried no
    #: intent (empty string, ``<tenant>`` leftover, empty container).
    params_dropped: List[str] = field(default_factory=list)
    #: Parameter keys whose container value was serialized into the string
    #: slot the tool declares (alias migration can route a list/dict there).
    params_coerced: List[str] = field(default_factory=list)


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
        prepare_params: Callable[[Dict[str, Any]], Dict[str, Any]] | None = None,
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
            prepare_params: Optional callable applied to the merged parameter
                    dict (after defaults, before template formatting) that
                    may normalize values — e.g. resolve a logical wordlist
                    name to a path, or complete a required URL keyword.
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

                if prepare_params is not None:
                    try:
                        kwargs = dict(prepare_params(dict(kwargs)))
                    except Exception as e:
                        _log.warning(
                            "MCPGateway: prepare_params failed for tool '%s': %s",
                            name, e,
                        )

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
                    no_prompt_env = tool_path_env({**os.environ, "PGPASSWORD": ""})
                    _use_pipefail = os.path.exists(_PIPEFAIL_SHELL)
                    if _use_pipefail:
                        cmd = _PIPEFAIL_PREFIX + cmd
                    proc = await asyncio.create_subprocess_shell(
                        cmd,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                        env=no_prompt_env,
                        executable=_PIPEFAIL_SHELL if _use_pipefail else None,
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
                        success=_pipeline_returncode(proc.returncode, stdout_s) == 0,
                        stdout=stdout_s,
                        stderr=stderr_s,
                        exit_code=_pipeline_returncode(proc.returncode, stdout_s),
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
                    except Exception as exc:
                        log.debug("swallowed exception: %s", exc, exc_info=True)

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
                    no_prompt_env = tool_path_env({**os.environ, "PGPASSWORD": ""})
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
                    except Exception as exc:
                        log.debug("swallowed exception: %s", exc, exc_info=True)

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

    def _normalize_params_report(
        self, name: str, params: Dict[str, Any], entry: "_ToolEntry",
    ) -> tuple[Dict[str, Any], list[str], dict[str, str], list[str], list[str]]:
        """Project a call onto the tool's declared parameters.

        The rules live in :mod:`darwin.tools.arg_contract` and are shared with
        every producer, so a key that survives projection unmapped is a real
        contract violation rather than a naming drift.  Returns
        ``(params, unmappable, migrated, dropped, coerced)``: ``unmappable``
        keys carry a value the tool cannot express (the dispatch path refuses
        such a call), ``migrated`` maps each redirected source key to its
        canonical name, ``dropped`` lists placeholder keys that were
        discarded and ``coerced`` lists string slots that received a
        container value serialized into text.

        Aliases are only applied when the canonical name exists in the tool's
        parameters schema — this prevents false matches like command→query on
        ssh_exec, which legitimately expects 'command'.
        """
        tool_params = entry.parameters  # declared parameter schema dict
        spec_aliases: Dict[str, list[str]] = {}
        if entry.spec is not None:
            spec_aliases = dict(entry.spec.aliases)

        normalized = dict(params)
        # 'anonymous' is a request flag, not a tool argument: it means
        # "connect with empty credentials".
        if normalized.pop("anonymous", None) is True:
            normalized.setdefault("user", "")
            normalized.setdefault("password", "")

        projected, migrated, dropped, unmappable = project_args(
            tool_params, normalized, spec_aliases,
        )
        projected, coerced = coerce_string_params(tool_params, projected)
        # host:port composition kept from the alias phase: the caller supplied
        # a host and a port, the tool wants one target string.
        _port = normalized.get("port")
        if "host" in migrated and _port not in (None, "") and isinstance(
            projected.get(migrated["host"]), str
        ):
            target = migrated["host"]
            projected[target] = f"{projected[target]}:{_port}"
        return projected, unmappable, migrated, dropped, coerced

    def project_params(
        self, name: str, params: Dict[str, Any],
    ) -> tuple[Dict[str, Any], list[str], dict[str, str], list[str], list[str]]:
        """Full projection report for callers that must explain a call.

        Returns ``(projected, unmappable, migrated, dropped, coerced)``. An
        unregistered tool has no contract to project against, so its arguments
        pass through untouched.
        """
        entry = self._registry.get(name)
        if entry is None:
            return dict(params or {}), [], {}, [], []
        return self._normalize_params_report(name, params or {}, entry)

    def _suggest_alternative_tools(
        self,
        name: str,
        entry: "_ToolEntry",
        unknown: list[str],
        missing: list[str],
        limit: int = 3,
    ) -> list[str]:
        """Registered tools that declare what this call wanted but lacked.

        A refused call is only actionable when the caller learns which tool
        *can* express the parameters it planned; without that the fix loop
        re-sends the same argument names (observed as repeated
        ``ignoring corrected param(s)`` warnings in the benchmark logs).
        Tools sharing the refused tool's capability rank first.
        """
        wanted = set(unknown) | set(missing)
        if not wanted:
            return []
        capability = ""
        spec = getattr(entry, "spec", None)
        if spec is not None:
            capability = str(getattr(spec, "capability", "") or "")
        ranked: list[tuple[int, int, str]] = []
        for other, other_entry in self._registry.items():
            if other == name:
                continue
            hits = len(wanted & set((other_entry.parameters or {}).keys()))
            if not hits:
                continue
            other_spec = getattr(other_entry, "spec", None)
            same_capability = bool(capability) and str(
                getattr(other_spec, "capability", "") or ""
            ) == capability
            ranked.append((0 if same_capability else 1, -hits, other))
        ranked.sort()
        return [tool for _rank, _hits, tool in ranked[:limit]]

    def _normalize_params(
        self, name: str, params: Dict[str, Any], entry: "_ToolEntry",
    ) -> Dict[str, Any]:
        """Preview form of :meth:`_normalize_params_report` (params only)."""
        normalized, _unknown, _migrated, _dropped, _coerced = (
            self._normalize_params_report(name, params, entry)
        )
        if _unknown:
            log.warning(
                "tool '%s': undeclared parameter(s) %s (declared: %s)",
                name, _unknown, sorted(entry.parameters or {}),
            )
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
        params, _unknown, _migrated, _dropped, _coerced = (
            self._normalize_params_report(name, params, entry)
        )

        # Refuse a call whose declared parameters are not satisfied:
        #   - unknown keys: the framework will not silently drop an argument
        #     the plan intended to use, because the tool would then run against
        #     a different request than the one the plan reasoned about.
        #   - missing required: doing it here turns an opaque runtime error
        #     ("TypeError: missing 1 required positional argument") into an
        #     actionable INVALID_ARGUMENT the fix loop can repair.
        _missing = [
            _param for _param, _schema in (entry.parameters or {}).items()
            if isinstance(_schema, dict) and "default" not in _schema
            and _param not in params
        ]
        if _missing or _unknown:
            _details: list[str] = []
            if _missing:
                _details.append(f"missing required parameter(s) {_missing}")
            if _unknown:
                _details.append(
                    f"unknown parameter(s) {_unknown} (declared: "
                    f"{sorted(entry.parameters or {})})"
                )
            _suggested = self._suggest_alternative_tools(name, entry, _unknown, _missing)
            if _suggested:
                _details.append(
                    "use one of these tools instead: " + ", ".join(_suggested)
                )
            _reason = "; ".join(_details)
            log.warning("tool '%s': refusing call — %s", name, _reason)
            return ToolResult(
                tool_name=name, success=False, stdout="",
                stderr=f"invalid argument: {_reason} for tool '{name}'",
                exit_code=2, elapsed_ms=0,
            )

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
            _repaired = sorted(set(_migrated) | set(_dropped))
            if _repaired:
                result.params_repaired = list(_repaired)
            if _dropped:
                result.params_dropped = list(_dropped)
            if _coerced:
                result.params_coerced = list(_coerced)
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

    def normalize_params(self, name: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Public form of the dispatch-time parameter normalization.

        Callers that need to know which parameters a tool would actually
        receive (e.g. the plan-first execution check in the orchestrator) must
        not re-implement alias handling, so this exposes the same rules the
        call path applies. Unknown tools yield an empty dict.
        """
        entry = self._registry.get(name)
        if entry is None:
            return {}
        try:
            return self._normalize_params(name, dict(params or {}), entry)
        except Exception as exc:
            self._log.warning("normalize_params failed for %s: %s", name, exc)
            return {}

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
