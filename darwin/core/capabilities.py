"""Capability layer (P8).

A Capability is an intent-level contract: the Task says WHAT to do
("verify_sql_injection on /login?user=x") and the system decides WHICH
tool to use and HOW to fill its parameters. This is the v2 answer to
"the LLM fills too many tool-level details" (architecture plan section 10).

Execution pipeline (wired through ``ToolExecutor``):

    Task
      -> CapabilityRegistry lookup
      -> PreconditionValidator   (missing context -> PRECONDITION_MISSING)
      -> ContextResolver         (task context -> per-tool params)
      -> ToolExecutor            (tries supported_tools in order)
      -> normalized ExecutionResult (capability + tool_attempts)

P8 scope: 4 built-in capabilities and the Executor dispatch path only.
Tools not covered by a capability keep the legacy direct-dispatch path
(``action["tool"]``) unchanged; the layer is additive, not a replacement.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, replace
from typing import Iterable

from darwin.tools.adapters import ToolAdapter, default_adapters
from darwin.core.task import Task


@dataclass
class Capability:
    """Intent-level contract for one class of tasks.

    Fields:
        name: unique capability id, referenced by Task.action["capability"].
        description: what the capability accomplishes (LLM-facing).
        required_context: context fields the task must supply before any
            tool runs. A "/"-joined entry means ANY alternative suffices
            (e.g. "credential/access").
        supported_tools: gateway tool names, tried in order.
        default_tool: the tool chosen when nothing forces a fallback
            (also the planned_tool recorded for adherence).
        success_condition: optional structured success criterion.
    """

    name: str
    description: str
    required_context: list[str] = field(default_factory=list)
    supported_tools: list[str] = field(default_factory=list)
    default_tool: str = ""
    success_condition: dict | None = None


class CapabilityRegistry:
    """Name -> Capability registry (data-driven; add capabilities freely)."""

    def __init__(self) -> None:
        self._capabilities: dict[str, Capability] = {}

    def register(self, capability: Capability) -> None:
        if not capability.name:
            raise ValueError("capability name must not be empty")
        self._capabilities[capability.name] = capability

    def get(self, name: str) -> Capability | None:
        return self._capabilities.get(name)

    def list(self) -> list[Capability]:
        return sorted(self._capabilities.values(), key=lambda c: c.name)


def default_registry() -> CapabilityRegistry:
    """Registry with the P8 first-round capabilities.

    Tool order follows the approved design table (default tool first):
    fetch_url / verify_sql_injection / test_credentials / acquire_shell.
    """
    reg = CapabilityRegistry()
    reg.register(
        Capability(
            name="fetch_url",
            description="Fetch an HTTP(S) resource from an endpoint.",
            required_context=["endpoint"],
            supported_tools=["curl_get", "http_post"],
            default_tool="curl_get",
            success_condition={"type": "http_response_received"},
        )
    )
    reg.register(
        Capability(
            name="verify_sql_injection",
            description="Verify a SQL injection hypothesis on an endpoint parameter.",
            required_context=["endpoint", "parameter"],
            supported_tools=["sqlmap_test", "http_post"],
            default_tool="sqlmap_test",
            success_condition={"type": "sql_injection_confirmed"},
        )
    )
    reg.register(
        Capability(
            name="test_credentials",
            description="Validate a credential against a service.",
            required_context=["credential"],
            supported_tools=["test_credential", "hydra_http_brute"],
            default_tool="test_credential",
            success_condition={"type": "credential_validated"},
        )
    )
    reg.register(
        Capability(
            name="acquire_shell",
            description=(
                "Obtain command execution on the target using a credential "
                "or existing access."
            ),
            required_context=["credential/access"],
            supported_tools=["ssh_exec", "ssh_key_exec", "shell_exec"],
            default_tool="ssh_exec",
            success_condition={"type": "remote_shell_obtained"},
        )
    )
    return reg


# ── Context extraction / validation ────────────────────────────────


def _task_params(task: Task) -> dict:
    """Normalized dict view of task.action["params"]."""
    action = task.action or {}
    params = action.get("params") or {}
    if isinstance(params, str):
        try:
            params = json.loads(params)
        except (json.JSONDecodeError, TypeError):
            params = {"value": params}
    return dict(params) if isinstance(params, dict) else {"value": params}


def _context_from_task(task: Task) -> dict:
    """One normalized context view shared by validator and resolver.

    Sources, in priority order: task.required_context, action.target
    (as endpoint), action.params (url / parameter / credential fields).
    """
    ctx = dict(task.required_context or {})
    action = task.action or {}
    target = str(action.get("target", "") or "")
    params = _task_params(task)

    if not str(ctx.get("endpoint", "") or ""):
        ctx["endpoint"] = target or str(params.get("url", "") or "")
    if "parameter" not in ctx:
        ctx["parameter"] = str(params.get("parameter") or params.get("param") or "")
    if "credential" not in ctx:
        cred = {}
        for key in (
            "host", "port", "username", "user", "password",
            "cred_type", "service_type", "command", "key_path",
        ):
            if params.get(key) is not None:
                cred[key] = params[key]
        if cred:
            ctx["credential"] = cred
    if "access" not in ctx:
        ctx["access"] = params.get("session") or params.get("access") or ""
    return ctx


def _present(ctx: dict, name: str) -> bool:
    val = ctx.get(name)
    if isinstance(val, dict):
        return bool(val)
    if isinstance(val, (list, tuple, set)):
        return len(val) > 0
    return bool(str(val or "").strip())


class PreconditionValidator:
    """Checks that a Task supplies the context a Capability requires."""

    def validate(self, capability: Capability, task: Task) -> list[str]:
        """Return the required-context entries the task does not supply."""
        ctx = _context_from_task(task)
        missing: list[str] = []
        for required in capability.required_context:
            alternatives = [part for part in required.split("/") if part] or [required]
            if not any(_present(ctx, alt) for alt in alternatives):
                missing.append(required)
        return missing


class ContextResolver:
    """Maps normalized task context onto each supported tool's parameters.

    P8 keeps this a pure field mapping (no DKG lookups, no LLM). Tool
    signatures are taken from darwin/tools/recon_server.py and
    darwin/tools/attack_server.py; tool-specific caveats are noted inline.

    P15 G5: capabilities with a registered ToolAdapter dispatch to it;
    everything else falls back to the legacy per-tool mapping.
    """

    def __init__(
        self, adapters: Iterable[ToolAdapter] | None = None
    ) -> None:
        self._adapters = {
            adapter.capability_name: adapter
            for adapter in (adapters if adapters is not None else default_adapters())
        }

    def resolve(self, capability: Capability, task: Task) -> dict[str, dict]:
        """Return {tool_name: params} for every supported tool."""
        adapter = self._adapters.get(capability.name)
        if adapter is not None:
            return adapter.resolve(self._build_env(task), _task_params(task))
        return self._resolve_legacy(capability, task)

    @staticmethod
    def _build_env(task: Task) -> dict:
        """Normalized context consumed by the ToolAdapters."""
        ctx = _context_from_task(task)
        params = _task_params(task)
        cred = ctx.get("credential") if isinstance(ctx.get("credential"), dict) else {}
        return {
            "endpoint": str(ctx.get("endpoint", "") or "") or str(params.get("url", "") or ""),
            "parameter": str(ctx.get("parameter", "") or ""),
            "credential": ctx.get("credential"),
            "port": int(cred.get("port") or params.get("port") or 22),
            "command": str(cred.get("command") or params.get("command") or "id"),
            "username": str(
                cred.get("username") or cred.get("user")
                or params.get("username") or "root"
            ),
        }

    def _resolve_legacy(
        self, capability: Capability, task: Task
    ) -> dict[str, dict]:
        """Legacy per-tool mapping for capabilities without an adapter."""
        env = self._build_env(task)
        params = _task_params(task)
        endpoint = env["endpoint"]
        parameter = env["parameter"]
        cred = env["credential"] if isinstance(env["credential"], dict) else {}
        port = env["port"]
        command = env["command"]
        username = env["username"]

        out: dict[str, dict] = {}
        for tool in capability.supported_tools:
            if tool == "curl_get":
                out[tool] = {
                    "url": endpoint,
                    **{k: params[k] for k in ("headers", "cookie") if params.get(k)},
                }
            elif tool == "http_post":
                out[tool] = {
                    "url": endpoint,
                    **{
                        k: params[k]
                        for k in ("data", "headers", "cookie")
                        if params.get(k)
                    },
                }
            elif tool == "sqlmap_test":
                out[tool] = {
                    "url": endpoint,
                    "param": parameter,
                    **{
                        k: params[k]
                        for k in ("technique", "method", "body_format", "content_type")
                        if params.get(k)
                    },
                }
            elif tool == "test_credential":
                # test_credential is the SSH-only credential tester; the
                # generic HTTP fallback (hydra_http_brute) follows it.
                out[tool] = {
                    "user": username,
                    "password": str(cred.get("password") or ""),
                    "host": str(cred.get("host") or ""),
                    "port": port,
                    "command": command,
                }
            elif tool == "hydra_http_brute":
                out[tool] = {
                    "url": endpoint,
                    **{
                        k: params[k]
                        for k in ("userlist", "passlist")
                        if params.get(k)
                    },
                }
            elif tool == "ssh_exec":
                out[tool] = {
                    "host": str(cred.get("host") or ""),
                    "port": port,
                    "username": username,
                    "password": str(cred.get("password") or ""),
                    "command": command,
                }
            elif tool == "ssh_key_exec":
                out[tool] = {
                    "key_path": str(
                        cred.get("key_path")
                        or params.get("key_path") or "~/.ssh/id_rsa"
                    ),
                    "user": username,
                    "host": str(cred.get("host") or ""),
                    "port": port,
                    "command": command,
                }
            elif tool == "shell_exec":
                # shell_exec runs on the LOCAL Darwin host (see the tool
                # docs in attack_server.py); kept as the approved last
                # resort in the acquire_shell tool list.
                out[tool] = {"command": command}
            else:
                out[tool] = dict(params)
        return out


def normalize_result(
    result: ExecutionResult, capability: str, tool_attempts: list[str]
) -> ExecutionResult:
    """Stamp capability metadata onto a raw tool ExecutionResult (P8)."""
    from darwin.core.executor import ExecutionResult  # lazy: executor imports this module

    return replace(result, capability=capability, tool_attempts=list(tool_attempts))
