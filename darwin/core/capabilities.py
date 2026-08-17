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
    """Registry with P8 capabilities plus the Phase 1 scenario families.

    Tool order follows the approved design table (default tool first):
    fetch_url / verify_sql_injection / test_credentials / acquire_shell /
    sql_query / web_exploit_send / container_escape / k8s_apply /
    secret_dump / cloud_iam_assume / registry_push / credential_test.
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
    reg.register(
        Capability(
            name="sql_query",
            description=(
                "Run a SQL/NoSQL query against a database service using "
                "discovered or default credentials."
            ),
            required_context=["credential"],
            supported_tools=[
                "psql_query", "mysql_query", "mssqlclient_query",
                "oracle_query", "redis_cmd", "mongodb_query",
            ],
            default_tool="psql_query",
            success_condition={"type": "sql_result_obtained"},
        )
    )
    reg.register(
        Capability(
            name="web_exploit_send",
            description=(
                "Deliver an exploitation payload to an HTTP endpoint "
                "(generic send, XXE, SSTI, GraphQL, command injection)."
            ),
            required_context=["endpoint"],
            supported_tools=[
                "send_payload", "http_post", "xxe_inject", "ssti_inject",
                "graphql_introspect", "command_injection_test",
            ],
            default_tool="send_payload",
            success_condition={"type": "payload_delivered"},
        )
    )
    reg.register(
        Capability(
            name="container_escape",
            description=(
                "Escape from a container to the host using capabilities, "
                "mounted sockets, procfs, or cgroup primitives."
            ),
            required_context=["access"],
            supported_tools=[
                "check_capabilities", "check_mounts",
                "container_escape_docker_sock", "container_escape_cgroup",
                "container_escape_procfs", "container_escape_cap_dac",
                "container_escape_mount_disk", "nsenter_exec",
            ],
            default_tool="check_capabilities",
            success_condition={"type": "host_access_obtained"},
        )
    )
    reg.register(
        Capability(
            name="k8s_apply",
            description=(
                "Create or execute inside Kubernetes workloads (pod, exec) "
                "for scheduling, webhook and post-exploitation scenarios."
            ),
            required_context=["endpoint"],
            supported_tools=["kubectl_run", "kubectl_exec", "shell_exec"],
            default_tool="kubectl_run",
            success_condition={"type": "workload_created"},
        )
    )
    reg.register(
        Capability(
            name="secret_dump",
            description=(
                "Extract Kubernetes secrets/configmaps directly via the API "
                "or etcd."
            ),
            required_context=["endpoint"],
            supported_tools=[
                "k8s_secret_dump", "k8s_configmap_dump",
                "kubectl_get_secrets", "etcdctl_get", "k8s_etcd_keys",
            ],
            default_tool="k8s_secret_dump",
            success_condition={"type": "secrets_extracted"},
        )
    )
    reg.register(
        Capability(
            name="cloud_iam_assume",
            description=(
                "Assume a cloud IAM role via STS, OIDC/SAML federation, "
                "or forged tokens."
            ),
            required_context=["credential/access"],
            supported_tools=[
                "aws_sts_query", "aws_iam_federation", "aws_cli",
                "saml_forge", "jwt_forge",
            ],
            default_tool="aws_sts_query",
            success_condition={"type": "role_assumed"},
        )
    )
    reg.register(
        Capability(
            name="registry_push",
            description=(
                "Push a (poisoned) container image to a registry for "
                "supply-chain attacks."
            ),
            required_context=["endpoint"],
            supported_tools=["docker_registry", "shell_exec"],
            default_tool="docker_registry",
            success_condition={"type": "image_pushed"},
        )
    )
    reg.register(
        Capability(
            name="credential_test",
            description=(
                "Validate a discovered credential against SSH, database or "
                "HTTP services."
            ),
            required_context=["credential"],
            supported_tools=[
                "test_credential", "test_db_credential",
                "hydra_http_brute", "wp_xmlrpc_brute",
            ],
            default_tool="test_credential",
            success_condition={"type": "credential_validated"},
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
            # ── Phase 1 scenario-family capabilities ──────────────────
            elif tool == "psql_query":
                out[tool] = {
                    "host": str(cred.get("host") or params.get("host") or ""),
                    "port": int(cred.get("port") or params.get("port") or 5432),
                    "user": str(cred.get("username") or cred.get("user") or params.get("user") or "postgres"),
                    "password": str(cred.get("password") or params.get("password") or ""),
                    "query": str(params.get("query") or "SELECT version()"),
                }
            elif tool == "mysql_query":
                out[tool] = {
                    "host": str(cred.get("host") or params.get("host") or ""),
                    "port": int(cred.get("port") or params.get("port") or 3306),
                    "user": str(cred.get("username") or cred.get("user") or params.get("user") or "root"),
                    "password": str(cred.get("password") or params.get("password") or ""),
                    "query": str(params.get("query") or "SELECT @@version"),
                }
            elif tool == "mssqlclient_query":
                out[tool] = {
                    "host": str(cred.get("host") or params.get("host") or ""),
                    "port": int(cred.get("port") or params.get("port") or 1433),
                    "user": str(cred.get("username") or cred.get("user") or params.get("user") or "sa"),
                    "password": str(cred.get("password") or params.get("password") or ""),
                    "query": str(params.get("query") or "SELECT @@version"),
                }
            elif tool == "oracle_query":
                out[tool] = {
                    "host": str(cred.get("host") or params.get("host") or ""),
                    "port": int(cred.get("port") or params.get("port") or 1521),
                    "user": str(cred.get("username") or cred.get("user") or params.get("user") or "system"),
                    "password": str(cred.get("password") or params.get("password") or ""),
                    "sid": str(params.get("sid") or "XE"),
                    "query": str(params.get("query") or "SELECT banner FROM v$version"),
                }
            elif tool == "redis_cmd":
                out[tool] = {
                    "host": str(cred.get("host") or params.get("host") or ""),
                    "port": int(cred.get("port") or params.get("port") or 6379),
                    "command": str(params.get("command") or "INFO"),
                }
            elif tool == "mongodb_query":
                out[tool] = {
                    "host": str(cred.get("host") or params.get("host") or ""),
                    "port": int(cred.get("port") or params.get("port") or 27017),
                    "user": str(cred.get("username") or params.get("user") or ""),
                    "password": str(cred.get("password") or ""),
                    "database": str(params.get("database") or "admin"),
                    "query_json": str(params.get("query_json") or '{"find": "test"}'),
                }
            elif tool == "send_payload":
                out[tool] = {
                    "url": endpoint,
                    "param": parameter,
                    "payload": str(params.get("payload") or ""),
                    "method": str(params.get("method") or "GET"),
                }
            elif tool == "xxe_inject":
                out[tool] = {
                    "target_url": endpoint,
                    "read_file": str(params.get("read_file") or "/flag.txt"),
                }
            elif tool == "ssti_inject":
                out[tool] = {
                    "target_url": endpoint,
                    "param_name": parameter or "name",
                }
            elif tool == "graphql_introspect":
                out[tool] = {"target_url": endpoint}
            elif tool == "command_injection_test":
                out[tool] = {"url": endpoint, "param": parameter}
            elif tool in ("check_capabilities", "check_mounts"):
                out[tool] = {}
            elif tool == "container_escape_docker_sock":
                out[tool] = {"shell_cmd": command}
            elif tool == "container_escape_cgroup":
                out[tool] = {"shell_cmd": command, "subsystem": str(params.get("subsystem") or "memory")}
            elif tool == "container_escape_procfs":
                out[tool] = {"pid": int(params.get("pid") or 1), "shell_cmd": command}
            elif tool == "container_escape_cap_dac":
                out[tool] = {"target_file": str(params.get("target_file") or "/flag.txt")}
            elif tool == "container_escape_mount_disk":
                out[tool] = {"shell_cmd": command, "device_path": str(params.get("device_path") or "")}
            elif tool == "nsenter_exec":
                out[tool] = {"target_pid": int(params.get("target_pid") or 1), "command": command}
            elif tool == "kubectl_run":
                out[tool] = {
                    "name": str(params.get("name") or "darwin-pod"),
                    "image": str(params.get("image") or "busybox"),
                    "namespace": str(params.get("namespace") or "default"),
                    "command": command,
                }
            elif tool == "kubectl_exec":
                out[tool] = {
                    "pod": str(params.get("pod") or ""),
                    "namespace": str(params.get("namespace") or "default"),
                    "command": command,
                }
            elif tool == "k8s_secret_dump":
                out[tool] = {}
            elif tool == "k8s_configmap_dump":
                out[tool] = {}
            elif tool == "kubectl_get_secrets":
                out[tool] = {"namespace": str(params.get("namespace") or "default")}
            elif tool in ("etcdctl_get", "k8s_etcd_keys"):
                out[tool] = {
                    "endpoint": str(params.get("endpoint") or "http://localhost:2379"),
                    "key": str(params.get("key") or "/"),
                }
            elif tool == "aws_sts_query":
                out[tool] = {
                    "endpoint_url": str(
                        params.get("endpoint_url")
                        or params.get("endpoint")
                        or ""
                    ),
                    "action": str(params.get("action") or "GetCallerIdentity"),
                    "access_key_id": str(params.get("access_key_id") or ""),
                    "secret_access_key": str(params.get("secret_access_key") or ""),
                }
            elif tool == "aws_iam_federation":
                out[tool] = {
                    "action": str(params.get("action") or "assume-role"),
                    "role_arn": str(params.get("role_arn") or ""),
                    "endpoint_url": str(params.get("endpoint_url") or ""),
                }
            elif tool == "aws_cli":
                out[tool] = {
                    "service": str(params.get("service") or "sts"),
                    "action": str(params.get("action") or "get-caller-identity"),
                    "resource": str(params.get("resource") or ""),
                    "payload_json": str(params.get("payload_json") or ""),
                }
            elif tool == "saml_forge":
                out[tool] = {
                    "issuer": str(params.get("issuer") or "http://idp.example.com/metadata"),
                    "name_id": str(params.get("name_id") or "admin"),
                    "recipient": str(params.get("recipient") or ""),
                    "audience": str(params.get("audience") or ""),
                    "attr_name": str(params.get("attr_name") or "https://aws.amazon.com/SAML/Attributes/Role"),
                    "attr_value": str(params.get("attr_value") or ""),
                }
            elif tool == "jwt_forge":
                out[tool] = {
                    "secret": str(params.get("secret") or ""),
                    "algorithm": str(params.get("algorithm") or "HS256"),
                    "claims_b64": str(
                        params.get("claims_b64") or params.get("claims") or ""
                    ),
                }
            elif tool == "docker_registry":
                out[tool] = {
                    "image": str(params.get("image") or ""),
                    "target_registry": str(params.get("target_registry") or ""),
                    "image_name": str(params.get("image_name") or ""),
                }
            elif tool == "test_db_credential":
                out[tool] = {
                    "host": str(cred.get("host") or params.get("host") or ""),
                    "port": int(cred.get("port") or params.get("port") or 5432),
                    "service_type": str(params.get("service_type") or "postgresql"),
                    "username": str(cred.get("username") or params.get("username") or ""),
                    "password": str(cred.get("password") or params.get("password") or ""),
                }
            elif tool == "wp_xmlrpc_brute":
                out[tool] = {
                    "target_url": endpoint,
                    "users": str(params.get("users") or "admin"),
                    "passwords": str(params.get("passwords") or ""),
                }
            else:
                out[tool] = dict(params)
        return out


def normalize_result(
    result: ExecutionResult, capability: str, tool_attempts: list[str]
) -> ExecutionResult:
    """Stamp capability metadata onto a raw tool ExecutionResult (P8)."""
    from darwin.core.executor import ExecutionResult  # lazy: executor imports this module

    return replace(result, capability=capability, tool_attempts=list(tool_attempts))
