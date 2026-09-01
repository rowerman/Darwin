"""PlanCoordinator — exploitation plan generation and review.

Owns plan sanitization, generation with registry lookup, cycle detection, plan review/fix and credential extraction. State and cross-coordinator calls are forwarded to the shared Orchestrator context.
"""
from __future__ import annotations

import asyncio
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
)
from darwin.prompts.planner import SYSTEM_PROMPT_PLANNER
from darwin.prompts.evaluator import SYSTEM_PROMPT_EVALUATOR
from darwin.prompts.research import SYSTEM_PROMPT_RESEARCH


from darwin.orchestration.context import CoordinatorContext

class PlanCoordinator(CoordinatorContext):
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
                        _tiller_host = (_svc.get("k8s_cluster_ip", "") or "")
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
                                    except ValueError:
                                        pass
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
        # LLM often defaults to shell_exec for tasks that have dedicated
        # tools (aws_cli, curl_get, send_payload).  Detect these at the
        # code level and correct — this is more reliable than prompt fixes.
        for t in tasks:
            if t.get("tool") != "shell_exec" or t.get("status") not in (None, "", "pending"):
                continue
            _inst = str(t.get("instruction", "")).lower()
            _cmd = str(t.get("params", {}).get("command", "")).lower()
            _combined = f"{_inst} {_cmd}"

            # S3 / AWS operations → aws_cli or curl_get
            if any(kw in _combined for kw in ("s3 ", "s3:", "bucket", "list-buckets",
                                               "list-objects", "aws s3", "object storage")):
                t["tool"] = "curl_get"
                t["instruction"] = (
                    f"[auto-corrected: shell_exec->curl_get (S3/object storage)] "
                    f"{t.get('instruction', '')}"
                )
                if "command" in t.get("params", {}):
                    del t["params"]["command"]
                continue

            # AWS IAM / STS / credential operations → aws_cli
            if any(kw in _combined for kw in ("aws ", "iam ", "sts ", "lambda ",
                                               "accesskeyid", "secretaccesskey",
                                               "list-roles", "get-caller-identity",
                                               "assume-role", "aws cli")):
                t["tool"] = "aws_cli"
                t["instruction"] = (
                    f"[auto-corrected: shell_exec->aws_cli (AWS cloud operation)] "
                    f"{t.get('instruction', '')}"
                )
                if "command" in t.get("params", {}):
                    del t["params"]["command"]
                continue

            # curl-based HTTP operations → curl_get
            if _cmd.strip().startswith("curl ") and "aws " not in _cmd:
                t["tool"] = "curl_get"
                t["instruction"] = (
                    f"[auto-corrected: shell_exec->curl_get (curl in shell_exec)] "
                    f"{t.get('instruction', '')}"
                )
                if "command" in t.get("params", {}):
                    del t["params"]["command"]

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
                )
            )
        # Sync appended hint tasks back to the caller's list.
        _caller_list[:] = _plan_tasks

    async def _generate_with_registry_lookup(
        self,
        prompt: str,
        system_prompt: str | None = None,
        stage: str | None = None,
        max_rounds: int = 2,
    ) -> tuple[str, list | None, bool]:
        """Run an LLM generation round where the model may query the tool
        registry (tool_registry_list / tool_registry_get) before producing
        its final response.

        Returns ``(content, tool_calls, registry_used)``. When the gateways
        do not expose the registry tools (tests, minimal deployments), this
        degrades to a single plain generation call.
        """
        registry_tools: list[dict] = []
        def _llm_timeout(default: float = 180.0) -> float:
            return max(1.0, min(default, float(self._remaining_budget())))
        try:
            for _td in self.attack_gateway.get_tool_definitions():
                _name = _td.get("function", {}).get("name", "")
                if _name in ("tool_registry_list", "tool_registry_get"):
                    registry_tools.append(_td)
        except Exception:
            pass

        if not registry_tools:
            content, tool_calls = self.llm.generate(
                prompt=prompt, system_prompt=system_prompt, stage=stage,
                timeout=_llm_timeout(),
            )
            if not content or self._extract_json(content) == {}:
                try:
                    retry_content, retry_calls = self.llm.generate(
                        prompt=(f"{prompt}\n\nReturn ONLY valid JSON now; "
                                "do not call tools or add explanations."),
                        system_prompt=system_prompt, stage=stage,
                        timeout=_llm_timeout(),
                    )
                    if retry_content:
                        content, tool_calls = retry_content, retry_calls
                except Exception as _exc:
                    log.warning("Structured %s retry failed: %s", stage or "LLM", _exc)
            return content, tool_calls, False

        registry_tool_names = {
            str(td.get("function", {}).get("name", ""))
            for td in registry_tools
        }
        registry_used = False
        content = ""
        tool_calls = None
        call_format = "none"
        for _round in range(max_rounds):
            _round_prompt = (
                prompt if _round == 0
                else "Continue. When you have the tool details you need, "
                     "output your final JSON response."
            )
            content, tool_calls = self.llm.generate(
                prompt=_round_prompt,
                system_prompt=system_prompt,
                tools=registry_tools,
                stage=stage,
                timeout=_llm_timeout(),
            )
            if not tool_calls:
                break
            registry_used = True
            call_format = (
                "dsml" if any(str(tc.get("id", "")).startswith("dsml-")
                              for tc in tool_calls)
                else "openai"
            )
            log.info(
                "Registry lookup %s: %d tool call(s) in %s format",
                stage or "?", len(tool_calls), call_format,
            )
            for tc in tool_calls:
                tc_name = tc.get("name", "")
                tc_args = tc.get("arguments", {})
                tc_id = tc.get("id", "")
                if tc_name not in registry_tool_names:
                    self.llm.add_tool_result(
                        tc_id,
                        f"Tool '{tc_name}' is not allowed during {stage or 'structured'} lookup; "
                        "return only the requested structured JSON.",
                    )
                    log.warning(
                        "Rejected non-registry tool '%s' during %s lookup",
                        tc_name, stage or "structured",
                    )
                    continue
                try:
                    if tc_name in self.attack_gateway.get_tool_names():
                        result = await self._call_tool(tc_name, tc_args)
                    elif tc_name in self.recon_gateway.get_tool_names():
                        result = await self._call_tool(tc_name, tc_args)
                    else:
                        continue
                    tool_stdout = self._format_tool_feedback(
                        tc_name, tc_args, result, ""
                    )
                    self.llm.add_tool_result(tc_id, tool_stdout[:3000])
                except Exception as _exc:
                    self.llm.add_tool_result(
                        tc_id, f"Tool '{tc_name}' failed: {_exc} — skipping"
                    )
        # Registry calls must converge to a structured payload.  A model can
        # spend the final round issuing another lookup and leave ``content``
        # empty; give it one tool-free, JSON-only completion opportunity.
        _parsed_completion = self._extract_json(content) if content else {}
        if isinstance(_parsed_completion, dict):
            final_json_ok = bool(_parsed_completion)
        else:
            final_json_ok = (
                isinstance(_parsed_completion, list)
                and len(_parsed_completion) > 0
            )
        log.info(
            "Registry lookup %s final JSON valid=%s (format=%s, content_len=%d)",
            stage or "?", final_json_ok, call_format, len(content or ""),
        )
        if not content or _parsed_completion == {}:
            retry_prompt = (
                f"{prompt}\n\nReturn the final answer now as ONLY valid JSON. "
                "Do not call tools, add markdown, or include explanations."
            )
            try:
                retry_content, retry_calls = self.llm.generate(
                    prompt=retry_prompt,
                    system_prompt=system_prompt,
                    stage=stage,
                    timeout=_llm_timeout(),
                )
                if retry_content:
                    content, tool_calls = retry_content, retry_calls
            except Exception as _exc:
                log.warning("Structured %s retry failed: %s", stage or "LLM", _exc)
        return content, tool_calls, registry_used

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

        # ── RAG knowledge injection ────────────────────────────────
        # Search RAG for attack patterns matching discovered services.
        # This gives the LLM concrete exploitation steps instead of
        # relying solely on technique names from the research phase.
        rag_context = ""
        probed_rag_endpoints: list[str] = []
        try:
            from darwin.rag import get_rag
            rag = get_rag()
            if rag and rag.loaded:
                # Build search query: service banners + app type + vuln types.
                # Service version alone (e.g. "Apache httpd 2.4.62") skews
                # results toward generic server exploits instead of the CMS
                # actually running on top.  Include application understanding
                # from the analyze phase (e.g. "WordPress 6.7.2").
                svc_terms = []
                for s in state.services[:3]:
                    if s.version:
                        # Keep just the server name, not the full version banner
                        ver = s.version.split("(")[0].strip()  # "Apache httpd 2.4.62"
                        svc_terms.append(ver[:40])
                    elif s.banner:
                        svc_terms.append(s.banner[:40])
                # Pull app-level context from analysis notes
                app_terms = []
                for note in state.analysis_notes:
                    # Extract CMS / framework names
                    for kw in ["WordPress", "Drupal", "Joomla", "Tomcat", "Jenkins",
                               "Django", "Laravel", "Rails", "PHP", "ASP.NET",
                               "Confluence", "GitLab", "Magento", "PrestaShop"]:
                        if kw.lower() in note.lower() and kw not in app_terms:
                            app_terms.append(kw)
                vuln_terms = list({v.vuln_type for v in self.vulnerabilities[:4]})
                query = " ".join(app_terms + svc_terms + vuln_terms)
                if query.strip():
                    # Two-pass search: (1) precise query, (2) broad app-level
                    # plugin/exploit search to catch what the precise query misses
                    results = rag.search(query, top_k=5, min_keyword_overlap=0.2)
                    if app_terms:
                        _app_str = " ".join(app_terms)
                        # Multiple query angles to catch different exploit
                        # patterns.  A single broad query ("plugin exploit")
                        # often misses entries that match specific technique
                        # descriptions (e.g. "unrestricted file upload").
                        _broad_queries = [
                            _app_str + " plugin exploit vulnerability",
                            _app_str + " unauthenticated file upload RCE",
                            _app_str + " arbitrary file upload vulnerability",
                            _app_str + " unrestricted file upload exploit",
                        ]
                        _broad_results: list[dict] = []
                        for _bq in _broad_queries:
                            try:
                                _br = rag.search(_bq, top_k=5, min_keyword_overlap=0.2)
                                _broad_results.extend(_br)
                            except Exception:
                                pass
                        # Merge: deduplicate by title, keep highest-score copy
                        seen_titles: set[str] = set()
                        merged: list[dict] = []
                        for r in results + _broad_results:
                            t = (r.get("title") or "").strip().lower()
                            if t and t not in seen_titles:
                                seen_titles.add(t)
                                merged.append(r)
                        merged.sort(key=lambda r: r.get("score", 0), reverse=True)
                        results = merged[:10]

                    # ── Cloud Platform Discovery enrichment ──────────
                    # When _cloud_discovery_hint() detected a cloud platform
                    # (AWS-compatible, K8s API), search RAG for privilege
                    # escalation and service discovery patterns beyond the
                    # initial service (S3 → IAM, STS, Lambda; K8s → RBAC).
                    _pd_vulns = [
                        v for v in self.dkg.query_nodes("Vulnerability")
                        if v.get("vuln_type") == "PlatformDiscovery"
                    ]
                    # Also detect cloud platforms from DKG Service nodes even if
                    # no PlatformDiscovery vuln was explicitly created. Cloud
                    # service banners (IMDS, S3, STS) are reliable signals.
                    if not _pd_vulns:
                        _cloud_svc_sigs = any(
                            cs in str(s).lower()
                            for cs in ("imds", "ec2 metadata", "s3-compatible",
                                       "aws sts", "lambda", "amazon ec2")
                            for s in self.dkg.query_nodes("Service")
                        )
                        if _cloud_svc_sigs:
                            _pd_vulns = [{"evidence": "cloud-service-banner-detected"}]
                    if _pd_vulns:
                        _pd_evidence = (_pd_vulns[0].get("evidence", "") or "").lower()
                        _platform_queries: list[str] = []
                        if "aws" in _pd_evidence or "s3" in _pd_evidence or "cloud-service" in _pd_evidence:
                            _platform_queries = [
                                "AWS IAM privilege escalation enumeration techniques",
                                "AWS cloud service discovery STS Lambda after S3 access",
                            ]
                        elif "kubernetes" in _pd_evidence or "k8s" in _pd_evidence:
                            _platform_queries = [
                                "Kubernetes RBAC enumeration privilege escalation",
                                "K8s API resource discovery after initial access",
                            ]
                        else:
                            # Generic cloud platform — search broadly
                            _platform_queries = [
                                "cloud platform service enumeration privilege escalation",
                            ]
                        _cloud_merged: list[dict] = []
                        _cloud_seen: set[str] = set()
                        for _pq in _platform_queries:
                            try:
                                _cr = rag.search(_pq, top_k=4, min_keyword_overlap=0.1)
                                for _r in _cr:
                                    _rt = (_r.get("title") or "").strip().lower()
                                    if _rt and _rt not in _cloud_seen:
                                        _cloud_seen.add(_rt)
                                        _cloud_merged.append(_r)
                            except Exception:
                                pass
                        if _cloud_merged:
                            # Merge cloud results with existing RAG results:
                            # cloud-specific knowledge about privilege
                            # escalation and multi-service exploration
                            # should appear alongside service-specific
                            # exploitation techniques.
                            _existing_titles = {
                                (r.get("title") or "").strip().lower()
                                for r in results
                            }
                            for _cr in _cloud_merged:
                                _crt = (_cr.get("title") or "").strip().lower()
                                if _crt and _crt not in _existing_titles:
                                    results.append(_cr)
                                    _existing_titles.add(_crt)
                            log.info(
                                "Cloud Platform RAG: %d results for platform %s",
                                len(_cloud_merged),
                                "AWS" if "aws" in _pd_evidence else
                                "K8s" if "kubernetes" in _pd_evidence else "generic",
                            )

                    if results:
                        # ── Probe RAG-suggested endpoints ─────────────────
                        # RAG technique entries often contain concrete paths
                        # (e.g. POST /wp-content/plugins/x/ee-upload-engine.php).
                        # Probe them proactively — if the endpoint exists,
                        # the LLM can plan exploitation directly.
                        _probe_paths: set[str] = set()
                        _path_re = re.compile(
                            r'(?:GET|POST|PUT|DELETE)\s+(/\S+)',
                            re.IGNORECASE,
                        )
                        _known_urls = {e.get("url", "") for e in self.dkg.query_nodes("Endpoint")}
                        # Derive the real HTTP base from discovered endpoints,
                        # not from target_url (which may lack a port, e.g.
                        # "http://localhost" vs the real "http://localhost:10103").
                        _base = target_url.rstrip("/")
                        _http_eps = [e.get("url", "") for e in self.dkg.query_nodes("Endpoint")
                                     if e.get("url", "").startswith("http")]
                        if _http_eps:
                            from urllib.parse import urlparse as _up
                            _parsed = _up(_http_eps[0])
                            _base = f"{_parsed.scheme}://{_parsed.netloc}"
                        for r in results:
                            for tech in r.get("techniques", []) or []:
                                for m in _path_re.finditer(str(tech)):
                                    path = m.group(1)
                                    # Skip placeholders like /{{path}} or /{{endpoint}}
                                    if "{{" in path or "}}" in path:
                                        continue
                                    if path not in _probe_paths:
                                        _probe_paths.add(path)

                        # Collect session cookies for authenticated probing
                        _cookies = ""
                        if self.client._session and self.client._session.cookie_jar:
                            jar = list(self.client._session.cookie_jar)
                            if jar:
                                _cookies = "; ".join(f"{c.key}={c.value}" for c in jar)

                        _probed: list[dict] = []
                        for path in list(_probe_paths)[:8]:
                            ep_url = f"{_base}{path}"
                            if ep_url in _known_urls:
                                continue
                            _known_urls.add(ep_url)
                            try:
                                curl_args: dict = {
                                    "url": ep_url, "follow_redirects": True,
                                    "insecure": True if "https" in _base else False,
                                }
                                if _cookies:
                                    curl_args["headers"] = f"Cookie: {_cookies}"
                                rp = await self._call_tool("curl_get", curl_args)
                                if rp.success:
                                    out = getattr(rp, "stdout", "") or ""
                                    st = 200
                                    fl = (out or "").split("\n")[0] if out else ""
                                    if fl.startswith("HTTP/"):
                                        pts = fl.split()
                                        if len(pts) >= 2 and pts[1].isdigit():
                                            st = int(pts[1])
                                    # 405 Method Not Allowed means the endpoint exists
                                    # but doesn't accept GET (likely POST-only)
                                    _probed.append({
                                        "url": ep_url, "status": st,
                                        "size": len(out),
                                    })
                            except Exception:
                                pass

                        if _probed:
                            # Endpoint exists if status is not 404 (includes 200, 403,
                            # 405, 500 — all indicate something is there).
                            _found = [p for p in _probed if p["status"] not in (404, 0)]
                            for p in _found:
                                label = p["url"].replace(_base, "").replace("/", "-")[:50]
                                self.dkg.add_node("Endpoint", f"ep-rag-{label}", {
                                    "url": p["url"], "method": "GET", "params": "",
                                    "sample_status": p["status"],
                                    "sample_response": f"HTTP {p['status']} ({p['size']} bytes)",
                                    "discovered_by": "rag-endpoint-probe",
                                })
                            # Build a concise summary for the plan prompt
                            _probed_lines = [
                                f"- {p['url']} → HTTP {p['status']} ({p['size']} bytes)"
                                for p in _probed[:8]
                            ]
                            probed_rag_endpoints = _probed_lines
                            log.info("RAG endpoint probe: %d/%d paths exist on target",
                                     len(_found), len(_probed))

                        lines = ["\n## Attack Pattern Knowledge (from RAG)\n"]
                        for r in results[:4]:
                            title = r.get("title", "") or ""
                            desc = (r.get("description", "") or "")
                            techniques = r.get("techniques", []) or []
                            tech_str = (" Techniques: " + "; ".join(str(t) for t in techniques[:3])) if techniques else ""
                            snippet = (desc[:250] + "...") if len(desc) > 250 else desc
                            lines.append(f"- **{title}**: {snippet}{tech_str}")
                            lines.append("")
                        lines.append("**CRITICAL: RAG results above contain proven attack techniques "
                                     "and credential combinations for the detected services. "
                                     "When the service name/type matches your target, the techniques "
                                     "and specific credentials listed MUST be used in your tasks. "
                                     "Only discard entries whose software/service type clearly does "
                                     "not match the target (e.g., MySQL techniques for a PostgreSQL target).")

                        # Extract concrete payload patterns from RAG results
                        _rag_payloads: list[str] = []
                        for r in results[:4]:
                            for tech in (r.get("techniques", []) or []):
                                tech_str = str(tech)
                                # Match payload-like patterns: ${...}, Fn::..., {{...}}
                                if (_re.search(r'\$\{[^}]+\}', tech_str)
                                        or 'Fn::' in tech_str
                                        or '{{' in tech_str):
                                    _rag_payloads.append(tech_str[:200])
                            # Also check description for payload patterns
                            desc = r.get("description", "") or ""
                            if _re.search(r'\$\{[^}]+\}', desc):
                                _rag_payloads.append(desc[:200])
                        if _rag_payloads:
                            _deduped = list(dict.fromkeys(_rag_payloads))  # preserve order, remove dups
                            lines.append("")
                            lines.append("**Extracted Payloads (use verbatim in tasks):**")
                            for _p in _deduped[:5]:
                                lines.append(f"  - `{_p}`")

                        rag_context = "\n".join(lines)
        except Exception:
            pass

        # If RAG returned nothing, provide a clear fallback so the prompt
        # doesn't have a blank "Attack Pattern Knowledge" section.
        if not rag_context:
            rag_context = ("\n## Attack Pattern Knowledge\n"
                           "No stored attack patterns matched the target's "
                           "technology stack. Use general exploitation knowledge "
                           "and web search for technique guidance.\n")

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
            if ("docker-distribution" in _ep_sig or "docker registry" in _ep_sig
                    or "registry/2.0" in _ep_sig or "/v2/" in _ep_sig
                    or "docker-registry" in _ep_sig) and "docker_registry" not in _artifact_seen:
                _artifact_lines.append(
                    "- **Docker Registry v2 API detected**: use `docker_registry` "
                    + "to pull, modify (backdoor), and push images. Then use "
                    + "`kubectl_get_pods` + `kubectl_exec` to trigger pod restart "
                    + "and read flag from the compromised container.")
                _artifact_seen.add("docker_registry")
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

        # Tool candidates derived from the current hypotheses — a compact
        # fallback so planning never degrades if the LLM skips registry lookup.
        _candidate_tools: list[str] = []
        for _v in self.vulnerabilities:
            if _v.suggested_tool and _v.suggested_tool not in _candidate_tools:
                _candidate_tools.append(_v.suggested_tool)
            _gt = self._guess_tool(_v.vuln_type)
            if _gt and _gt not in _candidate_tools:
                _candidate_tools.append(_gt)
        _candidate_tools_section = (
            "\n## Tool Candidates (hints — verify details in the registry)\n"
            "Candidate tools for the current hypotheses: "
            + (", ".join(_candidate_tools) if _candidate_tools
               else "(none — use tool_registry_list)")
            + "\nUse tool_registry_get(name) to fetch the exact parameter "
              "contract before writing each task. Do NOT guess parameter names.\n"
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
- Attack pattern knowledge (if RAG results matched your target's technology stack)
- Service version information from reconnaissance

Your job: COMBINE these sources when designing each task.
**CRITICAL — Unfamiliar Services/Technologies:** If you are not 100% certain how to exploit a
discovered service or technology, call `knowledge_search` tool FIRST with an empty category
to search the knowledge base for concrete exploitation techniques before writing tasks for it.
Do NOT assume — services like Oracle TNS, CouchDB, Elasticsearch, Redis, and MongoDB each
have protocol-specific exploitation methods that differ from generic HTTP exploitation.
**CRITICAL for WeakAuth/default credentials:** When RAG results contain specific credential
combinations (username:password pairs), you MUST include EVERY listed combination in your
batch credential test. Do NOT rely on your own memory of "common passwords" — the RAG
entries are the authoritative source for service-specific defaults.
- When an attack pattern matches a discovered service: use the pattern's technique as the task's approach. The RAG result title and techniques field tell you exactly what to do.
- **Payload injection**: If a vulnerability lists "Payloads:" in its summary or the Attack Pattern Knowledge section contains "Extracted Payloads", those are proven exploitation strings validated against the target's technology. Include them verbatim in the corresponding task's params["data"] or params["payload"]. Do NOT modify or truncate them.
- When patterns do NOT match: rely on general vulnerability exploitation principles for that vulnerability type.
- Service versions are primary signals: an outdated service with known weaknesses should generate high-priority exploitation tasks targeting those specific weaknesses.
- If the analyze phase produced attack_paths, translate each path into a chain of tasks with dependent_task_ids reflecting the path's step ordering. A 4-step path becomes 4 tasks where each depends on the previous one.
- Tasks targeting DIFFERENT services or vulnerabilities with no shared prerequisites should have empty dependent_task_ids so they can execute in parallel.

## Tool Discovery
The full tool list is NOT embedded in this prompt — use the read-only
registry tools to discover tools and their exact parameter contracts:
- tool_registry_list(domain=..., capability=..., keyword=...) — find
  candidate tools for the current scenario.
- tool_registry_get(name) — fetch the FULL contract (exact parameter names,
  required vs optional, aliases) for one tool.
{_candidate_tools_section}

{chr(10).join(['## RAG-Endpoint Probe Results (verified — these ENDPOINTS EXIST on the target):'] + probed_rag_endpoints) if probed_rag_endpoints else ''}

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
id, dependent_task_ids, instruction, tool, params, reason, priority.
Do NOT include "status", "dependencies", or any other key — the system
owns task status. dependent_task_ids is a JSON array of strings (empty
array for independent tasks). params is a JSON object of tool arguments.

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
        try:
            content, _, _ = await self._orch._generate_with_registry_lookup(
                prompt=prompt,
                system_prompt=SYSTEM_PROMPT_ORCHESTRATOR_UNIFIED,
                stage="plan",
            )
        except Exception as e:
            log.warning("Plan generation LLM call failed: %s — retrying with shorter prompt", e)
            self._maybe_compress()
            try:
                # Retry with top-5 vulns only (shorter prompt)
                short_prompt = prompt.split("## Analyzed Vulnerabilities")[0]
                if self.vulnerabilities:
                    short_vulns = self._format_vulnerability_summary_short(max_items=5)
                    short_prompt += f"## Analyzed Vulnerabilities\n{short_vulns}\n"
                short_prompt += prompt.split("## Available Tools")[1] if "## Available Tools" in prompt else ""
                content, _ = self.llm.generate(prompt=short_prompt, system_prompt=SYSTEM_PROMPT_ORCHESTRATOR_UNIFIED, timeout=180.0, stage="plan")
            except Exception as e2:
                log.warning("Plan generation retry also failed: %s — using hardcoded fallback", e2)
                content = ""

        try:
            _plan_model, _schema_err = parse_plan_tasks(content)
            if _plan_model is None:
                self._task_log_event(
                    "warning", "schema_violation",
                    boundary="plan", error=str(_schema_err)[:400],
                )
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
            except Exception:
                pass
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
                        t.action["tool"] = self._guess_tool(t.vuln_type)
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
                            "tool": v.suggested_tool or self._guess_tool(v.vuln_type),
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

    def _guess_tool(self, vuln_type: str) -> str:
        """Map vuln type to a default tool when no suggested_tool is available."""
        vt = vuln_type.lower()
        if "sql" in vt: return "sqlmap_test"
        if "xss" in vt: return "xss_reflection_test"
        if "cmdi" in vt or "command" in vt: return "command_injection_test"
        if "ssti" in vt: return "send_payload"
        if "lfi" in vt or "path" in vt: return "curl_get"
        if "idor" in vt: return "curl_get"
        if "ssrf" in vt: return "curl_get"
        return "curl_get"

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
        except Exception:
            pass
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
                    rag = get_rag()
                    rag_results = rag.search(f"{svc_name} exploitation authentication bypass techniques", top_k=3, category="", min_keyword_overlap=0.1)
                    if rag_results:
                        rag_text = "\n".join(
                            f"- {r.get('title','')}: {r.get('description','')[:200]}"
                            for r in rag_results[:3]
                        )
                        rag_hint = (
                            f"\n\n[META-COGNITION] The tool failure suggests unfamiliarity with {svc_name}. "
                            f"RAG knowledge about {svc_name} exploitation:\n{rag_text}\n"
                            f"Based on this knowledge, re-evaluate whether the task can be fixed "
                            f"by using the correct tool/protocol for {svc_name}."
                        )
                except Exception:
                    pass

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
Parameters used: {params_str}
Tool output:
{output_trunc}
{timeout_hint}
{rag_hint}
Classify:
- "fixable" if the tool was called with wrong/malformed parameters
  (e.g. wrong command syntax, non-existent file path, missing required
  args, command would cause an interactive prompt)
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
{{"fixable": true/false, "corrected_params": {{...}}, "partial_success": true/false, "credentials": {{...}}, "reason": "..."}}"""

        try:
            content, _ = self.llm.generate(
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
                    "corrected_params": result["corrected_params"],
                    "reason": result.get("reason", ""),
                }
            if result.get("partial_success"):
                return {
                    "fixable": False,
                    "partial_success": True,
                    "credentials": result.get("credentials", {}),
                    "reason": result.get("reason", ""),
                }
        except Exception:
            pass
        return None

    async def _extract_credentials_from_task(
        self, task: Task, raw_stdouts: list[str]
    ) -> None:
        """Extract discovered credentials from task stdout → DKG + CTEG.

        Regex pre-filters for credential patterns, then uses a lightweight
        LLM call (classifier profile, isolated session) to extract structured
        username:password pairs. Only fires for tools that commonly discover
        credentials (shell_exec, ssh_exec, test_credential).

        Extracted credentials are stored as DKG Credential nodes and in CTEG,
        making them available for $credentials.* placeholder resolution in
        subsequent tasks.
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
            # CTEG task recording is handled by the orchestrator's main loop
            # at orchestrator.py:630 via TaskRecord dataclass — no explicit
            # commit_task call needed here.
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

        # ── Store in DKG + CTEG ─────────────────────────────────────
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
                self.cteg.add_credential(
                    host=self.target_host,
                    port=int(_port) if _port and _port.isdigit() else 0,
                    service_type=_svc_name,
                    username=username, password=password,
                    source="task_discovery",
                )
            except Exception:
                pass
            log.info(
                "Credential extracted from task output: %s:*** → DKG + CTEG",
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

        Quality heuristic (in priority order):
        1. Tasks WITH a tool sort before tasks without (higher quality)
        2. Tasks with fewer dependencies sort first
        3. After sorting, keep at most *max_total* total tasks; excess
           pending tasks are trimmed (done/failed are always preserved).

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

        def _quality_key(t):
            deps = len(dependency_task_ids(t))
            has_tool = 1 if (t.action or {}).get("tool", "") else 0
            # -has_tool: tasks WITH tool (key=-1) sort BEFORE tasks without (key=0)
            return (deps, -has_tool)

        _pending.sort(key=_quality_key)
        _to_remove = set(t.id for t in _pending[_keep_pending:])
        trimmed = _pending[:_keep_pending]
        _removed_count = len(_to_remove)

        if _removed_count > 0:
            _removed_tools = [
                (t.action or {}).get("tool", "?") for t in _pending[_keep_pending:]
            ]
            print(f"\n[PLAN-CAP] Trimmed {_removed_count} low-quality pending task(s): {_removed_tools}")

        return [t for t in tasks if t.id not in _to_remove]

    async def _review_and_update_plan(
        self, task: Task, success: bool, task_result: str = ""
    ) -> None:
        """LLM reviews and updates the plan after every task (VulnBot-style).

        Called after each task completes, regardless of success or failure.
        The LLM sees what was learned and can add/remove/reorder tasks.
        """
        if not getattr(self, 'exploitation_plan', None):
            return

        # Local attack-path replan: paths that became stale/rejected release
        # the tasks blocked on them into the replanning queue.
        try:
            self._migrate_blocked_path_tasks()
        except Exception:
            pass

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
        except Exception:
            pass

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
        except Exception:
            pass
        # O1.2: diff-based discoveries — the review LLM sees exactly which
        # nodes this task added to the world model. Falls back to the legacy
        # "latest endpoints/credentials" view when there is no per-task
        # baseline (e.g. the plan-exhausted review).
        _before_nodes = getattr(self, "_cognition_before", None)
        try:
            new_discoveries = render_new_discoveries(_before_nodes, self.dkg)
        except Exception:
            new_discoveries = ""
        self._cognition_before = None
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
        except Exception:
            pass

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
        except Exception:
            pass

        # O1.3: unified cognition snapshot — beliefs (hypotheses with
        # confidence/status), plan summary, defense and preserved rationale,
        # so the review LLM plans from the same world model as execution.
        _belief_text = ""
        try:
            _belief_text = self._belief_context(compact=True)
            if _belief_text:
                _belief_text = f"\n{_belief_text}\n"
        except Exception:
            pass

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
            f"Output the COMPLETE updated task list as a JSON array. "
            f"Each task object MUST contain ONLY these keys: id, dependent_task_ids, "
            f"instruction, tool, params, reason, priority. Do NOT include status or "
            f"dependencies — the system owns task status. "
            f"Preserve done/failed tasks. Output ONLY valid JSON array."
        )

        try:
            self._maybe_compress()
            content, _, _ = await self._orch._generate_with_registry_lookup(
                prompt=prompt,
                system_prompt=SYSTEM_PROMPT_PLANNER,
                stage="plan_review",
            )
            _review_model, _schema_err = parse_plan_tasks(content)
            if _review_model is None:
                self._task_log_event(
                    "warning", "schema_violation",
                    boundary="plan_review", error=str(_schema_err)[:400],
                )
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
