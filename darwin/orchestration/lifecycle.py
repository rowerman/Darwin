"""LifecycleCoordinator — solo-mode lifecycle and shared utilities.

Owns run()/the main loop, termination and chain-mode decisions, state/belief/truncation contexts, task logging, metrics, tool-dependency checks and JSON extraction helpers. State and cross-coordinator calls are forwarded to the shared Orchestrator context.
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

class LifecycleCoordinator(CoordinatorContext):
    _PHASE_RATIOS = {
        "recon": 0.20,
        "service_research": 0.10,
        "analyze": 0.10,
        "vulnerability_research": 0.10,
        "exploit": 0.45,
        "finalize": 0.05,
    }

    def _remaining_budget(self) -> float:
        deadline = getattr(self._orch, "_run_deadline", 0.0)
        if not deadline:
            return float(self.time_budget)
        return max(0.0, deadline - time.monotonic())

    async def _run_phase_with_budget(self, name: str, awaitable):
        """Run one phase under its allocation and preserve its return value."""
        base = self.time_budget * self._PHASE_RATIOS[name]
        used = getattr(self._orch, "_phase_used", {}).get(name, 0.0)
        carry = getattr(self._orch, "_phase_carryover", 0.0)
        allowance = min(self._remaining_budget(), max(0.0, base - used) + carry)
        self._orch._phase_carryover = 0.0
        if allowance <= 0:
            close = getattr(awaitable, "close", None)
            if close:
                close()
            self._task_log_event("warning", "phase_timeout", phase=name,
                                 allocated_s=0.0)
            return False, None
        started = time.monotonic()
        value = None
        stop_heartbeat = asyncio.Event()

        async def _heartbeat():
            while not stop_heartbeat.is_set():
                try:
                    await asyncio.wait_for(stop_heartbeat.wait(), timeout=15.0)
                except asyncio.TimeoutError:
                    print(
                        f"[RUN] phase={name} elapsed={time.time() - self.start_time:.0f}s "
                        f"remaining={max(0.0, self._remaining_budget()):.0f}s",
                        flush=True,
                    )

        heartbeat_task = asyncio.create_task(_heartbeat())
        try:
            value = await asyncio.wait_for(awaitable, timeout=allowance)
        except asyncio.CancelledError:
            elapsed = time.time() - self.start_time
            result = TaskResult(
                success=False, steps=self.step_count,
                tokens_used=self.llm.token_count,
                time_elapsed=elapsed,
                phase_at_end=self.phase,
                error="Run cancelled",
            )
            self._task_log_event("warning", "run_cancelled", elapsed_s=elapsed)
        except asyncio.TimeoutError:
            self._task_log_event("warning", "phase_timeout", phase=name,
                                 allocated_s=allowance)
            return False, None
        finally:
            stop_heartbeat.set()
            heartbeat_task.cancel()
            elapsed = time.monotonic() - started
            self._orch._phase_used[name] = used + min(elapsed, allowance)
            unused = max(0.0, allowance - elapsed)
            self._orch._phase_carryover = unused
        return True, value

    async def run(
        self, task_description: str, target_url: str,
        username: str | None = None, password: str | None = None,
        port_range: str | None = None,
    ) -> TaskResult:
        """Run penetration test against a single target.

        Args:
            port_range: Optional nmap port range for benchmark mode.
                        When set, scans only those ports (e.g. "8080-8090").
                        When None, full 65535-port scan.
        """
        self.start_time = time.time()
        self._run_started_monotonic = time.monotonic()
        self._run_deadline = self._run_started_monotonic + self.time_budget
        self.llm._deadline = self._run_deadline
        self._phase_carryover = 0.0
        self._phase_used = {name: 0.0 for name in self._PHASE_RATIOS}
        self._solo_cycle_context_injected = False
        self.target_url = target_url
        self._provided_username = username
        self._provided_password = password

        ts = time.strftime("%Y%m%d_%H%M%S", time.localtime())
        self._task_log_path = f"checkpoints/task_{ts}.json"
        self._task_description = task_description
        self._task_log_event("info", "task_start", target=target_url, description=task_description)

        # Initialize phase logger with config-driven settings
        _log_dir = "log"
        _log_level = "INFO"
        _log_thoughts = True
        try:
            import yaml
            _config_path = getattr(self, "_config_path", "config/darwin.yaml")
            if os.path.exists(_config_path):
                with open(_config_path, encoding="utf-8") as _fh:
                    _cfg = yaml.safe_load(_fh) or {}
                _darwin = _cfg.get("darwin", {})
                _log_dir = _darwin.get("log_dir", "log")
                _log_level = _darwin.get("log_level", "INFO")
                _log_thoughts = _darwin.get("log_thoughts", True)
        except Exception:
            pass
        self.phase_logger = PhaseLogger(
            run_id=ts,
            log_dir=_log_dir,
            log_level=_log_level,
        )
        # P3: chain-of-thought logging — declarative wiring only. All logic
        # lives in ThoughtLogger; LLMSession just notifies it.
        self.thought_logger = ThoughtLogger(
            run_id=ts,
            log_dir=_log_dir,
            enabled=bool(_log_thoughts),
        )
        self.llm.thought_logger = self.thought_logger
        self.phase_logger.set_shared_metadata(
            target=target_url,
            model=getattr(self.llm, 'model', ''),
            provider=getattr(self.llm, 'provider', ''),
        )
        self.engagement_id = getattr(self, "engagement_id", "") or f"engagement-{ts}"
        self.dkg.set_scope(
            engagement_id=self.engagement_id,
            target_scope=target_url,
            environment_scope=getattr(self.dkg, "scope", {}).get("environment_scope", ""),
        )

        self._check_tool_dependencies()
        if self._missing_tools:
            self._task_log_event("warning", "missing_tools", tools=list(self._missing_tools))

        # MCP: parallel connection, non-blocking
        mcp_configs = load_mcp_config("config/mcp_servers.yaml")
        enabled_mcp = [c for c in mcp_configs if c.enabled]
        if enabled_mcp:
            log.info("Connecting to %d MCP server(s) in parallel: %s",
                     len(enabled_mcp), ", ".join(c.name for c in enabled_mcp))
            connected = await self.mcp_pool.connect_all(
                mcp_configs, per_server_timeout=30, total_timeout=90,
            )
            if connected > 0:
                tools = self.mcp_pool.get_tool_names()
                log.info("MCP: %d server(s) connected, %d tools available: %s",
                         connected, len(tools), ", ".join(sorted(tools)[:15]))
        else:
            log.info("No MCP servers enabled in config/mcp_servers.yaml")

        # Preload RAG in background (takes ~45s — run in parallel with bootstrap)
        _rag_task: asyncio.Task | None = None
        try:
            from darwin.rag import get_rag
            _rag_task = asyncio.create_task(asyncio.to_thread(get_rag))
        except Exception:
            pass

        self.phase = OrchestratorPhase.RECON
        result: TaskResult | None = None

        try:
            # ── Phase 1: Bootstrap scan (nmap + HTTP probe) ──
            _, _ = await self._run_phase_with_budget(
                "recon", self._bootstrap_scan(target_url, port_range=port_range)
            )
            self._task_log_event("info", "bootstrap_done",
                dkg_summary=self.dkg.summary(), step=self.step_count)
            self.dkg.save(self._checkpoint_path("bootstrap"))

            # ── Phase log: scan ──
            if self.phase_logger:
                _hosts = len(self.dkg.query_nodes("Host"))
                _svcs = len(self.dkg.query_nodes("Service"))
                _eps = len(self.dkg.query_nodes("Endpoint"))
                _svc_lines = []
                for s in self.dkg.query_nodes("Service")[:20]:
                    _svc_lines.append(
                        f"  {s.get('port','?')}/{s.get('protocol','tcp')} "
                        f"{s.get('service_name','unknown')} "
                        f"{s.get('version','')} {s.get('banner','')}".strip()
                    )
                _bootstrap_text = (
                    f"[BOOTSTRAP] {_hosts} host(s), {_svcs} service(s), {_eps} endpoint(s)\n"
                    + "\n".join(_svc_lines)
                )
                if _svcs > 20:
                    _bootstrap_text += f"\n  ... and {_svcs - 20} more services"
                self.phase_logger.log_phase("bootstrap", _bootstrap_text,
                    metadata={"hosts": _hosts, "services": _svcs, "endpoints": _eps})

            # ── Phase 1.5: Deep Recon (dirb, nikto, form_extract) ──
            await self._deep_recon()

            # ── Phase log: recon ──
            if self.phase_logger:
                _eps = self.dkg.query_nodes("Endpoint")
                _ep_lines = []
                for ep in _eps[:30]:
                    _url = ep.get("url", "") or ep.get("uri", "")
                    _ep_lines.append(f"  {_url[:100]}")
                _recon_text = (
                    f"[DEEP RECON] {len(_eps)} total endpoints\n"
                    + "\n".join(_ep_lines)
                )
                if len(_eps) > 30:
                    _recon_text += f"\n  ... and {len(_eps) - 30} more"
                self.phase_logger.log_phase("deep_recon", _recon_text,
                    metadata={"endpoints": len(_eps)})

            # ── Phase 1.55: Cloud Platform Discovery ──
            # Check endpoints for cloud-like response signatures and add
            # a vulnerability hint so the LLM explores additional services
            # on the same endpoint (e.g. S3 → IAM, STS, Lambda).
            await self._cloud_discovery_hint()

            # ── Phase 1.6: Defense Detection (DPM) ──
            await self._detect_defenses()

            # ── Phase log: defense detection ──
            if self.phase_logger:
                _waf_type = self.defense_state.waf_type or "none"
                _complexity = getattr(self.defense_state, 'defense_complexity', 0)
                _honeypot = getattr(self.defense_state, 'has_honeypot', False)
                self.phase_logger.log_phase("defense_detection",
                    f"WAF: {_waf_type} | complexity: {_complexity:.2f} | "
                    f"has_honeypot: {_honeypot}",
                    metadata={"waf_type": _waf_type,
                              "complexity": _complexity,
                              "has_honeypot": _honeypot})

            # Query CTEG for cross-task experience
            state = self._get_state()
            tech_query = " ".join(
                s.version or s.banner
                for s in state.services[:5]
                if s.version or s.banner
            )
            # P4: scenario-matched CTEG retrieval — only patterns whose
            # vuln/defense/tech/domain fingerprint overlaps the current task
            # are injected (hard gate, no placeholder when empty).
            cteg_hints = self.memory.experience_hints(
                profile=build_scenario_profile(
                    state, self.vulnerabilities, self.defense_state
                )
            )
            if cteg_hints.get("bypass_strategies") or cteg_hints.get("exploit_strategies"):
                self._task_log_event("info", "cteg_hints", hints=cteg_hints)

            # Load known credentials from CTEG (cross-task memory)
            # Only inject credentials whose service/port actually EXISTS on the current
            # target. A credential for MSSQL:10119 is useless (and noisy) when the
            # current target is an Apache HTTP server on port 10108.
            _current_ports = {str(s.port) for s in state.services if s.port}
            _current_svc_names = {
                (s.get("service_name", "") or "").lower()
                for s in self.dkg.query_nodes("Service")
                if s.get("service_name")  # exclude nodes without service_name (empty
            }                              # string matches ALL strings in Python)
            _cteg_creds = self.cteg.get_credentials(host=self.target_host)
            _cteg_creds_filtered = []
            for _c in _cteg_creds[:10]:
                _c_port = str(_c.get("port", ""))
                _c_svc = (_c.get("service_type", "") or "").lower()
                # Only inject if the port matches a currently open port, OR the
                # service type matches a discovered service
                _port_match = _c_port in _current_ports
                _svc_match = any(
                    _c_svc in _sn or _sn in _c_svc
                    for _sn in _current_svc_names
                ) if _current_svc_names else False
                if not _port_match and not _svc_match:
                    log.debug("CTEG: skipping credential %s:%s (port %s/%s not on target)",
                              _c['username'], _c['service_type'], _c_port, _c_svc)
                    continue
                _cteg_creds_filtered.append(_c)
                _cred_id = f"cred-cteg-{_c['username']}@{_c['host']}:{_c['port']}"
                self.dkg.add_node("Credential", _cred_id, {
                    "username": _c["username"],
                    "password": _c["password"],
                    "host": _c["host"],
                    "port": _c["port"],
                    "cred_type": _c["service_type"],
                    "source": "cteg_memory",
                })
            if _cteg_creds_filtered:
                log.info("CTEG: loaded %d matching credentials for %s (filtered from %d total)",
                         len(_cteg_creds_filtered), self.target_host, len(_cteg_creds))
            # Use filtered list for hints
            _cteg_creds = _cteg_creds_filtered

            # Inject CTEG credentials into cteg_hints so the LLM sees them
            if _cteg_creds:
                _cred_lines = []
                for _c in _cteg_creds[:8]:
                    _cred_lines.append(
                        f"  {_c['username']}:{_c['password']} → "
                        f"{_c['service_type']}://{_c['host']}:{_c['port']} "
                        f"(ONLY valid for {_c['service_type']} on port {_c['port']} — "
                        f"do NOT reuse for SSH, HTTP, or other services)"
                    )
                cteg_hints["known_credentials"] = _cred_lines

            # ── Main Loop: B-driven mode switching ────────────────
            self._loop_count = 0
            # Try to read max_iterations and chain_mode from darwin.yaml config
            _config_max_loops = 30
            _chain_mode_config = "auto"
            _chain_max_flags = 10
            try:
                import yaml
                _cfg_path = "config/darwin.yaml"
                if __import__("os").path.exists(_cfg_path):
                    with open(_cfg_path, encoding="utf-8") as _fh:
                        _cfg = yaml.safe_load(_fh)
                    _darwin = _cfg.get("darwin", {}) if isinstance(_cfg, dict) else {}
                    _configured = _darwin.get("max_iterations")
                    if isinstance(_configured, int) and _configured > 0:
                        _config_max_loops = _configured
                    _chain_mode_config = _darwin.get("chain_mode", "auto")
                    _chain_max_flags = int(_darwin.get("chain_max_flags", 10))
            except Exception:
                pass
            MAX_LOOPS = _config_max_loops
            self._known_flags: set[str] = set()

            # ── After recon, before main loop: detect chain topology ──
            # NOTE: scaling votes are no longer seeded before the first
            # loop iteration.  The hysteresis mechanism (2 consecutive
            # matching votes) naturally requires 2+ iterations to switch
            # modes, so the first iteration is always Solo.  This gives
            # the LLM a chance to exploit the target before committing
            # to expensive multi-agent spawning.

            # Detect chain topology for multi-flag awareness
            self._detect_chain_topology(_chain_mode_config)
            if self._chain_mode:
                log.info("Chain topology detected: %d services, "
                         "will continue after intermediate flags (max=%d)",
                         self._chain_services_total, _chain_max_flags)
                # Store chain_max_flags for use in termination checks
                self._chain_max_flags = _chain_max_flags
            else:
                self._chain_max_flags = _chain_max_flags  # keep default for safety

            # Snapshot DKG counts after bootstrap so first cycle summary only
            # counts discoveries made DURING the loop (not bootstrap + deep_recon).
            self._prev_endpoint_count = len(self.dkg.query_nodes("Endpoint"))
            self._prev_credential_count = len(self.dkg.query_nodes("Credential"))
            self._prev_vulnerability_count = len(self.dkg.query_nodes("Vulnerability"))

            while not self._should_terminate(result, MAX_LOOPS):
                self._loop_count += 1

                # Check DKG for flags found by sub-agents in previous iterations
                dkg_flags = [
                    f.get("value", "") for f in self.dkg.query_nodes("Flag")
                    if f.get("verified") or f.get("value", "").startswith("flag{")
                ]
                for fv in dkg_flags:
                    if fv and fv not in self._known_flags:
                        self._known_flags.add(fv)
                        if not self._chain_mode:
                            # ORIGINAL BEHAVIOR: stop on first flag
                            self.phase = OrchestratorPhase.DONE
                            result = TaskResult(
                                success=True, flag=fv, steps=self.step_count,
                                tokens_used=self.llm.token_count,
                                time_elapsed=time.time() - self.start_time,
                            )
                        else:
                            # CHAIN MODE: record intermediate flag, continue
                            self._captured_flags.append(fv)
                            log.info("Chain mode: captured intermediate flag %s (%d/%d services)",
                                     fv[:40], len(self._captured_flags),
                                     max(self._chain_services_total, 1))
                            # Check if all exploitable services are exhausted
                            if self._count_unexploited_services() == 0:
                                self._chain_exhausted = True
                                log.info("Chain mode: all services exhausted, chain complete")
                if result and result.success:
                    # In chain mode, only break if chain exhausted
                    if self._chain_mode:
                        if self._chain_exhausted:
                            # Build final result with last captured flag
                            final_flag = self._captured_flags[-1] if self._captured_flags else ""
                            result = TaskResult(
                                success=True, flag=final_flag, steps=self.step_count,
                                tokens_used=self.llm.token_count,
                                time_elapsed=time.time() - self.start_time,
                            )
                            result.all_flags = list(self._captured_flags)
                            break
                        # Otherwise continue the loop
                    else:
                        break

                # Solo-only loop (single-agent control plane)
                self._task_log_event("info", "loop_iteration", loop=self._loop_count)

                # Skip if solo already exhausted — avoid wasted iterations
                if self._solo_exhausted:
                    log.info("Solo mode exhausted, skipping loop %d", self._loop_count)
                    continue

                # Phase 1: Service research → known CVEs for each service (once)
                # Re-trigger if new services discovered since last analysis
                if self._analyze_done and self._reanalyze_count < self._max_reanalyze:
                    _current_svc = len(self.dkg.query_nodes("Service"))
                    _current_eps = len(self.dkg.query_nodes("Endpoint"))
                    _new_total = _current_svc + _current_eps
                    if _new_total > self._analyze_service_snapshot + 2:
                        log.info("New services/endpoints detected (%d→%d), re-running analysis",
                                 self._analyze_service_snapshot, _new_total)
                        self._analyze_done = False
                        self._svc_research_done = False
                        self._reanalyze_count += 1

                if not self._svc_research_done:
                    _, _ = await self._run_phase_with_budget(
                        "service_research", self._service_research()
                    )
                    self._svc_research_done = True

                    # ── Phase log: service research ──
                    if self.phase_logger:
                        _cves = []
                        for a in self.dkg.query_nodes("Analysis"):
                            if a.get("type") == "cve_findings" and a.get("content"):
                                _cves.append(a.get("content", "")[:500])
                        _cve_text = "\n".join(_cves[:10]) if _cves else "(no CVEs found)"
                        self.phase_logger.log_phase("service_research", _cve_text,
                            metadata={"cve_count": len(_cves)})

                # Phase 2: Analyze recon data + service research → vuln hypotheses
                if not self._analyze_done:
                    self.phase = OrchestratorPhase.ANALYZE
                    _, _ = await self._run_phase_with_budget("analyze", self._analyze_phase())
                    self._analyze_done = True
                    # Snapshot current discovery count so we can detect
                    # significant new services/endpoints for re-analysis
                    self._analyze_service_snapshot = (
                        len(self.dkg.query_nodes("Service"))
                        + len(self.dkg.query_nodes("Endpoint"))
                    )

                    # ── Phase log: analyze ──
                    if self.phase_logger:
                        _vuln_lines = []
                        for v in self.vulnerabilities[:20]:
                            _vuln_lines.append(
                                f"[{v.vuln_type}] {v.endpoint} param={v.param} "
                                f"conf={v.confidence:.0%}"
                            )
                        _vuln_text = "\n".join(_vuln_lines) if _vuln_lines else "(no vulnerabilities)"
                        if len(self.vulnerabilities) > 20:
                            _vuln_text += f"\n... and {len(self.vulnerabilities) - 20} more"
                        self.phase_logger.log_phase("analyze", _vuln_text,
                            metadata={"vuln_count": len(self.vulnerabilities)})

                # Phase 3: Research each vulnerability with tools
                if self.vulnerabilities and not self._research_done:
                    log.info("[PHASE] _research_phase START")
                    _, _ = await self._run_phase_with_budget(
                        "vulnerability_research", self._research_phase()
                    )
                    self._research_done = True
                    log.info("[PHASE] _research_phase DONE")

                    # ── Phase log: research ──
                    if self.phase_logger:
                        _researched = sum(
                            1 for v in self.vulnerabilities
                            if v.research_techniques or v.research_cves
                        )
                        self.phase_logger.log_phase("research_phase",
                            f"Researched {_researched}/{len(self.vulnerabilities)} vulnerabilities",
                            metadata={"vulns_total": len(self.vulnerabilities),
                                      "vulns_researched": _researched})

                # Phase 4: Runtime-driven loop (plan → execute → evaluate → replan)
                self.phase = OrchestratorPhase.EXPLOIT
                phase_ok, phase_result = await self._run_phase_with_budget(
                    "exploit", self._run_with_runtime(target_url, cteg_hints)
                )
                if phase_ok and isinstance(phase_result, TaskResult):
                    result = phase_result
                if not phase_ok:
                    result = TaskResult(
                        success=False, steps=self.step_count,
                        tokens_used=self.llm.token_count,
                        time_elapsed=time.time() - self.start_time,
                        phase_at_end=self.phase, error="exploit phase budget exceeded",
                    )
                    self._solo_exhausted = True

                # Allow up to 3 solo iterations before marking exhausted
                self._solo_iterations += 1
                if result is None or not result.success:
                    if self._solo_iterations >= 5:
                        self._solo_exhausted = True
                    # Fast exhaust: 2 consecutive plan-exhausted runs with 0 done tasks
                    _done_count = sum(
                        1 for t in (self.exploitation_plan.tasks if self.exploitation_plan else [])
                        if t.status is TaskStatus.SUCCESS
                    )
                    _prev_done = getattr(self, '_prev_solo_done_count', -1)
                    if result is None and _done_count == _prev_done:
                        _empty_runs = getattr(self, '_solo_empty_runs', 0) + 1
                        self._solo_empty_runs = _empty_runs
                        if _empty_runs >= 2:
                            log.info("Solo mode: 2 runs with no new progress — marking exhausted")
                            self._solo_exhausted = True
                    else:
                        self._solo_empty_runs = 0
                    self._prev_solo_done_count = _done_count
                else:
                    self._solo_exhausted = True

                # Checkpoint DKG after each loop iteration
                self.dkg.save(self._checkpoint_path(f"loop_{self._loop_count}"))
                self._persist_plan(f"loop_{self._loop_count}")

            # ── Last resort: generic flag search ──────────────────
            if result is None or not result.success:
                finalize_base = self.time_budget * self._PHASE_RATIOS["finalize"]
                allowance = min(
                    self._remaining_budget(), finalize_base
                    + getattr(self._orch, "_phase_carryover", 0.0)
                )
                self._orch._phase_carryover = 0.0
                if allowance > 0:
                    try:
                        flag_result = await asyncio.wait_for(
                            self._check_response_for_flag(target_url), timeout=allowance
                        )
                        if flag_result:
                            result = flag_result
                    except asyncio.TimeoutError:
                        self._task_log_event("warning", "phase_timeout",
                                             phase="finalize", allocated_s=allowance)

        except asyncio.TimeoutError:
            elapsed = time.time() - self.start_time
            if elapsed >= self.time_budget * 0.95:
                error_msg = "Time budget exceeded"
            else:
                error_msg = f"Internal timeout at {elapsed:.0f}s (budget: {self.time_budget}s)"
            result = TaskResult(
                success=False, steps=self.step_count,
                tokens_used=self.llm.token_count,
                time_elapsed=elapsed,
                phase_at_end=self.phase, error=error_msg,
            )
        except Exception as e:
            import traceback
            log.warning("Task failed with error: %s", e)
            log.warning("Traceback: %s", traceback.format_exc())
            result = TaskResult(
                success=False, steps=self.step_count,
                tokens_used=self.llm.token_count,
                time_elapsed=time.time() - self.start_time,
                phase_at_end=self.phase, error=str(e),
            )
        finally:
            # Both clients own independent aiohttp sessions.  Always close
            # them before tearing down the optional MCP pool.
            for _http_client in (self.client, self.probe_client):
                try:
                    await _http_client.close()
                except Exception as _exc:
                    log.warning("HTTP client cleanup failed: %s", _exc)
            if self.mcp_pool.is_connected:
                await self.mcp_pool.disconnect_all()

        # Write task log
        if result is None:
            result = TaskResult(
                success=False, steps=self.step_count,
                tokens_used=self.llm.token_count,
                time_elapsed=time.time() - self.start_time,
                phase_at_end=self.phase,
                error="No result produced",
            )
        self._apply_final_defense_state(result)
        self._task_log_event("info" if result.success else "error", "task_end",
            success=result.success,
            flag=result.flag,
            steps=result.steps,
            tokens_used=result.tokens_used,
            time_elapsed=result.time_elapsed,
            error=result.error,
        )

        # ── Phase log: write run summary ──
        if self.phase_logger:
            self.phase_logger.write_summary(
                task_result=result,
                dkg_summary=self.dkg.summary(),
                extra_metadata={
                    "phase_at_end": self.phase.value,
                    "loop_count": getattr(self, '_loop_count', 0),
                    "solo_iterations": self._solo_iterations,
                    "step_count": self.step_count,
                },
            )

        self._task_log_write()

        # Commit task to CTEG for cross-task learning
        if result and self.step_count > 0:
            vuln_types = [v.vuln_type for v in self.vulnerabilities]
            # Extract technology stack from discovered services
            tech_stack = []
            for s in self.dkg.query_nodes("Service"):
                ver = s.get("version", "") or s.get("banner", "")
                if ver and ver not in ("unknown", "tcpwrapped", "ssh"):
                    tech_stack.append(ver)
            # Extract key findings from task log
            key_findings = []
            if result.flag:
                key_findings.append(f"flag found: {result.flag[:30]}...")
            if result.waf_bypassed:
                key_findings.append(f"WAF bypassed: {self.defense_state.waf_type}")
            # Build exploit chain from LLM loop steps
            exploit_chain = getattr(self, '_exploit_chain', [])
            task_record = TaskRecord(
                task_id=f"task-{int(self.start_time)}",
                benchmark="unknown",
                vulnerability_types=vuln_types,
                outcome="success" if result.success else "failure",
                defense_encountered=self.defense_state.to_dict(),
                timestamp=time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(self.start_time)),
                technology_stack=tech_stack,
                key_findings=key_findings,
                exploit_chain=exploit_chain,
            )
            new_patterns = self.cteg.commit_task(task_record)
            self._cteg_committed = new_patterns
            if new_patterns > 0:
                log.info("CTEG: extracted %d new patterns from task", new_patterns)

        return result

    def _apply_final_defense_state(self, result: TaskResult) -> None:
        """Project the final DPM state onto every returned task result."""
        ds = self.defense_state
        category = getattr(getattr(ds, "defense_category", None), "value", "")
        waf_type = str(getattr(ds, "waf_type", "") or "")
        detected = bool(
            (waf_type and waf_type.lower() not in {"unknown", "none"})
            or (category and category.lower() not in {"none", "unknown"})
            or getattr(ds, "cloak_detected", False)
            or getattr(ds, "honeypot_count", 0) > 0
        )
        result.defense_detected = detected
        result.waf_type = "" if waf_type.lower() in {"unknown", "none"} else waf_type
        result.defense_complexity = float(getattr(ds, "defense_complexity", 0.0) or 0.0)
        result.waf_bypassed = bool(
            result.waf_bypassed
            or getattr(ds, "bypass_successes", 0) > 0
        )
    def _should_terminate(self, result: TaskResult | None, max_loops: int) -> bool:
        """Check if the main loop should stop."""
        if result and result.success:
            # Chain mode: only stop if chain exhausted or safety cap reached
            if getattr(self, '_chain_mode', False):
                if getattr(self, '_chain_exhausted', False):
                    log.info("Chain mode: chain exhausted, terminating")
                    return True
                _max_flags = getattr(self, '_chain_max_flags', 10)
                if len(getattr(self, '_captured_flags', [])) >= _max_flags:
                    log.info("Chain mode: safety cap reached (%d flags), terminating", _max_flags)
                    return True
                # Otherwise continue — don't terminate on intermediate flag
            else:
                return True
        if self._time_exceeded() or self._tokens_exceeded():
            return True
        if self.phase in (OrchestratorPhase.DONE, OrchestratorPhase.FAILED):
            return True
        if self._loop_count >= max_loops:
            log.info("Max loops (%d) reached", max_loops)
            return True
        if getattr(self, '_solo_exhausted', False):
            # A Runtime plan-exhausted result with no new progress is terminal
            # for Solo mode.  Continuing outer iterations only replays the
            # same blocked graph and wastes the remaining loop budget.
            if not getattr(self, '_chain_mode', False):
                log.info("Solo mode exhausted — terminating after plan exhaustion")
                return True
        else:
            self._solo_exhausted_stall = 0
        # No-progress: consecutive outer loops with zero new discoveries
        if getattr(self, '_no_progress_loops', 0) >= 2:
            log.info("No progress for %d consecutive loops — terminating", self._no_progress_loops)
            return True
        return False

    # ── Chain Topology Detection ──────────────────────────────────

    def _detect_chain_topology(self, chain_mode_config: str = "auto") -> bool:
        """Detect if the target has multi-step attack chain topology.

        Activates chain_mode when: >= 2 distinct services each have
        associated vulnerability hypotheses, or >= 3 services total,
        indicating a multi-step chain target.

        Args:
            chain_mode_config: "auto" (detect), "off" (never activate)
        """
        if chain_mode_config == "off":
            return False

        if chain_mode_config != "auto":
            # Unknown value — don't activate
            return False

        services = self.dkg.query_nodes("Service")
        vulns = self.dkg.query_nodes("Vulnerability")

        # Count services that have vulnerability hypotheses
        services_with_vulns: set[str] = set()
        for v in vulns:
            svc = v.get("service") or v.get("port")
            if svc:
                services_with_vulns.add(str(svc))

        # Need >= 2 distinct services with vulns to qualify as chain
        if len(services_with_vulns) >= 2:
            self._chain_mode = True
            self._chain_services_total = len(services_with_vulns)
            return True

        # Also activate if >= 3 services total (potential chain, even w/o vulns yet)
        if len(services) >= 3:
            self._chain_mode = True
            self._chain_services_total = len(services)
            return True

        return False

    def _count_unexploited_services(self) -> int:
        """Count services that still have unexploited vulnerability hypotheses.

        A service is considered exploited if its associated vulnerability
        nodes are marked as exploited.
        """
        vulns = self.dkg.query_nodes("Vulnerability")
        exploited: set[str] = set()
        for v in vulns:
            if v.get("exploited") or v.get("status") == "exploited":
                svc = v.get("service") or v.get("port")
                if svc:
                    exploited.add(str(svc))

        services_with_vulns: set[str] = set()
        for v in vulns:
            svc = v.get("service") or v.get("port")
            if svc:
                services_with_vulns.add(str(svc))

        return len(services_with_vulns - exploited)

    # ── Unified State Access ──────────────────────────────────────

    def _get_state(self) -> PipelineState:
        """Return a typed snapshot of the current world state.

        Reads through the MemoryManager WorkingMemory adapter (DKG) so the
        orchestrator has a single typed read path. Falls back to a direct
        DKG normalisation if the adapter is unavailable.
        """
        try:
            snapshot = self.memory.working_snapshot()
            if snapshot is not None:
                return snapshot
        except Exception:
            pass
        return normalize_dkg_state(self.dkg)

    def _belief_context(self, *, compact: bool = False) -> str:
        """O1: render the unified cognition snapshot for one LLM prompt.

        Single rendering path shared by task execution, plan review, plan
        generation, and compression/truncation. Never raises — prompt
        construction must not break the run.
        """
        try:
            rationale: list = []
            try:
                rationale = self.memory.plan.active_entries()
            except Exception:
                pass
            rendered = render_belief_snapshot(
                state=self._get_state(),
                vulnerabilities=self.vulnerabilities,
                plan=self.exploitation_plan,
                defense=self.defense_state,
                rationale_entries=rationale,
                compact=compact,
            )
            classification = getattr(self, "_scan_classification", None)
            if classification is not None and getattr(classification, "cloud_enabled", False):
                context = self.dkg.topology_context(
                    view="cloud", max_nodes=24 if compact else 48,
                    max_edges=48 if compact else 96,
                )
                coverage = context.get("coverage", {})
                rendered += (
                    "\n## Cloud Topology Context\n"
                    f"Environment: {classification.kind.value}; "
                    f"provider={classification.provider or 'unknown'}\n"
                    f"Coverage: nodes={coverage.get('included_nodes', 0)}/"
                    f"{coverage.get('total_nodes', 0)}, edges="
                    f"{coverage.get('included_edges', 0)}/"
                    f"{coverage.get('total_edges', 0)}, "
                    f"complete={coverage.get('complete', False)}\n"
                    f"Omitted: {context.get('omitted_count', {})}\n"
                )
            return rendered
        except Exception:
            return ""

    async def _check_response_for_flag(self, target_url: str) -> TaskResult | None:
        """Search response body for flag patterns across all discovered HTTP services.

        Uses LLM to suggest smart flag paths based on the technology stack
        and discovered endpoints, then probes them all.
        """
        import urllib.parse as _up3
        urls_to_check: list[str] = []

        for svc in self.dkg.query_nodes("Service"):
            port = svc.get("port", 0)
            proto = svc.get("protocol", "").lower()
            if port and port != 0 and "http" in proto:
                host = getattr(self, "target_host", None)
                if host:
                    scheme = "https" if port == 443 else "http"
                    base = f"{scheme}://{host}" if port in (80, 443) else f"{scheme}://{host}:{port}"
                    urls_to_check.append(base)

        parsed = _up3.urlparse(target_url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        if base not in urls_to_check:
            urls_to_check.append(base)

        # Probe all discovered endpoints
        for ep in self.dkg.query_nodes("Endpoint"):
            eu = ep.get("url", "")
            if eu and eu not in urls_to_check:
                urls_to_check.append(eu)

        # Ask LLM to suggest smart flag paths based on context
        svc_list = [f"{s.get('port')}/{s.get('protocol','tcp')} {s.get('version','')}"
                    for s in self.dkg.query_nodes("Service")]
        ep_list = [e.get("url", "") for e in self.dkg.query_nodes("Endpoint")[:20]]
        flag_paths = ["/flag", "/flag.txt", "/robots.txt", "/.git/HEAD"]  # sensible defaults
        try:
            self._maybe_compress()
            llm_paths_content, _ = await self._llm_generate_async(
                prompt=f"Target services: {svc_list}\n"
                       f"Discovered endpoints: {ep_list}\n\n"
                       f"Suggest additional URL paths to probe for flags/credentials. "
                       f"Consider: backup files, config leaks, admin panels, API docs, "
                       f"debug endpoints. Output JSON array of path strings only.",
                system_prompt="You are a penetration tester. Output only a JSON array of URL paths.",
                stage="flag_search",
            )
            llm_paths = self._extract_json(llm_paths_content)
            if isinstance(llm_paths, list):
                flag_paths = list(dict.fromkeys(flag_paths + llm_paths))  # dedup, defaults first
        except Exception:
            pass

        for bu in urls_to_check:
            for path in flag_paths:
                try:
                    response = await self.client.get(bu.rstrip("/") + path)
                    flags = self.flag_pattern.findall(response.body)
                    if flags:
                        self._task_log_event("info", "flag_found", url=bu+path, flag=flags[0])
                        self.phase = OrchestratorPhase.DONE
                        return TaskResult(
                            success=True, flag=flags[0], steps=self.step_count,
                            tokens_used=self.llm.token_count,
                            time_elapsed=time.time() - self.start_time,
                        )
                except Exception:
                    continue
        return None

    def _print_plan_status(self) -> None:
        """Print current exploitation plan status to console."""
        status = self._format_plan_status()
        if status and status != "(no plan)":
            print(f"\n{status}")

    def _task_log_event(self, level: str, event: str, **data: Any) -> None:
        """Record a structured event in the task log."""
        self._task_log.append({
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime()),
            "elapsed_s": round(time.time() - self.start_time, 3),
            "phase": self.phase.value,
            "level": level,
            "event": event,
            **data,
        })

    def metrics_report(self):
        """P19: aggregate the v2 success metrics from this run's traces."""
        return MetricsCalculator().calculate(self._task_log, self.replanner)

    def provenance_summary(self, max_items: int = 10) -> str:
        """P15 G2: render DKG node provenance for the replan LLM.

        Uses the nested P12 ``provenance`` dict when present; falls back to
        the legacy flat ``source`` property so existing nodes (e.g. CTEG
        credentials) still show where they came from. Facts with real
        provenance sort first; everything caps at ``max_items`` rows.
        """
        rows = []
        for node_type in ("Endpoint", "Credential", "Vulnerability", "Session"):
            for node in self.dkg.query_nodes(node_type):
                prov = node.get("provenance")
                if isinstance(prov, dict) and prov:
                    source = str(prov.get("source") or "unknown")
                    evidence = str(prov.get("evidence") or "")
                else:
                    source = str(node.get("source") or "unknown")
                    evidence = ""
                label = (
                    node.get("url")
                    or node.get("username")
                    or node.get("vuln_type")
                    or node.get("host")
                    or node.get("id", "")
                )
                rows.append((source != "unknown", node_type, label, source, evidence))

        rows.sort(key=lambda r: r[0], reverse=True)
        lines = []
        for _, node_type, label, source, evidence in rows[:max_items]:
            line = f"- [{node_type}] {str(label)[:60]} (source: {source})"
            if evidence:
                line += f"\n  evidence: {evidence[:80]}"
            lines.append(line)
        return "\n".join(lines)

    def _task_log_write(self) -> None:
        """Persist the task log to JSON file."""
        if self._task_log_path and self._task_log:
            os.makedirs(os.path.dirname(self._task_log_path) or ".", exist_ok=True)
            with open(self._task_log_path, "w", encoding="utf-8") as f:
                json.dump({
                    "target": self.target_url,
                    "model": self.llm.model,
                    "provider": self.llm.provider,
                    "time_budget": self.time_budget,
                    "events": self._task_log,
                    "dkg_summary": self.dkg.summary(),
                    "cteg_patterns_committed": getattr(self, '_cteg_committed', 0),
                }, f, indent=2, default=str)
            log.info("Task log written to %s (%d events)", self._task_log_path, len(self._task_log))

    def _checkpoint_path(self, phase: str) -> str:
        """Generate a checkpoint path for a given phase."""
        sanitized = re.sub(r"[^a-zA-Z0-9_.-]", "_", self.target_url)
        return os.path.join("checkpoints", f"checkpoint_{sanitized}_{phase}.json")

    def _check_tool_dependencies(self) -> None:
        """Verify external CLI tools exist on PATH. Warn for missing required ones."""
        self._missing_tools: set = set()
        for tool in self.REQUIRED_TOOLS:
            if not shutil.which(tool):
                self._missing_tools.add(tool)
                log.warning("Tool not found on PATH: %s — related commands will fail", tool)
        for tool in self.OPTIONAL_TOOLS:
            if not shutil.which(tool):
                log.info("Optional tool not found: %s — some features unavailable", tool)

    def _time_exceeded(self) -> bool:
        return self._remaining_budget() <= 0

    def _tokens_exceeded(self) -> bool:
        """Check if token budget is exceeded. Attempts compression first.

        Thin delegate — the logic lives in ContextManager (P3).
        """
        return self.context.tokens_exceeded(self.token_budget)

    def _maybe_compress(self) -> bool:
        """Compress conversation history if context load exceeds threshold.

        Thin delegate — the logic lives in ContextManager (P3). Returns True
        if a compression pass saved tokens.
        """
        return self.context.maybe_compress()

    def _build_truncation_context(self) -> str:
        """Build structured DKG state summary for injection when conversation is truncated.

        Thin delegate — the logic lives in ContextManager (P3).
        """
        return self.context.truncation_context()

    @staticmethod
    def _extract_json_array(text: str) -> list | None:
        """Extract the first complete JSON array using bracket counting.

        Handles nested brackets and trailing text — more robust than regex.
        Returns the parsed list, or None if no valid array found.
        """
        start = text.find('[')
        if start == -1:
            return None
        depth = 0
        for i, c in enumerate(text[start:], start):
            if c == '[':
                depth += 1
            elif c == ']':
                depth -= 1
                if depth == 0:
                    try:
                        return json.loads(text[start:i + 1])
                    except json.JSONDecodeError:
                        return None
        return None

    @staticmethod
    def _extract_json(text: str) -> Any:
        """Extract JSON from LLM response text."""
        # Try direct parse
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass
        # Try to find JSON array/object in markdown code blocks
        match = re.search(r"```(?:json)?\s*([\s\S]*?)```", text)
        if match:
            try:
                return json.loads(match.group(1))
            except json.JSONDecodeError:
                pass
        # Try bracket-counting for JSON arrays (handles nesting + trailing text)
        result = LifecycleCoordinator._extract_json_array(text)
        if result is not None:
            return result
        # Non-greedy match for JSON objects (no nesting issues with {})
        match = re.search(r"\{.*?\}", text, re.DOTALL)
        if match:
            try:
                return json.loads(match.group(0))
            except json.JSONDecodeError:
                pass
        return {}
