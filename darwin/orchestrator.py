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
from darwin.data_model import normalize_dkg_state, PipelineState, EndpointInfo
from darwin.dkg import DKG
from darwin.dpm import DefensePerceptionModule, DefenseStateVector
from darwin.dave import DAVE, ExploitAttempt, parse_tool_stdout
from darwin.dynamic_scaling import DynamicScalingEngine, ScalingLevel, compute_task_breadth
from darwin.tools.mcp_client import MCPClientPool, load_mcp_config
from darwin.tools.mcp_gateway import MCPGateway, ToolResult
from darwin.tools.recon_server import create_recon_gateway, parse_response
from darwin.tools.attack_server import create_attack_gateway
from darwin.utils.http_client import HTTPClient, ProbeClient, HTTPResponse
from darwin.utils.llm import LLMSession
from darwin.sub_agents.base import SubAgentPool


class OrchestratorPhase(str, Enum):
    INIT = "init"
    BOOTSTRAP = "bootstrap"
    EXPLOIT = "exploit"      # unified: LLM drives recon + analyze + exploit
    DONE = "done"
    FAILED = "failed"
    # Legacy phases kept for backward compat
    RECON = "recon"
    ANALYZE = "analyze"
    BYPASS = "defense_bypass"
    VERIFY = "verify"


@dataclass
class TaskResult:
    """Result of an orchestrated penetration test task."""
    success: bool
    flag: str = ""
    steps: int = 0
    tokens_used: int = 0
    time_elapsed: float = 0.0
    phase_at_end: OrchestratorPhase = OrchestratorPhase.DONE
    defense_detected: bool = False
    waf_bypassed: bool = False
    waf_type: str = ""
    defense_complexity: float = 0.0
    dkg_summary: str = ""
    error: str = ""


@dataclass
class VulnerabilityHypothesis:
    """A hypothesized vulnerability for testing."""
    vuln_type: str  # XSS, SQLi, CMDi, SSTI, LFI, etc.
    endpoint: str
    param: str
    confidence: float
    evidence: str
    suggested_tool: str = ""
    tool_args: dict = field(default_factory=dict)
    research_techniques: list = field(default_factory=list)
    research_cves: list = field(default_factory=list)


@dataclass
class ExploitationPlan:
    """Structured penetration test plan with dynamic task tracking."""
    plan_id: str
    phase: str
    goal: str
    tasks: list = field(default_factory=list)
    status: str = "pending"  # pending | in_progress | completed | stalled
    created_at: str = ""
    updated_at: str = ""


# -- System Prompts (imported from darwin.prompts) --------------------------
from darwin.prompts.orchestrator import (
    SYSTEM_PROMPT_ORCHESTRATOR,
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
        self.scaling_engine = DynamicScalingEngine(hysteresis=2)

        # Tool infrastructure
        self.recon_gateway = create_recon_gateway()
        self.attack_gateway = create_attack_gateway()
        self.mcp_pool = MCPClientPool()
        self.client = HTTPClient()
        self.probe_client = ProbeClient()
        self._multi_pool = None  # SubAgentPool, created on first multi-agent cycle

        # Task log — structured event log written to file
        self._task_log: List[Dict[str, Any]] = []
        self._task_log_path: str = ""

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
        self._solo_iterations = 0
        self._multi_agent_iterations = 0
        self._solo_exhausted = False
        self._multi_exhausted = False
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

            # ── Phase 1.5: Deep Recon (dirb, nikto, form_extract) ──
            await self._deep_recon()

            # ── Phase 1.6: Defense Detection (DPM) ──
            await self._detect_defenses()

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

            # ── After recon, before main loop: detect complexity & chain topology ──
            try:
                from darwin.dynamic_scaling import detect_complexity_hints
                hint = detect_complexity_hints(self.dkg, self.defense_state)
                if hint is not None:
                    self.scaling_engine.seed_votes(hint)
                    log.info("Seeded scaling votes to %s based on recon complexity", hint)
            except Exception:
                pass

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

                # Re-compute B dimension each iteration (DKG may have changed)
                B = compute_task_breadth(self.dkg, self.defense_state)
                scaling_level = self.scaling_engine.decide(self.dkg, self.defense_state)
                self._task_log_event("info", "loop_iteration",
                    loop=self._loop_count, b_value=B, mode=scaling_level.value)

                if scaling_level == ScalingLevel.SOLO:
                    # Skip if solo already exhausted — avoid wasted iterations
                    if self._solo_exhausted:
                        log.info("Solo mode exhausted, skipping loop %d", self._loop_count)
                        continue

                    # Phase 1: Service research → known CVEs for each service (once)
                    if not self._svc_research_done:
                        await self._service_research()
                        self._svc_research_done = True

                    # Phase 2: Analyze recon data + service research → vuln hypotheses
                    if not self._analyze_done:
                        await self._analyze_phase()
                        self._analyze_done = True

                    # Phase 3: Research each vulnerability with tools
                    if self.vulnerabilities and not self._research_done:
                        log.info("[PHASE] _research_phase START")
                        await self._research_phase()
                        self._research_done = True
                        log.info("[PHASE] _research_phase DONE")

                    # Phase 4: Unified LLM loop (plan → exploit → replan)
                    result = await self._unified_llm_loop(target_url, cteg_hints)

                    # Allow up to 3 solo iterations before marking exhausted
                    self._solo_iterations += 1
                    if result is None or not result.success:
                        if self._solo_iterations >= 5:
                            self._solo_exhausted = True
                        # Fast exhaust: 2 consecutive plan-exhausted runs with 0 done tasks
                        _done_count = sum(1 for t in (self.exploitation_plan.tasks if self.exploitation_plan else [])
                                         if t.get("status") == "done")
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
                else:
                    # Coordinated or Distributed — dispatch to multi-agent cycle
                    # with scaling_level and CTEG hints for mode-differentiated behavior
                    log.info("Entering %s Mode (B=%.2f)", scaling_level.value.title(), B)
                    result = await self._run_multi_agent_cycle(
                        target_url,
                        scaling_level=scaling_level,
                        cteg_hints=cteg_hints,
                    )
                    if result is None:
                        # Inject context so solo LLM knows why multi-agent was attempted
                        # but produced no results (no agents spawned, or all found nothing)
                        _ma_agents = getattr(self._multi_pool, '_agents', {}) if self._multi_pool else {}
                        _ma_results = getattr(self._multi_pool, '_results', {}) if self._multi_pool else {}
                        _ctx = (
                            f"[Multi-Agent Cycle Summary] Scaling level: {scaling_level.value} "
                            f"(B={B:.2f}). Agents spawned: {len(_ma_agents)}. "
                            f"Results collected: {len(_ma_results)}. "
                            f"No flag was captured by the multi-agent cycle. "
                            f"Falling back to solo mode for continued exploitation."
                        )
                        self.llm.add_context_message(_ctx, "user")
                        result = await self._unified_llm_loop(target_url, cteg_hints)

                    self._multi_agent_iterations += 1
                    if result is None or not result.success:
                        if self._multi_agent_iterations >= 3:
                            self._multi_exhausted = True
                    else:
                        # In chain mode, don't exhaust on first success — there may be
                        # more flags to find. Only exhaust when chain is truly done.
                        if not self._chain_mode:
                            self._multi_exhausted = True

                # Checkpoint DKG after each loop iteration
                self.dkg.save(self._checkpoint_path(f"loop_{self._loop_count}"))

                # DKG re-scan each iteration: new hosts/creds enable collaboration
                self._scan_collaboration_opportunities()

                # Update TDA with latest state
                try:
                    self.scaling_engine.tda.update_all(
                        token_count=self.llm.token_count,
                        successes=1 if result and result.success else 0,
                        attempts=1,
                        defense_state=self.defense_state,
                        dkg=self.dkg,
                    )
                except Exception:
                    pass

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
            log.warning("Task failed with error: %s", e)
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
            if technologies:
                log.info("bootstrap whatweb: %s → %s", url, technologies)
            for tech in technologies:
                self.dkg.add_node("Service", f"tech-{tech[:30]}", {
                    "port": 0, "protocol": "HTTP",
                    "version": tech, "banner": tech,
                    "discovered_by": "bootstrap-whatweb",
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
                                        self._add_form_endpoint(form, url)
                    except Exception:
                        pass
                scanned = True

            elif resp_len < 200000:
                # Small HTML page — full recon: gobuster + nikto + form_extract
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
                            self._add_form_endpoint(form, url)
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
                        if st != 404 and len(out) > 50:
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
            # Multi-agent mode also exhausted → terminate
            if getattr(self, '_multi_exhausted', False):
                log.info("All modes exhausted — terminating main loop")
                return True
            # Solo exhausted, multi never entered — track no-progress loops.
            # In chain mode with multi-agent active, don't count solo stalls
            # (multi-agent is the primary work mode for chain scenarios).
            if not getattr(self, '_chain_mode', False):
                _stalled = getattr(self, '_solo_exhausted_stall', 0) + 1
                self._solo_exhausted_stall = _stalled
                if _stalled >= 3:
                    log.info("Solo mode exhausted, no multi-agent entry after %d loops — terminating", _stalled)
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

    def _scan_collaboration_opportunities(self) -> None:
        """Scan DKG for new collaboration opportunities (new hosts/creds)."""
        try:
            from darwin.dynamic_scaling import scan_collaboration_opportunities
            opps = scan_collaboration_opportunities(self.dkg)
            for opp in opps:
                if opp.confidence > 0.6:
                    log.info("Collaboration opportunity: %s (%.2f)",
                             opp.opportunity_type, opp.confidence)
        except Exception:
            pass

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

        # Generate initial plan
        if not self.exploitation_plan or not self.exploitation_plan.tasks:
            self.exploitation_plan = await self._generate_exploitation_plan(target_url, cteg_hints)

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
        if systematic_result and systematic_result.success:
            return systematic_result

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
                task_prompt = (
                    f"Execute plan task {iteration}/{MAX_ITER}:\n"
                    f"  Instruction: {task_instruction}\n"
                    f"  Required tool: {task_tool if task_tool else '(choose the best tool)'}\n"
                    f"  Params: {json.dumps(task_params)}\n\n"
                    f"{freedom_note}"
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
            _all_task_stdouts: list[str] = []  # accumulate all tool outputs
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
                # send_payload defaults to form-encoded which fails on
                # JSON-only endpoints. Any DKG endpoint with method=POST
                # gets JSON body — modern APIs use JSON by default.
                if tc_name == "send_payload" and tc_args.get("method", "GET").upper() == "POST":
                    if not tc_args.get("body_format"):
                        url = tc_args.get("url", "")
                        dkg_eps = [e for e in self.dkg.query_nodes("Endpoint")
                                   if e.get("url", "") == url]
                        ep_method = dkg_eps[0].get("method", "GET") if dkg_eps else "GET"
                        if ep_method == "POST":
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
                    log.info("[EXPLOIT] %s: OK (exit=%d, %d bytes) — no flag",
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

                print(f"  [{tc_name}] {str(tc_args)[:120]} → "
                      f"{tool_stdout.split(chr(10))[0][:120]}")
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
                    for tech in parsed.get("technologies", [])[:5]:
                        self.dkg.add_node("Service", f"tech-{tech[:30]}", {
                            "port": 0, "protocol": "HTTP",
                            "version": tech, "banner": tech,
                            "discovered_by": "solo-unified",
                        })
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
                    creds = fix.get("credentials", {})
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

                task["params"] = fix["corrected_params"]
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

            await self._review_and_update_plan(
                task, task_success, task_result_text
            )
            log.info("[PLAN REVIEW] task %s → %s, plan updated",
                     task.get("id", ""), "done" if task_success else "failed")
            self._print_plan_status()

        log.info("_unified_llm_loop: %d iterations, flag not found", iteration)
        self._generate_phase_summary("exploit")

        return None

    # DEPRECATED: not currently wired into the main run() loop.
    # Kept for potential future use in automated vuln-to-tool mapping.
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
            "ssrf": ["curl_get"],
            "xxe": ["send_payload"],
            "jwt": ["jwt_forge"],
            "race condition": ["send_payload", "shell_exec"],
            "informationdisclosure": ["curl_get"],
            "privilege_escalation": ["shell_exec", "linux_priv_check"],
            "container_escape": ["check_capabilities", "check_mounts", "shell_exec"],
            "mysql_file_write": ["mysql_file_write"],
            "mysql_udf": ["mysql_query", "mysql_file_write", "shell_exec"],
            "postgres_rce": ["psql_query", "shell_exec"],
            "authbypass": ["redis_cmd", "mysql_query", "psql_query", "mssql_query", "mssqlclient_query", "mssqlclient_query",
                          "oracle_query", "ssh_exec", "shell_exec"],
            "weakauth": ["mssqlclient_query", "mssql_query", "mysql_query",
                        "psql_query", "redis_cmd", "oracle_query",
                        "test_credential", "ssh_exec"],
        }
        # Fuzzy match: if a vuln type CONTAINS one of these substrings, it maps
        FUZZY_MAP: dict[str, list[str]] = {
            "sqli": ["sqlmap_test"],
            "xss": ["xss_reflection_test"],
            "cmdi": ["command_injection_test"],
            "idor": ["curl_get"],
            "auth": ["curl_get"],
            "deserialization": ["send_payload"],
            "ssrf": ["curl_get"],
            "xxe": ["send_payload"],
            "jwt": ["jwt_forge"],
            "privilege": ["shell_exec", "linux_priv_check"],
            "escape": ["check_capabilities", "check_mounts", "shell_exec"],
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
            return []

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

        # Sort vulns: mapped first, then unmapped, so useful ones get processed
        mapped_vulns = []
        unmapped_vulns = []
        for v in vulns:
            vt = (v.get("vuln_type") or "").lower()
            if _resolve_tools(vt):
                mapped_vulns.append(v)
            else:
                unmapped_vulns.append(v)
        vulns_sorted = mapped_vulns + unmapped_vulns

        # Summarize
        vuln_type_counts: dict[str, int] = {}
        for v in vulns:
            vt = (v.get("vuln_type") or "").lower()
            if vt:
                vuln_type_counts[vt] = vuln_type_counts.get(vt, 0) + 1
        mapped_counts = {vt: c for vt, c in vuln_type_counts.items() if _resolve_tools(vt)}
        unmapped_counts = {vt: c for vt, c in vuln_type_counts.items() if not _resolve_tools(vt)}
        print(f"[systematic] {len(vulns)} vulns: {len(mapped_vulns)} mapped, {len(unmapped_vulns)} unmapped")
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
            # For non-HTTP endpoints, filter to protocol-matching tools only
            if not endpoint.startswith("http://") and not endpoint.startswith("https://"):
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
                    # No URI scheme — detect protocol from DKG Service node by port
                    detected = _detect_proto_from_service(endpoint, self.dkg)
                    if detected is not None:
                        tools = [t for t in tools if t in detected]
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

            # LLM-suggested tool from analysis — always extract, use if present
            llm_tool = v.get("suggested_tool", "") or ""
            llm_args = v.get("tool_args", {}) or {}
            if not isinstance(llm_args, dict):
                llm_args = {}
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
                tried.add(dedup_key)
                tested_count += 1

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
        # Build tool lists for analyze system prompt
        attack_tool_names = sorted(self.attack_gateway.get_tool_names())
        recon_tool_names = sorted(self.recon_gateway.get_tool_names())
        analyze_system_prompt = SYSTEM_PROMPT_ANALYZE.format(
            attack_tools=", ".join(attack_tool_names),
            recon_tools=", ".join(recon_tool_names),
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

        prompt = (
            f"## Mission\n{self._task_description}\n\n"
            f"Target information:\n"
            f"{unreachable_warning}"
            f"{app_context}"
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
        _svc_name = "service"
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
            # Fallback: check DKG services for protocol hints
            if _svc_name == "service":
                for s in self.dkg.query_nodes("Service"):
                    svc_port = str(s.get("port", ""))
                    vuln_port = str(v.tool_args.get("port", "")) if v.tool_args else ""
                    if svc_port and vuln_port and svc_port == vuln_port:
                        svc_data = (s.get("service_name", "") + " " + (s.get("version", "") or "")).lower()
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
            break

        _MCP_TIMEOUT_S = 45  # per-MCP-call cap

        # ── Round 1: Programmatic forced parallel search ──
        # Run ALL local tools + ddg_web_search in parallel. All are gateway-based
        # (no MCP dependency), fast and reliable.
        _queries = {
            "rag": f"{_svc_name} exploitation default credentials weaknesses",
            "exploitdb": _svc_name,
            "searchsploit": _svc_name,
            "web": f"{_svc_name} default credentials common passwords exploitation techniques",
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
            f"4. If you need more details, call additional research tools now.\n"
            f"5. When done, output a JSON summary of findings for each vuln:\n"
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
        for c in _dkg_creds:
            if c.get("username"):
                _resolved_user = str(c.get("username"))
                _resolved_pass = str(c.get("password", "") or "")
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
                _valid_tools = _PORT_VALID_TOOLS.get(
                    _task_port,
                    set()  # won't match anything → will be caught below
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
                for _key, _val in _params.items():
                    if isinstance(_val, str) and "$credentials." in _val:
                        if _resolved_user:
                            _params[_key] = _val.replace(
                                "$credentials.username", _resolved_user
                            ).replace(
                                "$credentials.password", _resolved_pass
                            )
                        else:
                            # No credentials available — task can't run
                            t["status"] = "skipped"
                            break

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
## Synthesizing Knowledge into Attack Tasks
You have received multiple intelligence sources above:
- Vulnerability hypotheses from the analysis phase
- Attack pattern knowledge (if RAG results matched your target's technology stack)
- Service version information from reconnaissance

Your job: COMBINE these sources when designing each task.
**CRITICAL for WeakAuth/default credentials:** When RAG results contain specific credential
combinations (username:password pairs), you MUST include EVERY listed combination in your
batch credential test. Do NOT rely on your own memory of "common passwords" — the RAG
entries are the authoritative source for service-specific defaults.
- When an attack pattern matches a discovered service: use the pattern's technique as the task's approach. The RAG result title and techniques field tell you exactly what to do.
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

Output ONLY valid JSON array (3-20 tasks depending on complexity. More tasks =\= better — prefer focused, high-impact exploitation tasks over exhaustive probing)."""

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
            "redis_cmd", "mysql_query", "psql_query", "mssql_query", "mssqlclient_query",
            "oracle_query", "tomcat_exploit", "php_filter_chain",
            "jwt_forge", "impacket_psexec", "impacket_wmiexec",
            "impacket_pth", "impacket_ticketer", "impacket_silver_ticket",
            "impacket_secretsdump", "impacket_secretsdump_dcsync",
            "impacket_GetUserSPNs", "impacket_GetNPUsers",
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
                if tool in _EXPLOIT_PRIORITY:
                    ready_exploit.append(task)
                elif tool in _LOW_PRIORITY:
                    ready_low.append(task)
                else:
                    ready_probe.append(task)
        return (ready_exploit[0] if ready_exploit
                else (ready_probe[0] if ready_probe
                      else (ready_low[0] if ready_low else None)))

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

        # Detect timeout/hang failures and add targeted hints
        timeout_hint = ""
        output_lower = output.lower()
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
        task["result_summary"] = task_result[:500]

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
            f"Output: {task_result[:1500]}\n"
            f"{cred_reminder}"
            f"{api_reminder}"
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
                           if t.get("status") in ("done", "failed", "skipped", "exhausted", "pending")
                           and t.get("id") != task.get("id")]
                # Add the just-completed task with updated status
                preserved.append(task)
                # Merge in new tasks from LLM (avoid duplicate IDs)
                existing_ids = {t["id"] for t in preserved}
                # Collect LLM's dependency updates for existing tasks
                llm_dep_updates: dict[str, list] = {}
                for nt in new_tasks:
                    if not isinstance(nt, dict):
                        continue
                    nt.setdefault("status", "pending")
                    nt.setdefault("dependent_task_ids", nt.pop("dependencies", []))
                    if nt["id"] not in existing_ids:
                        # Dedup: skip if duplicate of an existing pending task
                        _nt_inst = (nt.get("instruction") or "").lower()
                        _nt_tool = (nt.get("tool") or "").lower()
                        _nt_endpoint = (nt.get("endpoint") or nt.get("params", {}).get("target_url", "") or
                                       nt.get("params", {}).get("url", "") or
                                       nt.get("params", {}).get("target", "") or
                                       nt.get("params", {}).get("host", "")).lower()
                        _is_dup = False
                        for pt in preserved:
                            if pt.get("status") != "pending":
                                continue
                            # Same tool + same endpoint = definite duplicate
                            _pt_tool = (pt.get("tool") or "").lower()
                            _pt_endpoint = (pt.get("endpoint") or pt.get("params", {}).get("target_url", "") or
                                           pt.get("params", {}).get("url", "") or
                                           pt.get("params", {}).get("target", "") or
                                           pt.get("params", {}).get("host", "")).lower()
                            if _nt_tool and _pt_tool and _nt_endpoint and _pt_endpoint:
                                if _nt_tool == _pt_tool and _nt_endpoint == _pt_endpoint:
                                    _is_dup = True
                                    break
                            # Word overlap ratio check (fallback)
                            _pt_inst = (pt.get("instruction") or "").lower()
                            if _nt_inst and _pt_inst:
                                _nt_words = set(_nt_inst.split())
                                _pt_words = set(_pt_inst.split())
                                if _nt_words and _pt_words:
                                    _overlap = len(_nt_words & _pt_words) / min(len(_nt_words), len(_pt_words))
                                    if _overlap > 0.75:
                                        _is_dup = True
                                        break
                        if _is_dup:
                            continue
                        preserved.append(nt)
                        existing_ids.add(nt["id"])
                    else:
                        # LLM updated an existing task — capture its dependency changes
                        if "dependent_task_ids" in nt:
                            llm_dep_updates[nt["id"]] = nt["dependent_task_ids"]
                # Apply LLM's dependency updates to preserved tasks
                for t in preserved:
                    tid = t.get("id", "")
                    if tid in llm_dep_updates:
                        t["dependent_task_ids"] = llm_dep_updates[tid]
                self.exploitation_plan.tasks = preserved

                # Hard cap: trim lowest-quality pending tasks when plan
                # inflates beyond 15.  Done/failed tasks are kept for history.
                _MAX = 25
                if len(preserved) > _MAX:
                    _pending = [t for t in preserved if t.get("status") == "pending"]
                    if len(_pending) > (_MAX - len([t for t in preserved if t.get("status") != "pending"])):
                        # Sort pending by "quality": tasks with no dependencies
                        # and tool specified are higher quality than those
                        # with many dependencies or no tool.
                        def _pending_key(t):
                            deps = len(t.get("dependent_task_ids", []))
                            has_tool = 1 if t.get("tool", "") else 0
                            return (deps, -has_tool)
                        _pending.sort(key=_pending_key)
                        # Keep only the needed count of pending tasks.
                        # Clamp to 0 — when done+failed already exceed _MAX,
                        # all pending tasks must be removed.
                        _keep_pending = max(0, _MAX - len([t for t in preserved if t.get("status") != "pending"]))
                        _to_remove = set(t["id"] for t in _pending[_keep_pending:])
                        preserved = [t for t in preserved if t.get("id") not in _to_remove]
                    self.exploitation_plan.tasks = preserved

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
                for nt in new_tasks:
                    if nt.get("id") not in existing_ids:
                        self.exploitation_plan.tasks.append(nt)
                        existing_ids.add(nt.get("id"))
                # Sanitize: replace blacklisted tools in replanned tasks
                self._sanitize_plan_tools(self.exploitation_plan.tasks)
                print(f"[REPLAN] Added {len(new_tasks)} replacement task(s):")
                for nt in new_tasks[:5]:
                    print(f"  + {nt.get('id','?')}: {nt.get('instruction','')[:100]}")
                self._sync_plan_to_dkg()
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
            "multi_agent_iterations": self._multi_agent_iterations,
            "analyze_done": self._analyze_done,
            "svc_research_done": self._svc_research_done,
            "research_done": self._research_done,
            "known_flags": list(self._known_flags) if hasattr(self, '_known_flags') else [],
            "solo_exhausted": getattr(self, '_solo_exhausted', False),
            "multi_exhausted": getattr(self, '_multi_exhausted', False),
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
            self._multi_agent_iterations = checkpoint.get("multi_agent_iterations", 0)
            self._analyze_done = checkpoint.get("analyze_done", False)
            self._svc_research_done = checkpoint.get("svc_research_done", False)
            self._research_done = checkpoint.get("research_done", False)
            self._known_flags = set(checkpoint.get("known_flags", []))
            self._solo_exhausted = checkpoint.get("solo_exhausted", False)
            self._multi_exhausted = checkpoint.get("multi_exhausted", False)
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

        saved = self.llm.compress(
            max_context_tokens=self.max_context_tokens,
            compression_threshold=self.compression_threshold,
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

    # ── Persistent Multi-Agent System ─────────────────────────────────

    async def _run_multi_agent_cycle(
        self, target_url: str,
        scaling_level: "ScalingLevel | None" = None,
        cteg_hints: dict | None = None,
    ) -> TaskResult | None:
        """Run persistent multi-agent exploitation with DKG monitoring.

        Uses a persistent SubAgentPool (stored on self) that survives across
        loop iterations. Agents are spawned incrementally based on DKG state,
        and a background DKG monitor spawns follow-up agents when new
        hosts/credentials appear.

        Differentiates Coordinated vs Distributed mode via scaling_level:
          - Coordinated (B 0.3-0.6): max 1 ReconAgent + 1 ExploitAgent
          - Distributed (B >= 0.6): per-host ReconAgent + per-vuln ExploitAgent + PivotAgent
        """
        from darwin.sub_agents.base import SubAgentPool, SubAgentResult, TaskScope, TokenBudget, AgentType, SubAgentState
        from darwin.sub_agents.recon_agent import ReconAgent
        from darwin.sub_agents.exploit_agent import ExploitAgent
        from darwin.sub_agents.pivot_agent import PivotAgent

        # Create persistent pool if first call
        if self._multi_pool is None:
            self._multi_pool = SubAgentPool()

        pool = self._multi_pool

        # Determine which agents to spawn based on DKG state
        spawned_any = await self._spawn_agents_from_dkg(target_url, pool, scaling_level, cteg_hints)

        if not spawned_any and pool.active_count() == 0:
            return None

        # Run existing + new agents with DKG monitoring
        log.info("Multi-agent: %d active agents", pool.active_count())

        # Create a flag-detected event for early termination
        flag_found = asyncio.Event()

        async def _flag_watcher():
            """Background: watch DKG for flag nodes via asyncio.Event + poll."""
            flag_event = self.dkg.subscribe("Flag")
            if not flag_event:
                return
            try:
                while not flag_found.is_set():
                    flags = self.dkg.query_nodes("Flag")
                    for f in flags:
                        fv = f.get("value", "")
                        if fv and fv.startswith("flag{") and fv not in self._known_flags:
                            self._known_flags.add(fv)
                            if self._chain_mode:
                                # Chain mode: record flag, continue unless chain exhausted
                                self._captured_flags.append(fv)
                                log.info("Chain mode: captured flag %s in multi-agent (%d/%d)",
                                         fv[:40], len(self._captured_flags),
                                         max(self._chain_services_total, 1))
                                if self._count_unexploited_services() == 0:
                                    self._chain_exhausted = True
                                    self.__dict__['_multi_agent_flag'] = fv
                                    flag_found.set()
                                    return
                                # Don't set flag_found — continue to next service
                            else:
                                # Original behavior: stop immediately
                                self.__dict__['_multi_agent_flag'] = fv
                                flag_found.set()
                                return
                    try:
                        await asyncio.wait_for(flag_event.wait(), timeout=5.0)
                    except asyncio.TimeoutError:
                        pass
            except asyncio.CancelledError:
                pass

        flag_task = asyncio.create_task(_flag_watcher())

        try:
            # Partition agents. ExploitAgent deferred until after analyze+research.
            recon_agents = [a for a in pool._agents.values()
                            if getattr(a, 'agent_type', None) == AgentType.RECON
                            and getattr(a, 'state', None) != SubAgentState.DONE]
            exploit_agents = [a for a in pool._agents.values()
                              if getattr(a, 'agent_type', None) == AgentType.EXPLOIT
                              and getattr(a, 'state', None) != SubAgentState.DONE]
            other_agents = [a for a in pool._agents.values()
                            if getattr(a, 'agent_type', None) not in (AgentType.RECON, AgentType.EXPLOIT)
                            and getattr(a, 'state', None) != SubAgentState.DONE]

            # Pause ExploitAgent (deferred until after analyze+research).
            # Set state to WAITING instead of deleting — preserves plan, findings,
            # iteration, _stale_iterations, and _completed_task_ids across phases.
            for a in exploit_agents:
                a._pre_wait_state = getattr(a, 'state', SubAgentState.SPAWNING)
                a.state = SubAgentState.WAITING

            # Phase 1: Recon agents first
            if recon_agents and not flag_found.is_set():
                try:
                    recon_results = await asyncio.wait_for(
                        asyncio.gather(*[a.run() for a in recon_agents], return_exceptions=True),
                        timeout=120.0,
                    )
                except asyncio.TimeoutError:
                    # Preserve whatever completed before timeout
                    recon_results = [a._build_result() for a in recon_agents
                                     if getattr(a, 'state', None) == SubAgentState.DONE]
                for i, r in enumerate(recon_results):
                    if isinstance(r, SubAgentResult):
                        pool._results[recon_agents[i].agent_id] = r

            # Phase 2: Service research → Analyze → Vuln research → Plan
            if not flag_found.is_set():
                if not self._svc_research_done:
                    await self._service_research()
                    self._svc_research_done = True
                if not self._analyze_done:
                    await self._analyze_phase()
                    self._analyze_done = True
                if self.vulnerabilities and not self._research_done:
                    await self._research_phase()
                    self._research_done = True
                self.exploitation_plan = await self._generate_exploitation_plan(
                    target_url, cteg_hints)

            # Phase 3: Resume ExploitAgent (now DKG has Vulnerability nodes).
            # Restore previous state instead of recreating — preserves internal state.
            if not flag_found.is_set():
                exploit_agents = [a for a in pool._agents.values()
                                  if getattr(a, 'agent_type', None) == AgentType.EXPLOIT
                                  and getattr(a, 'state', None) == SubAgentState.WAITING]
                for a in exploit_agents:
                    a.state = getattr(a, '_pre_wait_state', SubAgentState.RUNNING)
                exploit_agents = [a for a in pool._agents.values()
                                  if getattr(a, 'agent_type', None) == AgentType.EXPLOIT
                                  and getattr(a, 'state', None) != SubAgentState.DONE]

            # Phase 4: Run Exploit agents
            if exploit_agents and not flag_found.is_set():
                try:
                    exploit_results = await asyncio.wait_for(
                        asyncio.gather(*[a.run() for a in exploit_agents], return_exceptions=True),
                        timeout=120.0,
                    )
                except asyncio.TimeoutError:
                    exploit_results = [a._build_result() for a in exploit_agents
                                       if getattr(a, 'state', None) == SubAgentState.DONE]
                for i, r in enumerate(exploit_results):
                    if isinstance(r, SubAgentResult):
                        pool._results[exploit_agents[i].agent_id] = r

            # Phase 5: Other agents (AD, Cloud, Pivot)
            if other_agents and not flag_found.is_set():
                try:
                    other_results = await asyncio.wait_for(
                        asyncio.gather(*[a.run() for a in other_agents], return_exceptions=True),
                        timeout=120.0,
                    )
                except asyncio.TimeoutError:
                    other_results = [a._build_result() for a in other_agents
                                     if getattr(a, 'state', None) == SubAgentState.DONE]
                for i, r in enumerate(other_results):
                    if isinstance(r, SubAgentResult):
                        pool._results[other_agents[i].agent_id] = r

            if flag_found.is_set():
                for aid in list(getattr(pool, '_agents', {}).keys()):
                    pool.terminate(agent_id=aid)

            # Check results
            results = getattr(pool, '_results', {})
            self.step_count += len(results)

            # Check for flag found by watcher (avoids _known_flags dedup skip)
            watcher_flag = self.__dict__.pop('_multi_agent_flag', None)
            if watcher_flag:
                total_tokens = self.llm.token_count + sum(
                    getattr(r, 'tokens_used', 0) for r in results.values()
                )
                if self._chain_mode:
                    # In chain mode: flag_watcher only sets this when chain exhausted
                    final_flag = self._captured_flags[-1] if self._captured_flags else watcher_flag
                    result_task = TaskResult(
                        success=True, flag=final_flag, steps=self.step_count,
                        tokens_used=total_tokens,
                        time_elapsed=time.time() - self.start_time,
                    )
                    result_task.all_flags = list(self._captured_flags)
                    self.phase = OrchestratorPhase.DONE
                    return result_task
                else:
                    self.phase = OrchestratorPhase.DONE
                    return TaskResult(
                        success=True, flag=watcher_flag, steps=self.step_count,
                        tokens_used=total_tokens,
                        time_elapsed=time.time() - self.start_time,
                    )

            # Query DKG for flags (fallback if watcher didn't catch it)
            flags = self.dkg.query_nodes("Flag")
            for flag in flags:
                fv = flag.get("value", "")
                if fv and fv.startswith("flag{") and fv not in self._known_flags:
                    self._known_flags.add(fv)
                    total_tokens = self.llm.token_count + sum(
                        getattr(r, 'tokens_used', 0) for r in results.values()
                    )
                    if self._chain_mode:
                        # Chain mode: record intermediate flag, only return if exhausted
                        self._captured_flags.append(fv)
                        if self._count_unexploited_services() == 0:
                            self._chain_exhausted = True
                            final_flag = self._captured_flags[-1] if self._captured_flags else fv
                            result_task = TaskResult(
                                success=True, flag=final_flag, steps=self.step_count,
                                tokens_used=total_tokens,
                                time_elapsed=time.time() - self.start_time,
                            )
                            result_task.all_flags = list(self._captured_flags)
                            self.phase = OrchestratorPhase.DONE
                            return result_task
                        # Not exhausted: don't return, let loop continue
                        log.info("Chain mode: captured flag %s in multi-agent fallback, continuing",
                                 fv[:40])
                    else:
                        self.phase = OrchestratorPhase.DONE
                        return TaskResult(
                            success=True, flag=fv, steps=self.step_count,
                            tokens_used=total_tokens,
                            time_elapsed=time.time() - self.start_time,
                        )

            # Inject sub-agent results into orchestrator LLM context
            if results:
                report_parts = []
                for agent_id, result in results.items():
                    agent_type = getattr(result, 'agent_type', 'unknown')
                    success = getattr(result, 'success', False)
                    end_state = getattr(result, 'end_state', None)
                    state_val = end_state.value if hasattr(end_state, 'value') else str(end_state)
                    findings = getattr(result, 'findings_count', 0)
                    status = "SUCCESS" if success else f"FAILED ({state_val})"
                    summary = getattr(result, 'summary', '')
                    tokens = getattr(result, 'tokens_used', 0)
                    elapsed = getattr(result, 'time_elapsed', 0.0)
                    report_parts.append(
                        f"  [{agent_type}] {agent_id}: {status}, "
                        f"{findings} findings, {tokens} tokens, {elapsed:.1f}s"
                    )
                    if summary:
                        report_parts.append(f"    {summary}")
                if report_parts:
                    # Include specific DKG findings in the summary
                    dkg_flags = self.dkg.query_nodes("Flag")
                    dkg_creds = self.dkg.query_nodes("Credential")
                    dkg_vulns = self.dkg.query_nodes("Vulnerability")
                    finding_lines = []
                    for f in dkg_flags:
                        fv = f.get("value", "")
                        if fv:
                            finding_lines.append(f"  Flag: {fv[:60]}")
                    for c in dkg_creds:
                        finding_lines.append(
                            f"  Credential: {c.get('username','?')}@{c.get('source_host','?')}"
                        )
                    for v in dkg_vulns[-5:]:
                        finding_lines.append(
                            f"  Vuln: {v.get('vuln_type','?')} at {v.get('endpoint','?')}"
                        )
                    findings_block = ""
                    if finding_lines:
                        findings_block = (
                            f"\n## Specific Findings in DKG\n{chr(10).join(finding_lines[:12])}\n"
                        )
                    self.llm.add_context_message(
                        f"[MULTI-AGENT CYCLE COMPLETE] {len(results)} agents finished:\n\n"
                        f"{chr(10).join(report_parts)}"
                        f"{findings_block}\n"
                        f"Avoid re-trying failed approaches.",
                        role="user",
                    )
                    # Update central plan based on sub-agent findings
                    if self.exploitation_plan:
                        self._maybe_compress()
                        plan_content, _ = self.llm.generate(
                            prompt=(
                                f"Sub-agents completed. Results:\n"
                                f"{chr(10).join(report_parts)}\n\n"
                                f"Update the central exploitation plan based on these results. "
                                f"Add tasks for newly discovered attack paths. "
                                f"Mark tasks that sub-agents completed as done. "
                                f"Output updated plan as JSON array."
                            ),
                            system_prompt=SYSTEM_PROMPT_ORCHESTRATOR_UNIFIED,
                        )
                        if plan_content:
                            try:
                                new_tasks = self._extract_json(plan_content)
                                if isinstance(new_tasks, list) and new_tasks:
                                    done_tasks = [t for t in self.exploitation_plan.tasks
                                                 if t.get("status") == "done"]
                                    self.exploitation_plan.tasks = done_tasks
                                    for nt in new_tasks:
                                        nt.setdefault("status", "pending")
                                        nt.setdefault("dependent_task_ids", nt.pop("dependencies", []))
                                        if not any(t["id"] == nt["id"] for t in self.exploitation_plan.tasks):
                                            self.exploitation_plan.tasks.append(nt)
                                    log.info("[PLAN] updated from multi-agent results: %d tasks",
                                             len(self.exploitation_plan.tasks))
                            except Exception as e:
                                log.warning("Multi-agent plan update failed: %s", e)
                                # Fallback: create plan tasks directly from DKG findings
                                try:
                                    vulns = self.dkg.query_nodes("Vulnerability")
                                    for v in vulns[-5:]:
                                        vt = v.get("vuln_type", "")
                                        ep = v.get("endpoint", "")
                                        param = v.get("parameter", "")
                                        if vt and ep:
                                            tool = {"SQLI": "sqlmap_test", "XSS": "xss_reflection_test",
                                                    "CMDI": "command_injection_test"}.get(
                                                    vt.upper(), "send_payload")
                                            self.exploitation_plan.tasks.append({
                                                "id": f"fallback-{len(self.exploitation_plan.tasks)}",
                                                "instruction": f"Exploit {vt} at {ep}",
                                                "tool": tool,
                                                "params": {"url": ep, "param": param or "q"},
                                                "vuln_type": vt, "status": "pending",
                                                "dependent_task_ids": [],
                                            })
                                except Exception:
                                    pass

            # Spawn follow-up agents based on new DKG data
            await self._spawn_followup_agents(target_url, pool, cteg_hints)

            # Clean up done agents
            pool.cleanup()

            return None

        finally:
            flag_task.cancel()
            try:
                await flag_task
            except (asyncio.CancelledError, Exception):
                pass

    async def _analyze_from_recon_findings(self) -> None:
        """Analyze DKG recon discoveries and create Vulnerability hypotheses.

        Called after ReconAgent completes in multi-agent mode.
        Reads Endpoint/Service nodes, asks LLM to hypothesize vulnerabilities,
        and writes Vulnerability nodes to DKG for ExploitAgent to use.
        """
        endpoints = self.dkg.query_nodes("Endpoint")
        services = self.dkg.query_nodes("Service")
        if not endpoints and not services:
            return

        ep_lines = []
        for ep in endpoints[:20]:
            url = ep.get("url", "")
            method = ep.get("method", "GET")
            params = ep.get("params", "")
            ep_lines.append(f"  {method} {url}" + (f" params={params}" if params else ""))
        svc_lines = []
        for s in services[:10]:
            version = s.get("version", "") or s.get("banner", "")
            port = s.get("port", 0)
            if version and version not in ("http", "https", ""):
                svc_lines.append(f"  port {port}: {version}")

        self._maybe_compress()
        try:
            content, _ = self.llm.generate(
                prompt=(
                    f"## Discovered Endpoints\n" + "\n".join(ep_lines or ["(none)"]) + "\n\n"
                    f"## Discovered Technologies\n" + "\n".join(svc_lines or ["(none)"]) + "\n\n"
                    f"Analyze these findings and identify potential vulnerabilities.\n"
                    f"For each vulnerability, specify: vuln_type (SQLI/XSS/CMDI/SSTI/LFI/IDOR), "
                    f"endpoint URL, parameter name, severity (low/medium/high/critical), "
                    f"and a brief reason.\n"
                    f"Output as JSON array:\n"
                    f'[{{"vuln_type": "SQLI", "endpoint": "...", "parameter": "...", '
                    f'"severity": "high", "reason": "..."}}]'
                ),
                system_prompt=getattr(self, '_analyze_prompt_formatted', SYSTEM_PROMPT_ANALYZE),
            )
        except Exception as e:
            log.warning("_analyze_from_recon_findings LLM call failed: %s", e)
            return
        try:
            vulns = self._extract_json(content)
            if isinstance(vulns, list):
                for v in vulns:
                    if isinstance(v, dict) and v.get("vuln_type"):
                        self.dkg.add_node("Vulnerability",
                            f"vuln-ma-{v.get('vuln_type','')}-{v.get('endpoint','')[:20]}", {
                                "vuln_type": v.get("vuln_type", ""),
                                "endpoint": v.get("endpoint", ""),
                                "parameter": v.get("parameter", ""),
                                "severity": v.get("severity", "medium"),
                                "evidence": v.get("reason", ""),
                                "discovered_by": "multi-agent-analyze",
                            })
        except Exception as e:
            log.warning("_analyze_from_recon_findings parse failed: %s", e)

    async def _spawn_agents_from_dkg(
        self, target_url: str, pool,
        scaling_level: "ScalingLevel | None" = None,
        cteg_hints: dict | None = None,
    ) -> bool:
        """Spawn agents based on current DKG state. Returns True if any spawned.

        Differentiates spawning strategy by scaling_level:
          - Coordinated: max 1 ReconAgent + 1 ExploitAgent, no PivotAgent
          - Distributed: per-host ReconAgent, per-vuln ExploitAgent (max 3),
            PivotAgent if credentials + multi-host
        """
        from darwin.dynamic_scaling import ScalingLevel
        from darwin.sub_agents.base import TaskScope, TokenBudget, AgentType
        from darwin.sub_agents.recon_agent import ReconAgent
        from darwin.sub_agents.exploit_agent import ExploitAgent
        from darwin.sub_agents.pivot_agent import PivotAgent

        spawned = False
        hosts = self.dkg.query_nodes("Host")
        vulns = self.dkg.query_nodes("Vulnerability")
        creds = self.dkg.query_nodes("Credential")
        domains = self.dkg.query_nodes("Domain")

        # Environment detection: spawn specialized agents for AD/cloud
        is_ad_env = bool(domains) or any(
            s.get("port") in (445, 389, 636) for s in self.dkg.query_nodes("Service")
        )
        is_cloud_env = any(
            s.get("port") in (6443, 10250, 2379) for s in self.dkg.query_nodes("Service")
        ) or "kube" in str(self.dkg.summary()).lower()

        if is_ad_env and "ad-primary" not in getattr(pool, '_agents', {}):
            try:
                from darwin.sub_agents.ad_agent import ADAgent
                dc_ip = ""
                for h in hosts:
                    for s in self.dkg.query_nodes("Service"):
                        if s.get("port") in (445, 389) and s.get("host") == h.get("ip"):
                            dc_ip = h.get("ip", "")
                            break
                domain_name = ""
                for d in domains:
                    domain_name = d.get("name", "")
                    break
                scope = TaskScope(target_hosts=[h.get("ip", h.get("id", "")) for h in hosts])
                ad = ADAgent(agent_id="ad-primary", task_scope=scope, dkg=self.dkg,
                            budget=TokenBudget(max_tokens=64000, max_iterations=20),
                            domain_context={"domain_name": domain_name, "dc_ip": dc_ip,
                                           "credentials": str([c.get("user","") for c in creds])})
                pool.spawn(ad)
                spawned = True
                log.info("Spawned ADAgent for domain environment: %s", domain_name or dc_ip)
            except ImportError:
                pass

        if is_cloud_env and "cloud-primary" not in getattr(pool, '_agents', {}):
            try:
                from darwin.sub_agents.cloud_agent import CloudAgent
                scope = TaskScope(target_hosts=[h.get("ip", h.get("id", "")) for h in hosts])
                # Build cloud_context from DKG discoveries
                cloud_services = [s for s in self.dkg.query_nodes("Service")
                                  if s.get("port") in (6443, 10250, 2379, 10255)]
                cloud_context = {
                    "cluster_info": ", ".join(
                        f"port {s.get('port')}/{s.get('protocol','tcp')}: {s.get('version','') or s.get('banner','')}"
                        for s in cloud_services[:5]
                    ),
                    "pod_info": "Not yet enumerated",
                    "sa_info": "Not yet enumerated",
                    "resources": [],
                }
                cloud = CloudAgent(agent_id="cloud-primary", task_scope=scope, dkg=self.dkg,
                                  budget=TokenBudget(max_tokens=48000, max_iterations=15),
                                  cloud_context=cloud_context)
                pool.spawn(cloud)
                spawned = True
                log.info("Spawned CloudAgent for K8s/cloud environment")
            except ImportError:
                pass

        # Determine max agents based on scaling level
        if scaling_level == ScalingLevel.COORDINATED:
            max_recon = 1
            max_exploit = 1
            allow_pivot = False
            recon_budget = TokenBudget(max_tokens=32000, max_iterations=10)
            exploit_budget = TokenBudget(max_tokens=48000, max_iterations=12)
        else:  # DISTRIBUTED or default
            max_recon = len(hosts) if hosts else 1
            max_exploit = 3
            allow_pivot = bool(creds and len(hosts) > 1)
            recon_budget = TokenBudget(max_tokens=32000, max_iterations=15)
            exploit_budget = TokenBudget(max_tokens=48000, max_iterations=12)

        # ReconAgent per host (up to max_recon, skip if already running)
        recon_count = 0
        for h in hosts:
            if recon_count >= max_recon:
                break
            agent_id = f"recon-{h.get('id', 'unknown')}"
            if agent_id not in getattr(pool, '_agents', {}):
                scope = TaskScope(target_hosts=[
                    h.get("ip", "") or h.get("id", "")
                ])
                recon = ReconAgent(
                    agent_id=agent_id, task_scope=scope,
                    dkg=self.dkg,
                    budget=recon_budget,
                )
                pool.spawn(recon)
                spawned = True
                recon_count += 1
                log.info("Spawned ReconAgent: %s", agent_id)

        # ExploitAgent per vuln type (dedup by type, up to max_exploit)
        spawned_types: set[str] = set()
        existing_agents = getattr(pool, '_agents', {})
        exploit_count = sum(
            1 for a in existing_agents.values()
            if getattr(a, 'agent_type', None) == AgentType.EXPLOIT
        )
        for v in vulns[:6]:
            vt = (v.get("vuln_type") or v.get("type") or "").lower()
            if not vt or vt in spawned_types:
                continue
            if exploit_count >= max_exploit:
                break
            spawned_types.add(vt)
            agent_id = f"exploit-{vt}"
            if agent_id not in existing_agents:
                endpoint = v.get("endpoint", target_url)
                scope = TaskScope(target_hosts=[endpoint])
                exploit = ExploitAgent(
                    agent_id=agent_id, task_scope=scope,
                    dkg=self.dkg, dpm=self.dpm, dave=self.dave,
                    cteg=self.cteg,
                    cteg_hints=cteg_hints,
                    budget=exploit_budget,
                )
                pool.spawn(exploit)
                spawned = True
                exploit_count += 1
                log.info("Spawned ExploitAgent: %s (type=%s)", agent_id, vt)

        # PivotAgent if credentials + multi-host (Distributed mode only)
        if allow_pivot:
            agent_id = "pivot-primary"
            if agent_id not in existing_agents:
                scope = TaskScope(
                    target_hosts=[h.get("ip", h.get("id", "")) for h in hosts],
                )
                pivot = PivotAgent(
                    agent_id=agent_id, task_scope=scope,
                    dkg=self.dkg,
                    budget=TokenBudget(max_tokens=32000, max_iterations=15),
                )
                pool.spawn(pivot)
                spawned = True
                log.info("Spawned PivotAgent: %s", agent_id)

        return spawned

    async def _spawn_followup_agents(
        self, target_url: str, pool, cteg_hints: dict | None = None,
    ) -> None:
        """Scan DKG for collaboration opportunities and spawn follow-up agents.

        Re-evaluates AD/cloud environment detection — infrastructure discovered
        mid-chain (after initial spawn) is handled here.
        """
        from darwin.sub_agents.base import TaskScope, TokenBudget, AgentType
        from darwin.sub_agents.recon_agent import ReconAgent
        from darwin.sub_agents.exploit_agent import ExploitAgent
        from darwin.sub_agents.pivot_agent import PivotAgent

        existing = getattr(pool, '_agents', {})

        # Re-evaluate AD/cloud environment (may have been discovered mid-chain)
        domains = self.dkg.query_nodes("Domain")
        is_ad_env = bool(domains) or any(
            s.get("port") in (445, 389, 636, 3268, 3269)
            for s in self.dkg.query_nodes("Service")
        )
        is_cloud_env = any(
            s.get("port") in (6443, 10250, 2379, 10255)
            for s in self.dkg.query_nodes("Service")
        )

        if is_ad_env and "ad-primary" not in existing:
            try:
                from darwin.sub_agents.ad_agent import ADAgent
                hosts = self.dkg.query_nodes("Host")
                scope = TaskScope(target_hosts=[h.get("ip", h.get("id", "")) for h in hosts])
                ad = ADAgent(agent_id="ad-primary", task_scope=scope, dkg=self.dkg,
                            budget=TokenBudget(max_tokens=64000, max_iterations=20),
                            domain_context={"domain_name": "", "dc_ip": "",
                                           "credentials": str([c.get("user","") for c in self.dkg.query_nodes("Credential")])})
                pool.spawn(ad)
                log.info("Spawned follow-up ADAgent for newly discovered AD environment")
            except ImportError:
                pass

        if is_cloud_env and "cloud-primary" not in existing:
            try:
                from darwin.sub_agents.cloud_agent import CloudAgent
                hosts = self.dkg.query_nodes("Host")
                scope = TaskScope(target_hosts=[h.get("ip", h.get("id", "")) for h in hosts])
                cloud_services = [s for s in self.dkg.query_nodes("Service")
                                  if s.get("port") in (6443, 10250, 2379, 10255)]
                cloud_context = {
                    "cluster_info": ", ".join(
                        f"port {s.get('port')}: {s.get('version','') or s.get('banner','')}"
                        for s in cloud_services[:5]
                    ),
                    "pod_info": "Not yet enumerated",
                    "sa_info": "Not yet enumerated",
                }
                cloud = CloudAgent(agent_id="cloud-primary", task_scope=scope, dkg=self.dkg,
                                  budget=TokenBudget(max_tokens=48000, max_iterations=15),
                                  cloud_context=cloud_context)
                pool.spawn(cloud)
                log.info("Spawned follow-up CloudAgent for newly discovered K8s/cloud environment")
            except ImportError:
                pass

        # Check for new credentials → spawn PivotAgent
        creds = self.dkg.query_nodes("Credential")
        hosts = self.dkg.query_nodes("Host")
        if creds and len(hosts) > 1 and "pivot-primary" not in existing:
            scope = TaskScope(
                target_hosts=[h.get("ip", h.get("id", "")) for h in hosts],
            )
            pivot = PivotAgent(
                agent_id="pivot-followup", task_scope=scope,
                dkg=self.dkg,
                budget=TokenBudget(max_tokens=32000, max_iterations=15),
            )
            pool.spawn(pivot)
            log.info("Spawned follow-up PivotAgent")

        # Check for new internal hosts → spawn ReconAgent
        internal_hosts = [h for h in hosts if h.get("is_internal")]
        for h in internal_hosts:
            agent_id = f"recon-internal-{h.get('id', h.get('ip', ''))}"
            if agent_id not in existing:
                scope = TaskScope(target_hosts=[
                    h.get("ip", "") or h.get("id", "")
                ])
                recon = ReconAgent(
                    agent_id=agent_id, task_scope=scope,
                    dkg=self.dkg,
                    budget=TokenBudget(max_tokens=32000, max_iterations=15),
                )
                pool.spawn(recon)
                log.info("Spawned internal ReconAgent: %s", agent_id)

        # Check for new vulns → spawn ExploitAgent (if not already targeting this type)
        vulns = self.dkg.query_nodes("Vulnerability")
        existing_vuln_types: set[str] = set()
        for aid, agent in existing.items():
            if getattr(agent, 'agent_type', None) == AgentType.EXPLOIT:
                # Extract vuln type from agent_id
                parts = aid.split("-", 1)
                if len(parts) > 1:
                    existing_vuln_types.add(parts[1])

        exploit_count = sum(
            1 for a in existing.values()
            if getattr(a, 'agent_type', None) == AgentType.EXPLOIT
        )
        for v in vulns:
            vt = (v.get("vuln_type") or v.get("type") or "").lower()
            if vt and vt not in existing_vuln_types and exploit_count < 3:
                agent_id = f"exploit-{vt}"
                endpoint = v.get("endpoint", target_url)
                scope = TaskScope(target_hosts=[endpoint])
                exploit = ExploitAgent(
                    agent_id=agent_id, task_scope=scope,
                    dkg=self.dkg, dpm=self.dpm, dave=self.dave,
                    cteg=self.cteg,
                    cteg_hints=cteg_hints,
                    budget=TokenBudget(max_tokens=48000, max_iterations=12),
                )
                pool.spawn(exploit)
                exploit_count += 1
                existing_vuln_types.add(vt)
                log.info("Spawned follow-up ExploitAgent: %s", agent_id)

