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
from darwin.dpm import (
    DefenseCategory,
    DefensePerceptionModule,
    DefenseStateVector,
    SanitizationStrategy,
)
from darwin.dave import DAVE, ExploitAttempt, VerificationResult, parse_tool_stdout
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
    SYSTEM_PROMPT_EXPLORE,
)

# Version strings that carry no useful information for RAG lookup.
# Filtering them avoids polluting LLM context with irrelevant matches.
_NOISE_VERSIONS = {"unknown", "tcpwrapped", "http", "https", "ssh", "tcp", "udp"}


def _is_meaningful_version(version: str) -> bool:
    """Check if a service version string is worth querying RAG with."""
    v = version.strip().lower()
    if not v or v in _NOISE_VERSIONS:
        return False
    # Pure version numbers like "2.0" or "1" are not useful RAG queries
    if all(c in "0123456789.+-_ " for c in v) and len(v) < 8:
        return False
    return True


class Orchestrator:
    """Main Orchestrator Agent — Solo Mode.

    In Solo Mode, the Orchestrator directly executes tools without spawning sub-agents.
    This is the most efficient mode for single-host, single-vulnerability challenges.

    Reference: Cochise planner.py — Planner + temporary Executor
    """

    REQUIRED_TOOLS = [
        "nmap", "dirb", "whatweb", "curl",
        "sqlmap", "ffuf", "python3", "ssh", "sshpass",
        "masscan", "gobuster", "nikto", "hydra", "smbmap",
    ]
    OPTIONAL_TOOLS = ["searchsploit", "msfconsole"]

    def __init__(
        self,
        llm_session: LLMSession | None = None,
        time_budget: int = 600,
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
        self.sub_agents = SubAgentPool()
        self._persistent_pool = None  # Created on first multi-agent cycle

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

    async def run(
        self, task_description: str, target_url: str,
        username: str | None = None, password: str | None = None,
    ) -> TaskResult:
        """Run penetration test against a single target."""
        self.start_time = time.time()
        self._solo_cycle_context_injected = False
        self.target_url = target_url
        self._provided_username = username
        self._provided_password = password

        ts = time.strftime("%Y%m%d_%H%M%S", time.localtime())
        self._task_log_path = f"checkpoints/task_{ts}.json"
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

        self.phase = OrchestratorPhase.RECON
        result: TaskResult | None = None

        try:
            # ── Phase 1: Bootstrap scan (nmap + HTTP probe) ──
            await self._bootstrap_scan(target_url)
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

            # ── Main Loop: B-driven mode switching ────────────────
            self._loop_count = 0
            MAX_LOOPS = 10
            self._known_flags: set[str] = set()

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
                        self.phase = OrchestratorPhase.DONE
                        result = TaskResult(
                            success=True, flag=fv, steps=self.step_count,
                            tokens_used=self.llm.token_count,
                            time_elapsed=time.time() - self.start_time,
                        )
                if result and result.success:
                    break

                # Re-compute B dimension each iteration (DKG may have changed)
                B = compute_task_breadth(self.dkg, self.defense_state)
                scaling_level = self.scaling_engine.decide(self.dkg, self.defense_state)
                self._task_log_event("info", "loop_iteration",
                    loop=self._loop_count, b_value=B, mode=scaling_level.value)

                if scaling_level == ScalingLevel.SOLO:
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
                        await self._research_phase()
                        self._research_done = True

                    # Phase 4: Unified LLM loop (plan → exploit → replan)
                    result = await self._unified_llm_loop(target_url, cteg_hints)

                    # Allow up to 3 solo iterations before marking exhausted
                    self._solo_iterations += 1
                    if result is None or not result.success:
                        if self._solo_iterations >= 3:
                            self._surface_exhausted = True
                    else:
                        self._surface_exhausted = True
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
                        result = await self._unified_llm_loop(target_url, cteg_hints)

                    self._multi_agent_iterations += 1
                    if result is None or not result.success:
                        if self._multi_agent_iterations >= 3:
                            self._surface_exhausted = True
                    else:
                        self._surface_exhausted = True

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

    async def _bootstrap_scan(self, target_url: str) -> None:
        """Minimal bootstrap: nmap port scan only. LLM drives all further recon.

        Records discovered ports as Host/Service nodes in DKG.
        Marks SSH ports as skip_exploit. Detects AD domain ports.
        Does NOT probe HTTP services — the LLM decides which ports to probe.
        """
        self.phase = OrchestratorPhase.BOOTSTRAP
        from urllib.parse import urlparse as _up
        parsed = _up(target_url)
        host = parsed.hostname or target_url
        self.target_host = host

        self._task_log_event("info", "bootstrap_nmap", host=host)
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

        for p in discovered_ports:
            self.dkg.add_node("Host", f"host-{host}", {
                "ip": host, "is_reachable": True, "is_internal": False,
            })
            self.dkg.add_node("Service", f"svc-{host}-{p['port']}", {
                "port": p["port"], "protocol": "tcp",
                "version": p.get("version", "") or p.get("service", ""),
                "banner": p.get("service", ""),
            })

        # AD detection
        _AD_PORTS = {445, 389, 636, 3268, 3269}
        if any(p["port"] in _AD_PORTS for p in discovered_ports):
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
        http_ports = [p for p in discovered_ports
                      if str(p.get("port")) not in {"22", "445", "389", "636", "3268", "3269"}]

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
                "sample_response": stdout[:500],
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
            for tech in technologies:
                self.dkg.add_node("Service", f"tech-{tech[:30]}", {
                    "port": 0, "protocol": "HTTP",
                    "version": tech, "banner": tech,
                    "discovered_by": "bootstrap",
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
                        "sample_status": st, "sample_response": out[:500],
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
                                "sample_status": st, "sample_response": out[:500],
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
                                    "sample_status": 200, "sample_response": out[:500],
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

        # Run deep recon in parallel across endpoints (max 6 concurrent)
        batch = [ep for ep in endpoints[:8] if ep.get("url","").startswith("http")]
        if batch:
            tasks = [asyncio.create_task(_probe_one(ep)) for ep in batch]
            await asyncio.gather(*tasks, return_exceptions=True)
        log.info("_deep_recon: complete")

    async def _detect_defenses(self) -> None:
        """Run DPM defense probes on discovered endpoints and update defense_state.

        Sends filter probes (classes A-E) to up to 3 GET endpoints, then
        runs the rule-based DPM detection pipeline (no LLM cost).
        """
        endpoints = self.dkg.query_nodes("Endpoint")
        get_endpoints = [
            e for e in endpoints
            if e.get("url", "").startswith("http") and e.get("method", "GET") == "GET"
        ][:3]
        if not get_endpoints:
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

    async def _verify_flag(
        self, flag: str, stdout: str, tc_args: dict, elapsed_ms: int = 0,
    ) -> tuple[bool, str]:
        """Verify a flag with full DAVE L1+L4 when HTTP data is available.

        Falls back to verify_basic for non-HTTP tools (sqlmap, ffuf, etc.).
        """
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
            if v_result.flag_found:
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
            return True
        if self._time_exceeded() or self._tokens_exceeded():
            return True
        if self.phase in (OrchestratorPhase.DONE, OrchestratorPhase.FAILED):
            return True
        if self._loop_count >= max_loops:
            log.info("Max loops (%d) reached", max_loops)
            return True
        if getattr(self, '_surface_exhausted', False):
            log.info("Attack surface exhausted — terminating main loop")
            return True
        return False

    # ── Unified State Access ──────────────────────────────────────

    def _get_state(self) -> PipelineState:
        """Return a typed snapshot of the current DKG state.

        All phases call this instead of raw dkg.query_nodes() + dict access.
        """
        return normalize_dkg_state(self.dkg)

    # ── Tool Result Feedback ─────────────────────────────────────

    EXPLOIT_TOOLS = {"sqlmap_test", "send_payload", "command_injection_test",
                     "xss_reflection_test", "ffuf_fuzz", "http_post"}

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
            parts.append(f"STDOUT: {stdout[:1500]}")
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
        MAX_ITER = 12
        if not self._solo_cycle_context_injected:
            self.llm.replace_system_prompt(SYSTEM_PROMPT_ORCHESTRATOR_UNIFIED)
            self._solo_cycle_context_injected = True

            # Build initial context from bootstrap DKG state
            state = self._get_state()
            services_lines = []
            for s in state.services:
                if s.port:
                    skip = " [skip_exploit]" if s.skip_exploit else ""
                    services_lines.append(
                        f"  port {s.port}/{s.protocol}: {s.version or s.banner}{skip}"
                    )
            services_text = "\n".join(services_lines) if services_lines else "(none)"

            initial_prompt = (
                f"Target: {target_url}\n\n"
                f"## Reconnaissance Complete\n"
                f"All scanning, probing, enumeration, vulnerability analysis, and research done.\n"
                f"- {len(state.services)} services, {len(state.endpoints)} endpoints\n"
                f"- {len(self.vulnerabilities)} vulnerability hypotheses researched\n\n"
                f"{services_text}\n"
                f"## Your Mission\n"
                f"Generate an EXPLOIT plan. For each vulnerability, use the appropriate "
                f"exploit tool. Credential discovery (try_login, reading config files) is "
                f"allowed but keep it to 1-2 tasks — the majority must be exploitation.\n"
                f"If blocked, try bypass techniques or alternative tools.\n"
                f"Adapt the plan after each task based on results.\n"
            )
            self.llm.add_context_message(initial_prompt, role="user")
        else:
            self._maybe_compress()
            state = self._get_state()
            flag_count = len(state.flags)
            self.llm.add_context_message(
                f"[CYCLE TRANSITION] New loop cycle. "
                f"Flags found: {flag_count}. "
                f"Endpoints: {len(state.endpoints)}, Services: {len(state.services)}.",
                role="user",
            )

        self._exploit_chain: list[dict] = []

        # Generate initial plan
        if not self.exploitation_plan or not self.exploitation_plan.tasks:
            self.exploitation_plan = await self._generate_exploitation_plan(target_url, cteg_hints)

        # Plan already generated before systematic exploit — skip duplicate

        # Build tool definitions from recon + attack gateways + MCP servers
        tool_defs = self.attack_gateway.get_tool_definitions()
        tool_defs += self.recon_gateway.get_tool_definitions()
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
            if parts:
                cteg_text = "\n## Prior Experience (CTEG):\n" + "\n".join(parts) + "\n"

        # Query DarwinRAG for relevant static knowledge patterns
        knowledge_text = ""
        try:
            tech_hints = " ".join(
                s.get("version", "") or s.get("banner", "")
                for s in self.dkg.query_nodes("Service")[:5]
                if _is_meaningful_version(s.get("version", "") or s.get("banner", ""))
            )
            from darwin.rag import get_rag
            rag = get_rag()
            kb_results = rag.search(
                f"exploitation techniques for {tech_hints} web application", top_k=4,
                min_keyword_overlap=0.1,
            )
            if kb_results:
                knowledge_text = "\n## Relevant Knowledge Base Patterns:\n"
                for r in kb_results[:3]:
                    knowledge_text += (f"- **{r['title']}** ({r.get('collection','')}/{r['category']}): "
                                       f"{r['description'][:200]}\n")
                    for t in r.get("techniques", [])[:3]:
                        knowledge_text += f"  - {t}\n"
                knowledge_text += "\n"
        except Exception:
            pass

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
{knowledge_text}

## Guidance:
- Endpoints with params: {param_endpoints}
- POST endpoints: {post_endpoints}
- Auto-login tried: test/test (failed), admin/admin (failed)
- Already tested: {systematic_tested}
- For POST endpoints, check body_format before choosing content_type
- Use knowledge_search for technique guidance if stuck

{plan_status}
{vuln_text}
"""

        # Inject initial context into LLM conversation (no tool calling yet).
        # The plan-driven loop below will start task execution.
        self.llm.add_context_message(initial_prompt, role="user")

        print(f"\n[solo] Starting plan-driven loop: "
              f"{len(self.exploitation_plan.tasks) if self.exploitation_plan else 0} tasks, "
              f"token_count={self.llm.token_count}")

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
                    # Build a meaningful summary so the LLM can decide
                    # whether to add new tasks or give up.
                    state = self._get_state()
                    ep_list = [f"{ep.method} {ep.url}" for ep in state.endpoints[-8:]]
                    exhaustion_summary = (
                        f"Plan exhausted. {len(self.exploitation_plan.tasks)} tasks completed/failed.\n"
                        + (f"Known endpoints: {', '.join(ep_list)}" if ep_list else "No endpoints discovered.")
                        + (f"\nCredentials: {len(state.credentials)} known" if state.credentials else "")
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
                log.info("Solo loop: plan exhausted after %d iterations — "
                         "entering free-form exploration", iteration - 1)
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

            # Tell LLM to execute this specific task
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
                freedom_note = (
                    f"You may use a different tool if you have a better approach, "
                    f"but you MUST target this task's objective."
                )
            task_prompt = (
                f"Execute plan task {iteration}/{MAX_ITER}:\n"
                f"  Instruction: {task_instruction}\n"
                f"  Suggested tool: {task_tool}\n"
                f"  Params: {json.dumps(task_params)}\n\n"
                f"{freedom_note}"
            )
            content, tool_calls = self.llm.generate(
                prompt=task_prompt,
                system_prompt=SYSTEM_PROMPT_ORCHESTRATOR,
                tools=tool_defs,
            )

            if not tool_calls:
                # Retry once with more explicit instruction
                content2, tool_calls = self.llm.generate(
                    prompt=f"You MUST call the tool '{task_tool}' now. "
                           f"Do not explain. Just execute the function call.",
                    system_prompt=SYSTEM_PROMPT_ORCHESTRATOR,
                    tools=tool_defs,
                )
            if not tool_calls:
                log.info("[PLAN] task %s: LLM produced no tool calls — skipping",
                         task.get("id", ""))
                task["status"] = "skipped"
                continue

            # Execute tool calls for this task
            tc_names = [tc.get('name', '?') for tc in tool_calls]
            print(f"\n[solo:{iteration}] task={task.get('id','')} → "
                  f"{', '.join(tc_names)}")
            task_success = False  # at least one tool must succeed
            _any_success = False
            task_summary = ""
            _all_task_stdouts: list[str] = []  # accumulate all tool outputs
            _auto_test_negative = False  # track "no evidence" / "no flag"

            for tc in tool_calls:
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

                try:
                    if tc_name in self.attack_gateway.get_tool_names():
                        result = await self.attack_gateway.call(tc_name, tc_args)
                    elif tc_name in self.recon_gateway.get_tool_names():
                        result = await self.recon_gateway.call(tc_name, tc_args)
                    elif tc_name in self.mcp_pool.get_tool_names():
                        mcp_raw = await self.mcp_pool.call_tool(tc_name, tc_args)
                        mcp_text = json.dumps(mcp_raw, ensure_ascii=False)
                        result = type('obj', (object,), {
                            'success': True, 'stdout': mcp_text,
                            'stderr': '', 'exit_code': 0, 'elapsed_ms': 0,
                        })()
                    else:
                        result = type('obj', (object,), {
                            'success': False, 'stdout': f"Unknown tool: {tc_name}",
                            'stderr': '', 'exit_code': 1, 'elapsed_ms': 0,
                        })()
                except Exception as e:
                    result = type('obj', (object,), {
                        'success': False, 'stdout': '', 'stderr': str(e),
                        'exit_code': 1, 'elapsed_ms': 0,
                    })()

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
                self.llm.add_tool_result(tc_id, tool_stdout[:2500])

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
                # Accumulate each tool's output for plan review context
                _out = getattr(result, 'stdout', '') or ''
                _all_task_stdouts.append(f"[{tc_name}] {_out[:800]}")
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
            await self._review_and_update_plan(
                task, task_success, task_result_text
            )
            log.info("[PLAN REVIEW] task %s → %s, plan updated",
                     task.get("id", ""), "done" if task_success else "failed")

        log.info("_unified_llm_loop: %d iterations, flag not found", iteration)

        # ── Free-form exploration (plan exhausted but LLM can still try) ──
        # After plan tasks are done, let the LLM explore freely for a few
        # more rounds — it may try creative approaches the plan missed.
        if getattr(self, '_surface_exhausted', False):
            pass  # skip if already exhausted
        else:
            explore_rounds = min(3, MAX_ITER - iteration)
            for explore_iter in range(1, explore_rounds + 1):
                if self._time_exceeded() or self._tokens_exceeded():
                    break
                self._maybe_compress()

                # Build a summary of what we learned from the plan phase
                learnings = self._summarize_plan_learnings()
                explore_prompt = (
                    f"FREE EXPLORATION round {explore_iter}/{explore_rounds}.\n"
                    f"All automated and planned tests completed. No flag found yet.\n\n"
                    f"## What We Have Learned\n{learnings}\n\n"
                    f"## Your Task\n"
                    f"Based on the learnings above, try 2-4 manual approaches:\n"
                    f"- If an API returned JSON data with resource listings, follow the "
                    f"resource paths: enumerate individual items, check nested sub-resources, "
                    f"look for fields containing secrets/tokens/keys.\n"
                    f"- If an endpoint returned different response sizes for different "
                    f"inputs, enumerate MORE input values to find hidden data.\n"
                    f"- If you got JSON responses, inspect field values (description, name, "
                    f"notes, data, secret, token, key, password) — flags are often hidden there.\n"
                    f"- If you found an OpenAPI spec or API docs, use those paths directly.\n"
                    f"- Use curl_get to access paths you haven't tried yet based on "
                    f"patterns seen in responses (IDs, paths, resource types).\n"
                    f"- Use http_post with JSON body for POST/JSON endpoints to query or mutate.\n"
                    f"Do NOT repeat tests that already returned the same result."
                )
                content, tool_calls = self.llm.generate(
                    prompt=explore_prompt,
                    system_prompt=SYSTEM_PROMPT_ORCHESTRATOR,
                    tools=tool_defs,
                )
                if not tool_calls:
                    # LLM responded with text but no action — push once more
                    content2, tool_calls = self.llm.generate(
                        prompt="You MUST call a tool. Try an exploit tool or curl_get to search for the flag.",
                        system_prompt=SYSTEM_PROMPT_ORCHESTRATOR,
                        tools=tool_defs,
                    )
                if not tool_calls:
                    break
                tc_names = [tc.get('name', '?') for tc in tool_calls]
                print(f"\n[solo:explore:{explore_iter}] {', '.join(tc_names)}")
                for tc in tool_calls:
                    tc_name = tc.get("name", "")
                    tc_args = tc.get("arguments", {})
                    tc_id = tc.get("id", "")
                    if self._time_exceeded():
                        self.llm.add_tool_result(tc_id, "Skipped: time exceeded")
                        continue
                    self.step_count += 1
                    try:
                        if tc_name in self.attack_gateway.get_tool_names():
                            result = await self.attack_gateway.call(tc_name, tc_args)
                        elif tc_name in self.recon_gateway.get_tool_names():
                            result = await self.recon_gateway.call(tc_name, tc_args)
                        elif tc_name in self.mcp_pool.get_tool_names():
                            mcp_raw = await self.mcp_pool.call_tool(tc_name, tc_args)
                            mcp_text = json.dumps(mcp_raw, ensure_ascii=False)
                            result = type('obj', (object,), {
                                'success': True, 'stdout': mcp_text,
                                'stderr': '', 'exit_code': 0, 'elapsed_ms': 0})()
                        else:
                            result = type('obj', (object,), {
                                'success': False, 'stdout': f"Unknown tool: {tc_name}",
                                'stderr': '', 'exit_code': 1, 'elapsed_ms': 0})()
                    except Exception as e:
                        result = type('obj', (object,), {
                            'success': False, 'stdout': '', 'stderr': str(e),
                            'exit_code': 1, 'elapsed_ms': 0})()
                    result_stdout = getattr(result, 'stdout', '') or ''
                    tool_stdout = self._format_tool_feedback(tc_name, tc_args, result, "")
                    self.llm.add_tool_result(tc_id, tool_stdout[:2500])
                    print(f"  [{tc_name}] → {tool_stdout.split(chr(10))[0][:120]}")
                    flags = self.flag_pattern.findall(result_stdout)
                    if flags:
                        is_valid, reason = await self._verify_flag(
                            flags[0], result_stdout, tc_args,
                            getattr(result, "elapsed_ms", 0),
                        )
                        if is_valid:
                            self.phase = OrchestratorPhase.DONE
                            return TaskResult(
                                success=True, flag=flags[0], steps=self.step_count,
                                tokens_used=self.llm.token_count,
                                time_elapsed=time.time() - self.start_time)

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
        }
        # Fuzzy match: if a vuln type CONTAINS one of these substrings, it maps
        FUZZY_MAP: dict[str, list[str]] = {
            "sqli": ["sqlmap_test"],
            "xss": ["xss_reflection_test"],
            "cmdi": ["command_injection_test"],
            "idor": ["curl_get"],
            "auth": ["curl_get"],
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

        tried: set[tuple[str, str, str]] = set()  # (tool, url, param) dedup
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
                    args = {"url": endpoint, "param": param} if param else {"url": endpoint}
                # Merge LLM-suggested args (method, body_format, etc.) as overrides
                if tool_name == llm_tool and llm_args:
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
                        is_valid, reason = DAVE.verify_basic(f, stdout)
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
                        is_valid, reason = DAVE.verify_basic(f, stdout)
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
        self.llm.reset()

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

        # Enrich with DarwinRAG knowledge
        try:
            from darwin.rag import get_rag
            rag = get_rag()
            services = self.dkg.query_nodes("Service")
            tech_hints = []
            for s in services[:5]:
                version = s.get("version", "") or s.get("banner", "")
                if version and _is_meaningful_version(version):
                    rag_results = rag.search(version, top_k=2, min_keyword_overlap=0.1)
                    for r in rag_results:
                        tech_hints.append(f"[{r.get('collection','')}/{r.get('category','')}/{r.get('subcategory','')}] {r['title']}: {r['description'][:200]}")
            if tech_hints:
                prompt += f"\n\n## Relevant Attack Techniques from Knowledge Base\n" + "\n".join(tech_hints)
        except Exception:
            pass

        self._maybe_compress()
        tokens_before = self.llm.token_count

        print(f"\n{'='*50}")
        print(f"[ANALYZE] Asking LLM to identify vulnerabilities...")
        print(f"[ANALYZE] State: {len(state.endpoints)} endpoints, "
              f"{len(state.services)} services, "
              f"{len(state.vulnerabilities)} vulns")

        # Build tool lists for the analyze prompt so LLM uses exact names
        attack_tool_names = sorted(self.attack_gateway.get_tool_names())
        recon_tool_names = sorted(self.recon_gateway.get_tool_names())
        analyze_system_prompt = SYSTEM_PROMPT_ANALYZE.format(
            attack_tools=", ".join(attack_tool_names),
            recon_tools=", ".join(recon_tool_names),
        )

        content, _ = self.llm.generate(
            prompt=prompt,
            system_prompt=analyze_system_prompt,
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
            if not url or any(v.endpoint == url for v in self.vulnerabilities):
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
            from darwin.rag import get_rag
            rag = get_rag()
            for s in services[:10]:
                port = s.get("port", 0)
                version = s.get("version", "") or s.get("banner", "")
                if s.get("skip_exploit"):
                    continue
                if not version or version in ("unknown", "tcpwrapped", "http", "https", ""):
                    continue
                # Local RAG
                rag_results = rag.search(f"{version} exploit vulnerability", top_k=2,
                                         min_keyword_overlap=0.1)
                for r in rag_results:
                    service_research_text += (
                        f"\n[port {port}] {version}: {r['title']} "
                        f"({r.get('collection','')}) — {r['description'][:200]}\n"
                    )
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
            if service_research_text:
                self.llm.add_context_message(
                    f"[SERVICE RESEARCH] Known vulnerabilities for discovered services:\n"
                    f"{service_research_text}",
                    role="user",
                )
                log.info("_service_research: injected %d chars of CVE data",
                         len(service_research_text))
        except Exception as e:
            log.warning("_service_research failed: %s", e)

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
        for gw in [self.attack_gateway]:
            for td in gw.get_tool_definitions():
                name = td.get("function", {}).get("name", "")
                if name in ("knowledge_search", "cve_lookup",
                            "metasploit_search", "searchsploit_search",
                            "go_exploitdb_search", "curl_get"):
                    research_tools.append(td)
        # Add MCP research tools (search, code search, CVE lookup)
        try:
            for td in self.mcp_pool.get_tool_definitions():
                name = td.get("function", {}).get("name", "")
                if any(kw in name.lower() for kw in
                       ("search", "cve", "vuln", "exploit", "code", "repo")):
                    research_tools.append(td)
        except Exception:
            pass

        vuln_text = self._format_vulnerability_summary()
        research_prompt = (
            f"You are in the RESEARCH phase. Do NOT run any exploit tools "
            f"(no sqlmap, command_injection, xss_reflection, send_payload, ffuf, hydra).\n\n"
            f"## Vulnerabilities to research:\n{vuln_text}\n\n"
            f"## Available research tools:\n"
            f"- knowledge_search: query the knowledge base for techniques and bypass patterns\n"
            f"- cve_lookup: look up CVE details (CVSS, severity, exploit availability)\n"
            f"- metasploit_search: search for Metasploit modules\n"
            f"- searchsploit_search: search ExploitDB for public exploits\n"
            f"- go_exploitdb_search: search local exploit database\n"
            f"- curl_get: fetch documentation or verify endpoint details\n\n"
            f"## Instructions:\n"
            f"1. For each vulnerability, research the attack technique using knowledge_search\n"
            f"2. If nmap_vulners found CVE IDs, look them up with cve_lookup\n"
            f"3. Search for known exploits using metasploit_search and searchsploit_search\n"
            f"4. After researching, output a JSON summary of findings for each vuln:\n"
            f'   [{{"vuln_type": "...", "cve_ids": [...], "exploit_modules": [...],'
            f'     "key_techniques": [...], "confidence_adjustment": 0.0}}]\n'
        )

        self._maybe_compress()
        content, tool_calls = self.llm.generate(
            prompt=research_prompt,
            system_prompt=SYSTEM_PROMPT_ANALYZE,
            tools=research_tools,
        )

        # Execute research tool calls (max 3 rounds)
        for _ in range(3):
            if not tool_calls:
                break
            for tc in tool_calls:
                tc_name = tc.get("name", "")
                tc_args = tc.get("arguments", {})
                tc_id = tc.get("id", "")
                if tc_name in self.attack_gateway.get_tool_names():
                    result = await self.attack_gateway.call(tc_name, tc_args)
                elif tc_name in self.recon_gateway.get_tool_names():
                    result = await self.recon_gateway.call(tc_name, tc_args)
                elif tc_name in self.mcp_pool.get_tool_names():
                    import json as _json
                    mcp_raw = await self.mcp_pool.call_tool(tc_name, tc_args)
                    mcp_text = _json.dumps(mcp_raw, ensure_ascii=False)
                    result = type('obj', (object,), {
                        'success': True, 'stdout': mcp_text,
                        'stderr': '', 'exit_code': 0, 'elapsed_ms': 0})()
                else:
                    continue
                tool_stdout = self._format_tool_feedback(tc_name, tc_args, result, "")
                self.llm.add_tool_result(tc_id, tool_stdout[:2000])

            self._maybe_compress()
            content, tool_calls = self.llm.generate(
                prompt="Continue researching. Output JSON summary when done.",
                system_prompt=SYSTEM_PROMPT_ANALYZE,
                tools=research_tools,
            )

        # Execute any remaining tool calls from the last round
        if tool_calls:
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
                        import json as _json
                        mcp_raw = await self.mcp_pool.call_tool(tc_name, tc_args)
                        mcp_text = _json.dumps(mcp_raw, ensure_ascii=False)
                        result = type('obj', (object,), {
                            'success': True, 'stdout': mcp_text,
                            'stderr': '', 'exit_code': 0, 'elapsed_ms': 0})()
                    else:
                        continue
                    tool_stdout = self._format_tool_feedback(tc_name, tc_args, result, "")
                    self.llm.add_tool_result(tc_id, tool_stdout[:2000])
                except Exception:
                    self.llm.add_tool_result(tc_id, "Tool execution failed")
            # Final summary generation (no tools — closes the tool_call cycle)
            self._maybe_compress()
            content, tool_calls = self.llm.generate(
                prompt="All research complete. Output final JSON summary of findings for each vulnerability.",
                system_prompt=SYSTEM_PROMPT_ANALYZE,
            )
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
                                    if f.get("key_techniques"):
                                        v.evidence = (v.evidence or "") + f" Techniques: {f['key_techniques']}"
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
            system_prompt=SYSTEM_PROMPT_ANALYZE,
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
                system_prompt=SYSTEM_PROMPT_ANALYZE,
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

    def _summarize_plan_learnings(self) -> str:
        """Build a summary of what we learned from plan task execution.

        Extracts response patterns, discovered endpoints, and anomalies from
        the exploitation_plan and DKG to guide free-form exploration.
        """
        parts: list[str] = []

        # Summarize plan task outcomes
        plan = getattr(self, 'exploitation_plan', None)
        if plan and plan.tasks:
            done_tasks = [t for t in plan.tasks if t.get("status") == "done"]
            failed_tasks = [t for t in plan.tasks if t.get("status") in ("failed", "skipped")]
            for t in done_tasks[:5]:
                summary = t.get("result_summary", "")[:200]
                inst = t.get("instruction", "")[:120]
                if summary:
                    parts.append(f"- DONE: {inst} → {summary}")
                else:
                    parts.append(f"- DONE: {inst}")
            for t in failed_tasks[:3]:
                inst = t.get("instruction", "")[:120]
                parts.append(f"- FAILED: {inst}")

        # Summarize endpoints from typed state
        state = self._get_state()
        for ep in state.endpoints[:10]:
            if ep.sample_response:
                parts.append(
                    f"- Endpoint {ep.url}: HTTP {ep.sample_status}, "
                    f"response: {ep.sample_response[:200]}"
                )
            elif ep.sample_status:
                parts.append(f"- Endpoint {ep.url}: HTTP {ep.sample_status}")

        return "\n".join(parts) if parts else "(no learnings yet)"

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
        # All tools: recon + attack, since LLM drives everything
        all_tools = sorted(set(
            self.attack_gateway.get_tool_names() +
            self.recon_gateway.get_tool_names()
        ))

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

        # DarwinRAG knowledge from service versions
        knowledge_context = ""
        try:
            from darwin.rag import get_rag
            rag = get_rag()
            seen_titles = set()
            for s in state.services[:5]:
                if s.version and s.version not in ("unknown", "tcpwrapped"):
                    results = rag.search(s.version, top_k=2, min_keyword_overlap=0.1)
                    for r in results:
                        if r["title"] not in seen_titles:
                            seen_titles.add(r["title"])
                            knowledge_context += f"\n  - [{r.get('collection','')}] {r['title']}: {r['description'][:200]}"
            if knowledge_context:
                knowledge_context = "\n## Relevant Knowledge\n" + knowledge_context + "\n"
        except Exception:
            pass

        prompt = f"""Target: {target_url}

## Discovered Services (from nmap)
{chr(10).join(services_lines) if services_lines else '(none)'}

## Current State
- {len(state.endpoints)} endpoints discovered so far
- {len(state.services)} services detected
- Credentials: {len(state.credentials)} known
{phase_summary}
{knowledge_context}
## Analyzed Vulnerabilities
{self._format_vulnerability_summary()}
## Available Tools (all recon + attack)
{', '.join(all_tools)}

## Task
Generate a plan as a JSON array of EXPLOIT tasks. Reconnaissance and research
have already been completed. Each task should test or exploit a vulnerability:
- id: unique string (e.g. "task-1")
- dependent_task_ids: list of task IDs that must complete first
- instruction: what to exploit and how
- tool: exact exploit tool name (sqlmap_test, command_injection_test, etc.)
- params: tool parameters dict
- reason: which vulnerability this targets

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
  {"id": "task-1", "dependent_task_ids": [],
   "instruction": "Test SQLi on login endpoint", "tool": "sqlmap_test", ...},
  {"id": "task-2", "dependent_task_ids": [],
   "instruction": "Test CMDi on upload endpoint", "tool": "command_injection_test", ...},
  {"id": "task-3", "dependent_task_ids": ["task-1", "task-2"],
   "instruction": "Use obtained credentials for SSH pivot",
   "tool": "ssh_execute", ...}
]
```
task-1 and task-2 run first (parallel, independent). task-3 waits for both.

## Strategy
1. For each vulnerability listed above, create one exploit task using the
   suggested tool. Prioritize high-confidence vulnerabilities first.
2. If an exploit succeeds or reveals new information, the plan will be
   updated after each task — new tasks can be added in replanning.
3. Do NOT add curl_get/http_post probing tasks — services have already been
   probed during reconnaissance.
4. If a vulnerability's suggested tool is curl_get (for LFI/IDOR/SSRF), use
   curl_get with the exact URL and parameter.

Output ONLY valid JSON array. One task per vulnerability (3-8 tasks)."""

        self._maybe_compress()
        try:
            content, _ = self.llm.generate(prompt=prompt, timeout=120.0)
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
                content, _ = self.llm.generate(prompt=short_prompt, timeout=120.0)
            except Exception as e2:
                log.warning("Plan generation retry also failed: %s — using hardcoded fallback", e2)
                content = ""

        try:
            tasks = [t for t in (self._extract_json_array(content) or []) if isinstance(t, dict)]
            for t in tasks:
                t.setdefault("status", "pending")
                t.setdefault("dependent_task_ids", t.pop("dependencies", []))
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
        task_map = {t["id"]: t for t in tasks}
        in_degree = {t["id"]: 0 for t in tasks}
        adj = {t["id"]: [] for t in tasks}
        for t in tasks:
            for dep_id in t.get("dependent_task_ids", []) or t.get("dependencies", []):
                if dep_id in task_map:
                    adj[dep_id].append(t["id"])
                    in_degree[t["id"]] += 1
        queue = deque([tid for tid, deg in in_degree.items() if deg == 0])
        result = []
        while queue:
            tid = queue.popleft()
            result.append(task_map[tid])
            for neighbor in adj[tid]:
                in_degree[neighbor] -= 1
                if in_degree[neighbor] == 0:
                    queue.append(neighbor)
        result.extend([task_map[tid] for tid in in_degree if tid not in {r["id"] for r in result}])
        return result

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
            "xss_reflection_test", "ffuf_fuzz", "hydra_http_brute",
            "hydra_ssh_brute",
        }
        ready_exploit = []
        ready_probe = []
        for task in self._topological_sort(plan.tasks):
            if task.get("status") != "pending":
                continue
            deps_met = True
            for dep_id in task.get("dependent_task_ids", []) or task.get("dependencies", []):
                dep_task = next((t for t in plan.tasks if t["id"] == dep_id), None)
                if not dep_task or dep_task.get("status") != "done":
                    deps_met = False
                    break
            if deps_met:
                tool = task.get("tool", "")
                if tool in _EXPLOIT_PRIORITY:
                    ready_exploit.append(task)
                else:
                    ready_probe.append(task)
        return ready_exploit[0] if ready_exploit else (ready_probe[0] if ready_probe else None)

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
        failed = sum(1 for t in plan.tasks if t.get("status") in ("failed", "skipped"))
        pending = sum(1 for t in plan.tasks if t.get("status") == "pending")
        lines = [f"## Exploitation Plan ({done}/{len(plan.tasks)} done, {failed} failed, {pending} pending)"]
        for t in self._topological_sort(plan.tasks):
            status = t.get("status", "pending").upper()
            deps = t.get("dependent_task_ids", []) or t.get("dependencies", [])
            dep_str = f" (waits for: {', '.join(deps)})" if deps else ""
            lines.append(f"  {t['id']}: [{status}] {t.get('instruction','')[:100]}{dep_str}")
        return "\n".join(lines)

    async def _review_and_update_plan(
        self, task: dict, success: bool, task_result: str = ""
    ) -> None:
        """LLM reviews and updates the plan after every task (VulnBot-style).

        Called after each task completes, regardless of success or failure.
        The LLM sees what was learned and can add/remove/reorder tasks.
        """
        if not getattr(self, 'exploitation_plan', None):
            return

        # Mark task status
        task["status"] = "done" if success else "failed"
        task["attempts"] = task.get("attempts", 0) + 1
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
                    "password:", "apiVersion:", "server: https://")):
                cred_reminder = (
                    "\nIMPORTANT: The task output above CONTAINS CREDENTIALS. "
                    "You MUST add tasks that USE these credentials now. "
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

        prompt = (
            f"Just completed: {task.get('instruction','')}\n"
            f"Tool: {task.get('tool','')}\n"
            f"Result: {success and 'SUCCESS' or 'FAILED'}\n"
            f"Output: {task_result[:1500]}\n"
            f"{cred_reminder}"
            f"{api_reminder}\n"
            f"{self._format_plan_status()}\n"
            f"{new_discoveries}\n\n"
            f"## Your Job: Update the Plan\n"
            f"Review the plan and apply relevant changes from:\n"
            f"- If credentials or tokens were obtained, ADD tasks that USE them immediately "
            f"(e.g., send authenticated requests to the relevant API endpoint)\n"
            f"- If a task discovered new endpoints/services, ADD exploration tasks for them\n"
            f"- If a REST API or OpenAPI spec was discovered, ADD tasks to explore "
            f"resource paths and individual items\n"
            f"- If pending tasks target endpoints that returned errors, REMOVE or CHANGE them\n"
            f"- If a task partially succeeded (some calls worked, some failed), SPLIT it\n"
            f"- If progress has been made, REMOVE low-value pending tasks\n"
            f"- If the plan is already optimal for the current state, it is OK to keep it unchanged\n\n"
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
            if new_tasks and isinstance(new_tasks, list):
                # Keep done/failed tasks, replace pending with LLM's updated list
                preserved = [t for t in self.exploitation_plan.tasks
                           if t.get("status") in ("done", "failed", "skipped")
                           and t.get("id") != task.get("id")]
                # Add the just-completed task with updated status
                preserved.append(task)
                # Merge in new tasks from LLM (avoid duplicate IDs)
                existing_ids = {t["id"] for t in preserved}
                for nt in new_tasks:
                    if not isinstance(nt, dict):
                        continue
                    nt.setdefault("status", "pending")
                    nt.setdefault("dependent_task_ids", nt.pop("dependencies", []))
                    if nt["id"] not in existing_ids:
                        preserved.append(nt)
                        existing_ids.add(nt["id"])
                self.exploitation_plan.tasks = preserved
                self._sync_plan_to_dkg()
                log.info("[PLAN REVIEW] plan updated: %d tasks (%d done, %d failed, %d pending)",
                         len(preserved),
                         sum(1 for t in preserved if t.get("status") == "done"),
                         sum(1 for t in preserved if t.get("status") in ("failed", "skipped")),
                         sum(1 for t in preserved if t.get("status") == "pending"))
        except Exception as e:
            log.warning("Plan review failed: %s — keeping current plan", e)
            self._sync_plan_to_dkg()

    async def _update_plan_after_task(self, task: dict, success: bool, result: Any = None):
        """Legacy: kept for sub-agent compatibility. Use _review_and_update_plan instead."""
        if not getattr(self, 'exploitation_plan', None):
            return
        task["status"] = "done" if success else "failed"
        task["attempts"] = task.get("attempts", 0) + 1
        if result:
            task["result_summary"] = str(result)[:500]

    async def _replan_after_failure(self, failed_task: dict, result: Any = None):
        """LLM generates replacement tasks when a task fails."""
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
                self.exploitation_plan.tasks = [
                    t for t in self.exploitation_plan.tasks if t["id"] != failed_task["id"]
                ]
                self.exploitation_plan.tasks.extend(new_tasks)
                self._sync_plan_to_dkg()
        except Exception:
            failed_task["status"] = "skipped"

    def _sync_plan_to_dkg(self):
        """Sync in-memory plan state to DKG nodes."""
        plan = getattr(self, 'exploitation_plan', None)
        if not plan:
            return
        done = sum(1 for t in plan.tasks if t.get("status") == "done")
        failed = sum(1 for t in plan.tasks if t.get("status") in ("failed", "skipped"))
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
        failed = [t.get("instruction", "") for t in plan.tasks if t.get("status") in ("failed", "skipped")]
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

    async def _llm_explore(self, base_url: str) -> TaskResult | None:
        """LLM-driven post-authentication exploration.

        Gives the LLM authenticated page content and lets it decide what
        actions to try. Falls back to heuristic crawl if LLM fails.
        """
        base_norm = base_url.rstrip("/")
        MAX_ITER = 5
        MAX_ACTIONS_PER_ITER = 10

        # Seed pages to show the LLM
        seed_pages: list[tuple[str, str]] = []  # (url, body)
        visited: set[str] = set()

        for ep in self.dkg.query_nodes("Endpoint"):
            eu = ep.get("url", "")
            if eu and eu.startswith(base_norm) and eu not in visited:
                visited.add(eu)
                try:
                    resp = await self.client.get(eu)
                    if resp.status_code == 200 and len(resp.body) > 100:
                        seed_pages.append((eu, resp.body))
                        # Check for flag immediately
                        flags = self.flag_pattern.findall(resp.body)
                        if flags:
                            self._task_log_event("info", "flag_found_llm_seed",
                                url=eu, flag=flags[0])
                            self.phase = OrchestratorPhase.DONE
                            return TaskResult(
                                success=True, flag=flags[0], steps=self.step_count,
                                tokens_used=self.llm.token_count,
                                time_elapsed=time.time() - self.start_time,
                            )
                except Exception:
                    pass

        if not seed_pages:
            seed_pages.append((base_norm, ""))  # at least try base URL

        # Build context for LLM
        pages_text = f"You are logged in to {base_norm}. The app is a trading platform.\n"
        pages_text += "Look for custom HTTP headers (X-UserId etc.) and hidden fields with user IDs.\n"
        # Extract known user IDs from pages
        import re as _re
        all_discovered_ids: set[str] = set()
        for url, body in seed_pages[:6]:
            # Extract IDs from hidden fields, data attrs, and text
            for m in _re.findall(r'(?:user[_-]?id|user_id|userId)\s*[=:"\'\s]+(\d+)', body, _re.I):
                all_discovered_ids.add(m)
            for m in _re.findall(r'data-user[_-]?id=["\'](\d+)["\']', body, _re.I):
                all_discovered_ids.add(m)
        if all_discovered_ids:
            pages_text += f"Known user IDs: {', '.join(sorted(all_discovered_ids, key=int))}\n"
            # Generate candidate IDs: known IDs, adjacent, and common ranges
            candidates: set[int] = set()
            for sid in all_discovered_ids:
                vid = int(sid)
                for off in range(-50, 51):
                    cid = vid + off
                    if cid > 0:
                        candidates.add(cid)
            pages_text += f"Candidate IDs to try: {', '.join(str(c) for c in sorted(candidates)[:30])} (and more up to {max(candidates) if candidates else 0})\n"
        pages_text += "\n"

        for url, body in seed_pages[:6]:  # limit to 6 pages for context
            # Extract visible text and key elements
            import re as _re
            # Remove scripts, styles, and excessive whitespace
            clean = _re.sub(r'<script[^>]*>.*?</script>', '', body, flags=_re.DOTALL | _re.I)
            clean = _re.sub(r'<style[^>]*>.*?</style>', '', clean, flags=_re.DOTALL | _re.I)
            clean = _re.sub(r'<[^>]+>', ' ', clean)
            clean = _re.sub(r'\s+', ' ', clean).strip()
            # Get key HTML: hidden inputs, data-*, comments
            hidden = _re.findall(r'<input[^>]+type=["\']hidden["\'][^>]*>', body, _re.I)
            comments = _re.findall(r'<!--(.*?)-->', body, _re.DOTALL)
            data_attrs = _re.findall(r'(data-[\w-]+)=["\']([^"\']*)["\']', body, _re.I)
            js_ids = _re.findall(r'''(?:user|account|customer|order)[-_]?id\w*\s*[=:]\s*["\']?(\d+)["\']?''', body, _re.I)

            pages_text += f"=== {url} ===\n"
            if comments:
                pages_text += f"Comments: {'; '.join(c[:200] for c in comments[:3])}\n"
            if hidden:
                pages_text += f"Hidden inputs: {'; '.join(h[:200] for h in hidden[:3])}\n"
            if data_attrs:
                pages_text += f"Data attrs: {'; '.join(f'{k}={v}' for k,v in data_attrs[:8])}\n"
            if js_ids:
                pages_text += f"JS IDs: {', '.join(js_ids[:10])}\n"
            if clean:
                pages_text += f"Text: {clean[:1500]}\n"

        # Reset LLM session for fresh exploration context
        self.llm.reset()

        # LLM interaction loop
        all_actions: list[dict] = []
        iteration = 0
        executed_actions: set[str] = set()

        while iteration < MAX_ITER:
            if self._time_exceeded() or self._tokens_exceeded():
                break
            iteration += 1

            prompt = f"You have authenticated access to {base_norm}.\n\nPages seen:\n{pages_text}\n"
            if all_actions:
                prompt += f"\nPrevious actions taken:\n"
                for a in all_actions[-8:]:
                    prompt += f"  {a.get('action','?').upper()} {a.get('url','?')} -> {a.get('result','?')[:200]}\n"

            prompt += "\nWhat actions should we try next to find the flag? Respond with JSON array only."

            self._maybe_compress()
            try:
                content, _ = self.llm.generate(
                    prompt=prompt,
                    system_prompt=SYSTEM_PROMPT_EXPLORE,
                )
                self._task_log_event("info", "llm_explore_call",
                    iteration=iteration, response=content[:1000],
                    tokens_used=self.llm.token_count,
                )
                actions = self._extract_json(content)
                if not isinstance(actions, list):
                    log.warning("_llm_explore: LLM returned non-list: %s", str(content)[:200])
                    actions = []
            except Exception as e:
                log.warning("_llm_explore: LLM call failed: %s", e)
                break

            if not actions:
                break

            # Execute actions
            new_pages_text = ""
            action_count = 0
            for act in actions[:MAX_ACTIONS_PER_ITER]:
                if not isinstance(act, dict):
                    continue
                action_type = str(act.get("action", "get")).lower()
                act_url = str(act.get("url", ""))
                if not act_url:
                    continue
                # Resolve relative URLs
                from urllib.parse import urljoin as _uj2
                if not act_url.startswith("http"):
                    act_url = _uj2(base_norm, act_url)

                headers = act.get("headers", {}) or {}
                data = act.get("data", {}) or {}

                # Deduplicate
                action_key = f"{action_type}:{act_url}:{headers}:{data}"
                if action_key in executed_actions:
                    continue
                executed_actions.add(action_key)

                if action_count >= MAX_ACTIONS_PER_ITER:
                    break

                if self._time_exceeded():
                    break
                action_count += 1
                self.step_count += 1

                try:
                    if action_type == "post":
                        resp = await self.client.post(act_url, data=data, headers=headers)
                    else:
                        resp = await self.client.get(act_url, headers=headers)
                except Exception:
                    continue

                # Check for flag
                flags = self.flag_pattern.findall(resp.body)
                result_summary = f"status={resp.status_code} len={len(resp.body)}"
                if flags:
                    result_summary += f" FLAG={flags[0]}"
                else:
                    # Extract title and key content for LLM feedback
                    import re as _re2
                    title_m = _re2.search(r'<title>(.*?)</title>', resp.body, _re.I)
                    if title_m:
                        result_summary += f" title='{title_m.group(1)}'"
                    # Check body for interesting patterns
                    bf = resp.body[:2000]
                    id_matches = _re2.findall(r'\b(\d{3,6})\b', bf)
                    if id_matches:
                        result_summary += f" ids={id_matches[:5]}"

                act["result"] = result_summary
                all_actions.append(act)
                self._task_log_event("info", "llm_action",
                    iteration=iteration, action=action_type, url=act_url,
                    headers=headers, status=resp.status_code,
                    result=result_summary[:500])

                if flags:
                    self._task_log_event("info", "flag_found_llm",
                        url=act_url, flag=flags[0])
                    self.phase = OrchestratorPhase.DONE
                    return TaskResult(
                        success=True, flag=flags[0], steps=self.step_count,
                        tokens_used=self.llm.token_count,
                        time_elapsed=time.time() - self.start_time,
                    )

                # If response looks like HTML with useful content, show LLM next iteration
                ct = resp.headers.get("content-type", "")
                if ("text/html" in ct or not ct) and len(resp.body) > 200:
                    clean = _re.sub(r'<script[^>]*>.*?</script>', '', resp.body, flags=_re.DOTALL | _re.I)
                    clean = _re.sub(r'<style[^>]*>.*?</style>', '', clean, flags=_re.DOTALL | _re.I)
                    clean = _re.sub(r'<[^>]+>', ' ', clean)
                    clean = _re.sub(r'\s+', ' ', clean).strip()
                    new_pages_text += f"=== {act_url} (result) ===\nText: {clean[:1000]}\n"

            pages_text += new_pages_text

        log.info("_llm_explore: %d iterations, %d actions, no flag found",
                 iteration, len(all_actions))
        return None

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
                            # Try LLM-driven exploration
                            result = await self._llm_explore(base)
                            if result:
                                return result
                            # Fall back to heuristic crawl
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

        self.llm.reset()
        self._maybe_compress()
        content, _ = self.llm.generate(
            prompt=prompt,
            system_prompt=SYSTEM_PROMPT_ORCHESTRATOR,
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

                if tool_name not in self.attack_gateway.get_tool_names():
                    continue

                self.step_count += 1
                try:
                    result = await self.attack_gateway.call(tool_name, params)
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
                    system_prompt=SYSTEM_PROMPT_ORCHESTRATOR,
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
        from darwin.sub_agents.base import SubAgentPool, TaskScope, TokenBudget, AgentType, SubAgentState
        from darwin.sub_agents.recon_agent import ReconAgent
        from darwin.sub_agents.exploit_agent import ExploitAgent
        from darwin.sub_agents.pivot_agent import PivotAgent

        # Create persistent pool if first call
        if self._persistent_pool is None:
            self._persistent_pool = SubAgentPool()

        pool = self._persistent_pool

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
            flag_event = self.dkg._events.get("Flag")
            if not flag_event:
                return
            try:
                while not flag_found.is_set():
                    flags = self.dkg.query_nodes("Flag")
                    for f in flags:
                        fv = f.get("value", "")
                        if fv and fv.startswith("flag{") and fv not in self._known_flags:
                            self._known_flags.add(fv)
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

            # Save ExploitAgent specs (deferred until after analyze+research)
            saved_exploit_specs = [
                (a.agent_id, a.task_scope, a.dkg, a.dpm, a.dave, a.cteg, a.cteg_hints, a.budget)
                for a in exploit_agents
            ]
            for aid in [s[0] for s in saved_exploit_specs]:
                if aid in pool._agents:
                    del pool._agents[aid]

            # Phase 1: Recon agents first
            if recon_agents and not flag_found.is_set():
                await asyncio.wait_for(
                    asyncio.gather(*[a.run() for a in recon_agents], return_exceptions=True),
                    timeout=120.0,
                )

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

            # Phase 3: Re-create ExploitAgent (now DKG has Vulnerability nodes)
            if not flag_found.is_set() and saved_exploit_specs:
                for agent_id, scope, dkg, dpm, dave, cteg, cteg_hints, budget in saved_exploit_specs:
                    if agent_id not in pool._agents:
                        exploit = ExploitAgent(
                            agent_id=agent_id, task_scope=scope,
                            dkg=dkg, dpm=dpm, dave=dave,
                            cteg=cteg, cteg_hints=cteg_hints,
                            budget=budget,
                        )
                        pool.spawn(exploit)
                exploit_agents = [a for a in pool._agents.values()
                                  if getattr(a, 'agent_type', None) == AgentType.EXPLOIT
                                  and getattr(a, 'state', None) != SubAgentState.DONE]

            # Phase 4: Run Exploit agents
            if exploit_agents and not flag_found.is_set():
                await asyncio.wait_for(
                    asyncio.gather(*[a.run() for a in exploit_agents], return_exceptions=True),
                    timeout=120.0,
                )

            # Phase 5: Other agents (AD, Cloud, Pivot)
            if other_agents and not flag_found.is_set():
                await asyncio.wait_for(
                    asyncio.gather(*[a.run() for a in other_agents], return_exceptions=True),
                    timeout=120.0,
                )

            if flag_found.is_set():
                pool.terminate()

            # Check results
            results = getattr(pool, '_results', {})
            self.step_count += len(results)

            # Check for flag found by watcher (avoids _known_flags dedup skip)
            watcher_flag = self.__dict__.pop('_multi_agent_flag', None)
            if watcher_flag:
                total_tokens = self.llm.token_count + sum(
                    getattr(r, 'tokens_used', 0) for r in results.values()
                )
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
                    self.llm.add_context_message(
                        f"[MULTI-AGENT CYCLE COMPLETE] {len(results)} agents finished:\n\n"
                        f"{chr(10).join(report_parts)}\n\n"
                        f"DKG now contains all findings. Avoid re-trying failed approaches.",
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
                            system_prompt=SYSTEM_PROMPT_ORCHESTRATOR,
                        )
                        if plan_content:
                            try:
                                new_tasks = json.loads(self._extract_json(plan_content))
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
                system_prompt=SYSTEM_PROMPT_ANALYZE,
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
        from darwin.sub_agents.base import TaskScope, TokenBudget
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
            s.get("port") in (6443, 10250) for s in self.dkg.query_nodes("Service")
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
                cloud = CloudAgent(agent_id="cloud-primary", task_scope=scope, dkg=self.dkg,
                                  budget=TokenBudget(max_tokens=48000, max_iterations=15))
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
        """Scan DKG for collaboration opportunities and spawn follow-up agents."""
        from darwin.sub_agents.base import TaskScope, TokenBudget
        from darwin.sub_agents.recon_agent import ReconAgent
        from darwin.sub_agents.exploit_agent import ExploitAgent
        from darwin.sub_agents.pivot_agent import PivotAgent

        existing = getattr(pool, '_agents', {})

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
            if hasattr(agent, 'agent_type') and str(agent.agent_type) == 'exploit':
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

