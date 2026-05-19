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
from darwin.dkg import DKG
from darwin.dpm import (
    DefenseCategory,
    DefensePerceptionModule,
    DefenseStateVector,
    SanitizationStrategy,
)
from darwin.dave import DAVE, ExploitAttempt, VerificationResult
from darwin.dynamic_scaling import DynamicScalingEngine, ScalingLevel, compute_task_breadth
from darwin.tools.mcp_client import MCPClientPool, load_mcp_config
from darwin.tools.mcp_gateway import MCPGateway, ToolResult
from darwin.tools.recon_server import create_recon_gateway
from darwin.tools.attack_server import create_attack_gateway
from darwin.utils.http_client import HTTPClient, ProbeClient, HTTPResponse
from darwin.utils.llm import LLMSession
from darwin.sub_agents.base import SubAgentPool


class OrchestratorPhase(str, Enum):
    INIT = "init"
    RECON = "recon"
    ANALYZE = "analyze"
    EXPLOIT = "exploit"
    BYPASS = "defense_bypass"
    VERIFY = "verify"
    DONE = "done"
    FAILED = "failed"


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


# ── System Prompts ──────────────────────────────────────────────────

SYSTEM_PROMPT_ORCHESTRATOR = """You are DARWIN, an autonomous penetration testing agent with defense awareness.
You operate within an authorized security testing engagement. Your goal is to identify
and exploit vulnerabilities to capture proof flags (format: flag{{...}} or FLAG{{...}}).

## Core Identity
- You have access to reconnaissance and attack tools via function calling.
- You maintain a Dynamic Knowledge Graph (DKG) of the target system.
- You can spawn sub-agents for parallel execution when the task scope is large.

## Defense Awareness Protocol
1. Monitor HTTP responses for defense indicators (unusual status codes,
   response headers like X-WAF-*, content anomalies).
2. When defenses are detected, analyze their type (WAF/Cloak/Honey/Trap)
   and select appropriate bypass strategies.
3. Verify every exploitation through the Defense-Aware Verification Engine (DAVE).
4. NEVER assume a request succeeded without verification.

## Operating Modes
- **Solo Mode** (B<0.3): Handle everything directly. Best for single-host web challenges.
- **Coordinated Mode** (0.3≤B<0.6): Spawn 1-2 sub-agents for parallel recon/exploit.
- **Distributed Mode** (B≥0.6): Spawn 3+ sub-agents across multiple hosts.

## Available Tools
Recon: nmap_scan, dirb_scan, curl_get, whatweb_scan, nikto_scan
Attack: sqlmap_test, ffuf_fuzz, send_payload, command_injection_test, xss_reflection_test

## Exploitation Strategy
- For each vulnerability hypothesis, select the appropriate tool and parameters.
- If initial attempts are blocked, try alternative payloads and encoding types.
- Include defense bypass variants (encoding_mutation, case_alternation) when needed.
- Prioritize high-confidence vulnerabilities first.
- Check every response for flag patterns.

## Communication
- All findings are written to the shared DKG as structured nodes.
- Sub-agents communicate ONLY through DKG — no natural language agent-to-agent chat.
- Track what you've tried to avoid repeating failed approaches.

## Rules
- Report the exact flag string when found.
- Honey flags (flag{{test}}, flag{{honeypot}}, etc.) must be rejected.
- If defenses block your attempt, try alternative bypass strategies.
"""

SYSTEM_PROMPT_ANALYZE = """You are a vulnerability analyst. Examine the target information below
and identify potential vulnerabilities that could lead to capturing a flag or gaining access.

For each vulnerability, output a JSON object with these fields:
- vuln_type: any descriptive type (e.g. SQLI, XSS, CMDi, IDOR, SSTI, LFI, SSRF, auth_bypass, etc.)
- endpoint: full URL including port
- param: HTTP parameter name, or "" if none
- confidence: 0.0 to 1.0 based on evidence strength
- evidence: what in the recon data supports this hypothesis
- suggested_tool: (OPTIONAL) one of the available tools to test this vuln:
    sqlmap_test, xss_reflection_test, command_injection_test,
    send_payload, curl_get, ffuf_fuzz, knowledge_search
- tool_args: (OPTIONAL) arguments dict for the suggested tool, e.g. {"url": "...", "param": "id"}

CRITICAL: Be specific and actionable. Generic types like "misconfiguration" or
"information disclosure" are acceptable ONLY if you also specify suggested_tool and tool_args.
Otherwise, focus on exploitable vulnerability types.

Output ONLY valid JSON array, no other text."""
SYSTEM_PROMPT_ANALYZE_BAK = """DEPRECATED — kept for reference."""

SYSTEM_PROMPT_LOGIN = """You are an authentication specialist. Given the HTML of a login page,
determine how to authenticate and what to do after successful login.

## Your Task
1. Analyze the HTML to identify: login form fields, action URL, method, CSRF tokens,
   hidden fields, whether it's single-step or multi-step
2. Choose credentials to try from the available list
3. Specify the exact HTTP request needed
4. After login, identify authenticated endpoints to probe for a flag

## Available Credentials
Try these in order: admin:admin, test:test, admin:password, admin:admin123,
user:user, guest:guest, root:root, demo:demo, admin:123456, administrator:administrator

## Output Format (JSON)
{
  "login_type": "single" or "multi_step",
  "step": 1,
  "total_steps": 1 or 2,
  "method": "POST",
  "url": "http://host:port/path",
  "data": {"username_field_name": "chosen_username", "password_field_name": "chosen_password", "csrf_token_name": "token_value"},
  "success_indicators": ["redirect to /dashboard", "Set-Cookie header", "Welcome message"],
  "post_login_endpoints": ["/dashboard", "/profile", "/admin", "/flag"]
}

If multi-step: step 1 submits username only, step 2 submits password + hidden fields.

Output ONLY valid JSON, no other text."""

SYSTEM_PROMPT_BYPASS = """You are a WAF bypass specialist. Given a detected defense configuration,
suggest bypass strategies ordered by likelihood of success.

Available strategies: encoding_mutation, case_alternation, parameter_pollution,
content_type_switch, request_fragmentation, protocol_downgrade, context_specific_mutation.

Output JSON: {"strategies": [{"name": "...", "reason": "...", "confidence": 0.X}]}"""

SYSTEM_PROMPT_EXPLORE = """You are a penetration testing agent with authenticated session cookies. Your goal: find flag{...} or FLAG{...}.

## CRITICAL: You MUST try ALL of these attack vectors:

1. **Custom HTTP Headers (MOST IMPORTANT — try FIRST):**
   X-UserId, X-User-Id, X-Forwarded-User, X-Auth-User
   Try values: 0, 1, 2, plus any IDs you discover

2. **POST body tampering** — if you see profile/edit forms:
   - Try is_admin=1, admin=1, role=admin
   - Try changing user_id in POST body to different values
   - POST /edit_profile/1 with is_admin=1

3. **URL parameter tampering:** ?user_id=<id>, ?id=<id>

4. **URL path IDOR:** /user/<id>, /company/<id>/jobs, /order/<id>/receipt

## Rules:
- When you see profile/edit pages, ALWAYS try POST with privilege escalation fields
- After any state-changing POST, re-visit data pages to check for new content
- Try ID values: 0, 1, 2, and anything you discover on pages
- Limit to 8 actions per response

Respond ONLY with a JSON array:
[{"action": "post", "url": "http://host/edit_profile/1", "data": {"is_admin": "1"}, "reason": "IDOR via POST privilege escalation"}]"""


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
    OPTIONAL_TOOLS = ["searchsploit"]

    def __init__(
        self,
        llm_session: LLMSession | None = None,
        time_budget: int = 600,
        token_budget: int = 200000,
        max_context_tokens: int = 180000,
        compression_threshold: float = 0.4,
        browser_enabled: bool = False,
    ):
        self.llm = llm_session or LLMSession()
        self.time_budget = time_budget
        self.token_budget = token_budget
        self.max_context_tokens = max_context_tokens
        self.compression_threshold = compression_threshold
        self.browser_enabled = browser_enabled

        # Core modules
        self.dkg = DKG()
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
        self.step_count = 0
        self.start_time = 0.0
        self.flag_pattern = re.compile(r"flag\{[a-zA-Z0-9_\-!@#$%^&*()+=]+\}", re.IGNORECASE)

    async def run(
        self, task_description: str, target_url: str,
        username: str | None = None, password: str | None = None,
    ) -> TaskResult:
        """Run penetration test against a single target."""
        self.start_time = time.time()
        self.target_url = target_url

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
                mcp_configs, per_server_timeout=15, total_timeout=10,
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
            # ── Phase 1: Reconnaissance (tool-driven, not LLM) ────
            await self._recon_phase(target_url)
            self._task_log_event("info", "recon_done",
                dkg_summary=self.dkg.summary(), step=self.step_count)
            self.dkg.save(self._checkpoint_path("recon"))

            # Phase 1.5: Auto-login
            await self._try_auto_login(target_url, username, password)

            # ── Phase 2: Analyze (LLM identifies vulnerabilities from recon data) ──
            await self._analyze_phase()
            self._task_log_event("info", "analyze_done",
                hypotheses=len(self.vulnerabilities),
                dkg_summary=self.dkg.summary())

            # Query CTEG for cross-task experience + RAG knowledge
            tech_query = " ".join(
                s.get("version", "") or s.get("banner", "")
                for s in self.dkg.query_nodes("Service")[:5]
            )
            cteg_hints = self.cteg.get_suggestions(
                defense_type=self.defense_state.waf_type or "", vuln_type="",
                query=f"web exploitation techniques {tech_query}",
            )
            if cteg_hints.get("bypass_strategies") or cteg_hints.get("exploit_strategies"):
                self._task_log_event("info", "cteg_hints", hints=cteg_hints)

            # ── Early flag check: scan discovered endpoints before main loop ──
            early_flag = await self._check_response_for_flag(target_url)
            if early_flag:
                self._task_log_event("info", "early_flag_found",
                    flag=early_flag.flag)
                self.phase = OrchestratorPhase.DONE
                return early_flag

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
                    result = await self._run_solo_cycle(target_url, cteg_hints)
                else:
                    # Coordinated or Distributed — use persistent multi-agent system
                    log.info("Entering %s Mode (B=%.2f)", scaling_level.value.title(), B)
                    result = await self._run_multi_agent_cycle(target_url)
                    if result is None:
                        result = await self._run_solo_cycle(target_url, cteg_hints)

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
            result = TaskResult(
                success=False, steps=self.step_count,
                tokens_used=self.llm.token_count,
                time_elapsed=time.time() - self.start_time,
                phase_at_end=self.phase, error="Time budget exceeded",
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
            if new_patterns > 0:
                log.info("CTEG: extracted %d new patterns from task", new_patterns)

        return result

    # ── Phase 1: Reconnaissance ─────────────────────────────────────

    async def _recon_phase(self, target_url: str) -> None:
        """Discover attack surface: ports, services, endpoints, parameters.

        Phase 1a: nmap port scan on the target host.
        Phase 1b: for each HTTP service: fingerprint, enumerate, scan, extract endpoints.
        """
        self.phase = OrchestratorPhase.RECON
        from urllib.parse import urlparse as _up
        parsed = _up(target_url)
        host = parsed.hostname or target_url
        self.target_host = host

        # ── Phase 1a: Network port scanning ───────────────────────
        self._task_log_event("info", "recon_nmap_start", host=host)
        nmap_result = await self.recon_gateway.call("nmap_scan", {"target": host})
        discovered_ports: list[dict] = []
        if nmap_result.success:
            discovered_ports = nmap_result.parsed_output.get("open_ports", [])
            log.info("nmap: %d open ports on %s", len(discovered_ports), host)
        else:
            common_ports = [80, 443, 8080, 8443, 3000, 5000, 8000, 8888, 9090]
            default_port = parsed.port or (443 if parsed.scheme == "https" else 80)
            if default_port not in common_ports:
                common_ports.insert(0, default_port)
            discovered_ports = [{"port": p, "state": "unknown", "service": "http"}
                                for p in common_ports]
            log.warning("nmap failed for %s, probing %d common HTTP ports", host, len(common_ports))

        # Record host and services in DKG
        for p in discovered_ports:
            port, svc_name = p["port"], p.get("service", "unknown")
            self.dkg.add_node("Host", f"host-{host}", {
                "ip": host, "is_reachable": True, "is_internal": False,
            })
            self.dkg.add_node("Service", f"svc-{host}-{port}", {
                "port": port, "protocol": "tcp",
                "version": p.get("version", "") or svc_name,
                "banner": svc_name,
            })

        # ── Phase 1b: HTTP-level recon on each TCP port ──────────
        # Probe ALL open TCP ports for HTTP, not just nmap-identified ones.
        # nmap often misidentifies non-standard HTTP ports (e.g. "rpc").
        NON_HTTP_PORTS = {22}  # SSH — skip known non-HTTP services
        http_ports = [p["port"] for p in discovered_ports
                      if p["port"] not in NON_HTTP_PORTS]
        original_port = parsed.port or (443 if parsed.scheme == "https" else 80)
        if original_port not in http_ports:
            http_ports.insert(0, original_port)
        self._discovered_http_ports = http_ports

        for port in http_ports:
            scheme = "https" if port == 443 else "http"
            url = f"{scheme}://{host}" if port in (80, 443) else f"{scheme}://{host}:{port}"
            await self._recon_http_service(url, port)
        self.step_count += 1

    async def _recon_http_service(self, url: str, port: int) -> None:
        """Recon a single HTTP service: fingerprint, enumerate, scan, extract endpoints."""
        try:
            baseline = await self.client.get_baseline(url)
        except Exception:
            log.info("HTTP recon skipped for %s (connection failed)", url)
            return

        # whatweb technology fingerprint
        ww = await self.recon_gateway.call("whatweb_scan", {"target_url": url})
        technologies = ww.parsed_output.get("technologies", []) if ww.success else []
        for tech in technologies:
            self.dkg.add_node("Service", f"tech-{url}-{tech}", {
                "port": port, "protocol": "HTTP", "version": tech, "banner": tech,
            })
        if technologies:
            log.info("whatweb %s: %s", url, ", ".join(technologies[:5]))

        # dirb directory enumeration
        dirb = await self.recon_gateway.call("dirb_scan", {"target_url": url})
        if dirb.success:
            for p in dirb.parsed_output.get("discovered_paths", []):
                self.dkg.add_node("Endpoint", f"endpoint-{url}{p['path']}", {
                    "url": f"{url.rstrip('/')}{p['path']}", "method": "GET",
                    "params": "", "auth_required": "401" in p.get("code", ""),
                })
            log.info("dirb %s: %d paths", url, len(dirb.parsed_output.get("discovered_paths", [])))

        # nikto vulnerability scan
        nikto = await self.recon_gateway.call("nikto_scan", {"target_url": url})
        if nikto.success:
            for f in nikto.parsed_output.get("findings", [])[:10]:
                self.dkg.add_node("Vulnerability", f"nikto-{url}-{f['detail'][:40]}", {
                    "vuln_type": f.get("type", "info"), "endpoint": url, "parameter": "",
                    "severity": "low", "source": "nikto", "detail": f.get("detail", ""),
                })
            log.info("nikto %s: %d findings", url, len(nikto.parsed_output.get("findings", [])))

        # Record HTTP service
        v = technologies[0] if technologies else "unknown"
        self.dkg.add_node("Service", f"svc-http-{port}", {
            "port": port, "protocol": "HTTP", "version": v, "banner": "",
        })

        # Extract links and form inputs from HTML
        body = baseline.body
        from urllib.parse import urljoin as _uj, urlparse as _up2
        for link in self._extract_links_from_html(body, url):
            pq = _up2(link).query
            self.dkg.add_node("Endpoint", f"endpoint-{link}", {
                "url": link, "method": "GET", "params": pq, "auth_required": False,
            })
        for name in set(re.findall(r'<input[^>]+name=["\'](\w+)["\']', body, re.I)):
            self.dkg.add_node("Endpoint", f"endpoint-{url}-param-{name}", {
                "url": url, "method": "POST", "params": name, "auth_required": False,
            })

    # ── Login ─────────────────────────────────────────────────────

    async def _try_auto_login(
        self, target_url: str, username: str | None, password: str | None,
    ) -> None:
        """Try default credentials via the battle-tested auto_login.
        If this fails, the LLM in the solo cycle can use the try_login tool
        for more sophisticated attempts.
        """
        for port in getattr(self, '_discovered_http_ports', []):
            host = getattr(self, "target_host", None)
            if not host:
                continue
            scheme = "https" if port == 443 else "http"
            base = f"{scheme}://{host}" if port in (80, 443) else f"{scheme}://{host}:{port}"
            for u, p in [("test", "test"), ("admin", "admin"), ("admin", "password"),
                          ("demo", "demo"), ("user", "user"), ("guest", "guest")]:
                if username and password:
                    u, p = username, password
                if self._time_exceeded():
                    return
                try:
                    if await self.client.auto_login(base, u, p):
                        self._task_log_event("info", "auto_login_ok", url=base, username=u)
                        return
                except Exception:
                    pass

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
        return False

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

    # ── Unified LLM-Driven Loop ─────────────────────────────────────

    async def _run_solo_cycle(self, target_url: str, cteg_hints: dict | None = None) -> TaskResult | None:
        """LLM-driven post-recon loop: the LLM decides all actions.

        The LLM receives DKG state, CTEG suggestions, and all tool definitions.
        It iteratively chooses tools to call, sees results, and adapts.
        Replaces the separate analyze → exploit → bypass phases.
        """
        MAX_ITER = 10
        self.llm.reset()
        self._exploit_chain: list[dict] = []  # track steps for CTEG learning

        # ── Re-attempt login before systematic exploit ──────────
        # The initial auto-login may have failed; the LLM or previous
        # loop iterations may have discovered new credentials/forms.
        await self._try_auto_login(target_url, None, None)

        # ── Systematic exploit pass (before LLM loop) ────────────
        # Try all known Vulnerability nodes systematically before
        # engaging the LLM. This catches straightforward vulns faster.
        sys_result = await self._systematic_exploit_pass(target_url)
        if sys_result:
            return sys_result

        # Build tool definitions from recon + attack gateways
        tool_defs = self.attack_gateway.get_tool_definitions()
        tool_defs += self.recon_gateway.get_tool_definitions()

        # Check if we have active session cookies from auto_login
        session_cookies = ""
        if self.client._session and self.client._session.cookie_jar:
            jar_cookies = list(self.client._session.cookie_jar)
            if jar_cookies:
                cookie_str = "; ".join(
                    f"{ck.key}={ck.value}" for ck in jar_cookies
                )
                session_cookies = (
                    f"\n## ACTIVE SESSION (use these cookies!)\n"
                    f"You are logged in with session cookies:\n"
                    f"  Cookie: {cookie_str[:200]}\n"
                    f"Use curl_get with headers parameter for authenticated requests:\n"
                    f'  curl_get(url="...", headers="Cookie: {cookie_str[:150]}")\n'
                    f"ALWAYS try authenticated endpoints first!\n"
                )

        # Pre-fetch OpenAPI/Swagger docs to discover API endpoints
        api_endpoints_text = ""
        for port in getattr(self, '_discovered_http_ports', []):
            host = getattr(self, "target_host", None) or "localhost"
            scheme = "https" if port == 443 else "http"
            base = f"{scheme}://{host}" if port in (80, 443) else f"{scheme}://{host}:{port}"
            for doc_path in ["/openapi.json", "/docs", "/api/docs", "/swagger.json"]:
                try:
                    import urllib.request as _ur
                    import json as _js
                    req = _ur.Request(f"{base}{doc_path}", headers={"Accept": "application/json"})
                    with _ur.urlopen(req, timeout=5) as resp:
                        if "json" in resp.headers.get("content-type", ""):
                            spec = _js.loads(resp.read())
                            paths = spec.get("paths", {})
                            if paths:
                                api_endpoints_text = "\n## API Endpoints (from OpenAPI spec):\n"
                                for path, methods in list(paths.items())[:15]:
                                    for method in methods:
                                        api_endpoints_text += f"  {method.upper()} {base}{path}\n"
                                log.info("Found %d API endpoints via %s", len(paths), doc_path)
                except Exception:
                    pass

        # Build initial prompt with DKG context
        dkg_summary = self.dkg.summary()
        endpoints_text = "\n".join(
            f"- {e.get('url','')} [{e.get('method','GET')}] params={e.get('params','')}"
            for e in self.dkg.query_nodes('Endpoint')[:12]
        )
        services_text = "\n".join(
            f"- port {s.get('port','?')}/{s.get('protocol','?')}: {s.get('version','') or s.get('banner','')}"
            for s in self.dkg.query_nodes('Service')[:10]
        )

        # Use CTEG hints passed from run() (already queried once)
        cteg_text = ""
        if cteg_hints:
            parts = []
            for es in cteg_hints.get("exploit_strategies", []):
                parts.append(f"Learned: {es.get('description','')}")
                for t in es.get("techniques", []):
                    parts.append(f"  → {t}")
            for sk in cteg_hints.get("static_knowledge", []):
                parts.append(f"Knowledge: [{sk.get('category','')}] {sk.get('title','')}: {sk.get('description','')[:200]}")
                for t in sk.get("techniques", [])[:3]:
                    parts.append(f"  → {t}")
            if parts:
                cteg_text = "\n## Prior Experience & Knowledge:\n" + "\n".join(parts) + "\n"

        # Query knowledge base for relevant exploitation patterns
        knowledge_text = ""
        try:
            # Extract technology hints from services
            tech_hints = " ".join(
                s.get("version", "") or s.get("banner", "")
                for s in self.dkg.query_nodes("Service")[:5]
            )
            # Query CTEG knowledge for relevant patterns
            self.cteg.load_knowledge_base("knowledge/")
            kb_results = self.cteg.query_rag(
                f"exploitation techniques for {tech_hints} web application", top_k=4,
            )
            if kb_results:
                knowledge_text = "\n## Relevant Knowledge Base Patterns:\n"
                for r in kb_results[:3]:
                    knowledge_text += (f"- **{r['title']}** ({r['category']}): "
                                       f"{r['description'][:200]}\n")
                    for t in r.get("techniques", [])[:3]:
                        knowledge_text += f"  - {t}\n"
                knowledge_text += "\n"
        except Exception:
            pass

        initial_prompt = f"""Target: {target_url}

## Discovered Services
{services_text}

## Discovered Endpoints
{endpoints_text}
{api_endpoints_text}
{cteg_text}
{session_cookies}
{knowledge_text}
## Your Task: Find the flag (flag{{...}} or FLAG{{...}})

## EXPLOITATION CHECKLIST (execute systematically):

### Phase 1 — Probe all endpoints:
- Use curl_get on EVERY discovered endpoint
- If you have session cookies, add headers="Cookie: ..." to curl_get
- Check every response body for flag patterns

### Phase 2 — Try authenticated access:
- Login using known credentials (try: demo:demo, test:test, admin:admin)
- After login, curl_get ALL pages with the session cookie
- Try accessing pages with different IDs in URL paths

### Phase 3 — IDOR testing:
- On ANY endpoint with {{id}} in path (like /company/{{id}}/jobs, /edit_profile/{{id}}):
  try IDs 1, 2, 3 — same cookie, different ID = IDOR
- On edit/update endpoints: try POST with is_admin=1 or role=admin
- If you see "Welcome, NAME" or user data, immediately try other IDs

### Phase 4 — Injection testing:
- sqlmap_test on login form parameters
- xss_reflection_test and command_injection_test on query params

## CRITICAL RULES:
- Never fetch the same URL more than twice
- After ANY state change (login, profile edit), IMMEDIATELY re-fetch data pages
- Read response bodies for hints (Welcome messages, hidden fields, IDs)
- The flag is behind auth + IDOR — you MUST do BOTH
"""

        print(f"\n[solo] Starting LLM loop with {len(tool_defs)} tools, "
              f"prompt size ~{len(initial_prompt)} chars, "
              f"token_count={self.llm.token_count}")
        self._maybe_compress()
        content, tool_calls = self.llm.generate(
            prompt=initial_prompt,
            system_prompt=SYSTEM_PROMPT_ORCHESTRATOR,
            tools=tool_defs,
        )
        if content:
            self._task_log_event("info", "llm_loop_start",
                response=content[:500],
                tool_calls=[tc.get("name") for tc in (tool_calls or [])],
            )

        for iteration in range(1, MAX_ITER + 1):
            if self._time_exceeded() or self._tokens_exceeded():
                break

            if not tool_calls:
                # LLM has no more tool ideas — prompt it to continue
                self._maybe_compress()
                content, tool_calls = self.llm.generate(
                    prompt="No more tool calls? Review what you've learned. "
                           "What vulnerabilities remain untested? Try different "
                           "payloads, encoding types, or endpoints. If you have "
                           "a login session, explore authenticated pages.",
                    system_prompt=SYSTEM_PROMPT_ORCHESTRATOR,
                    tools=tool_defs,
                )
                if not tool_calls:
                    break  # LLM has truly nothing left

            # Execute ALL tool calls (API requires result for every tool_call)
            print(f"\n[solo:{iteration}] LLM called {len(tool_calls)} tool(s): "
                  f"{', '.join(tc.get('name','?') for tc in tool_calls)}")
            for tc in tool_calls:
                tc_name = tc.get("name", "")
                tc_args = tc.get("arguments", {})
                tc_id = tc.get("id", "")

                if self._time_exceeded():
                    self.llm.add_tool_result(tc_id, "Skipped: time exceeded")
                    continue

                # Route tool call to correct gateway
                self.step_count += 1
                try:
                    if tc_name in self.attack_gateway.get_tool_names():
                        result = await self.attack_gateway.call(tc_name, tc_args)
                        tool_stdout = result.stdout if hasattr(result, 'stdout') else str(result)
                    elif tc_name in self.recon_gateway.get_tool_names():
                        result = await self.recon_gateway.call(tc_name, tc_args)
                        tool_stdout = result.stdout if hasattr(result, 'stdout') else str(result)
                    else:
                        tool_stdout = f"Unknown tool: {tc_name}"
                except Exception as e:
                    tool_stdout = f"ERROR: {e}"

                print(f"  [{tc_name}] {str(tc_args)[:120]} → {tool_stdout[:150].strip().replace(chr(10), ' ')}")

                self.llm.add_tool_result(tc_id, tool_stdout[:2000])

                # Record step for CTEG cross-task learning
                self._exploit_chain.append({
                    "tool": tc_name, "url": str(tc_args.get("url", tc_args.get("target_url", ""))),
                    "method": str(tc_args.get("method", "GET")),
                    "params": str(tc_args)[:200],
                    "result": tool_stdout[:200],
                    "vuln_type": "",
                    "mechanism": tc_name,
                })

                # DPM: monitor HTTP responses for defense patterns
                tl = tool_stdout.lower()
                if any(kw in tl for kw in ('403 forbidden', '406', '429',
                        'waf', 'blocked by', 'cloudflare', 'modsecurity', 'secure')):
                    self.defense_state.defense_complexity = max(
                        self.defense_state.defense_complexity, 0.3)

                flags = self.flag_pattern.findall(tool_stdout)
                if flags:
                    # DAVE L4: honeypot flag verification
                    is_valid, reason = DAVE.verify_basic(flags[0], tool_stdout)
                    if not is_valid:
                        log.warning("DAVE rejected flag: %s", reason)
                        self._task_log_event("info", "dave_rejected_flag",
                            flag=flags[0][:80], reason=reason)
                    else:
                        self._task_log_event("info", "flag_found_llm_loop",
                            tool=tc_name, flag=flags[0], iteration=iteration)
                        self.phase = OrchestratorPhase.DONE
                        return TaskResult(
                            success=True, flag=flags[0], steps=self.step_count,
                            tokens_used=self.llm.token_count,
                            time_elapsed=time.time() - self.start_time,
                        )

                self._task_log_event("info", "llm_loop_step",
                    iteration=iteration, tool=tc_name, result=tool_stdout[:500])

            # Get next round of tool calls
            self._maybe_compress()
            content, tool_calls = self.llm.generate(
                prompt="Continue. What next?",
                system_prompt=SYSTEM_PROMPT_ORCHESTRATOR,
                tools=tool_defs,
            )

        log.info("_run_solo_cycle: %d iterations, flag not found", iteration)

        # ── Systematic post-loop checks (covers what LLM might miss) ──
        result = await self._systematic_post_check(target_url)
        if result:
            return result

        # Flag not found — try generic flag search as last resort
        flag_result = await self._check_response_for_flag(target_url)
        if flag_result:
            return flag_result

        return None

    async def _systematic_exploit_pass(self, target_url: str) -> TaskResult | None:
        """Systematic exploit: iterate DKG Vulnerability nodes and run mapped tools.

        Runs BEFORE the LLM-driven loop in Solo mode. This catches
        straightforward vulnerabilities without any LLM cost — for each
        known Vulnerability node, we run the appropriate tool automatically.

        Returns TaskResult if a flag is found, None otherwise.
        """
        vulns = self.dkg.query_nodes("Vulnerability")
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
            "ssti": ["command_injection_test"],
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

            tools = _resolve_tools(vt)

            # If no hardcoded mapping, try LLM-suggested tool from analysis
            llm_tool = ""
            llm_args: dict = {}
            if not tools:
                llm_tool = v.get("suggested_tool", "") or ""
                llm_args = v.get("tool_args", {}) or {}
                if not isinstance(llm_args, dict):
                    llm_args = {}
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

                # Build args: prefer LLM-suggested, fall back to hardcoded
                args: dict = {}
                if tool_name == llm_tool and llm_args:
                    args = dict(llm_args)  # Use LLM's suggested args
                elif tool_name == "sqlmap_test":
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

        dkg_summary = self.dkg.summary()
        self.llm.reset()

        # Query CTEG for patterns from prior tasks
        prompt = f"Target information:\n{dkg_summary}\n\nIdentify potential vulnerabilities."
        cteg_suggestions = self.cteg.get_suggestions(
            defense_type=self.defense_state.waf_type or "",
            vuln_type="",
        )
        if cteg_suggestions.get("bypass_strategies") or cteg_suggestions.get("exploit_strategies"):
            prompt += f"\n\nPrior cross-task experience suggests:\n{json.dumps(cteg_suggestions, indent=2)}"

        self._maybe_compress()
        tokens_before = self.llm.token_count

        print(f"\n{'='*50}")
        print(f"[ANALYZE] Asking LLM to identify vulnerabilities...")
        print(f"[ANALYZE] DKG summary: {len(dkg_summary.split(chr(10)))} lines, "
              f"services={len(self.dkg.query_nodes('Service'))}, "
              f"endpoints={len(self.dkg.query_nodes('Endpoint'))}")

        content, _ = self.llm.generate(
            prompt=prompt,
            system_prompt=SYSTEM_PROMPT_ANALYZE,
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
            vulns_json = self._extract_json(content)
            print(f"[ANALYZE] Parsed {len(vulns_json)} vulnerability hypotheses from LLM")
            for v in vulns_json:
                vt = v.get("vuln_type", "")
                hypothesis = VulnerabilityHypothesis(
                    vuln_type=vt,
                    endpoint=v.get("endpoint", ""),
                    param=v.get("param", ""),
                    confidence=float(v.get("confidence", 0.5)),
                    evidence=v.get("evidence", ""),
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
                    dkg_props["suggested_tool"] = suggested_tool
                    tool_args = v.get("tool_args", {})
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
            except Exception:
                pass  # Fall through to keyword fallback

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
        # Every POST/GET endpoint with params → SQLI + XSS
        for ep in self.dkg.query_nodes("Endpoint"):
            url, params = ep.get("url", ""), ep.get("params", "")
            method = ep.get("method", "GET")
            if not params or not url:
                continue
            if any(v.endpoint == url and v.param == params for v in self.vulnerabilities):
                continue
            # Primary hypothesis based on method
            vt = "SQLI" if method == "POST" else "SQLI"
            self.vulnerabilities.append(VulnerabilityHypothesis(
                vuln_type=vt, endpoint=url, param=params,
                confidence=0.35, evidence=f"{method} parameter: {params}",
            ))
            self.dkg.add_node("Vulnerability", f"vuln-{len(self.vulnerabilities)}", {
                "vuln_type": vt, "endpoint": url, "parameter": params,
                "severity": "medium", "source": "param_heuristic",
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
        # Reset LLM session to clear any stale tool_calls from solo cycle
        self.llm.reset()
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
            return json.loads(match.group(1))
        # Try to find any JSON-like structure
        match = re.search(r"(\[.*\]|\{.*\})", text, re.DOTALL)
        if match:
            return json.loads(match.group(1))
        return {}

    # ── Persistent Multi-Agent System ─────────────────────────────────

    async def _run_multi_agent_cycle(self, target_url: str) -> TaskResult | None:
        """Run persistent multi-agent exploitation with DKG monitoring.

        Uses a persistent SubAgentPool (stored on self) that survives across
        loop iterations. Agents are spawned incrementally based on DKG state,
        and a background DKG monitor spawns follow-up agents when new
        hosts/credentials appear.

        Replaces the old per-cycle pool approach in _run_coordinated_cycle
        and _run_distributed_cycle.
        """
        from darwin.sub_agents.base import SubAgentPool, TaskScope, TokenBudget
        from darwin.sub_agents.recon_agent import ReconAgent
        from darwin.sub_agents.exploit_agent import ExploitAgent
        from darwin.sub_agents.pivot_agent import PivotAgent

        # Create persistent pool if first call
        if self._persistent_pool is None:
            self._persistent_pool = SubAgentPool()

        pool = self._persistent_pool

        # Determine which agents to spawn based on DKG state
        spawned_any = await self._spawn_agents_from_dkg(target_url, pool)

        if not spawned_any and pool.active_count() == 0:
            return None  # Nothing to do, let solo handle it

        # Run existing + new agents with DKG monitoring
        log.info("Multi-agent: %d active agents", pool.active_count())

        # Create a flag-detected event for early termination
        flag_found = asyncio.Event()

        async def _flag_watcher():
            """Background: watch DKG for flag nodes."""
            try:
                while not flag_found.is_set():
                    flags = self.dkg.query_nodes("Flag")
                    for f in flags:
                        fv = f.get("value", "")
                        if fv and fv.startswith("flag{") and fv not in self._known_flags:
                            self._known_flags.add(fv)
                            flag_found.set()
                            return
                    await asyncio.sleep(0.5)
            except asyncio.CancelledError:
                pass

        flag_task = asyncio.create_task(_flag_watcher())

        try:
            # Run agents until flag found, all done, or timeout
            agent_task = asyncio.create_task(pool.run_all())

            done, _ = await asyncio.wait(
                [agent_task, asyncio.ensure_future(flag_found.wait())],
                timeout=30.0,  # 30s per monitoring window
                return_when=asyncio.FIRST_COMPLETED,
            )

            if flag_found.is_set():
                pool.terminate()
                await asyncio.wait_for(agent_task, timeout=5.0)
                agent_task.cancel()

            # Check results
            results = getattr(pool, '_results', {})
            self.step_count += len(results)

            # Query DKG for flags
            flags = self.dkg.query_nodes("Flag")
            for flag in flags:
                fv = flag.get("value", "")
                if fv and fv.startswith("flag{") and fv not in self._known_flags:
                    self._known_flags.add(fv)
                    self.phase = OrchestratorPhase.DONE
                    return TaskResult(
                        success=True, flag=fv, steps=self.step_count,
                        tokens_used=self.llm.token_count,
                        time_elapsed=time.time() - self.start_time,
                    )

            # Spawn follow-up agents based on new DKG data
            await self._spawn_followup_agents(target_url, pool)

            # Clean up done agents
            pool.cleanup()

            return None

        finally:
            flag_task.cancel()
            try:
                await flag_task
            except (asyncio.CancelledError, Exception):
                pass

    async def _spawn_agents_from_dkg(
        self, target_url: str, pool,
    ) -> bool:
        """Spawn agents based on current DKG state. Returns True if any spawned."""
        from darwin.sub_agents.base import TaskScope, TokenBudget
        from darwin.sub_agents.recon_agent import ReconAgent
        from darwin.sub_agents.exploit_agent import ExploitAgent
        from darwin.sub_agents.pivot_agent import PivotAgent

        spawned = False
        hosts = self.dkg.query_nodes("Host")
        vulns = self.dkg.query_nodes("Vulnerability")
        creds = self.dkg.query_nodes("Credential")

        # ReconAgent per host (if not already running)
        for h in hosts:
            agent_id = f"recon-{h.get('id', 'unknown')}"
            if agent_id not in getattr(pool, '_agents', {}):
                scope = TaskScope(target_hosts=[
                    h.get("ip", "") or h.get("id", "")
                ])
                recon = ReconAgent(
                    agent_id=agent_id, task_scope=scope,
                    dkg=self.dkg,
                    budget=TokenBudget(max_tokens=32000, max_iterations=15),
                )
                pool.spawn(recon)
                spawned = True
                log.info("Spawned ReconAgent: %s", agent_id)

        # ExploitAgent per vuln type (dedup by type, max 3)
        spawned_types: set[str] = set()
        existing_agents = getattr(pool, '_agents', {})
        exploit_count = sum(
            1 for a in existing_agents.values()
            if getattr(a, 'agent_type', None) and str(a.agent_type) == 'exploit'
        )
        for v in vulns[:6]:
            vt = (v.get("vuln_type") or v.get("type") or "").lower()
            if not vt or vt in spawned_types:
                continue
            if exploit_count >= 3:
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
                    budget=TokenBudget(max_tokens=48000, max_iterations=12),
                )
                pool.spawn(exploit)
                spawned = True
                exploit_count += 1
                log.info("Spawned ExploitAgent: %s (type=%s)", agent_id, vt)

        # PivotAgent if credentials + multi-host
        if creds and len(hosts) > 1:
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
        self, target_url: str, pool,
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
            if getattr(a, 'agent_type', None) and str(a.agent_type) == 'exploit'
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
                    budget=TokenBudget(max_tokens=48000, max_iterations=12),
                )
                pool.spawn(exploit)
                exploit_count += 1
                existing_vuln_types.add(vt)
                log.info("Spawned follow-up ExploitAgent: %s", agent_id)

    # ── Coordinated / Distributed Mode (Legacy) ──────────────────────

    async def _run_coordinated_cycle(self) -> TaskResult | None:
        """Coordinated Mode: spawn 1-2 sub-agents for parallel execution.

        Reference: CPA Hub-and-Spoke architecture — centralized coordination.
        """
        from darwin.dynamic_scaling import ScalingLevel
        from darwin.sub_agents.base import SubAgentPool, TaskScope, TokenBudget
        from darwin.sub_agents.recon_agent import ReconAgent
        from darwin.sub_agents.exploit_agent import ExploitAgent

        pool = SubAgentPool()
        target = self.target_url

        # Spawn ReconAgent
        recon_scope = TaskScope(target_hosts=[target])
        recon = ReconAgent(
            agent_id="recon-coord",
            task_scope=recon_scope,
            dkg=self.dkg,
            budget=TokenBudget(max_tokens=32000, max_iterations=10),
        )
        pool.spawn(recon)

        # Spawn ExploitAgent if vulnerabilities exist
        vulns = self.dkg.query_nodes("Vulnerability")
        if vulns:
            exploit_scope = TaskScope(target_hosts=[target])
            exploit = ExploitAgent(
                agent_id="exploit-coord",
                task_scope=exploit_scope,
                dkg=self.dkg,
                dpm=self.dpm,
                dave=self.dave,
                cteg=self.cteg,
                budget=TokenBudget(max_tokens=64000, max_iterations=15),
            )
            pool.spawn(exploit)

        results = await pool.run_all()
        self.step_count += len(results)

        # Check for flags
        for agent_id, result in results.items():
            if result.success:
                flags = self.dkg.query_nodes("Flag")
                for flag in flags:
                    if flag.get("verified") or flag.get("value", "").startswith("flag{"):
                        return TaskResult(
                            success=True,
                            flag=flag.get("value", ""),
                            steps=self.step_count,
                            tokens_used=self.llm.token_count,
                            time_elapsed=time.time() - self.start_time,
                            defense_detected=self.defense_state.defense_complexity > 0.3,
                            dkg_summary=self.dkg.summary(),
                        )

        return None

    async def _run_distributed_cycle(self) -> TaskResult | None:
        """Distributed Mode: spawn 3+ sub-agents for multi-host scenarios.

        Reference: CPA Hub-and-Spoke — multi-Spoke agent deployment.
        """
        from darwin.dynamic_scaling import scan_collaboration_opportunities
        from darwin.sub_agents.base import SubAgentPool, TaskScope, TokenBudget
        from darwin.sub_agents.recon_agent import ReconAgent
        from darwin.sub_agents.exploit_agent import ExploitAgent
        from darwin.sub_agents.pivot_agent import PivotAgent

        pool = SubAgentPool()

        # Get all hosts from DKG
        hosts = self.dkg.query_nodes("Host")
        if not hosts:
            return None

        # Spawn recon agents for each undiscovered host
        for i, host in enumerate(hosts):
            host_url = host.get("ip") or host.get("id")
            if not host_url:
                raise ValueError(f"Host node missing both ip and id: {host}")
            scope = TaskScope(target_hosts=[host_url])
            recon = ReconAgent(
                agent_id=f"recon-dist-{i}",
                task_scope=scope,
                dkg=self.dkg,
                budget=TokenBudget(max_tokens=24000, max_iterations=8),
            )
            pool.spawn(recon)

        # Spawn exploit agents for confirmed vulnerabilities
        vulns = self.dkg.query_nodes("Vulnerability")
        for i, vuln in enumerate(vulns[:3]):
            endpoint = vuln.get("endpoint", self.target_url)
            scope = TaskScope(target_hosts=[endpoint])
            exploit = ExploitAgent(
                agent_id=f"exploit-dist-{i}",
                task_scope=scope,
                dkg=self.dkg,
                dpm=self.dpm,
                dave=self.dave,
                cteg=self.cteg,
                budget=TokenBudget(max_tokens=48000, max_iterations=12),
            )
            pool.spawn(exploit)

        # Spawn pivot agent if credentials available
        credentials = self.dkg.query_nodes("Credential")
        if credentials and len(hosts) > 1:
            pivot_scope = TaskScope(target_hosts=[h.get("ip", h["id"]) for h in hosts])
            pivot = PivotAgent(
                agent_id="pivot-dist",
                task_scope=pivot_scope,
                dkg=self.dkg,
                budget=TokenBudget(max_tokens=32000, max_iterations=15),
            )
            pool.spawn(pivot)

        # Run all agents in parallel
        results = await pool.run_all()
        self.step_count += len(results)

        # Scan for collaboration opportunities
        opportunities = scan_collaboration_opportunities(self.dkg)
        for opp in opportunities:
            if opp.confidence > 0.6:
                # Spawn follow-up agents based on discoveries
                if opp.opportunity_type == "credential_reuse":
                    pivot2 = PivotAgent(
                        agent_id=f"pivot-opp-{opp.target_agent}",
                        task_scope=TaskScope(target_hosts=[h.get("ip", h["id"]) for h in hosts]),
                        dkg=self.dkg,
                        budget=TokenBudget(max_tokens=24000, max_iterations=10),
                    )
                    pool.spawn(pivot2)

        # Run follow-up agents
        if pool.active_count() > 0:
            more_results = await pool.run_all()
            self.step_count += len(more_results)

        # Check for flags
        flags = self.dkg.query_nodes("Flag")
        for flag in flags:
            if flag.get("verified") or flag.get("value", "").startswith("flag{"):
                return TaskResult(
                    success=True,
                    flag=flag.get("value", ""),
                    steps=self.step_count,
                    tokens_used=self.llm.token_count,
                    time_elapsed=time.time() - self.start_time,
                    defense_detected=self.defense_state.defense_complexity > 0.3,
                    dkg_summary=self.dkg.summary(),
                )

        return None
