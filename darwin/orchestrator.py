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
from darwin.dynamic_scaling import DynamicScalingEngine, ScalingLevel
from darwin.tools.mcp_client import MCPClientPool, load_mcp_config
from darwin.tools.mcp_gateway import MCPGateway, ToolResult
from darwin.tools.recon_server import create_recon_gateway
from darwin.tools.attack_server import create_attack_gateway
from darwin.utils.http_client import HTTPClient, ProbeClient, HTTPResponse
from darwin.utils.llm import LLMSession


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
and identify potential vulnerabilities. For each, specify:
1. Vulnerability type (XSS, SQLi, CMDi, SSTI, LFI, etc.)
2. Endpoint URL
3. Parameter name
4. Confidence (0.0-1.0) based on evidence
5. Evidence that supports this hypothesis

Output as JSON array:
[{"vuln_type": "...", "endpoint": "...", "param": "...", "confidence": 0.X, "evidence": "..."}]"""

SYSTEM_PROMPT_BYPASS = """You are a WAF bypass specialist. Given a detected defense configuration,
suggest bypass strategies ordered by likelihood of success.

Available strategies: encoding_mutation, case_alternation, parameter_pollution,
content_type_switch, request_fragmentation, protocol_downgrade, context_specific_mutation.

Output JSON: {"strategies": [{"name": "...", "reason": "...", "confidence": 0.X}]}"""

SYSTEM_PROMPT_EXPLORE = """You are a penetration testing agent with authenticated session cookies. Your goal: find flag{...} or FLAG{...}.

## CRITICAL: You MUST try ALL of these attack vectors on every authenticated page:

1. **Custom HTTP Headers (MOST IMPORTANT — try these FIRST):**
   - X-UserId: <id>
   - X-User-Id: <id>
   - X-Forwarded-User: <id>
   - X-Auth-User: <id>
   - X-Authenticated-User: <id>
   Applications often trust these headers for IDOR. Try values: 0, 1, 2, 10032, 10033, 10052

2. **URL parameter tampering:**
   - ?user_id=<id>
   - ?id=<id>
   - ?userId=<id>

3. **URL path IDOR:**
   - /user/<id>, /users/<id>, /account/<id>, /profile/<id>
   - /order/<id>/receipt, /order/<id>/view

4. **POST body tampering** on forms with hidden user_id fields.

## Rules:
- Try headers FIRST before path enumeration
- When you see a numeric ID anywhere, try adjacent values (±1, ±10, ±20)
- Try ID values: 0, 1, 2, 10032, 10033, 10052, 10053
- If a response shows different user data than expected, you found IDOR — extract the flag
- Limit to 8 actions per response

Respond ONLY with a JSON array:
[{"action": "get", "url": "http://host/dashboard", "headers": {"X-UserId": "10052"}, "reason": "IDOR via X-UserId header"}]"""


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
            # Phase 1: Reconnaissance
            await self._recon_phase(target_url)
            self._task_log_event("info", "recon_done",
                dkg_summary=self.dkg.summary(), step=self.step_count)
            self.dkg.save(self._checkpoint_path("recon"))

            # Phase 1.5: Auto-login if credentials provided
            if username and password:
                for port in getattr(self, '_discovered_http_ports', []):
                    host = getattr(self, "target_host", None)
                    if host:
                        scheme = "https" if port == 443 else "http"
                        login_url = f"{scheme}://{host}" if port in (80, 443) else f"{scheme}://{host}:{port}"
                        if await self.client.auto_login(login_url, username, password):
                            self._task_log_event("info", "auto_login_success", url=login_url)
                            break

            # Determine scaling mode
            scaling_level = self.scaling_engine.decide(self.dkg, self.defense_state)
            self._task_log_event("info", "scaling_decision",
                scaling_level=scaling_level.value,
                dkg_summary=self.dkg.get_defense_context(),
            )

            if scaling_level == ScalingLevel.SOLO:
                await self._analyze_phase()
                self._task_log_event("info", "analyze_done",
                    vuln_count=len(self.vulnerabilities),
                    vulns=[{"type": v.vuln_type, "endpoint": v.endpoint, "confidence": v.confidence}
                           for v in self.vulnerabilities],
                    tokens_used=self.llm.token_count,
                )
                self.dkg.save(self._checkpoint_path("analyze"))
                result = await self._exploit_phase(target_url)
            elif scaling_level == ScalingLevel.COORDINATED:
                log.info("Entering Coordinated Mode (B >= 0.3)")
                result = await self._run_coordinated_cycle()
                if result is None:
                    result = await self._exploit_phase(target_url)
            else:
                log.info("Entering Distributed Mode (B >= 0.6)")
                result = await self._run_distributed_cycle()
                if result is None:
                    result = await self._exploit_phase(target_url)

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
            task_record = TaskRecord(
                task_id=f"task-{int(self.start_time)}",
                benchmark="unknown",
                vulnerability_types=vuln_types,
                outcome="success" if result.success else "failure",
                defense_encountered=self.defense_state.to_dict(),
                timestamp=time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(self.start_time)),
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

        # ── Phase 1b: HTTP-level recon on each HTTP port ──────────
        def _is_http(p: dict) -> bool:
            svc = p.get("service", "").lower()
            return any(kw in svc for kw in ("http", "https", "www", "ssl"))

        http_ports = [p["port"] for p in discovered_ports if _is_http(p)
                      or p["port"] in (80, 443, 8080, 8443, 3000, 5000, 8000, 8888, 9090)]
        original_port = parsed.port or (443 if parsed.scheme == "https" else 80)
        if original_port not in http_ports:
            http_ports.append(original_port)
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
                    "type": f.get("type", "info"), "endpoint": url, "parameter": "",
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

        # Parse LLM's vulnerability hypotheses
        try:
            vulns_json = self._extract_json(content)
            for v in vulns_json:
                hypothesis = VulnerabilityHypothesis(
                    vuln_type=v.get("vuln_type", ""),
                    endpoint=v.get("endpoint", ""),
                    param=v.get("param", ""),
                    confidence=float(v.get("confidence", 0.5)),
                    evidence=v.get("evidence", ""),
                )
                self.vulnerabilities.append(hypothesis)

                # Record in DKG
                self.dkg.add_node("Vulnerability", f"vuln-{len(self.vulnerabilities)}", {
                    "type": hypothesis.vuln_type,
                    "endpoint": hypothesis.endpoint,
                    "parameter": hypothesis.param,
                    "severity": "unknown",
                })
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
        """Add vulnerability hypotheses derived from DKG endpoints and findings."""
        # DKG nikto findings → vulnerability hypotheses
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
        # Every POST/GET endpoint with params → SQLi + XSS
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
        # Endpoints with numeric path segments → IDOR + SQLI
        for ep in self.dkg.query_nodes("Endpoint"):
            url = ep.get("url", "")
            if not url or any(v.endpoint == url for v in self.vulnerabilities):
                continue
            if re.search(r'/\d+', url):
                self.vulnerabilities.append(VulnerabilityHypothesis(
                    vuln_type="IDOR", endpoint=url, param="id",
                    confidence=0.3, evidence=f"Numeric ID in URL path",
                ))
                self.vulnerabilities.append(VulnerabilityHypothesis(
                    vuln_type="SQLI", endpoint=url, param="id",
                    confidence=0.25, evidence=f"Numeric ID in URL path",
                ))

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

    # ── Phase 3: Exploit ────────────────────────────────────────────

    DEFAULT_CREDENTIALS = [
        ("test", "test"), ("admin", "admin"), ("admin", "password"),
        ("user", "user"), ("guest", "guest"), ("root", "root"),
    ]

    async def _exploit_phase(self, target_url: str) -> TaskResult:
        """Attempt exploitation of identified vulnerabilities."""
        self.phase = OrchestratorPhase.EXPLOIT

        # ── Phase 3a: Default credential brute-forcing ────────────
        has_protected = any(
            kw in ep.get("url", "").lower()
            for ep in self.dkg.query_nodes("Endpoint")
            for kw in ("dashboard", "orders", "admin", "account", "profile")
        )
        if has_protected:
            for port in getattr(self, '_discovered_http_ports', []):
                host = getattr(self, "target_host", None) or "localhost"
                scheme = "https" if port == 443 else "http"
                base = f"{scheme}://{host}" if port in (80, 443) else f"{scheme}://{host}:{port}"
                for u, p in self.DEFAULT_CREDENTIALS:
                    if self._time_exceeded():
                        break
                    try:
                        if await self.client.auto_login(base, u, p):
                            self._task_log_event("info", "auto_login_ok", url=base, username=u)
                            # Try LLM-driven exploration first
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


    # ── Flag Search ──────────────────────────────────────────────────

    # Common paths where flags might be exposed
    _FLAG_PATHS = ["/flag", "/flag.txt", "/robots.txt", "/.git/HEAD", "/admin", "/secret", "/api/flag", "/debug"]

    async def _check_response_for_flag(self, target_url: str) -> TaskResult | None:
        """Search response body for flag patterns across all discovered HTTP services."""
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

        # Also probe all discovered endpoints
        for ep in self.dkg.query_nodes("Endpoint"):
            eu = ep.get("url", "")
            if eu and eu not in urls_to_check:
                urls_to_check.append(eu)

        for bu in urls_to_check:
            for path in self._FLAG_PATHS:
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

    # ── Coordinated / Distributed Mode ─────────────────────────────

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
