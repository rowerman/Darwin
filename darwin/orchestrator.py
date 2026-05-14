"""Orchestrator Agent — Solo Mode main loop with defense awareness.

Reference:
  - Cochise src/cochise/planner.py:131 — Planner + temporary Executor
  - Cochise src/cochise/executor.py:129 — SSH command execution loop
  - CPA hub/task/engine.go:70-121 — TaskEngine state machine
"""

from __future__ import annotations

import asyncio
import json
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

from darwin.dkg import DKG
from darwin.dpm import (
    DefenseCategory,
    DefensePerceptionModule,
    DefenseStateVector,
    SanitizationStrategy,
)
from darwin.dave import DAVE, ExploitAttempt, VerificationResult
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
You operate within an authorized security testing engagement.

## Core Directives
1. Discover the target's attack surface (ports, services, endpoints, parameters).
2. Identify vulnerabilities through systematic probing and analysis of responses.
3. Exploit confirmed vulnerabilities to capture proof flags (format: flag{{...}}).
4. Detect and adapt to active defenses (WAF, filters, honeypots, traps).

## Defense Awareness
- Monitor HTTP responses for defense indicators (unusual status codes, response headers).
- When defenses are detected, analyze their type and select appropriate bypass strategies.
- NEVER assume a request succeeded — verify through the Defense-Aware Verification Engine.

## Available Tools
You have access to reconnaissance tools (nmap_scan, dirb_scan, curl_get, whatweb_scan)
and attack tools (sqlmap_test, send_payload, command_injection_test, xss_reflection_test, ffuf_fuzz).

## Rules
- Report the exact flag string when found.
- If defenses block your attempt, try alternative bypass strategies.
- Track what you've tried to avoid repeating failed approaches.
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


class Orchestrator:
    """Main Orchestrator Agent — Solo Mode.

    In Solo Mode, the Orchestrator directly executes tools without spawning sub-agents.
    This is the most efficient mode for single-host, single-vulnerability challenges.

    Reference: Cochise planner.py — Planner + temporary Executor
    """

    def __init__(
        self,
        llm_session: LLMSession | None = None,
        time_budget: int = 600,
        token_budget: int = 200000,
        browser_enabled: bool = False,
    ):
        self.llm = llm_session or LLMSession()
        self.time_budget = time_budget
        self.token_budget = token_budget
        self.browser_enabled = browser_enabled

        # Core modules
        self.dkg = DKG()
        self.dpm = DefensePerceptionModule(llm_session=self.llm)
        self.dave = DAVE(browser_enabled=browser_enabled)

        # Tool infrastructure
        self.recon_gateway = create_recon_gateway()
        self.attack_gateway = create_attack_gateway()
        self.client = HTTPClient()
        self.probe_client = ProbeClient()

        # State tracking
        self.phase = OrchestratorPhase.INIT
        self.defense_state = DefenseStateVector()
        self.vulnerabilities: List[VulnerabilityHypothesis] = []
        self.step_count = 0
        self.start_time = 0.0
        self.flag_pattern = re.compile(r"flag\{[a-zA-Z0-9_\-!@#$%^&*()+=]+\}")

    async def run(self, task_description: str, target_url: str) -> TaskResult:
        """Run penetration test against a single target.

        Args:
            task_description: Natural language description of the task
            target_url: Target URL to test

        Returns:
            TaskResult with success/failure and captured flag
        """
        self.start_time = time.time()
        self.target_url = target_url
        self.dkg.add_node("Host", "target", {
            "ip": target_url, "is_reachable": True, "is_internal": False,
        })
        self.phase = OrchestratorPhase.RECON

        try:
            # Phase 1: Reconnaissance
            await self._recon_phase(target_url)

            # Phase 2: Analyze
            await self._analyze_phase()

            # Phase 3: Exploit (with defense bypass if needed)
            result = await self._exploit_phase(target_url)

            return result

        except asyncio.TimeoutError:
            return TaskResult(
                success=False, steps=self.step_count,
                time_elapsed=time.time() - self.start_time,
                phase_at_end=self.phase, error="Time budget exceeded",
            )
        except Exception as e:
            return TaskResult(
                success=False, steps=self.step_count,
                time_elapsed=time.time() - self.start_time,
                phase_at_end=self.phase, error=str(e),
            )
        finally:
            await self.client.close()

    # ── Phase 1: Reconnaissance ─────────────────────────────────────

    async def _recon_phase(self, target_url: str) -> None:
        """Discover attack surface: ports, services, endpoints, parameters."""
        self.phase = OrchestratorPhase.RECON

        # Get baseline response
        baseline = await self.client.get_baseline(target_url)

        # Run whatweb for technology fingerprint
        whatweb_result = await self.recon_gateway.call("whatweb_scan", {"target_url": target_url})
        if whatweb_result.success:
            for tech in whatweb_result.parsed_output.get("technologies", []):
                self.dkg.add_node("Service", f"tech-{tech}", {
                    "port": 0, "protocol": "HTTP", "version": tech, "banner": tech,
                })

        # Try directory enumeration
        dirb_result = await self.recon_gateway.call("dirb_scan", {"target_url": target_url})
        for path_info in dirb_result.parsed_output.get("discovered_paths", []):
            self.dkg.add_node("Endpoint", f"endpoint-{path_info['path']}", {
                "url": f"{target_url.rstrip('/')}{path_info['path']}",
                "method": "GET",
                "params": "",
                "auth_required": "401" in path_info.get("code", ""),
            })

        # Record discovered services
        self.dkg.add_node("Service", f"service-http", {
            "port": 443 if target_url.startswith("https") else 80,
            "protocol": "HTTP",
            "version": whatweb_result.parsed_output.get("technologies", ["unknown"])[0],
            "banner": "",
        })

        self.step_count += 1

    # ── Phase 2: Analyze ────────────────────────────────────────────

    async def _analyze_phase(self) -> None:
        """Analyze reconnaissance data to identify potential vulnerabilities."""
        self.phase = OrchestratorPhase.ANALYZE

        dkg_summary = self.dkg.summary()
        self.llm.reset()

        content, _ = self.llm.generate(
            prompt=f"Target information:\n{dkg_summary}\n\nIdentify potential vulnerabilities.",
            system_prompt=SYSTEM_PROMPT_ANALYZE,
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
        except Exception:
            # If parsing fails, try a generic approach
            pass

        self.step_count += 1

    # ── Phase 3: Exploit ────────────────────────────────────────────

    async def _exploit_phase(self, target_url: str) -> TaskResult:
        """Attempt exploitation of identified vulnerabilities."""
        self.phase = OrchestratorPhase.EXPLOIT

        # Priority-sort vulnerabilities by confidence
        self.vulnerabilities.sort(key=lambda v: v.confidence, reverse=True)

        for vuln in self.vulnerabilities:
            if self._time_exceeded() or self._tokens_exceeded():
                break

            self.step_count += 1

            # Attempt exploitation based on vulnerability type
            exploit_attempt = await self._attempt_exploit(vuln, target_url)

            # Verify
            verification = await self.dave.verify(exploit_attempt)

            if verification.passed and verification.flag_value and not verification.is_honeypot_flag:
                self.phase = OrchestratorPhase.DONE
                return TaskResult(
                    success=True,
                    flag=verification.flag_value,
                    steps=self.step_count,
                    tokens_used=self.llm.token_count,
                    time_elapsed=time.time() - self.start_time,
                    defense_detected=verification.defense_detected,
                    waf_bypassed=verification.defense_detected,
                    waf_type=self.defense_state.waf_type,
                    defense_complexity=self.defense_state.defense_complexity,
                    dkg_summary=self.dkg.summary(),
                )

            # If defense blocked us, attempt bypass
            if verification.defense_detected:
                bypass_result = await self._defense_bypass_attempt(vuln, target_url)
                if bypass_result:
                    return bypass_result

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

    # ── Exploit Attempt ──────────────────────────────────────────────

    async def _attempt_exploit(
        self, vuln: VulnerabilityHypothesis, target_url: str
    ) -> ExploitAttempt:
        """Attempt to exploit a specific vulnerability."""
        response = None
        tool_stdout = ""

        if vuln.vuln_type.upper() in ("SQLI", "SQL_INJECTION"):
            result = await self.attack_gateway.call("sqlmap_test", {
                "url": vuln.endpoint or target_url,
                "param": vuln.param or "id",
            })
            tool_stdout = result.stdout
            response = await self.client.get(target_url)

        elif vuln.vuln_type.upper() in ("XSS", "CROSS_SITE_SCRIPTING"):
            result = await self.attack_gateway.call("xss_reflection_test", {
                "url": vuln.endpoint or target_url,
                "param": vuln.param or "q",
            })
            tool_stdout = result.stdout
            response = await self.client.get(target_url)

        elif vuln.vuln_type.upper() in ("CMDI", "COMMAND_INJECTION"):
            result = await self.attack_gateway.call("command_injection_test", {
                "url": vuln.endpoint or target_url,
                "param": vuln.param or "cmd",
            })
            tool_stdout = result.stdout
            response = await self.client.get(target_url)

        else:
            # Generic: send common payloads and check response
            for payload in ["' OR '1'='1", "<script>alert(1)</script>", ";id"]:
                result = await self.attack_gateway.call("send_payload", {
                    "url": vuln.endpoint or target_url,
                    "param": vuln.param or "input",
                    "payload": payload,
                    "method": "GET",
                    "encode_type": "none",
                })
                tool_stdout += result.stdout + "\n"
            response = await self.client.get(target_url)

        return ExploitAttempt(
            target_url=target_url,
            vuln_type=vuln.vuln_type,
            payload=vuln.evidence or "",
            http_response=response,
            tool_stdout=tool_stdout,
        )

    # ── Defense Bypass ───────────────────────────────────────────────

    async def _defense_bypass_attempt(
        self, vuln: VulnerabilityHypothesis, target_url: str
    ) -> TaskResult | None:
        """Attempt to bypass detected defenses."""
        self.phase = OrchestratorPhase.BYPASS

        # Run defense probes
        probe_results = await self.probe_client.send_all_probe_classes(
            target_url, vuln.param or "q"
        )

        # Get all HTTP responses for DPM analysis
        responses = []
        for probe in probe_results:
            responses.append(probe.response)

        # DPM analysis
        self.defense_state = self.dpm.detect(probe_results, responses)

        # If defense complexity is significant, attempt bypass
        if self.defense_state.defense_complexity < 0.3:
            return None  # defense too weak to justify bypass

        # Get bypass strategies from WAF fingerprint or LLM
        bypass_hints = self.defense_state.waf_match.bypass_hints if self.defense_state.waf_match else []
        if not bypass_hints:
            self.llm.reset()
            content, _ = self.llm.generate(
                prompt=f"Defense detected: {self.defense_state.to_dict()}. Suggest bypass strategies.",
                system_prompt=SYSTEM_PROMPT_BYPASS,
            )
            try:
                result = json.loads(content)
                bypass_hints = [s["name"] for s in result.get("strategies", [])]
            except json.JSONDecodeError:
                bypass_hints = ["encoding_mutation", "case_alternation"]

        # Try each bypass strategy
        for strategy in bypass_hints[:5]:
            if self._time_exceeded():
                break

            self.defense_state.bypass_attempts += 1
            self.defense_state.attempted_strategies.append(strategy)

            encode_type = "none"
            if strategy == "encoding_mutation":
                encode_type = "double_url"
            elif strategy == "case_alternation":
                payload = vuln.evidence.swapcase() if vuln.evidence else "<ScRiPt>alert(1)</sCrIpT>"

            result = await self.attack_gateway.call("send_payload", {
                "url": vuln.endpoint or target_url,
                "param": vuln.param or "input",
                "payload": vuln.evidence or "<script>alert(1)</script>",
                "method": "GET",
                "encode_type": encode_type,
            })

            response = await self.client.get(target_url)
            attempt = ExploitAttempt(
                target_url=target_url,
                vuln_type=vuln.vuln_type,
                payload=result.stdout,
                http_response=response,
                tool_stdout=result.stdout,
            )
            verification = await self.dave.verify(attempt, probe_results)

            if verification.passed and verification.flag_value and not verification.is_honeypot_flag:
                self.defense_state.bypass_successes += 1
                self.phase = OrchestratorPhase.DONE
                return TaskResult(
                    success=True,
                    flag=verification.flag_value,
                    steps=self.step_count,
                    tokens_used=self.llm.token_count,
                    time_elapsed=time.time() - self.start_time,
                    defense_detected=True,
                    waf_bypassed=True,
                    waf_type=self.defense_state.waf_type,
                    defense_complexity=self.defense_state.defense_complexity,
                    dkg_summary=self.dkg.summary(),
                )

        return None  # all bypass strategies failed

    # ── Flag Search ──────────────────────────────────────────────────

    async def _check_response_for_flag(self, target_url: str) -> TaskResult | None:
        """Search response body for flag patterns."""
        try:
            response = await self.client.get(target_url)
            flags = self.flag_pattern.findall(response.body)
            if flags:
                self.phase = OrchestratorPhase.DONE
                return TaskResult(
                    success=True,
                    flag=flags[0],
                    steps=self.step_count,
                    time_elapsed=time.time() - self.start_time,
                )
        except Exception:
            pass
        return None

    # ── Helpers ──────────────────────────────────────────────────────

    def _time_exceeded(self) -> bool:
        return (time.time() - self.start_time) > self.time_budget

    def _tokens_exceeded(self) -> bool:
        return self.llm.token_count > self.token_budget

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
        target = getattr(self, "target_url", "http://localhost")

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
            host_url = host.get("ip", host.get("id", "http://localhost"))
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
