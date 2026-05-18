"""Base Sub-Agent — lifecycle, Plan-Act-Observe loop, DKG integration.

Reference:
  - VulnBot roles/role.py:16-90 — Role._plan() + Role._react()
  - Cochise executor.py:129 — temporary Executor per task
  - CPA hub/task/engine.go — TaskEngine state machine
"""

from __future__ import annotations

import asyncio
import json
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

from darwin.dkg import DKG
from darwin.tools.mcp_gateway import MCPGateway, ToolResult
from darwin.utils.llm import LLMSession


class SubAgentState(str, Enum):
    """Sub-agent lifecycle states.

    Reference: CPA task/model.go — Task state machine
    """
    SPAWNING = "spawning"
    INITIALIZING = "initializing"
    RUNNING = "running"
    WAITING_DKG = "waiting_dkg"
    TERMINATING = "terminating"
    DONE = "done"
    BUDGET_EXHAUSTED = "budget_exhausted"
    STALLED = "stalled"
    CANCELLED = "cancelled"
    SAFETY_ABORT = "safety_abort"


class AgentType(str, Enum):
    RECON = "recon"
    EXPLOIT = "exploit"
    PIVOT = "pivot"
    AD = "ad"
    PERSIST = "persist"


@dataclass
class TaskScope:
    """Defines what a sub-agent is responsible for."""
    target_hosts: List[str] = field(default_factory=list)
    target_services: List[str] = field(default_factory=list)
    target_vulns: List[str] = field(default_factory=list)
    constraints: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TokenBudget:
    """Token and time budget for a sub-agent."""
    max_tokens: int = 32000
    max_time_seconds: int = 300
    max_iterations: int = 25
    tokens_used: int = 0
    start_time: float = 0.0

    def remaining(self) -> int:
        return self.max_tokens - self.tokens_used

    def time_remaining(self) -> float:
        if self.start_time == 0:
            return self.max_time_seconds
        elapsed = time.time() - self.start_time
        return max(0.0, self.max_time_seconds - elapsed)

    def time_exceeded(self) -> bool:
        return self.time_remaining() <= 0

    def tokens_exceeded(self) -> bool:
        return self.tokens_used >= self.max_tokens


@dataclass
class SubAgentResult:
    """Result of a sub-agent run."""
    agent_id: str
    agent_type: str
    success: bool
    end_state: SubAgentState
    findings_count: int
    tokens_used: int
    time_elapsed: float
    summary: str = ""


class BaseSubAgent(ABC):
    """Base class for all tactical sub-agents.

    Key design:
      - Independent LLM session (does NOT pollute Orchestrator context)
      - Only communicates via DKG (no natural language agent-to-agent chat)
      - Plan → Act → Observe loop (reference: VulnBot Role.run())

    Reference:
      - VulnBot roles/role.py:38-82 — Role._plan() + Role._react()
      - Cochise executor.py:129 — temporary Executor per task with own LLM
    """

    def __init__(
        self,
        agent_id: str,
        agent_type: AgentType,
        task_scope: TaskScope,
        dkg: DKG,
        llm_session: LLMSession,
        budget: TokenBudget,
        tools: MCPGateway | None = None,
    ):
        self.agent_id = agent_id
        self.agent_type = agent_type
        self.task_scope = task_scope
        self.dkg = dkg
        self.llm = llm_session
        self.budget = budget
        self.tools = tools or MCPGateway()

        self.state = SubAgentState.SPAWNING
        self.plan: List[Dict[str, Any]] = []
        self.iteration = 0
        self.findings: List[Dict[str, Any]] = []
        self._start_time = time.time()

    # ── Main Loop ─────────────────────────────────────────────────

    async def run(self) -> SubAgentResult:
        """Main Plan → Act → Observe loop.

        Reference: VulnBot Role.run() (role.py:58-82)
        """
        self.state = SubAgentState.INITIALIZING
        self.budget.start_time = time.time()

        try:
            # Phase 1: Generate plan
            self._maybe_compress()
            self.plan = await self._generate_plan()
            if not self.plan:
                # No plan generated — create a default exploration task
                self.plan = [{
                    "id": "default",
                    "instruction": "Explore the target and identify vulnerabilities",
                    "action": "recon",
                    "dependent_task_ids": [],
                }]
            self.state = SubAgentState.RUNNING

            # Phase 2: Execute plan
            while self._should_continue():
                task = self._select_next_task()
                if not task:
                    break

                self.iteration += 1

                # Act
                command_result = await self._execute_task(task)

                # Observe
                success, new_findings = await self._evaluate_result(task, command_result)

                # Write findings to DKG
                self._write_findings_to_dkg(task, command_result, new_findings)

                # Replan if needed — compress context before LLM calls
                self._maybe_compress()
                if not success:
                    self.plan = await self._replan_after_failure(task, command_result)
                else:
                    self._mark_task_done(task)

                self.plan = await self._update_plan(task, command_result)

            # Determine end state
            if self._all_tasks_done():
                self.state = SubAgentState.DONE
            elif self.budget.tokens_exceeded():
                self.state = SubAgentState.BUDGET_EXHAUSTED
            elif self.iteration >= self.budget.max_iterations:
                self.state = SubAgentState.DONE
            elif self._is_stalled():
                self.state = SubAgentState.STALLED
            else:
                self.state = SubAgentState.DONE

        except Exception as e:
            self.state = SubAgentState.CANCELLED
            self.findings.append({"error": str(e)})

        return self._build_result()

    # ── Plan Generation ─────────────────────────────────────────

    @abstractmethod
    async def _generate_plan(self) -> List[Dict[str, Any]]:
        """Generate initial attack plan for this sub-agent's scope."""

    # ── Task Execution ──────────────────────────────────────────

    @abstractmethod
    async def _execute_task(self, task: Dict[str, Any]) -> ToolResult:
        """Execute a single task and return the result."""

    # ── Result Evaluation ───────────────────────────────────────

    async def _evaluate_result(
        self, task: Dict[str, Any], result: ToolResult
    ) -> tuple[bool, List[Dict[str, Any]]]:
        """Evaluate whether a task was successful.

        Returns:
            (success, new_findings) — findings are dictionaries of discovered information.
        """
        if not result.success:
            return False, []

        findings = self._extract_findings(task, result)
        self.findings.extend(findings)
        return len(findings) > 0, findings

    def _extract_findings(
        self, task: Dict[str, Any], result: ToolResult
    ) -> List[Dict[str, Any]]:
        """Extract structured findings from tool output."""
        findings = []
        # Try to extract flags
        import re
        flags = re.findall(r"flag\{[a-zA-Z0-9_\-!@#$%^&*()+=]+\}", result.stdout, re.IGNORECASE)
        for flag in flags:
            findings.append({"type": "flag", "value": flag, "source": result.tool_name})
        # Include parsed output
        if result.parsed_output:
            findings.append({"type": "parsed", "data": result.parsed_output, "source": result.tool_name})
        return findings

    # ── Replanning ─────────────────────────────────────────────

    async def _replan_after_failure(
        self, failed_task: Dict[str, Any], result: ToolResult
    ) -> List[Dict[str, Any]]:
        """Replan after a task failure. Override for agent-specific logic."""
        # Default: remove failed task if it's blocking and continue with remaining
        self._mark_task_done(failed_task)
        return self.plan

    async def _update_plan(
        self, completed_task: Dict[str, Any], result: ToolResult
    ) -> List[Dict[str, Any]]:
        """Update plan after a completed task. Override for agent-specific logic."""
        return self.plan

    # ── DKG Integration ────────────────────────────────────────

    def _write_findings_to_dkg(
        self, task: Dict[str, Any], result: ToolResult, findings: List[Dict[str, Any]]
    ) -> None:
        """Write discovered information to the shared DKG.

        This is the ONLY way sub-agents communicate — no direct agent-to-agent chat.
        """
        for finding in findings:
            ftype = finding.get("type", "")
            if ftype == "flag":
                self.dkg.add_node("Flag", f"flag-{finding['value'][:20]}", {
                    "value": finding["value"],
                    "location": result.tool_name,
                    "verified": False,
                    "discovered_by": self.agent_id,
                })
            elif ftype == "parsed":
                data = finding.get("data", {})
                if "open_ports" in data:
                    for port_info in data["open_ports"]:
                        self.dkg.add_node("Service", f"svc-{port_info['port']}", {
                            "port": port_info["port"],
                            "protocol": "tcp",
                            "version": port_info.get("service", ""),
                            "discovered_by": self.agent_id,
                        })
                if "technologies" in data:
                    for tech in data["technologies"]:
                        self.dkg.add_node("Service", f"tech-{tech[:30]}", {
                            "port": 0, "protocol": "HTTP",
                            "version": tech,
                            "discovered_by": self.agent_id,
                        })

    # ── Helpers ─────────────────────────────────────────────────

    def _select_next_task(self) -> Dict[str, Any] | None:
        """Select the next pending task from the plan.

        Reference: VulnBot PlanModel.topological_sort() (db/models/plan_model.py:34-71)
        """
        for task in self.plan:
            if not task.get("done", False):
                # Check dependencies
                deps = task.get("dependent_task_ids", [])
                if all(
                    any(t.get("id") == dep and t.get("done") for t in self.plan)
                    for dep in deps
                ):
                    return task
        return None

    def _mark_task_done(self, task: Dict[str, Any]) -> None:
        """Mark a task as completed."""
        task["done"] = True
        task["completed_at"] = time.time()

    def _all_tasks_done(self) -> bool:
        return all(t.get("done", False) for t in self.plan) if self.plan else True

    def _is_stalled(self) -> bool:
        """Detect if agent is stalled (3 consecutive iterations with no new findings)."""
        recent = self.findings[-3:]
        return len(recent) >= 3 and len(recent[-1]) == 0

    def _should_continue(self) -> bool:
        """Check if the agent should continue running."""
        if self.budget.time_exceeded():
            return False
        if self.iteration >= self.budget.max_iterations:
            return False
        if self.state in (SubAgentState.CANCELLED, SubAgentState.SAFETY_ABORT):
            return False
        if self.budget.tokens_exceeded():
            # Try compression before giving up
            if self._maybe_compress():
                return not self.budget.tokens_exceeded()
            return False
        return True

    def _maybe_compress(self) -> bool:
        """Compress conversation history if context load exceeds threshold.

        Sub-agents use a fixed 40% threshold relative to their budget's max_tokens.
        Returns True if compression was performed.
        """
        ctx_load = self.llm.context_load
        threshold = 0.4
        if ctx_load < threshold:
            return False

        saved = self.llm.compress(
            max_context_tokens=180000,
            compression_threshold=threshold,
        )
        if saved > 0:
            self.budget.tokens_used = self.llm.token_count
            return True
        return False

    def _build_result(self) -> SubAgentResult:
        return SubAgentResult(
            agent_id=self.agent_id,
            agent_type=self.agent_type.value,
            success=self.state == SubAgentState.DONE,
            end_state=self.state,
            findings_count=len(self.findings),
            tokens_used=self.budget.tokens_used,
            time_elapsed=time.time() - self._start_time,
            summary=f"{self.agent_type.value}: {self.state.value} "
                    f"({len(self.findings)} findings, {self.iteration} iterations)",
        )


# ── Sub-Agent Pool ──────────────────────────────────────────────

class SubAgentPool:
    """Manages active sub-agents.

    Reference: CPA hub/task/engine.go — concurrent agent management.
    """

    def __init__(self):
        self._agents: Dict[str, BaseSubAgent] = {}
        self._results: Dict[str, SubAgentResult] = {}

    def spawn(self, agent: BaseSubAgent) -> str:
        """Register a spawned sub-agent."""
        self._agents[agent.agent_id] = agent
        return agent.agent_id

    def get(self, agent_id: str) -> BaseSubAgent | None:
        return self._agents.get(agent_id)

    def active_count(self) -> int:
        """Count agents in RUNNING state."""
        return sum(
            1 for a in self._agents.values()
            if a.state == SubAgentState.RUNNING
        )

    def all_done(self) -> bool:
        """Check if all agents have finished."""
        done_states = {
            SubAgentState.DONE, SubAgentState.BUDGET_EXHAUSTED,
            SubAgentState.STALLED, SubAgentState.CANCELLED,
            SubAgentState.SAFETY_ABORT,
        }
        return all(a.state in done_states for a in self._agents.values())

    async def run_all(self) -> Dict[str, SubAgentResult]:
        """Run all spawned agents concurrently and collect results."""
        tasks = []
        for agent in self._agents.values():
            tasks.append(agent.run())

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for agent, result in zip(self._agents.values(), results):
            if isinstance(result, Exception):
                self._results[agent.agent_id] = SubAgentResult(
                    agent_id=agent.agent_id,
                    agent_type=agent.agent_type.value,
                    success=False,
                    end_state=SubAgentState.CANCELLED,
                    findings_count=0,
                    tokens_used=agent.budget.tokens_used,
                    time_elapsed=time.time(),
                    summary=str(result),
                )
            else:
                self._results[agent.agent_id] = result

        return self._results

    def terminate(self, agent_id: str) -> None:
        """Force-terminate a sub-agent."""
        if agent_id in self._agents:
            self._agents[agent_id].state = SubAgentState.CANCELLED

    def cleanup(self):
        """Remove all terminated agents."""
        self._agents = {
            aid: agent for aid, agent in self._agents.items()
            if agent.state == SubAgentState.RUNNING
        }
