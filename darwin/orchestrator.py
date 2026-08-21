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

# Version strings that carry no useful information for RAG lookup.
# Filtering them avoids polluting LLM context with irrelevant matches.

# -- Phase coordinators (darwin.orchestration) --------------------------------
from darwin.orchestration.execution import (
    ExecutionCoordinator,
    TaskExecution,
    _RuntimeFlagFound,
    _RuntimePlannerAdapter,
    _RuntimeExecutorAdapter,
    _RuntimeEvaluatorAdapter,
)
from darwin.orchestration.lifecycle import LifecycleCoordinator
from darwin.orchestration.planning import PlanCoordinator
from darwin.orchestration.ports import GatewayToolCallPort
from darwin.orchestration.recon import ReconCoordinator
from darwin.orchestration.research import ResearchCoordinator

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
        max_context_tokens: int = 384000,
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
        # P5/P5c: Task-based executor is the sole execution path (fix-retry
        # seam since P5; main-loop dispatch migrated in P5c).
        self.executor = ToolExecutor(
            attack_gateway=self.attack_gateway,
            recon_gateway=self.recon_gateway,
            mcp_pool=self.mcp_pool,
        )
        # P6: rule-based Evaluator for structured failure classification
        self.evaluator = CoreEvaluator()
        # P7: local-first replanner with duplicate-failure protection
        self.replanner = Replanner()
        # P10/P11/P13: Memory layers — plan rationale + execution history
        # feed the replan fallback; preserve-level / key-tool executions
        # are shared to CTEG as cross-task experience.
        # v2: WorkingMemory layer (DKG) is wired through the manager; all
        # world-state reads go through _get_state() -> memory.working_snapshot().
        self.memory = MemoryManager(working=self.dkg, experience=self.cteg)
        # O3.1/O3.3: belief provider renders the CURRENT cognition snapshot
        # at compression time, so decision-critical facts (beliefs, plan,
        # defense, rationale) ride the preserved payload verbatim.
        self.memory.belief_provider = lambda: self._belief_context(compact=True)
        # P2: full-value critical facts (passwords, tokens, flags) for the
        # structured compression digest — compression path only.
        self.memory.critical_facts_provider = lambda: render_critical_facts(
            self._get_state()
        )
        # P3: compression orchestration lives in ContextManager; the
        # orchestrator only delegates (thin loop controller).
        self.context = ContextManager(
            llm=self.llm,
            memory=self.memory,
            dkg=self.dkg,
            max_context_tokens=self.max_context_tokens,
            compression_threshold=self.compression_threshold,
            event_logger=self._task_log_event,
        )

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

        # Phase coordinators — shared-context composition. Each coordinator
        # forwards state/method access to this orchestrator (see
        # darwin/orchestration/context.py) and calls tools via _tool_port.
        self._tool_port = GatewayToolCallPort(self.attack_gateway, self.recon_gateway)
        self.recon = ReconCoordinator(self)
        self.research = ResearchCoordinator(self)
        self.planning = PlanCoordinator(self)
        self.execution = ExecutionCoordinator(self)
        self.lifecycle = LifecycleCoordinator(self)

    async def run(self, task_description: str, target_url: str, username: str | None=None, password: str | None=None, port_range: str | None=None) -> TaskResult:
        return await self.lifecycle.run(task_description, target_url, username, password, port_range)

    async def _bootstrap_scan(self, target_url: str, port_range: str | None=None) -> None:
        return await self.recon._bootstrap_scan(target_url, port_range)

    async def _k8s_cluster_discovery(self) -> None:
        return await self.recon._k8s_cluster_discovery()

    async def _deep_recon(self) -> None:
        return await self.recon._deep_recon()

    async def _detect_defenses(self) -> None:
        return await self.recon._detect_defenses()

    async def _verify_flag(self, flag: str, stdout: str, tc_args: dict, elapsed_ms: int=0, tool_name: str='') -> tuple[bool, str]:
        return await self.recon._verify_flag(flag, stdout, tc_args, elapsed_ms, tool_name)

    def _should_terminate(self, result: TaskResult | None, max_loops: int) -> bool:
        return self.lifecycle._should_terminate(result, max_loops)

    def _detect_chain_topology(self, chain_mode_config: str='auto') -> bool:
        return self.lifecycle._detect_chain_topology(chain_mode_config)

    def _count_unexploited_services(self) -> int:
        return self.lifecycle._count_unexploited_services()

    def _get_state(self) -> PipelineState:
        return self.lifecycle._get_state()

    def _belief_context(self, *, compact: bool=False) -> str:
        return self.lifecycle._belief_context(compact=compact)

    def _find_vuln_dkg_id(self, v) -> str | None:
        return self.execution._find_vuln_dkg_id(v)

    def _apply_vulnerability_feedback(self, task: Task, *, success: bool, failure_type: str | None=None, delta: float=0.0, flag_found: bool=False) -> None:
        return self.execution._apply_vulnerability_feedback(task, success=success, failure_type=failure_type, delta=delta, flag_found=flag_found)

    @staticmethod
    def _format_parse_summary(parsed: dict) -> str:
        return ExecutionCoordinator._format_parse_summary(parsed)

    def _format_tool_feedback(self, tc_name: str, tc_args: dict, result, defence_probe: str='') -> str:
        return self.execution._format_tool_feedback(tc_name, tc_args, result, defence_probe)

    async def _probe_for_defense(self, url: str, param: str, method: str='GET', tool_name: str='') -> str:
        return await self.execution._probe_for_defense(url, param, method, tool_name)

    async def _execute_task_with_policies(self, task: Task, tool_defs: list[dict], iteration: int=0, max_iter: int=25) -> 'TaskExecution':
        return await self.execution._execute_task_with_policies(task, tool_defs, iteration, max_iter)

    async def _run_with_runtime(self, target_url: str, cteg_hints: dict | None=None) -> TaskResult | None:
        return await self.execution._run_with_runtime(target_url, cteg_hints)

    def _build_plan_exhaustion_context(self) -> str:
        return self.execution._build_plan_exhaustion_context()

    async def _execute_privesc(self, target_url: str) -> str | None:
        return await self.execution._execute_privesc(target_url)

    async def _try_db_default_credentials(self, host: str, discovered_ports: list) -> None:
        return await self.execution._try_db_default_credentials(host, discovered_ports)

    async def _systematic_exploit_pass(self, target_url: str) -> TaskResult | None:
        return await self.execution._systematic_exploit_pass(target_url)

    async def _analyze_phase(self) -> None:
        return await self.research._analyze_phase()

    def _augment_from_dkg(self) -> None:
        return self.research._augment_from_dkg()

    async def _cloud_discovery_hint(self) -> None:
        return await self.research._cloud_discovery_hint()

    async def _service_research(self) -> None:
        return await self.research._service_research()

    async def _research_phase(self) -> None:
        return await self.research._research_phase()

    async def _active_service_research(self) -> None:
        return await self.research._active_service_research()

    async def _probe_endpoints(self) -> str:
        return await self.research._probe_endpoints()

    def _format_vulnerability_summary(self) -> str:
        return self.research._format_vulnerability_summary()

    def _format_vulnerability_summary_short(self, max_items: int=5) -> str:
        return self.research._format_vulnerability_summary_short(max_items)

    def _sanitize_plan_tools(self, tasks: list[Task]) -> None:
        return self.planning._sanitize_plan_tools(tasks)

    async def _generate_with_registry_lookup(self, prompt: str, system_prompt: str | None=None, stage: str | None=None, max_rounds: int=3) -> tuple[str, list | None, bool]:
        return await self.planning._generate_with_registry_lookup(prompt, system_prompt, stage, max_rounds)

    async def _generate_exploitation_plan(self, target_url: str, cteg_hints: dict | None=None) -> ExploitationPlan:
        return await self.planning._generate_exploitation_plan(target_url, cteg_hints)

    def _guess_tool(self, vuln_type: str) -> str:
        return self.planning._guess_tool(vuln_type)

    @staticmethod
    def _task_from_llm_dict(d: dict) -> Task:
        return PlanCoordinator._task_from_llm_dict(d)

    def _topological_sort(self, tasks: list[Task]) -> list[Task]:
        return self.planning._topological_sort(tasks)

    @staticmethod
    def _detect_cycle(tasks: list[Task]) -> list[str]:
        return PlanCoordinator._detect_cycle(tasks)

    @staticmethod
    def _break_cycle(tasks: list[Task], cycle: list[str]) -> None:
        return PlanCoordinator._break_cycle(tasks, cycle)

    def _select_next_plan_task(self, plan: ExploitationPlan | None=None) -> Task | None:
        return self.planning._select_next_plan_task(plan)

    def _extract_recent_artifacts(self) -> str | None:
        return self.planning._extract_recent_artifacts()

    def _build_defense_evasion_context(self) -> str:
        return self.planning._build_defense_evasion_context()

    @staticmethod
    def _summarize_task_result(tc_names: list[str], success: bool, all_stdouts: list[str]) -> str:
        return PlanCoordinator._summarize_task_result(tc_names, success, all_stdouts)

    def _format_plan_status(self) -> str:
        return self.planning._format_plan_status()

    def _build_cycle_summary(self) -> 'CycleTransitionSummary':
        return self.planning._build_cycle_summary()

    async def _analyze_and_fix_task(self, task: Task, output: str) -> dict | None:
        return await self.planning._analyze_and_fix_task(task, output)

    async def _extract_credentials_from_task(self, task: Task, raw_stdouts: list[str]) -> None:
        return await self.planning._extract_credentials_from_task(task, raw_stdouts)

    @staticmethod
    def _is_duplicate_task(new_task: Task, existing_tasks: list[Task]) -> bool:
        return PlanCoordinator._is_duplicate_task(new_task, existing_tasks)

    def _cap_pending_tasks(self, tasks: list[Task], max_total: int=20, max_new_this_cycle: int=8) -> list[Task]:
        return self.planning._cap_pending_tasks(tasks, max_total, max_new_this_cycle)

    async def _review_and_update_plan(self, task: Task, success: bool, task_result: str='') -> None:
        return await self.planning._review_and_update_plan(task, success, task_result)

    def _persist_plan(self, phase: str='exploit') -> None:
        return self.planning._persist_plan(phase)

    def _generate_phase_summary(self, phase: str='exploit') -> str:
        return self.planning._generate_phase_summary(phase)

    async def _check_response_for_flag(self, target_url: str) -> TaskResult | None:
        return await self.lifecycle._check_response_for_flag(target_url)

    def _print_plan_status(self) -> None:
        return self.lifecycle._print_plan_status()

    def _task_log_event(self, level: str, event: str, **data: Any) -> None:
        return self.lifecycle._task_log_event(level, event, **data)

    def metrics_report(self):
        return self.lifecycle.metrics_report()

    def provenance_summary(self, max_items: int=10) -> str:
        return self.lifecycle.provenance_summary(max_items)

    def _task_log_write(self) -> None:
        return self.lifecycle._task_log_write()

    def _checkpoint_path(self, phase: str) -> str:
        return self.lifecycle._checkpoint_path(phase)

    def _check_tool_dependencies(self) -> None:
        return self.lifecycle._check_tool_dependencies()

    def _time_exceeded(self) -> bool:
        return self.lifecycle._time_exceeded()

    def _tokens_exceeded(self) -> bool:
        return self.lifecycle._tokens_exceeded()

    def _maybe_compress(self) -> bool:
        return self.lifecycle._maybe_compress()

    def _build_truncation_context(self) -> str:
        return self.lifecycle._build_truncation_context()

    @staticmethod
    def _extract_json_array(text: str) -> list | None:
        return LifecycleCoordinator._extract_json_array(text)

    @staticmethod
    def _extract_json(text: str) -> Any:
        return LifecycleCoordinator._extract_json(text)
