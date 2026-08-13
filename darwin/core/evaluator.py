"""Evaluator / FailureAnalyzer (P6).

P6a: rule-based failure classification (zero token cost) plus an Evaluator
that assembles the v2 Evaluation contract (outcome, failure_type, evidence,
confidence_delta, replan recommendation).

P6b: the orchestrator's failure path classifies with the rule-based analyzer
first; only ambiguous cases fall through to the existing LLM fix call.

The keyword tables revive the archived ``classify_and_replan`` logic
(EXPLORATORY_TOOLS / DEAD_END_KEYWORDS) in structured form.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from darwin.core.contracts import (
    ReplanRecommendation,
    Task,
    TaskOutcome,
    TaskStatus,
)


class FailureType(str, Enum):
    """Structured failure taxonomy (v2 plan section 13)."""

    TOOL_ERROR = "tool_error"
    INVALID_ARGUMENT = "invalid_argument"
    PRECONDITION_MISSING = "precondition_missing"
    ENVIRONMENT_ERROR = "environment_error"
    AUTH_FAILURE = "auth_failure"
    TARGET_UNREACHABLE = "target_unreachable"
    HYPOTHESIS_REJECTED = "hypothesis_rejected"
    STRATEGY_FAILED = "strategy_failed"
    DEFENSE_BLOCKED = "defense_blocked"
    INCONCLUSIVE = "inconclusive"
    BUDGET_EXCEEDED = "budget_exceeded"


@dataclass
class Classification:
    """Rule-based classification output."""

    failure_type: FailureType | None
    reason: str = ""
    confidence: float = 1.0


@dataclass
class Evaluation:
    """Concrete Evaluator output (P6)."""

    task_id: str
    outcome: TaskOutcome
    failure_type: FailureType | None = None
    evidence: list[str] = field(default_factory=list)
    confidence_delta: float = 0.0
    replan: ReplanRecommendation = ReplanRecommendation.NONE


# Tools whose empty/failed result means "nothing found", not "attack failed".
# Revived from the archived classify_and_replan EXPLORATORY_TOOLS.
EXPLORATORY_TOOLS = frozenset(
    {
        "dirb_scan",
        "gobuster_dir",
        "curl_get",
        "whatweb_scan",
        "nikto_scan",
        "form_extract",
        "nmap_scan",
        "knowledge_search",
        "ddg_web_search",
        "searchsploit_search",
        "metasploit_search",
        "go_exploitdb_search",
        "cve_lookup",
        "nvd_search_cves",
        "check_capabilities",
        "check_mounts",
        "check_cloud_metadata",
        "container_find_sockets",
        "container_find_docker",
        "container_recon_env",
        "linux_priv_check",
        "kubectl_auth_check",
        "kubectl_get_pods",
        "kubectl_get_secrets",
    }
)


class FailureAnalyzer:
    """Deterministic, rule-based failure classification."""

    _BUDGET_MARKERS = (
        "budget exceeded",
        "time budget",
        "token budget",
    )
    _INVALID_ARGUMENT_MARKERS = (
        "unexpected keyword argument",
        "missing required",
        "invalid argument",
        "typeerror",
        "keyerror",
        "template format error",
        "unknown parameter",
        "got an unexpected",
        "required field",
        "unknown tool",
    )
    _ENVIRONMENT_MARKERS = (
        "command not found",
        "executable not found",
        "no such file",
        "modulenotfounderror",
        "no module named",
        "not found on path",
        "binary not found",
    )
    _UNREACHABLE_MARKERS = (
        "connection refused",
        "could not connect",
        "can't connect",
        "cannot connect",
        "no route to host",
        "network is unreachable",
        "connection timed out",
        "name or service not known",
        "dns resolution",
        "failed to establish a new connection",
    )
    _AUTH_MARKERS = (
        "authentication failed",
        "login failed",
        "credential rejected",
        "invalid credentials",
        "unauthorized",
        "access denied",
        "not authorized",
        "401 unauthorized",
        "403 forbidden",
        "permission denied",
    )
    _DEFENSE_MARKERS = (
        "blocked",
        "waf",
        "modsecurity",
        "cloudflare",
        "captcha",
        "challenge",
        "rate limit",
        "forbidden by",
    )
    _HYPOTHESIS_REJECTED_MARKERS = (
        "not vulnerable",
        "no vulnerability",
        "not injectable",
        "not exploitable",
        "does not appear",
        "no evidence",
        "negative result",
    )
    _TOOL_ERROR_MARKERS = (
        "traceback",
        "exception",
        "tool error",
        "internal error",
        "timed out",
        "timeout",
        "no output",
        "segmentation fault",
    )
    _PRECONDITION_MARKERS = (
        "no tool available",
        "not supported",
        "no handler",
        "not implemented",
        "prerequisite",
        "precondition",
        "requires ",
    )

    def classify(
        self,
        result: Any,
        tool: str = "",
        output: str | None = None,
    ) -> Classification:
        """Classify an execution result into a structured failure type."""
        tool = tool or str(getattr(result, "tool", "") or "")
        stdout = str(output or getattr(result, "stdout", "") or "")
        stderr = str(getattr(result, "stderr", "") or "")
        _exit = getattr(result, "exit_code", -1)
        exit_code = -1 if _exit is None else int(_exit)
        success = bool(getattr(result, "success", False))
        text = f"{stdout}\n{stderr}".lower()

        if not success:
            if any(m in text for m in self._BUDGET_MARKERS):
                return Classification(FailureType.BUDGET_EXCEEDED, "budget marker in output")
            if any(m in text for m in self._INVALID_ARGUMENT_MARKERS):
                return Classification(FailureType.INVALID_ARGUMENT, "argument/schema marker in output")
            if any(m in text for m in self._ENVIRONMENT_MARKERS):
                return Classification(FailureType.ENVIRONMENT_ERROR, "environment marker in output")
            if any(m in text for m in self._UNREACHABLE_MARKERS) or (
                exit_code == 7 and tool == "curl_get"
            ):
                return Classification(FailureType.TARGET_UNREACHABLE, "connection marker in output")
            if any(m in text for m in self._DEFENSE_MARKERS):
                return Classification(FailureType.DEFENSE_BLOCKED, "defense marker in output")
            if any(m in text for m in self._AUTH_MARKERS):
                return Classification(FailureType.AUTH_FAILURE, "auth marker in output")
            if any(m in text for m in self._HYPOTHESIS_REJECTED_MARKERS):
                return Classification(FailureType.HYPOTHESIS_REJECTED, "hypothesis-rejection marker in output")
            if any(m in text for m in self._TOOL_ERROR_MARKERS):
                return Classification(FailureType.TOOL_ERROR, "tool-error marker in output")
            if any(m in text for m in self._PRECONDITION_MARKERS):
                return Classification(FailureType.PRECONDITION_MISSING, "precondition marker in output")
            if exit_code != 0:
                return Classification(FailureType.TOOL_ERROR, f"non-zero exit code {exit_code}")
            return Classification(FailureType.INCONCLUSIVE, "failed without a recognized signal")

        # Tool succeeded but produced no actionable evidence.
        if any(m in text for m in self._HYPOTHESIS_REJECTED_MARKERS):
            return Classification(FailureType.HYPOTHESIS_REJECTED, "tool ran but output rejects the hypothesis")
        if tool in EXPLORATORY_TOOLS:
            return Classification(FailureType.INCONCLUSIVE, "exploratory tool found nothing")
        return Classification(FailureType.INCONCLUSIVE, "success without clear evidence")


class Evaluator:
    """Assembles the v2 Evaluation contract from task + result (+ future state)."""

    def __init__(self, analyzer: FailureAnalyzer | None = None) -> None:
        self.analyzer = analyzer or FailureAnalyzer()

    async def evaluate(
        self,
        task: Task,
        result: Any,
        state: Any = None,
    ) -> Evaluation:
        """Evaluate one execution result (world state unused until P10)."""
        success = bool(getattr(result, "success", False))
        task_id = getattr(task, "id", "") or getattr(result, "task_id", "")

        if success:
            return Evaluation(
                task_id=task_id,
                outcome=TaskOutcome.SUCCESS,
                replan=ReplanRecommendation.NONE,
            )

        cls = self.analyzer.classify(result, tool=getattr(result, "tool", ""))
        ft = cls.failure_type or FailureType.INCONCLUSIVE
        evidence = [f"{ft.value}: {cls.reason}"] if cls.reason else [ft.value]

        outcome_delta_replan = {
            FailureType.HYPOTHESIS_REJECTED: (TaskOutcome.FAILED, -0.5, ReplanRecommendation.LOCAL),
            FailureType.AUTH_FAILURE: (TaskOutcome.FAILED, -0.2, ReplanRecommendation.LOCAL),
            FailureType.DEFENSE_BLOCKED: (TaskOutcome.FAILED, 0.1, ReplanRecommendation.LOCAL),
            FailureType.TARGET_UNREACHABLE: (TaskOutcome.FAILED, 0.0, ReplanRecommendation.NONE),
            FailureType.TOOL_ERROR: (TaskOutcome.FAILED, 0.0, ReplanRecommendation.NONE),
            FailureType.INVALID_ARGUMENT: (TaskOutcome.FAILED, 0.0, ReplanRecommendation.NONE),
            FailureType.PRECONDITION_MISSING: (TaskOutcome.BLOCKED, 0.0, ReplanRecommendation.NONE),
            FailureType.ENVIRONMENT_ERROR: (TaskOutcome.FAILED, 0.0, ReplanRecommendation.NONE),
            FailureType.BUDGET_EXCEEDED: (TaskOutcome.FAILED, 0.0, ReplanRecommendation.GLOBAL),
            FailureType.STRATEGY_FAILED: (TaskOutcome.FAILED, -0.2, ReplanRecommendation.LOCAL),
            FailureType.INCONCLUSIVE: (TaskOutcome.INCONCLUSIVE, 0.0, ReplanRecommendation.LOCAL),
        }
        outcome, delta, replan = outcome_delta_replan[ft]
        return Evaluation(
            task_id=task_id,
            outcome=outcome,
            failure_type=ft,
            evidence=evidence,
            confidence_delta=delta,
            replan=replan,
        )
