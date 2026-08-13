"""Replanner — local-first replanning (P7).

Replanning becomes rule-based and local-first: the Evaluation from P6
decides the repair action, and the LLM plan review remains only the
GLOBAL fallback. A session-level failed-signature registry prevents
re-proposing the same tool+params that already failed (this is also the
data source for the v2 "replan novelty" metric).
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

from darwin.core.contracts import ReplanRecommendation, TaskOutcome, TaskStatus
from darwin.core.evaluator import Evaluation, FailureType
from darwin.core.task import Task


@dataclass
class LocalRepair:
    """Rule-based repair decision for one failed Task."""

    action: str  # none | retry | replace | invalidate | abandon | defer | global_stop
    replacement: Task | None = None
    reason: str = ""
    rejected_duplicate: bool = False


# Conservative rule-based alternatives. The LLM planner remains the
# creative fallback for anything not covered here.
_TOOL_ALTERNATIVES: dict[str, str] = {
    "sqlmap_test": "http_post",
    "xss_reflection_test": "send_payload",
    "command_injection_test": "send_payload",
    "curl_get": "http_post",
    "http_post": "send_payload",
    "send_payload": "curl_get",
    "ssh_exec": "ssh_key_exec",
    "hydra_http_brute": "test_credential",
    "redis_cmd": "curl_get",
}


class Replanner:
    """Session-level local replanner with duplicate-failure protection."""

    def __init__(self) -> None:
        self._failed_signatures: set[str] = set()
        self._proposed = 0
        self._rejected = 0
        self._alt_counter = 0

    # ── Failed-signature registry ───────────────────────────────────

    @staticmethod
    def _signature(tool: str, params: dict) -> str:
        raw = json.dumps(params, sort_keys=True, default=str)
        return hashlib.sha1(f"{tool}|{raw}".encode("utf-8")).hexdigest()[:16]

    def task_signature(self, task: Task) -> str:
        action = task.action or {}
        return self._signature(
            str(action.get("tool", "") or ""),
            dict(action.get("params", {}) or {}),
        )

    def record_failure(self, task: Task) -> str:
        sig = self.task_signature(task)
        self._failed_signatures.add(sig)
        return sig

    def is_duplicate(self, task: Task) -> bool:
        return self.task_signature(task) in self._failed_signatures

    @property
    def proposed_count(self) -> int:
        return self._proposed

    @property
    def rejected_count(self) -> int:
        return self._rejected

    @property
    def novelty_ratio(self) -> float | None:
        """1 - duplicates/proposals; None when nothing was proposed yet."""
        if self._proposed == 0:
            return None
        return 1.0 - (self._rejected / self._proposed)

    # ── Replacement generation ──────────────────────────────────────

    def _make_replacement(
        self,
        task: Task,
        *,
        force_alternative: bool = False,
        encode_bypass: bool = False,
        tweak_param: bool = False,
    ) -> Task | None:
        action = dict(task.action or {})
        tool = str(action.get("tool", "") or "")
        if not tool:
            return None
        params = dict(action.get("params", {}) or {})

        new_tool = tool
        if force_alternative:
            new_tool = _TOOL_ALTERNATIVES.get(tool, "")
            if not new_tool:
                return None
        if encode_bypass:
            params["encode_type"] = params.get("encode_type") or "url_double"
        if tweak_param:
            params["tweak_hint"] = "try alternate evidence source"

        self._alt_counter += 1
        replacement = Task(
            id=f"{task.id}-alt{self._alt_counter}",
            type=task.type,
            goal=task.goal,
            instruction=task.instruction or task.goal,
            hypothesis=f"alternative to {task.id}: {task.hypothesis or 'unknown'}",
            rationale=task.rationale,
            evidence=list(task.evidence),
            confidence=max(0.3, task.confidence - 0.1),
            action={
                "tool": new_tool,
                "target": action.get("target", ""),
                "params": params,
            },
            required_context=dict(task.required_context),
            success_condition=(
                dict(task.success_condition) if task.success_condition else None
            ),
            failure_policy=dict(task.failure_policy),
            dependencies=list(task.dependencies),
            priority=max(0.3, task.priority - 0.1),
            status=TaskStatus.CREATED,
            attempt_count=0,
        )
        self._proposed += 1
        if self.is_duplicate(replacement):
            self._rejected += 1
            return None
        return replacement

    # ── Repair decision ─────────────────────────────────────────────

    def local_repair(self, task: Task, evaluation: Evaluation) -> LocalRepair:
        """Decide the local repair action from the P6 Evaluation."""
        ft = evaluation.failure_type
        self.record_failure(task)

        if ft is None or evaluation.outcome is TaskOutcome.SUCCESS:
            return LocalRepair("none", reason="no failure to repair")
        if ft == FailureType.BUDGET_EXCEEDED:
            return LocalRepair("global_stop", reason="budget exceeded — stop")
        if ft in (FailureType.TARGET_UNREACHABLE, FailureType.ENVIRONMENT_ERROR):
            return LocalRepair("invalidate", reason=f"{ft.value}: invalidate branch")
        if ft in (FailureType.INVALID_ARGUMENT, FailureType.TOOL_ERROR):
            return LocalRepair("retry", reason=f"{ft.value}: parameter fix/retry path")
        if ft == FailureType.DEFENSE_BLOCKED:
            replacement = self._make_replacement(task, encode_bypass=True)
            if replacement is None:
                return LocalRepair(
                    "defer",
                    reason="defense blocked and duplicate variant — defer to planner",
                    rejected_duplicate=True,
                )
            return LocalRepair(
                "replace",
                replacement=replacement,
                reason="defense blocked: try encoded variant",
            )
        if ft == FailureType.HYPOTHESIS_REJECTED:
            replacement = self._make_replacement(task, force_alternative=True)
            if replacement is None:
                return LocalRepair(
                    "abandon",
                    reason="hypothesis rejected and no alternative",
                    rejected_duplicate=True,
                )
            return LocalRepair(
                "replace",
                replacement=replacement,
                reason="hypothesis rejected: try alternative tool",
            )
        if ft == FailureType.AUTH_FAILURE:
            return LocalRepair(
                "abandon", reason="auth failure — planner should supply other credentials"
            )
        if ft == FailureType.INCONCLUSIVE:
            replacement = self._make_replacement(task, tweak_param=True)
            if replacement is None:
                return LocalRepair(
                    "defer", reason="inconclusive — keep task, change evidence source"
                )
            return LocalRepair(
                "replace",
                replacement=replacement,
                reason="inconclusive: alternative evidence source",
            )
        if ft == FailureType.STRATEGY_FAILED:
            replacement = self._make_replacement(task, force_alternative=True)
            if replacement is None:
                return LocalRepair("defer", reason="strategy failed — defer to planner")
            return LocalRepair(
                "replace",
                replacement=replacement,
                reason="strategy failed: alternative approach",
            )
        return LocalRepair("defer", reason="no rule for this failure type")
