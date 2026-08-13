"""Task data model (P3).

The Task is the single unit Planner produces, Scheduler orders, Executor
executes, and Evaluator judges. It replaces the legacy plan-task dicts
(``{id, instruction, tool, params, dependent_task_ids, status, ...}``)
with a typed object that also carries decision provenance (hypothesis,
rationale, evidence) and success/failure semantics.

Compatibility: ``from_legacy_dict`` / ``to_legacy_dict`` bridge the
current orchestrator plan dicts. The orchestrator still produces and
consumes dicts until P5 migrates the Executor; these converters keep that
transition behavior-neutral.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any

from darwin.core.contracts import TaskStatus


DEFAULT_FAILURE_POLICY: dict = {"retry": 1, "replan_on_failure": True}


def _coerce_status(value: Any) -> TaskStatus:
    """Map a legacy/unknown status string onto the TaskStatus enum."""
    try:
        return TaskStatus(str(value))
    except ValueError:
        return TaskStatus.PENDING


@dataclass
class Task:
    """Typed plan task with decision provenance and execution semantics."""

    id: str
    type: str
    goal: str

    # Natural-language description kept for LLM-facing contexts (legacy).
    instruction: str = ""

    # ── Decision provenance ─────────────────────────────────────────
    hypothesis: str = ""
    rationale: str = ""
    evidence: list[str] = field(default_factory=list)
    confidence: float = 0.5

    # ── Execution specification ─────────────────────────────────────
    # action = {"tool": ..., "target": ..., "params": {...}}
    # capability names land in P8; until then "tool" mirrors the gateway name.
    action: dict = field(default_factory=dict)
    required_context: dict = field(default_factory=dict)
    success_condition: dict | None = None
    failure_policy: dict = field(
        default_factory=lambda: dict(DEFAULT_FAILURE_POLICY)
    )

    # ── Graph / lifecycle ───────────────────────────────────────────
    dependencies: list[str] = field(default_factory=list)
    priority: float = 0.5
    status: TaskStatus = TaskStatus.PENDING
    created_at: str = field(
        default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%S")
    )
    attempt_count: int = 0
    result_summary: str = ""

    @classmethod
    def from_legacy_dict(cls, d: dict) -> "Task":
        """Build a Task from the orchestrator's current plan-task dict."""
        params = d.get("params", {})
        if isinstance(params, str):
            try:
                params = json.loads(params)
            except (json.JSONDecodeError, TypeError):
                params = {"url": params}
        if not isinstance(params, dict):
            params = {"value": params}

        target = (
            d.get("endpoint")
            or d.get("target")
            or (params.get("url") if isinstance(params, dict) else "")
            or ""
        )
        instruction = d.get("instruction", "") or ""

        return cls(
            id=str(d.get("id", "")),
            type=d.get("type", "task"),
            goal=d.get("goal") or instruction or "",
            instruction=instruction,
            hypothesis=d.get("hypothesis", "") or "",
            rationale=d.get("rationale", "") or "",
            evidence=list(d.get("evidence") or []),
            confidence=float(d.get("confidence", 0.5)),
            action={
                "tool": d.get("tool", "") or "",
                "target": target,
                "params": params,
            },
            required_context=dict(d.get("required_context") or {}),
            success_condition=d.get("success_condition"),
            failure_policy=dict(
                d.get("failure_policy") or DEFAULT_FAILURE_POLICY
            ),
            dependencies=list(
                d.get("dependent_task_ids") or d.get("dependencies") or []
            ),
            priority=float(d.get("priority", 0.5)),
            status=_coerce_status(d.get("status", "pending")),
            created_at=d.get("created_at")
            or time.strftime("%Y-%m-%dT%H:%M:%S"),
            attempt_count=int(d.get("attempts", 0)),
            result_summary=d.get("result_summary", "") or "",
        )

    def to_legacy_dict(self) -> dict:
        """Serialize back to the orchestrator's current plan-task dict."""
        action = self.action or {}
        params = action.get("params") or {}
        return {
            "id": self.id,
            "type": self.type,
            "goal": self.goal,
            "instruction": self.instruction or self.goal,
            "hypothesis": self.hypothesis,
            "rationale": self.rationale,
            "evidence": list(self.evidence),
            "confidence": self.confidence,
            "tool": action.get("tool", "") or "",
            "endpoint": action.get("target", "") or "",
            "params": params,
            "required_context": dict(self.required_context),
            "success_condition": self.success_condition,
            "failure_policy": dict(self.failure_policy),
            "dependent_task_ids": list(self.dependencies),
            "dependencies": list(self.dependencies),
            "priority": self.priority,
            "status": self.status.value,
            "attempts": self.attempt_count,
            "result_summary": self.result_summary,
        }

    def summary(self, max_len: int = 80) -> str:
        """Compact one-line description for logs and traces."""
        return f"{self.id}: [{self.status.value}] {(self.instruction or self.goal)[:max_len]}"
