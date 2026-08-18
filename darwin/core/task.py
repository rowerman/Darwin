"""Task data model (P3).

The Task is the single unit Planner produces, Scheduler orders, Executor
executes, and Evaluator judges. It replaces the legacy plan-task dicts
(``{id, instruction, tool, params, dependent_task_ids, status, ...}``)
with a typed object that also carries decision provenance (hypothesis,
rationale, evidence) and success/failure semantics.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Iterable

from darwin.core.contracts import TaskStatus


DEFAULT_FAILURE_POLICY: dict = {"retry": 1, "replan_on_failure": True}


def _deps_to_structured(deps: Iterable[Any]) -> list[dict]:
    """Convert legacy string/Task-ID deps into structured dependency entries."""
    out: list[dict] = []
    for d in deps:
        if isinstance(d, dict):
            out.append(dict(d))
        else:
            out.append({"type": "requires_task_success", "task_id": str(d)})
    return out


def deps_from_task_ids(task_ids: Iterable[Any]) -> list[dict]:
    """Build structured dependencies from plain Task-ID strings/entries."""
    return _deps_to_structured(task_ids)


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
    # Structured dependencies (P4): each entry is a dict with a "type"
    # from DependencyType, e.g. {"type": "requires_evidence", "evidence": ...}
    # or {"type": "requires_task_success", "task_id": "recon_001"}.
    dependencies: list[dict] = field(default_factory=list)
    priority: float = 0.5
    status: TaskStatus = TaskStatus.CREATED
    created_at: str = field(
        default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%S")
    )
    attempt_count: int = 0
    result_summary: str = ""

    # ── Runtime bookkeeping (v2) ────────────────────────────────────
    # Carried through plan generation/review for scheduler priority and
    # tool guessing; not part of the LLM task contract.
    source: str = ""
    vuln_type: str = ""

    def to_dict(self) -> dict:
        """Canonical JSON-safe serialization for plan checkpoints.

        Status is stored as the canonical TaskStatus value and
        dependencies keep their structured form.
        """
        return {
            "id": self.id,
            "type": self.type,
            "goal": self.goal,
            "instruction": self.instruction,
            "hypothesis": self.hypothesis,
            "rationale": self.rationale,
            "evidence": list(self.evidence),
            "confidence": self.confidence,
            "action": dict(self.action),
            "required_context": dict(self.required_context),
            "success_condition": self.success_condition,
            "failure_policy": dict(self.failure_policy),
            "dependencies": list(self.dependencies),
            "priority": self.priority,
            "status": self.status.value,
            "created_at": self.created_at,
            "attempt_count": self.attempt_count,
            "result_summary": self.result_summary,
            "source": self.source,
            "vuln_type": self.vuln_type,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Task":
        """Rebuild a Task from ``to_dict()`` (canonical status/deps)."""
        return cls(
            id=str(d.get("id", "")),
            type=d.get("type", "task"),
            goal=d.get("goal", "") or "",
            instruction=d.get("instruction", "") or "",
            hypothesis=d.get("hypothesis", "") or "",
            rationale=d.get("rationale", "") or "",
            evidence=list(d.get("evidence") or []),
            confidence=float(d.get("confidence", 0.5)),
            action=dict(d.get("action") or {}),
            required_context=dict(d.get("required_context") or {}),
            success_condition=d.get("success_condition"),
            failure_policy=dict(d.get("failure_policy") or DEFAULT_FAILURE_POLICY),
            dependencies=list(d.get("dependencies") or []),
            priority=float(d.get("priority", 0.5)),
            status=TaskStatus(d.get("status", TaskStatus.CREATED.value)),
            created_at=d.get("created_at") or time.strftime("%Y-%m-%dT%H:%M:%S"),
            attempt_count=int(d.get("attempt_count", 0)),
            result_summary=d.get("result_summary", "") or "",
            source=str(d.get("source", "") or ""),
            vuln_type=str(d.get("vuln_type", "") or ""),
        )

    def summary(self, max_len: int = 80) -> str:
        """Compact one-line description for logs and traces."""
        return f"{self.id}: [{self.status.value}] {(self.instruction or self.goal)[:max_len]}"
