"""Memory layer v2 (P10).

P10 delivers the first two concrete layers plus the compression-grading
rules, without touching the orchestrator:

    - ExecutionRecord — the unified record of one tool execution
      (merges the P5 ExecutionResult shape with the tool_result trace
      fields; the data source for P13 CTEG and P19 metrics).
    - PlanMemory — why each Task exists (goal / hypothesis / rationale /
      evidence), so replan never loses decision provenance.
    - ExecutionMemory — what actually happened, each record graded
      preserve / compress / discard by zero-token rules.
    - ImportanceClassifier — the compression-v2 grading: PRESERVE keeps
      decision-critical facts, DISCARD drops empty/repetitive noise, and
      only COMPRESS material is a candidate for LLM summarization later.

Working (DKG) and Experience (CTEG) layers already exist as concrete
stores; P10 maps them through MemoryManager as duck-typed adapters and
does not rewrite them.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from darwin.core.task import Task


# ── Unified execution record ────────────────────────────────────────


@dataclass
class ExecutionRecord:
    """Unified, normalized record of one tool execution (P10/P14 shape)."""

    task_id: str
    tool: str
    planned_tool: str
    adherence: bool
    success: bool
    stdout: str = ""
    stderr: str = ""
    exit_code: int = 0
    elapsed_ms: float = 0.0
    capability: str = ""
    tool_attempts: list[str] = field(default_factory=list)
    normalized: dict = field(default_factory=dict)
    parsed_output: dict = field(default_factory=dict)
    failure_type: str | None = None
    timestamp: str = field(
        default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%S")
    )

    @classmethod
    def from_result(cls, result: Any, failure_type: str | None = None) -> "ExecutionRecord":
        """Build a record from an ExecutionResult-like object."""
        return cls(
            task_id=str(getattr(result, "task_id", "") or ""),
            tool=str(getattr(result, "tool", "") or ""),
            planned_tool=str(getattr(result, "planned_tool", "") or ""),
            adherence=bool(getattr(result, "adherence", True)),
            success=bool(getattr(result, "success", False)),
            stdout=str(getattr(result, "stdout", "") or ""),
            stderr=str(getattr(result, "stderr", "") or ""),
            exit_code=0
            if getattr(result, "exit_code", 0) is None
            else int(getattr(result, "exit_code", 0)),
            elapsed_ms=float(getattr(result, "elapsed_ms", 0.0) or 0.0),
            capability=str(getattr(result, "capability", "") or ""),
            tool_attempts=list(getattr(result, "tool_attempts", []) or []),
            normalized=dict(getattr(result, "normalized", {}) or {}),
            parsed_output=dict(getattr(result, "parsed_output", {}) or {}),
            failure_type=failure_type,
        )

    @classmethod
    def from_trace(cls, trace: dict) -> "ExecutionRecord":
        """Build a record from a tool_result trace event dict (M0 shape)."""
        return cls(
            task_id=str(trace.get("task_id", "") or ""),
            tool=str(trace.get("tool", "") or ""),
            planned_tool=str(trace.get("planned_tool", "") or ""),
            adherence=bool(trace.get("adherence", True)),
            success=bool(trace.get("success", False)),
            stdout=str(trace.get("stdout", "") or ""),
            stderr=str(trace.get("stderr", "") or ""),
            exit_code=int(trace.get("exit_code", 0) or 0),
            elapsed_ms=float(trace.get("elapsed_ms", 0.0) or 0.0),
            capability=str(trace.get("capability", "") or ""),
            tool_attempts=list(trace.get("tool_attempts", []) or []),
            failure_type=trace.get("failure_type"),
        )


# ── Compression grading (zero-token, rule-based) ───────────────────


class ImportanceClass(str, Enum):
    """Compression-v2 importance classes (architecture plan section 9)."""

    PRESERVE = "preserve"  # never compress: decision-critical facts
    COMPRESS = "compress"  # may be summarized by the LLM later
    DISCARD = "discard"    # low-value noise: drop or aggressively compress


class ImportanceClassifier:
    """Deterministic preserve/compress/discard rules.

    PRESERVE wins over everything else (better to keep too much than to
    lose decision provenance). DISCARD targets empty output and repeated
    timeouts; everything else lands in COMPRESS, the only class that is a
    candidate for LLM summarization.
    """

    _HIGH_COST_MS = 60000.0

    _PRESERVE_MARKERS = (
        "flag{",
        "sql injection",
        "injectable",
        "vulnerable",
        "cve-",
        "exploit",
        "password",
        "credential",
        "session",
        "shell",
        "login successful",
        "waf",
        "blocked",
        "cloudflare",
        "modsecurity",
        "captcha",
        "rate limit",
        "privilege",
        "sudo",
        "root@",
        "ssh key",
        "private key",
    )

    def classify(self, record: ExecutionRecord) -> tuple[ImportanceClass, str]:
        """Grade one execution record -> (importance, reason)."""
        stdout = str(record.stdout or "")
        stderr = str(record.stderr or "")
        text = f"{stdout} {stderr}".lower()

        for marker in self._PRESERVE_MARKERS:
            if marker in text:
                return ImportanceClass.PRESERVE, f"preserve marker: {marker}"
        if not record.success and record.elapsed_ms >= self._HIGH_COST_MS:
            return (
                ImportanceClass.PRESERVE,
                f"high-cost failure ({record.elapsed_ms:.0f}ms)",
            )
        if not stdout.strip() and not stderr.strip():
            return ImportanceClass.DISCARD, "empty output"
        if (
            not record.success
            and ("timeout" in text or "timed out" in text)
            and not stdout.strip()
        ):
            return ImportanceClass.DISCARD, "timeout with no output"
        return ImportanceClass.COMPRESS, "routine output"


# ── Plan Memory ─────────────────────────────────────────────────────


@dataclass
class PlanEntry:
    """Why a Task exists — preserved verbatim, never LLM-summarized."""

    task_id: str
    goal: str
    rationale: str = ""
    hypothesis: str = ""
    evidence: list[str] = field(default_factory=list)
    confidence: float = 0.5
    status: str = "created"
    dependencies: list[str] = field(default_factory=list)
    priority: float = 0.5
    created_at: str = field(
        default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%S")
    )

    @classmethod
    def from_task(cls, task: Task) -> "PlanEntry":
        deps: list[str] = []
        for dep in task.dependencies or []:
            if isinstance(dep, dict):
                value = dep.get("task_id") or dep.get("evidence") or ""
                if value:
                    deps.append(str(value))
            elif dep:
                deps.append(str(dep))
        return cls(
            task_id=task.id,
            goal=task.goal or task.instruction,
            rationale=task.rationale,
            hypothesis=task.hypothesis,
            evidence=list(task.evidence or []),
            confidence=task.confidence,
            status=task.status.value,
            dependencies=deps,
            priority=task.priority,
            created_at=task.created_at,
        )

    def to_context_block(self) -> str:
        """Render the entry for replan / planner context."""
        lines = [
            f"[TASK {self.task_id}] status={self.status}",
            f"  goal: {self.goal}",
        ]
        if self.hypothesis:
            lines.append(f"  hypothesis: {self.hypothesis}")
        if self.rationale:
            lines.append(f"  rationale: {self.rationale}")
        if self.evidence:
            for item in self.evidence[:10]:
                lines.append(f"  evidence: {item}")
        if self.dependencies:
            lines.append(f"  depends_on: {', '.join(self.dependencies)}")
        return "\n".join(lines)


class PlanMemory:
    """Task-rationale store (architecture plan section 8.2)."""

    def __init__(self) -> None:
        self._entries: dict[str, PlanEntry] = {}

    def record_task(self, task: Task | dict) -> PlanEntry:
        if isinstance(task, dict):
            task = Task.from_legacy_dict(task)
        entry = PlanEntry.from_task(task)
        self._entries[entry.task_id] = entry
        return entry

    def get(self, task_id: str) -> PlanEntry | None:
        return self._entries.get(task_id)

    def entries(self) -> list[PlanEntry]:
        return list(self._entries.values())

    def active_entries(self) -> list[PlanEntry]:
        """Entries still driving the current plan (not resolved)."""
        resolved = {"success", "failed", "abandoned", "invalidated"}
        return [e for e in self._entries.values() if e.status not in resolved]

    def replan_context(self, task_id: str | None = None) -> str:
        """Render preserved rationale for the replanner."""
        if task_id and task_id in self._entries:
            return self._entries[task_id].to_context_block()
        blocks = [e.to_context_block() for e in self.active_entries()]
        return "\n".join(blocks)


# ── Execution Memory ────────────────────────────────────────────────


@dataclass
class MemoryItem:
    """One stored execution record plus its importance grade."""

    record: ExecutionRecord
    importance: ImportanceClass
    reason: str = ""


class ExecutionMemory:
    """What actually happened (architecture plan section 8.3)."""

    def __init__(self, max_records: int = 500) -> None:
        self.max_records = max_records
        self._items: list[MemoryItem] = []
        self._by_task: dict[str, list[MemoryItem]] = {}

    def add(self, record: ExecutionRecord | MemoryItem) -> MemoryItem:
        item = record if isinstance(record, MemoryItem) else MemoryItem(record)
        self._items.append(item)
        self._by_task.setdefault(item.record.task_id, []).append(item)
        if len(self._items) > self.max_records:
            overflow = self._items[: len(self._items) - self.max_records]
            self._items = self._items[-self.max_records :]
            for old in overflow:
                bucket = self._by_task.get(old.record.task_id)
                if bucket and old in bucket:
                    bucket.remove(old)
        return item

    def recent(self, n: int = 20) -> list[MemoryItem]:
        return list(self._items[-n:])

    def for_task(self, task_id: str) -> list[MemoryItem]:
        return list(self._by_task.get(task_id, []))

    def preserved(self) -> list[MemoryItem]:
        return [i for i in self._items if i.importance is ImportanceClass.PRESERVE]


# ── Manager ─────────────────────────────────────────────────────────


@dataclass
class CompressionView:
    """Compression-v2 consumption view (P11).

    ``preserved`` stays verbatim; ``compressible`` may be LLM-summarized;
    ``discarded_count`` is noise that can be dropped without review.
    """

    preserved: list[ExecutionRecord] = field(default_factory=list)
    compressible: list[ExecutionRecord] = field(default_factory=list)
    discarded_count: int = 0


class MemoryManager:
    """Coordinates the four layers (P10: Plan + Execution concrete;
    Working/Experience passed in as existing stores, duck-typed)."""

    def __init__(
        self,
        plan_memory: PlanMemory | None = None,
        execution_memory: ExecutionMemory | None = None,
        working: Any = None,
        experience: Any = None,
    ) -> None:
        self.plan = plan_memory or PlanMemory()
        self.execution = execution_memory or ExecutionMemory()
        self.working = working  # DKG adapter (interface mapping in P10)
        self.experience = experience  # CTEG adapter (interface mapping in P10)
        self.classifier = ImportanceClassifier()

    def record_task(self, task: Task | dict) -> PlanEntry:
        return self.plan.record_task(task)

    def record_execution(
        self, result: Any, failure_type: str | None = None
    ) -> MemoryItem:
        record = ExecutionRecord.from_result(result, failure_type=failure_type)
        importance, reason = self.classifier.classify(record)
        return self.execution.add(MemoryItem(record, importance, reason))

    def record_trace(self, trace: dict) -> MemoryItem:
        record = ExecutionRecord.from_trace(trace)
        importance, reason = self.classifier.classify(record)
        return self.execution.add(MemoryItem(record, importance, reason))

    def replan_context(self, task_id: str | None = None) -> str:
        """Combine preserved plan rationale and execution history."""
        parts = []
        plan_block = self.plan.replan_context(task_id)
        if plan_block:
            parts.append(plan_block)
        items = (
            self.execution.for_task(task_id)
            if task_id
            else self.execution.recent()
        )
        if items:
            exec_lines = ["[EXECUTION HISTORY]"]
            for item in items[-10:]:
                rec = item.record
                exec_lines.append(
                    f"- {rec.tool} {'OK' if rec.success else 'FAIL'} "
                    f"(exit={rec.exit_code}, {rec.elapsed_ms:.0f}ms) "
                    f"[{item.importance.value}]"
                )
            parts.append("\n".join(exec_lines))
        return "\n".join(parts)

    def compression_view(
        self, max_preserved: int = 30, max_compressible: int = 30
    ) -> CompressionView:
        """Split the recent execution window into preserve/compress/discard.

        P11 consumption API only — it does not modify ``_maybe_compress``;
        the orchestrator's LLM summary flow is intentionally untouched.
        """
        items = self.execution.recent(500)
        preserved = [
            item.record
            for item in items
            if item.importance is ImportanceClass.PRESERVE
        ][-max_preserved:]
        compressible = [
            item.record
            for item in items
            if item.importance is ImportanceClass.COMPRESS
        ][-max_compressible:]
        discarded_count = sum(
            1 for item in items if item.importance is ImportanceClass.DISCARD
        )
        return CompressionView(
            preserved=preserved,
            compressible=compressible,
            discarded_count=discarded_count,
        )
