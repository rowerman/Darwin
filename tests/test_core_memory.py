"""Unit tests for the P10 Memory layer (darwin.core.memory)."""

from darwin.core.contracts import TaskStatus
from darwin.core.executor import ExecutionResult
from darwin.core.memory import (
    ExecutionMemory,
    ExecutionRecord,
    ImportanceClass,
    ImportanceClassifier,
    MemoryItem,
    MemoryManager,
    PlanEntry,
    PlanMemory,
)
from darwin.core.task import Task


def sample_result(**overrides):
    base = dict(
        task_id="t1",
        tool="curl_get",
        planned_tool="curl_get",
        adherence=True,
        success=True,
        stdout="page body",
        stderr="",
        exit_code=0,
        elapsed_ms=5.0,
    )
    base.update(overrides)
    return ExecutionResult(**base)


# ── ExecutionRecord ─────────────────────────────────────────────────


def test_record_from_result_unifies_fields():
    result = sample_result(
        capability="fetch_url",
        tool_attempts=["curl_get", "http_post"],
        stdout="FLAG{abc}",
        elapsed_ms=12.0,
    )
    rec = ExecutionRecord.from_result(result, failure_type=None)
    assert rec.task_id == "t1"
    assert rec.tool == "curl_get"
    assert rec.adherence is True
    assert rec.capability == "fetch_url"
    assert rec.tool_attempts == ["curl_get", "http_post"]
    assert rec.stdout == "FLAG{abc}"
    assert rec.elapsed_ms == 12.0


def test_record_from_trace_maps_trace_event():
    rec = ExecutionRecord.from_trace(
        {
            "task_id": "t2",
            "tool": "sqlmap_test",
            "planned_tool": "sqlmap_test",
            "adherence": True,
            "success": False,
            "exit_code": 1,
            "elapsed_ms": 100,
            "failure_type": "tool_error",
        }
    )
    assert rec.task_id == "t2"
    assert rec.success is False
    assert rec.exit_code == 1
    assert rec.failure_type == "tool_error"


# ── ImportanceClassifier ────────────────────────────────────────────


def test_preserve_marker_wins():
    classifier = ImportanceClassifier()
    importance, reason = classifier.classify(
        ExecutionRecord.from_result(sample_result(stdout="password=admin123"))
    )
    assert importance is ImportanceClass.PRESERVE
    assert "password" in reason


def test_preserve_high_cost_failure():
    classifier = ImportanceClassifier()
    importance, _ = classifier.classify(
        ExecutionRecord.from_result(
            sample_result(success=False, stdout="", stderr="slow failure", elapsed_ms=120000.0)
        )
    )
    assert importance is ImportanceClass.PRESERVE


def test_discard_empty_output():
    classifier = ImportanceClassifier()
    importance, _ = classifier.classify(
        ExecutionRecord.from_result(sample_result(success=True, stdout="", stderr=""))
    )
    assert importance is ImportanceClass.DISCARD


def test_discard_timeout_without_output():
    classifier = ImportanceClassifier()
    importance, _ = classifier.classify(
        ExecutionRecord.from_result(
            sample_result(success=False, stdout="", stderr="timed out", elapsed_ms=15000.0)
        )
    )
    assert importance is ImportanceClass.DISCARD


def test_routine_output_compress():
    classifier = ImportanceClassifier()
    importance, _ = classifier.classify(
        ExecutionRecord.from_result(sample_result(stdout="HTTP/1.1 200 OK\nsome page"))
    )
    assert importance is ImportanceClass.COMPRESS


# ── PlanMemory ──────────────────────────────────────────────────────


def test_plan_memory_records_task_provenance():
    memory = PlanMemory()
    task = Task(
        id="sql_001",
        type="exploit",
        goal="Verify SQLi",
        hypothesis="username is injectable",
        rationale="single quote caused a DB error",
        evidence=["POST /login exists", "quote error observed"],
        confidence=0.78,
        status=TaskStatus.READY,
        dependencies=[{"type": "requires_evidence", "evidence": "form observed"}],
    )
    memory.record_task(task)

    entry = memory.get("sql_001")
    assert entry is not None
    assert entry.rationale == "single quote caused a DB error"
    assert entry.status == "ready"
    assert entry.dependencies == ["form observed"]
    block = memory.replan_context("sql_001")
    assert "single quote caused a DB error" in block
    assert "username is injectable" in block


def test_plan_memory_accepts_legacy_dict():
    memory = PlanMemory()
    memory.record_task(
        {
            "id": "legacy-1",
            "instruction": "Probe endpoint",
            "tool": "curl_get",
            "params": {"url": "http://x"},
            "status": "pending",
        }
    )
    entry = memory.get("legacy-1")
    assert entry is not None
    assert entry.goal == "Probe endpoint"


def test_plan_memory_active_entries_exclude_resolved():
    memory = PlanMemory()
    memory.record_task(Task(id="a", type="t", goal="g", status=TaskStatus.READY))
    memory.record_task(Task(id="b", type="t", goal="g", status=TaskStatus.SUCCESS))
    assert [e.task_id for e in memory.active_entries()] == ["a"]


# ── ExecutionMemory ─────────────────────────────────────────────────


def test_execution_memory_add_and_query():
    memory = ExecutionMemory()
    item = memory.add(
        MemoryItem(
            ExecutionRecord.from_result(sample_result(task_id="t1")),
            ImportanceClass.PRESERVE,
            "marker",
        )
    )
    memory.add(
        MemoryItem(
            ExecutionRecord.from_result(sample_result(task_id="t2", stdout="")),
            ImportanceClass.DISCARD,
            "empty",
        )
    )
    assert memory.recent() == [item, memory.recent()[-1]]
    assert len(memory.for_task("t1")) == 1
    assert [i.record.task_id for i in memory.preserved()] == ["t1"]


def test_execution_memory_trims_overflow():
    memory = ExecutionMemory(max_records=3)
    for i in range(5):
        memory.add(
            MemoryItem(
                ExecutionRecord.from_result(sample_result(task_id=f"t{i}")),
                ImportanceClass.COMPRESS,
                "",
            )
        )
    assert len(memory.recent()) == 3
    assert memory.for_task("t0") == []  # oldest trimmed
    assert memory.for_task("t4") != []


# ── MemoryManager ───────────────────────────────────────────────────


def test_manager_records_and_renders_replan_context():
    manager = MemoryManager()
    manager.record_task(
        Task(
            id="x",
            type="exploit",
            goal="Get shell",
            rationale="ssh creds found",
            status=TaskStatus.READY,
        )
    )
    manager.record_execution(
        sample_result(
            task_id="x",
            success=False,
            stderr="connection refused",
            exit_code=7,
            elapsed_ms=800.0,
        )
    )
    ctx = manager.replan_context("x")
    assert "ssh creds found" in ctx
    assert "EXECUTION HISTORY" in ctx
    assert "curl_get" in ctx


def test_manager_record_trace():
    manager = MemoryManager()
    item = manager.record_trace(
        {"task_id": "t9", "tool": "nmap_scan", "success": True, "exit_code": 0}
    )
    assert item.record.tool == "nmap_scan"
    assert item.importance is ImportanceClass.DISCARD  # empty output


def test_manager_compression_view_splits_importance():
    manager = MemoryManager()
    manager.record_execution(sample_result(task_id="p1", stdout="password=secret"))
    manager.record_execution(sample_result(task_id="p2", stdout="FLAG{keep}"))
    manager.record_execution(sample_result(task_id="c1", stdout="routine page"))
    manager.record_execution(sample_result(task_id="d1", stdout="", stderr=""))

    view = manager.compression_view()
    assert [r.task_id for r in view.preserved] == ["p1", "p2"]
    assert [r.task_id for r in view.compressible] == ["c1"]
    assert view.discarded_count == 1


def test_compression_view_respects_limits():
    manager = MemoryManager()
    for i in range(5):
        manager.record_execution(sample_result(task_id=f"p{i}", stdout="password=x"))
        manager.record_execution(sample_result(task_id=f"c{i}", stdout="routine"))
    view = manager.compression_view(max_preserved=2, max_compressible=2)
    assert len(view.preserved) == 2
    assert len(view.compressible) == 2


# ── P13: experience sharing filter ──────────────────────────────────


class FakeExperience:
    def __init__(self):
        self.records = []

    def record_execution(self, record):
        self.records.append(record)


def test_memory_manager_shares_preserve_and_key_tools():
    exp = FakeExperience()
    manager = MemoryManager(experience=exp)
    # PRESERVE (credential marker) -> shared
    manager.record_execution(sample_result(task_id="p", stdout="password=x"))
    # Successful key exploit tool -> shared even without a preserve marker
    manager.record_execution(sample_result(task_id="k", tool="sqlmap_test", stdout="ok"))
    # Routine curl_get -> not shared
    manager.record_execution(sample_result(task_id="r", tool="curl_get", stdout="page"))
    # DISCARD (empty) -> never shared
    manager.record_execution(sample_result(task_id="d", stdout="", stderr=""))

    assert [r.task_id for r in exp.records] == ["p", "k"]


def test_memory_manager_failed_key_tool_not_shared():
    exp = FakeExperience()
    manager = MemoryManager(experience=exp)
    manager.record_execution(
        sample_result(task_id="f", tool="sqlmap_test", success=False, stdout="internal error")
    )
    assert exp.records == []


def test_memory_manager_experience_failure_is_swallowed():
    class BrokenExperience:
        def record_execution(self, record):
            raise RuntimeError("boom")

    manager = MemoryManager(experience=BrokenExperience())
    item = manager.record_execution(sample_result(stdout="password=x"))
    assert item.record.task_id == "t1"  # execution recording still worked
