"""Unit tests for the P13 Execution Memory -> CTEG bridge."""

from darwin.cteg import CTEG
from darwin.core.executor import ExecutionResult


def result(**overrides):
    base = dict(
        task_id="t1",
        tool="sqlmap_test",
        planned_tool="sqlmap_test",
        adherence=True,
        success=True,
        stdout="injectable: yes",
        stderr="",
        exit_code=0,
        elapsed_ms=10.0,
    )
    base.update(overrides)
    return ExecutionResult(**base)


def test_cteg_record_execution_creates_exploit_pattern(tmp_path):
    cteg = CTEG(storage_path=str(tmp_path / "cteg.json"))
    new_count = cteg.record_execution(result())

    assert new_count >= 1
    assert "ep-sqli-t1" in cteg.graph
    node = cteg.graph.nodes["ep-sqli-t1"]
    assert node["type"] == "ExploitPattern"
    assert node["total_attempts"] == 1
    assert node["total_successes"] == 1


def test_cteg_record_execution_merges_duplicate(tmp_path):
    cteg = CTEG(storage_path=str(tmp_path / "cteg.json"))
    rec = result()
    cteg.record_execution(rec)

    assert cteg.record_execution(rec) == 0  # merged, not a new pattern
    node = cteg.graph.nodes["ep-sqli-t1"]
    assert node["total_attempts"] >= 2
    assert node["total_successes"] >= 2


def test_cteg_record_execution_failure_outcome(tmp_path):
    cteg = CTEG(storage_path=str(tmp_path / "cteg.json"))
    cteg.record_execution(result(success=False, stdout="", stderr="internal error"))

    node = cteg.graph.nodes["ep-sqli-t1"]
    assert node["total_attempts"] == 1
    assert node["total_successes"] == 0


def test_cteg_record_execution_ignores_empty_tool(tmp_path):
    cteg = CTEG(storage_path=str(tmp_path / "cteg.json"))
    assert cteg.record_execution(result(tool="")) == 0
    assert len(list(cteg.graph.nodes)) == 0


def test_cteg_persists_after_record_execution(tmp_path):
    path = str(tmp_path / "cteg.json")
    cteg = CTEG(storage_path=path)
    cteg.record_execution(result())

    reloaded = CTEG(storage_path=path)
    assert "ep-sqli-t1" in reloaded.graph
