"""Success conditions are a closed vocabulary the runtime can actually check.

A condition type the executor does not understand used to degrade to "the
tool exited 0", so a substituted call or a wrong-verb request could be counted
as a completed task (cloud-28 logged `output unexpectedly contains
'source-IP allowlist'` style conditions that never described the real goal).
"""

from __future__ import annotations

import inspect

import pytest

from darwin.orchestration.execution import ExecutionCoordinator
from darwin.orchestration.planning import normalize_success_condition
from darwin.prompts.orchestrator import KNOWN_CONDITION_TYPES, SUCCESS_CONDITION_GUIDE


def test_known_condition_types_are_documented_in_the_planner_guide():
    for ctype in KNOWN_CONDITION_TYPES:
        assert ctype in SUCCESS_CONDITION_GUIDE, ctype


def test_every_known_condition_type_is_handled_by_the_executor():
    source = inspect.getsource(ExecutionCoordinator._verify_success_condition)
    for ctype in KNOWN_CONDITION_TYPES:
        assert ctype in source, f"{ctype} is accepted at plan time but unhandled"


def test_unknown_condition_type_is_dropped_not_degraded():
    assert normalize_success_condition({"type": "output_mentions", "value": "x"}) is None
    assert normalize_success_condition(None) is None
    assert normalize_success_condition({}) is None
    assert normalize_success_condition("flag_captured") is None


def test_known_condition_type_is_normalized_and_kept():
    cond = normalize_success_condition({"type": "HTTP_STATUS_IN", "status": [200]})
    assert cond == {"type": "http_status_in", "status": [200]}
    cond = normalize_success_condition({"type": "tool_success", "tool": "curl_get"})
    assert cond is not None and cond["tool"] == "curl_get"


def test_write_intent_without_a_condition_asserts_the_server_accepted_it():
    """A write is not done because the tool exited 0."""
    source = inspect.getsource(ExecutionCoordinator._execute_task_with_policies)
    assert '"type": "http_status_in"' in source


@pytest.mark.asyncio
async def test_status_condition_reads_the_latest_answer_not_the_stale_one():
    """After a verb upgrade the repaired request's status decides, not the 405."""
    coord = ExecutionCoordinator.__new__(ExecutionCoordinator)
    object.__setattr__(coord, "_orch", type("Orch", (), {})())
    executed = [
        {"name": "curl_get", "method": "GET",
         "stdout": "HTTP/1.1 405 METHOD NOT ALLOWED\nAllow: OPTIONS, POST\n"},
        {"name": "http_post", "method": "POST",
         "stdout": 'HTTP 200\nContent-Type: application/json\n\n{"ok": true}'},
    ]
    met, detail = await coord._verify_success_condition(
        {"type": "http_status_in", "status": [200, 201]}, executed, True, False,
    )
    assert met is True, detail
