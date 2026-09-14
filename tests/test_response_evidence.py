"""Observed disclosures become grounded hypotheses; guesses stay guesses."""

from __future__ import annotations

from darwin.core.contracts import TaskStatus
from darwin.core.scheduler import ParityScheduler
from darwin.core.task import Task, deps_from_task_ids
from darwin.core.task_graph import TaskGraph
from darwin.response_evidence import (
    detect_response_anomalies,
    disclosed_paths,
    disclosed_subjects,
    traversal_hypotheses,
)
from darwin.tools.arg_contract import unresolved_placeholders

# The body cloud-29 actually returned from POST /workflows.
_WORKFLOW_BODY = (
    '{"content":"-- tenant-a pipeline\\n'
    "SELECT 'hello from tenant-a';\\n"
    '","resolved_path":"/app/workspaces/default/test"}'
)


def test_server_path_disclosed_by_a_workflow_response():
    assert disclosed_paths(_WORKFLOW_BODY) == ["/app/workspaces/default/test"]


def test_path_already_present_in_the_request_is_not_a_disclosure():
    request = "POST /workflows {'workspace': '/app/workspaces/default/test'}"

    assert disclosed_paths(_WORKFLOW_BODY, request) == []


def test_urls_and_mime_types_are_not_paths():
    body = "text/html http://localhost:10640/workflows /api/v1/status"

    assert disclosed_paths(body) == []


def test_cross_subject_identifier_is_detected():
    # The body names another tenant's pipeline; the request never did.
    assert "tenant-a" in disclosed_subjects(_WORKFLOW_BODY)
    assert disclosed_subjects(_WORKFLOW_BODY, "workspace=tenant-a") == []


def test_path_segments_are_not_subject_identifiers():
    assert disclosed_subjects('{"resolved_path":"/app/workspaces/default/x"}') == []


def test_path_oracle_becomes_an_lfi_hypothesis_with_payloads():
    anomalies = detect_response_anomalies(
        tool="http_post",
        params={"url": "http://localhost:10640/workflows", "data": "{}"},
        response_text=_WORKFLOW_BODY,
        endpoint="http://localhost:10640/workflows",
        param="dataset_ref",
    )

    kinds = {a.kind for a in anomalies}
    assert "path_oracle" in kinds and "cross_subject_echo" in kinds

    oracle = next(a for a in anomalies if a.kind == "path_oracle")
    payloads = traversal_hypotheses(oracle)
    assert payloads, "the oracle must yield concrete follow-up hypotheses"
    assert all(p["vuln_type"] == "LFI" for p in payloads)
    assert all(p["param"] == "dataset_ref" for p in payloads)
    assert any("../" in p["tool_args"]["payload"] for p in payloads)


def test_clean_response_produces_no_evidence():
    anomalies = detect_response_anomalies(
        tool="curl_get",
        params={"url": "http://t/a"},
        response_text='{"status":"ok"}',
        endpoint="http://t/a",
    )

    assert anomalies == []


def test_unresolved_placeholder_is_visible_before_dispatch():
    params = {"url": "http://localhost:10641/<function-invoke-route>", "param": "code"}

    assert unresolved_placeholders(params) == {
        "url": "http://localhost:10641/<function-invoke-route>",
    }
    assert unresolved_placeholders({"url": "http://localhost:10641/functions"}) == {}


def test_scheduler_abandons_a_task_that_would_send_a_placeholder():
    task = Task(
        id="t1", type="task", goal="g", instruction="invoke the function",
        action={
            "tool": "send_payload",
            "params": {"url": "http://t/<function-invoke-route>", "param": "code"},
        },
        dependencies=deps_from_task_ids([]),
        status=TaskStatus.READY,
    )
    graph = TaskGraph([task])

    assert ParityScheduler().next_ready(graph) is None
    assert graph.get("t1").status is TaskStatus.ABANDONED
