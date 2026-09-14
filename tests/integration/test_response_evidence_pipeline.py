"""End-to-end: a real HTTP target, real gateways, real world-model growth.

The target reproduces the shape that cloud-29 answered with: a POST-only
workflow route that returns another tenant's data and discloses the server
path it resolved the request into. The test drives the real tool gateways
against it and asserts the observation becomes a grounded hypothesis, and
that a task still carrying an unfilled placeholder is never dispatched.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from darwin.core.contracts import TaskStatus
from darwin.core.scheduler import ParityScheduler
from darwin.core.task import Task, deps_from_task_ids
from darwin.core.task_graph import TaskGraph
from darwin.dkg import DKG
from darwin.orchestration.execution import ExecutionCoordinator
from darwin.tools.attack_server import create_attack_gateway
from darwin.tools.recon_server import create_recon_gateway

pytestmark = pytest.mark.integration

_TENANT_BODY = (
    "-- tenant-a pipeline\nSELECT 'hello from tenant-a';\n"
)


@pytest.fixture
def workflow_target(tmp_path):
    """Threaded target: POST-only workflow route with a privileged readback."""

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):  # keep the test output quiet
            return

        def _send(self, status, body, content_type="application/json", allow=""):
            payload = body.encode()
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            if allow:
                self.send_header("Allow", allow)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def do_GET(self):
            if self.path == "/":
                self._send(200, json.dumps({
                    "service": "Data Workflow Control Plane",
                    "write_endpoint": "POST /workflows {workspace, dataset_ref}",
                }))
            elif self.path == "/workflows":
                self._send(405, "method not allowed", allow="OPTIONS, POST")
            else:
                self._send(404, "not found")

        def do_POST(self):
            length = int(self.headers.get("Content-Length", 0) or 0)
            body = self.rfile.read(length).decode("utf-8", errors="replace")
            if self.path != "/workflows":
                self._send(404, "not found")
                return
            try:
                payload = json.loads(body or "{}")
            except ValueError:
                payload = {}
            workspace = str(payload.get("workspace", "") or "")
            dataset = str(payload.get("dataset_ref", "") or "")
            if not workspace or not dataset:
                self._send(400, json.dumps({"error": "missing workspace/dataset_ref"}))
                return
            self._send(200, json.dumps({
                "content": _TENANT_BODY,
                "resolved_path": f"/app/workspaces/{workspace}/{dataset}",
            }))

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()


def _coordinator(dkg_path: str) -> ExecutionCoordinator:
    coord = ExecutionCoordinator.__new__(ExecutionCoordinator)
    orch = type("Orch", (), {
        "attack_gateway": create_attack_gateway(),
        "recon_gateway": create_recon_gateway(),
    })()
    object.__setattr__(coord, "_orch", orch)
    object.__setattr__(coord, "dkg", DKG(storage_path=dkg_path))
    return coord


@pytest.mark.asyncio
async def test_post_only_route_disclosure_becomes_a_grounded_hypothesis(
    workflow_target, tmp_path,
):
    coord = _coordinator(str(tmp_path / "dkg.json"))
    gateway = coord.recon_gateway  # http_post is a reconnaissance-domain tool

    result = await gateway.call("http_post", {
        "url": f"{workflow_target}/workflows",
        "content_type": "application/json",
        "data": json.dumps({"workspace": "default", "dataset_ref": "test"}),
    })

    assert result.success is True
    assert "tenant-a" in result.stdout
    assert "/app/workspaces/default/test" in result.stdout

    promoted = coord._ingest_response_evidence(
        "http_post",
        {"url": f"{workflow_target}/workflows", "param": "dataset_ref"},
        result,
    )

    kinds = {item["vuln_type"] for item in promoted}
    assert "LFI" in kinds and "IDOR" in kinds
    stored = coord.dkg.query_nodes("Vulnerability")
    assert any(
        "disclosed server path" in str(n.get("evidence", "")) for n in stored
    )
    assert any(
        str(n.get("source", "")) == "response_evidence" for n in stored
    )
    assert coord._evidence_since_review is True

    # Re-probing the same route must not inflate the plan again.
    again = coord._ingest_response_evidence(
        "http_post",
        {"url": f"{workflow_target}/workflows", "param": "dataset_ref"},
        result,
    )
    assert again == []


def test_task_with_an_unfilled_route_placeholder_is_abandoned(tmp_path):
    task = Task(
        id="invoke", type="task", goal="invoke the function",
        instruction="Invoke the discovered function route",
        action={
            "tool": "send_payload",
            "params": {"url": "http://t/<function-invoke-route>", "param": "code"},
        },
        dependencies=deps_from_task_ids([]),
        status=TaskStatus.READY,
    )
    graph = TaskGraph([task])

    assert ParityScheduler().next_ready(graph) is None
    assert graph.get("invoke").status is TaskStatus.ABANDONED
