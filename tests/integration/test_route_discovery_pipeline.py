"""A fuzz run must turn into a testable route, verb included.

cloud-30's intended entry point (``POST /deploy``) never entered the world
model: ffuf reported ``deploy [Status: 405]`` and the parser dropped every
line of it. This drives the real ffuf binary against a local target and
asserts the discovered route becomes an Endpoint whose verb the target itself
declared via ``Allow``.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from darwin.dkg import DKG
from darwin.orchestration.execution import ExecutionCoordinator
from darwin.orchestration.ports import GatewayToolCallPort
from darwin.tools.attack_server import create_attack_gateway
from darwin.tools.recon_server import create_recon_gateway

pytestmark = pytest.mark.integration


@pytest.fixture
def post_only_target():
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            return

        def _send(self, status, payload, allow=""):
            body = json.dumps(payload).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            if allow:
                self.send_header("Allow", allow)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if self.path == "/":
                self._send(200, {"service": "Serverless Functions"})
            elif self.path == "/deploy":
                self._send(405, {"error": "method not allowed"}, allow="POST, OPTIONS")
            else:
                self._send(404, {"error": "not found"})

        def do_POST(self):
            self._send(200, {"ok": True})

        def do_OPTIONS(self):
            self._send(200, {}, allow="POST, OPTIONS")

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _coordinator(dkg, port):
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


@pytest.mark.asyncio
async def test_ffuf_hit_becomes_a_route_with_a_declared_verb(post_only_target):
    dkg = DKG()
    port = GatewayToolCallPort(create_attack_gateway(), create_recon_gateway())
    coord = _coordinator(dkg, port)

    params = {"url": f"{post_only_target}/FUZZ", "wordlist": "common.txt"}
    result = await coord._call_tool("ffuf_fuzz", params)

    assert result.parsed_output["count"] >= 1, result.stdout[:400]
    coord._ingest_observed_routes("ffuf_fuzz", params, result)
    await coord._probe_route_verbs()

    deploy = [
        ep for ep in dkg.query_nodes("Endpoint")
        if str(ep.get("url", "")).endswith("/deploy")
    ]
    assert deploy, sorted(str(ep.get("url")) for ep in dkg.query_nodes("Endpoint"))
    assert deploy[0]["provenance_level"] == "verified"
    assert "POST" in str(deploy[0].get("allow_methods", ""))
    assert (str(deploy[0]["url"]), "POST") in coord._untested_documented_routes()
