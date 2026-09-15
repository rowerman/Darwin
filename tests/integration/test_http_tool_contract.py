"""A 4xx answer must reach the caller as a status, not as a success.

The benchmark logs recorded ``send_payload: OK (exit=0, 32 bytes)`` for a
request the target answered with 404 — the JSON body and the ``Allow`` header
of a 405 were thrown away with it, so the repair loop had nothing to act on.
This drives the real gateway against a local target that only accepts POST.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from darwin.tools.attack_server import create_attack_gateway

pytestmark = pytest.mark.integration


@pytest.fixture
def post_only_target():
    """Target exposing ``POST /workflows`` only."""

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
            self._send(405, {"error": "method not allowed"}, allow="POST, OPTIONS")

        def do_POST(self):
            length = int(self.headers.get("Content-Length") or 0)
            body = json.loads(self.rfile.read(length) or b"{}")
            self._send(200, {"resolved_path": "/app/workspaces/tenant-a", "body": body})

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.mark.asyncio
async def test_post_json_body_is_delivered_and_status_is_structured(post_only_target):
    gateway = create_attack_gateway()

    result = await gateway.call("send_payload", {
        "url": f"{post_only_target}/workflows",
        "method": "POST",
        "body_format": "json",
        "payload": json.dumps({"workspace": "tenant-a", "dataset_ref": "script.sql"}),
    })

    assert result.success is True
    assert result.parsed_output["status"] == 200
    assert "tenant-a" in result.parsed_output["body"]


@pytest.mark.asyncio
async def test_wrong_verb_reports_status_and_allow_header(post_only_target):
    gateway = create_attack_gateway()

    result = await gateway.call("send_payload", {
        "url": f"{post_only_target}/workflows",
        "method": "GET",
        "param": "dataset_ref",
        "payload": "../../etc/passwd",
    })

    assert result.success is False
    assert result.exit_code == 405
    assert result.parsed_output["status"] == 405
    assert result.parsed_output["headers"]["Allow"] == "POST, OPTIONS"


@pytest.mark.asyncio
async def test_unreachable_target_is_not_a_success():
    gateway = create_attack_gateway()

    result = await gateway.call("send_payload", {
        "url": "http://127.0.0.1:1/workflows",
        "method": "POST",
        "body_format": "json",
        "payload": '{"workspace": "tenant-a"}',
    })

    assert result.success is False
    assert result.exit_code == -1
    assert result.parsed_output == {}
