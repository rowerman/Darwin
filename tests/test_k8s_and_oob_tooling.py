"""K8s tooling and out-of-band callback coverage.

These are the capabilities whose absence made k8s-01/02 and cloud-31 fail: no
way to read a pod's logs, K8s tools that assumed "we are inside a pod", a
DaemonSet that could not use a locally loaded image, a bare netcat process
standing in for a real callback endpoint, and HTTP tools that gave up on a
self-signed certificate.
"""

from __future__ import annotations

import asyncio
import json
import ssl

import pytest

import darwin.tools.attack_server as attack_server
import darwin.tools.oob_listener as oob
from darwin.tools.attack_server import _python_request, create_attack_gateway
from darwin.tools.mcp_gateway import ToolResult
from darwin.tools.oob_listener import (
    callback_payloads,
    callback_urls,
    stop_all_listeners,
)
from darwin.tools.tls import is_cert_verify_error, unverified_context


@pytest.fixture(autouse=True)
def _clean_listeners():
    stop_all_listeners()
    yield
    stop_all_listeners()


class _Proc:
    def __init__(self, stdout: bytes = b"", returncode: int = 0) -> None:
        self._stdout = stdout
        self.returncode = returncode

    async def communicate(self):
        return self._stdout, b""


# ── kubectl tools ───────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_kubectl_logs_reads_pod_output(monkeypatch):
    gateway = create_attack_gateway()
    captured: dict = {}

    async def fake_exec(*argv, **kwargs):
        captured["argv"] = list(argv)
        return _Proc(b"flag{k8s-test}\n")

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)
    result = await gateway.call(
        "kubectl_logs", {"pod": "runc-escape-poc", "tail_lines": 50}
    )
    assert captured["argv"] == [
        "kubectl", "logs", "runc-escape-poc", "-n", "default", "--tail=50",
    ]
    assert result.success and "flag{k8s-test}" in result.stdout


@pytest.mark.asyncio
async def test_kubectl_auth_check_defaults_to_current_identity(monkeypatch):
    gateway = create_attack_gateway()
    calls: list[list[str]] = []

    async def fake_exec(*argv, **kwargs):
        calls.append(list(argv))
        return _Proc(b"*.*  []  []  [*]\n")

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)
    await gateway.call("kubectl_auth_check", {})
    await gateway.call("kubectl_auth_check", {"sa": "builder", "namespace": "ci"})
    # No impersonation unless asked: the empty --as= used to turn every check
    # into system:anonymous and hid that darwin held cluster-admin.
    assert calls[0] == ["kubectl", "auth", "can-i", "--list"]
    assert calls[1] == [
        "kubectl", "auth", "can-i", "--list", "--as=builder", "-n", "ci",
    ]


@pytest.mark.asyncio
async def test_k8s_secret_dump_prefers_ambient_kubeconfig(monkeypatch):
    gateway = create_attack_gateway()
    commands: list[str] = []

    async def fake_shell(cmd, timeout=60):
        commands.append(cmd)
        return ToolResult(
            tool_name="shell", success=True,
            stdout='{"kind":"SecretList","items":[]}', stderr="", exit_code=0,
            elapsed_ms=0,
        )

    monkeypatch.setattr(attack_server, "_run_shell", fake_shell)
    result = await gateway.call("k8s_secret_dump", {})
    assert len(commands) == 1 and "kubectl get secrets -A -o json" in commands[0]
    assert "kubectl (kubeconfig)" in result.stdout


@pytest.mark.asyncio
async def test_k8s_backdoor_daemonset_yaml_is_quote_safe(monkeypatch):
    gateway = create_attack_gateway()
    commands: list[str] = []

    async def fake_shell(cmd, timeout=60):
        commands.append(cmd)
        return ToolResult(
            tool_name="shell", success=True,
            stdout="daemonset.apps/cdk-backdoor created\n=== Pod status ===\n"
                   "backdoor-abc 1/1 Running",
            stderr="", exit_code=0, elapsed_ms=0,
        )

    monkeypatch.setattr(attack_server, "_run_shell", fake_shell)
    result = await gateway.call(
        "k8s_backdoor_daemonset", {"image": "localhost/poc:latest"}
    )
    assert len(commands) == 1
    manifest_cmd = commands[0]
    # The YAML is written through a quoted heredoc; the old code embedded the
    # whole manifest inside a single-quoted echo, which broke on any quote in
    # the command and on multi-line content.
    assert "cat > /tmp/cdk-backdoor-localhost-poc-latest.yaml <<'DARWIN_DS_EOF'" in manifest_cmd
    assert "echo 'apiVersion" not in manifest_cmd
    assert "imagePullPolicy: IfNotPresent" in manifest_cmd
    assert "mountPath: /host" in manifest_cmd
    assert result.success


@pytest.mark.asyncio
async def test_k8s_backdoor_daemonset_retries_when_image_cannot_be_pulled(monkeypatch):
    gateway = create_attack_gateway()
    commands: list[str] = []

    async def fake_shell(cmd, timeout=60):
        commands.append(cmd)
        text = "ErrImagePull" if len(commands) == 1 else "backdoor-abc 1/1 Running"
        return ToolResult(
            tool_name="shell", success=True, stdout=text, stderr="",
            exit_code=0, elapsed_ms=0,
        )

    monkeypatch.setattr(attack_server, "_run_shell", fake_shell)
    await gateway.call("k8s_backdoor_daemonset", {})
    assert len(commands) == 2
    assert "imagePullPolicy: Never" in commands[1]


@pytest.mark.asyncio
async def test_container_escape_runc_fails_fast_on_patched_runc(monkeypatch):
    gateway = create_attack_gateway()
    commands: list[str] = []

    async def fake_shell(cmd, timeout=60):
        commands.append(cmd)
        return ToolResult(
            tool_name="shell", success=True,
            stdout="[Checking runc]\nrunc version 1.1.7\ncommit: v1.1.7-0",
            stderr="", exit_code=0, elapsed_ms=0,
        )

    monkeypatch.setattr(attack_server, "_run_shell", fake_shell)
    result = await gateway.call("container_escape_runc", {})
    assert result.success is False
    assert "not vulnerable" in result.stderr
    # The version banner must never be spliced into the exploit command, and
    # the exploit must not run at all on a patched runc.
    assert len(commands) == 1
    assert "PAYLOAD_EOF" not in commands[0]


@pytest.mark.asyncio
async def test_k8s_etcd_keys_requires_binary_and_uses_keys_only(monkeypatch):
    gateway = create_attack_gateway()
    monkeypatch.setattr(attack_server.shutil, "which", lambda _name: None)
    missing = await gateway.call(
        "k8s_etcd_keys", {"endpoint": "http://127.0.0.1:2379"}
    )
    assert missing.exit_code == 127 and "etcdctl is not installed" in missing.stderr

    commands: list[str] = []

    async def fake_shell(cmd, timeout=60):
        commands.append(cmd)
        return ToolResult(tool_name="shell", success=True, stdout="/registry/x",
                          stderr="", exit_code=0, elapsed_ms=0)

    monkeypatch.setattr(attack_server.shutil, "which",
                        lambda _name: "/usr/bin/etcdctl")
    monkeypatch.setattr(attack_server, "_run_shell", fake_shell)
    await gateway.call(
        "k8s_etcd_keys", {"endpoint": "http://127.0.0.1:2379", "key": "/registry/"}
    )
    assert "--keys-only" in commands[0] and "/registry/" in commands[0]


# ── TLS handling ────────────────────────────────────────────────────


def test_tls_helpers_recognize_verification_failures():
    assert is_cert_verify_error(
        "<urlopen error [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed"
    )
    assert is_cert_verify_error(
        "curl: (60) SSL certificate problem: self signed certificate"
    )
    assert not is_cert_verify_error("connection refused")
    assert unverified_context().verify_mode == ssl.CERT_NONE


@pytest.mark.asyncio
async def test_python_request_retries_without_tls_verification(monkeypatch):
    calls: list[str] = []

    async def fake_shell(cmd, timeout=60):
        calls.append(cmd)
        if len(calls) == 1:
            return ToolResult(
                tool_name="shell", success=True,
                stdout="ERROR:<urlopen error [SSL: CERTIFICATE_VERIFY_FAILED] "
                       "certificate verify failed>",
                stderr="", exit_code=0, elapsed_ms=0,
            )
        return ToolResult(
            tool_name="shell", success=True,
            stdout="STATUS:200\nBODY_START\nok", stderr="", exit_code=0, elapsed_ms=0,
        )

    monkeypatch.setattr(attack_server, "_run_shell", fake_shell)
    result = await _python_request(
        "GET", "https://127.0.0.1:45889/", tool_name="send_payload"
    )
    assert len(calls) == 2
    assert result.success
    assert "retried with TLS verification disabled" in result.stdout


# ── Injection tools that must speak JSON ────────────────────────────


class _FakeResponse:
    def __init__(self, body: bytes) -> None:
        self._body = body
        self.status = 200

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self) -> bytes:
        return self._body


@pytest.mark.asyncio
async def test_command_injection_reports_async_execution(monkeypatch):
    import urllib.request

    gateway = create_attack_gateway()
    requests: list = []

    def fake_urlopen(req, **kwargs):
        requests.append(req)
        return _FakeResponse(b'{"count":3,"status":"registered"}')

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    result = await gateway.call(
        "command_injection_test",
        {"url": "http://localhost:10642/runbooks", "param": "script",
         "method": "POST", "body_format": "json"},
    )
    assert "ASYNC-EXECUTION SUSPECTED" in result.stdout
    assert requests[0].get_header("Content-type") == "application/json"
    assert json.loads(requests[0].data.decode()) == {"script": ";id"}


@pytest.mark.asyncio
async def test_ssti_inject_can_send_a_json_body(monkeypatch):
    import urllib.request

    gateway = create_attack_gateway()
    requests: list = []

    def fake_urlopen(req, **kwargs):
        requests.append(req)
        return _FakeResponse(b"no reflection")

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    await gateway.call(
        "ssti_inject",
        {"target_url": "http://localhost:10642/runbooks", "param_name": "script",
         "method": "POST", "body_format": "json"},
    )
    assert requests and requests[0].get_header("Content-type") == "application/json"
    assert json.loads(requests[0].data.decode()) == {"script": "{{7*7}}"}


def test_repair_loop_allows_tool_switch_inside_one_domain():
    from darwin.orchestration.execution import ExecutionCoordinator

    same = ExecutionCoordinator._tool_in_same_capability_family
    assert same("k8s_etcd_keys", "kubectl_logs")
    assert same("kubectl_auth_check", "kubectl_logs")
    assert same("send_payload", "curl_get")
    # A read-only k8s tool must not be silently replaced by an HTTP injector.
    assert not same("kubectl_auth_check", "http_post")


# ── OOB listener ────────────────────────────────────────────────────


class _StubListener:
    instances: list["_StubListener"] = []

    def __init__(self, listener_id: str, port: int = 0, host: str = "0.0.0.0") -> None:
        self.listener_id = listener_id
        self.port = int(port) or 40100 + len(_StubListener.instances)
        self.hits: list[dict] = []
        self.started = False
        self.stopped = False
        _StubListener.instances.append(self)

    def start(self) -> None:
        self.started = True

    def stop(self) -> None:
        self.stopped = True

    def count(self) -> int:
        return len(self.hits)

    def snapshot(self, since: int = 0, limit: int = 20):
        return list(self.hits[since:][:limit])


@pytest.fixture
def _stub_listeners(monkeypatch):
    _StubListener.instances = []
    monkeypatch.setattr(oob, "OOBListener", _StubListener)
    monkeypatch.setattr(
        oob, "_local_ipv4_addresses", lambda: ["10.42.0.1", "172.17.0.1"]
    )
    yield _StubListener
    _StubListener.instances = []


def test_callback_urls_and_payloads_are_target_usable(monkeypatch):
    monkeypatch.setattr(oob, "_local_ipv4_addresses", lambda: ["10.42.0.1"])
    urls = callback_urls(40000)
    assert urls == ["http://10.42.0.1:40000/"]
    payloads = callback_payloads(urls[0])
    assert set(payloads) == {"curl", "python3", "sh", "nc"}
    assert "http://10.42.0.1:40000/cb" in payloads["python3"]
    monkeypatch.setattr(oob, "_local_ipv4_addresses", lambda: [])
    assert callback_urls(40000) == ["http://127.0.0.1:40000/"]


@pytest.mark.asyncio
async def test_oob_listener_start_read_stop(_stub_listeners):
    gateway = create_attack_gateway()
    started = await gateway.call("oob_listener", {"action": "start"})
    assert started.success
    payload = json.loads(started.stdout)
    assert payload["callback_urls"] == [
        "http://10.42.0.1:40100/", "http://172.17.0.1:40100/",
    ]
    assert "python3" in payload["payloads"]
    assert _stub_listeners.instances[0].started

    listener = _stub_listeners.instances[0]
    listener.hits.append({
        "index": 0, "method": "POST",
        "path": "/collect?flag=flag{oob-callback-unit}",
        "body": "", "flags": ["flag{oob-callback-unit}"],
    })
    read = await gateway.call(
        "oob_listener", {"action": "read", "listener_id": listener.listener_id}
    )
    assert read.success and "flag{oob-callback-unit}" in read.stdout

    stopped = await gateway.call(
        "oob_listener", {"action": "stop", "listener_id": listener.listener_id}
    )
    assert stopped.success and listener.stopped
    empty = await gateway.call("oob_listener", {"action": "read"})
    assert not empty.success


@pytest.mark.asyncio
async def test_oob_listener_caps_concurrent_listeners(_stub_listeners):
    gateway = create_attack_gateway()
    assert (await gateway.call("oob_listener", {"action": "start"})).success
    assert (await gateway.call("oob_listener", {"action": "start"})).success
    third = await gateway.call("oob_listener", {"action": "start"})
    assert not third.success and "already running" in third.stderr
    assert stop_all_listeners() == 2
    assert all(listener.stopped for listener in _stub_listeners.instances)
