"""Deterministic local integration coverage for the public control plane.

These tests use the production gateway registrations and Orchestrator path.
Only the LLM response stream and external command binaries are substituted.
"""

from __future__ import annotations

import asyncio
import html
import json
import os
import stat
import sys
import textwrap
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

import pytest
import pytest_asyncio

from darwin.core.contracts import Budget, Objective, ReplanRecommendation, TaskOutcome
from darwin.core.evaluator import Evaluation, FailureType
from darwin.core.executor import ToolExecutor
from darwin.core.memory import ImportanceClass, MemoryManager
from darwin.core.metrics import MetricsCalculator
from darwin.core.runtime import Runtime
from darwin.core.task import Task
from darwin.core.task_graph import TaskGraph
from darwin.dave import DAVE, ExploitAttempt, VerifyStatus
from darwin.dpm import DefenseCategory, DefensePerceptionModule
from darwin.cteg import CTEG
from darwin.dkg import DKG
from darwin.tools.mcp_gateway import MCPGateway, ToolResult
from darwin.tools.recon_server import create_recon_gateway
from darwin.utils.http_client import HTTPResponse, ProbeClient


pytestmark = pytest.mark.integration


FLAG = "flag{local-integration-ok}"


class ReplayLLM:
    """Scripted LLMSession-compatible object with no network access."""

    def __init__(self, plan_url: str, root_url: str | None = None):
        self.plan_url = plan_url
        self.root_url = root_url or plan_url.rsplit("/flag", 1)[0]
        self.model = "replay/test"
        self.provider = "replay"
        self.token_count = 0
        self.context_load = 0.0
        self.calls: list[tuple] = []
        self.thought_logger = None

    def replace_system_prompt(self, prompt):
        self.calls.append(("replace_system_prompt", prompt))

    def add_context_message(self, content, role="user"):
        self.calls.append(("add_context_message", content, role))

    def add_tool_result(self, tool_call_id, result):
        self.calls.append(("add_tool_result", tool_call_id, result))

    def compress(self, **kwargs):
        self.calls.append(("compress", kwargs))
        return 0

    def generate(self, prompt, system_prompt=None, tools=None, temperature=None,
                 timeout=180.0, stage=None):
        self.calls.append(("generate", stage, prompt, tools))
        self.token_count += 1
        stage_text = str(stage or "").lower()
        if "analy" in stage_text:
            return '{"application_understanding":"local test app","vulnerabilities":[]}', None
        if "research" in stage_text:
            return "[]", None
        if "task_execution" in stage_text:
            url = self.plan_url if "Fetch the target flag" in str(prompt) else self.root_url
            return "", [{
                "name": "curl_get",
                "arguments": {"url": url},
                "id": "replay-task-1",
            }]
        if "plan" in stage_text or "review" in stage_text or not stage_text:
            return (
                '[{"id":"local-root","instruction":"Fetch the local target root page",'
                f'"tool":"curl_get","params":{{"url":"{self.root_url}"}},"dependent_task_ids":[]}},'
                '{"id":"local-flag","instruction":"Fetch the target flag",'
                f'"tool":"curl_get","params":{{"url":"{self.plan_url}"}},"dependent_task_ids":["local-root"]}}]'
            ), None
        return "[]", None


@pytest_asyncio.fixture
async def local_http_target(unused_tcp_port):
    """Small HTTP target that exposes a flag endpoint and WAF behavior."""

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        try:
            raw = await asyncio.wait_for(reader.read(8192), timeout=2)
            request_line = raw.decode("latin1", errors="replace").splitlines()[0]
            request_target = request_line.split()[1] if len(request_line.split()) > 1 else "/"
            request_method = request_line.split()[0].upper() if request_line else "GET"
            request_body = ""
            if b"\r\n\r\n" in raw:
                request_body = raw.split(b"\r\n\r\n", 1)[1].decode(
                    "utf-8", errors="replace")
            parsed = urlsplit(request_target)
            query = parse_qs(parsed.query)
            probe = query.get("q", [""])[0]
            status, body = 404, "not found"
            content_type = "text/html"
            extra_headers = ""
            if parsed.path == "/flag":
                status, body = 200, FLAG
            elif parsed.path == "/plane":
                # Self-describing manifest: advertises a POST route and the
                # body fields that route expects.
                status = 200
                body = json.dumps({
                    "endpoint": "POST /plane/workflows {workspace, dataset_ref}",
                    "service": "Local Workflow Plane",
                })
                content_type = "application/json"
            elif parsed.path == "/plane/workflows":
                extra_headers = "Allow: OPTIONS, POST\r\n"
                if request_method == "OPTIONS":
                    status, body = 200, "options ok"
                elif request_method == "POST":
                    try:
                        payload = json.loads(request_body or "{}")
                    except ValueError:
                        payload = {}
                    if {"workspace", "dataset_ref"} <= set(payload):
                        status, body = 200, json.dumps({"content": FLAG})
                        content_type = "application/json"
                    else:
                        status, body = 400, "missing fields"
                else:
                    status, body = 405, "method not allowed"
            elif parsed.path in {"/search", "/"}:
                if any(token in probe.lower() for token in ("<", ">", "script", "javascript", "onerror")):
                    status, body = 403, "blocked by local waf"
                elif parsed.path == "/search":
                    status, body = 200, f"search result: {html.escape(probe)}"
                else:
                    status, body = 200, "local integration target"
            payload = body.encode()
            reason = {200: "OK", 400: "Bad Request", 403: "Forbidden",
                      404: "Not Found", 405: "Method Not Allowed"}.get(status, "Unknown")
            response = (
                f"HTTP/1.1 {status} {reason}\r\n"
                f"Content-Type: {content_type}\r\n"
                f"{extra_headers}"
                f"Content-Length: {len(payload)}\r\nConnection: close\r\n\r\n"
            ).encode() + payload
            writer.write(response)
            await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()

    server = await asyncio.start_server(handle, "127.0.0.1", unused_tcp_port)
    base_url = f"http://127.0.0.1:{unused_tcp_port}"
    try:
        yield base_url
    finally:
        server.close()
        await server.wait_closed()


def _install_cli_stubs(tmp_path, monkeypatch, port: int):
    """Install parser-compatible command stubs ahead of the real PATH."""
    stub_dir = tmp_path / "bin"
    stub_dir.mkdir()
    runner = stub_dir / "darwin_cli_stub.py"
    runner.write_text(
        textwrap.dedent(
            f"""
            import os, subprocess, sys
            import urllib.error, urllib.request
            from urllib.parse import urlsplit

            name = sys.argv[1].lower()
            args = sys.argv[2:]
            log_path = os.environ.get('DARWIN_STUB_LOG')
            if log_path:
                with open(log_path, 'a', encoding='utf-8') as log:
                    log.write(name + ' ' + repr(args) + '\\n')
            if name.startswith('nmap'):
                print('{port}/tcp open http LocalHTTP/1.0')
            elif name == 'dirb':
                print('+ /flag (CODE:200)')
            elif name == 'whatweb':
                print('http://127.0.0.1:{port} [200 OK] [LocalHTTP] [Python]')
            elif name == 'nikto':
                print('+ Server: LocalHTTP')
            elif name == 'head':
                sys.stdout.write(''.join(sys.stdin.read().splitlines(True)[:200]))
            elif name == 'timeout':
                command = args[1:]
                if command:
                    subprocess.run(command, check=False)
            elif name == 'curl':
                urls = [a.strip(chr(39) + chr(34)) for a in args if a.startswith(('http://', 'https://'))]
                url = urls[-1] if urls else 'http://127.0.0.1:{port}/'
                method = 'POST' if '-X' in args and args[args.index('-X') + 1].upper() == 'POST' else 'GET'
                request = urllib.request.Request(url, method=method)
                try:
                    with urllib.request.urlopen(request, timeout=5) as response:
                        print(f'HTTP/{{response.version}} {{response.status}} {{response.reason}}')
                        for key, value in response.headers.items():
                            print(f'{{key}}: {{value}}')
                        print()
                        sys.stdout.write(response.read().decode(errors='replace'))
                except urllib.error.HTTPError as error:
                    print(f'HTTP/1.1 {{error.code}} {{error.reason}}')
                    sys.stdout.write(error.read().decode(errors='replace'))
                    if error.code == 404:
                        raise SystemExit(22)
            """
        ).strip()
        + "\n",
        encoding="utf-8",
    )

    names = ("nmap", "dirb", "whatweb", "nikto", "curl", "timeout", "head")
    for name in names:
        if os.name == "nt":
            wrapper = stub_dir / f"{name}.cmd"
            wrapper.write_text(f'@"{sys.executable}" "{runner}" "{name}" %*\n', encoding="utf-8")
        else:
            wrapper = stub_dir / name
            wrapper.write_text(
                f"#!/bin/sh\nexec \"{sys.executable}\" \"{runner}\" \"{name}\" \"$@\"\n",
                encoding="utf-8",
            )
            wrapper.chmod(wrapper.stat().st_mode | stat.S_IXUSR)
    monkeypatch.setenv("PATH", os.pathsep.join((str(stub_dir), os.environ.get("PATH", ""))))
    monkeypatch.setenv("DARWIN_STUB_LOG", str(stub_dir / "calls.log"))
    # Keep nmap cloud-probe preparation (triggered by real recon gateway calls)
    # inside the sandbox instead of the developer's real ~/.nmap.
    monkeypatch.setenv("NMAP_DATADIR", str(tmp_path / "nmap-datadir"))
    return stub_dir


@pytest.fixture
def cli_stub_path(tmp_path, local_http_target, monkeypatch):
    return _install_cli_stubs(
        tmp_path, monkeypatch, urlsplit(local_http_target).port,
    )


@pytest.fixture
def manifest_target():
    """Threaded HTTP target that documents a POST-only route.

    Threaded on purpose: several HTTP tools call urllib inline on the event
    loop, so an in-loop asyncio server would deadlock against them.
    """
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    hits: list[tuple[str, str]] = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):  # keep the test output quiet
            return

        def _send(self, status, body, content_type="text/html", allow=""):
            payload = body.encode()
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            if allow:
                self.send_header("Allow", allow)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def do_GET(self):
            hits.append(("GET", self.path))
            if self.path == "/plane":
                self._send(200, json.dumps({
                    "endpoint": "POST /plane/workflows {workspace, dataset_ref}",
                    "service": "Local Workflow Plane",
                }), "application/json")
            elif self.path == "/plane/workflows":
                self._send(405, "method not allowed", allow="OPTIONS, POST")
            elif self.path == "/":
                self._send(200, "local manifest target")
            else:
                self._send(404, "not found")

        def do_OPTIONS(self):
            hits.append(("OPTIONS", self.path))
            if self.path == "/plane/workflows":
                self._send(200, "options ok", allow="OPTIONS, POST")
            else:
                self._send(404, "not found")

        def do_POST(self):
            length = int(self.headers.get("Content-Length", 0) or 0)
            body = self.rfile.read(length).decode("utf-8", errors="replace")
            hits.append(("POST", self.path))
            if self.path != "/plane/workflows":
                self._send(404, "not found")
                return
            try:
                payload = json.loads(body or "{}")
            except ValueError:
                payload = {}
            if {"workspace", "dataset_ref"} <= set(payload):
                self._send(200, json.dumps({"content": FLAG}), "application/json")
            else:
                self._send(400, f"missing fields: {sorted(payload)}")

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}", hits
    finally:
        server.shutdown()
        server.server_close()


@pytest.fixture
def manifest_cli_stub_path(tmp_path, manifest_target, monkeypatch):
    base, _hits = manifest_target
    return _install_cli_stubs(tmp_path, monkeypatch, urlsplit(base).port)


@pytest.mark.asyncio
async def test_public_orchestrator_run_uses_local_target_and_real_gateways(
    tmp_path, monkeypatch, local_http_target, cli_stub_path
):
    """The public run path reaches Runtime and captures a remote flag."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("darwin.rag.get_rag", lambda: None)
    monkeypatch.setattr(
        ProbeClient,
        "PROBE_CLASSES",
        {"A": ["<"], "B": ["<script>"], "C": ["onerror="],
         "D": ["javascript:"], "E": ["%3C"]},
    )
    flag_url = f"{local_http_target}/flag"
    from darwin.orchestrator import Orchestrator

    llm = ReplayLLM(flag_url)
    orchestrator = Orchestrator(llm_session=llm, time_budget=30, token_budget=2000)
    # Keep this public-path test focused on the control-plane wiring. The
    # heuristic vulnerability augmenter is covered by its own unit tests and
    # would otherwise spend time probing every numeric loopback URL.
    monkeypatch.setattr(orchestrator, "_augment_from_dkg", lambda: None)
    real_recon_call = orchestrator.recon_gateway.call

    async def recon_call_without_cms_noise(name, params):
        url = str((params or {}).get("url", ""))
        if name == "curl_get" and any(
            path in url for path in (
                "/wp-admin/", "/wp-login.php", "/wp-content/", "/wp-json/",
                "/administrator/", "/user/login", "/api/", "/.env", "/config.php",
            )
        ):
            return ToolResult(
                tool_name=name, success=False, stdout="", stderr="not a local CMS endpoint",
                exit_code=22, elapsed_ms=1.0,
            )
        return await real_recon_call(name, params)

    monkeypatch.setattr(orchestrator.recon_gateway, "call", recon_call_without_cms_noise)
    try:
        result = await orchestrator.run(
            "Capture the flag from the local integration target",
            local_http_target,
            port_range=str(urlsplit(local_http_target).port),
        )
    finally:
        await orchestrator.probe_client.close()

    assert result.success is True
    assert result.flag == FLAG
    assert orchestrator.dkg.query_nodes("Service")
    assert orchestrator.dkg.query_nodes("Endpoint")
    endpoint_nodes = orchestrator.dkg.query_nodes("Endpoint", with_provenance=True)
    assert endpoint_nodes and all(isinstance(node["provenance"], dict) for node in endpoint_nodes)
    assert any(call[0] == "generate" for call in llm.calls)
    # Plan review is now conditional (failure / world-model delta / stall), so
    # assert the topology-aware context reaches the LLM loop rather than
    # requiring a review prompt in a run that never needed one.  The review
    # prompt contract itself is covered by
    # tests/test_topology_context.py::test_execution_to_review_prompt_contains_topology_diff
    llm_prompts = [
        str(entry[2]) for entry in llm.calls if entry[0] == "generate"
    ]
    assert any("Topology (revision=" in p for p in llm_prompts)
    assert orchestrator.phase.value == "done"
    stub_calls = (cli_stub_path / "calls.log").read_text(encoding="utf-8")
    assert "nmap" in stub_calls
    assert "curl" in stub_calls


class ManifestReplayLLM(ReplayLLM):
    """Plans a READ tool against a POST-only route, then repairs it.

    Models the observed failure shape: the planner reaches for `curl_get`
    (with a parameter the tool does not even declare), the route answers 405 /
    rejects the request, and the fix must switch to a tool that can send the
    documented body.
    """

    def __init__(self, workflow_url: str):
        super().__init__(workflow_url)
        self.workflow_url = workflow_url
        self.fix_calls = 0

    def generate(self, prompt, system_prompt=None, tools=None, temperature=None,
                 timeout=180.0, stage=None):
        stage_text = str(stage or "").lower()
        if "fix_analysis" in stage_text:
            self.fix_calls += 1
            self.calls.append(("generate", stage, prompt, tools))
            return json.dumps({
                "fixable": True,
                "tool": "http_post",
                "corrected_params": {
                    "url": self.workflow_url,
                    "method": "POST",
                    "data": json.dumps({
                        "workspace": "tenant-a",
                        "dataset_ref": "../tenant-b/secret.txt",
                    }),
                },
                "reason": "the route only accepts POST with a JSON body",
            }), None
        if "task_execution" in stage_text:
            self.calls.append(("generate", stage, prompt, tools))
            return "", [{
                "name": "curl_get",
                "arguments": {
                    "url": self.workflow_url,
                    "param": "dataset_ref",
                    "payload": "../tenant-b/secret.txt",
                },
                "id": "replay-manifest-1",
            }]
        if "plan" in stage_text or "review" in stage_text or not stage_text:
            self.calls.append(("generate", stage, prompt, tools))
            return json.dumps([{
                "id": "local-workflow-read",
                "instruction": "Read the tenant dataset through the workflow control plane",
                "tool": "curl_get",
                "params": {
                    "url": self.workflow_url,
                    "param": "dataset_ref",
                    "payload": "../tenant-b/secret.txt",
                },
                "dependent_task_ids": [],
            }]), None
        return super().generate(
            prompt, system_prompt, tools, temperature, timeout, stage,
        )


@pytest.mark.asyncio
async def test_manifest_route_is_exercised_with_its_documented_method(
    tmp_path, monkeypatch, manifest_target, manifest_cli_stub_path
):
    """End-to-end: a read tool on a POST-only route is repaired, not abandoned."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("darwin.rag.get_rag", lambda: None)
    base_url, hits = manifest_target
    workflow_url = f"{base_url}/plane/workflows"
    from darwin.orchestrator import Orchestrator

    llm = ManifestReplayLLM(workflow_url)
    orchestrator = Orchestrator(llm_session=llm, time_budget=30, token_budget=2000)
    monkeypatch.setattr(orchestrator, "_augment_from_dkg", lambda: None)
    try:
        result = await orchestrator.run(
            "Capture the flag from the local workflow plane",
            base_url,
            port_range=str(urlsplit(base_url).port),
        )
    finally:
        await orchestrator.probe_client.close()

    assert result.success is True, result.error
    assert result.flag == FLAG
    assert ("POST", "/plane/workflows") in hits
    endpoints = {
        str(ep.get("url", "")): ep
        for ep in orchestrator.dkg.query_nodes("Endpoint")
    }
    workflow_ep = endpoints.get(workflow_url)
    assert workflow_ep is not None
    # The POST the target documented is the one that produced the flag.
    assert (workflow_ep.get("methods") or {}).get("POST") == 200
    # No route invented from the request's own verb ever entered world state.
    assert not [u for u in endpoints if u.rstrip("/").endswith("/POST")]


@pytest.mark.asyncio
async def test_recon_cli_stub_matches_production_parser(local_http_target, cli_stub_path):
    gateway = create_recon_gateway()
    result = await gateway.call("dirb_scan", {"target_url": local_http_target})
    assert result.success is True
    assert result.parsed_output["discovered_paths"] == [{"path": "/flag", "code": "(CODE:200)"}]
    assert "dirb" in (cli_stub_path / "calls.log").read_text(encoding="utf-8")


@pytest.mark.asyncio
async def test_runtime_executor_and_gateway_use_strict_shell_argv(tmp_path):
    """Runtime integration rejects unknown tools and executes a real argv tool."""
    gateway = MCPGateway()
    gateway.register_shell_argv_tool(
        "emit_flag",
        [sys.executable, "-c", "{code}"],
        "emit deterministic test output",
        {"code": {"type": "string"}},
    )
    executor = ToolExecutor(attack_gateway=gateway)

    task = Task(
        id="emit-flag",
        type="exploit",
        goal="emit a flag",
        action={"tool": "emit_flag", "params": {"code": f"print('{FLAG}')"}},
    )

    class Planner:
        async def plan(self, state, objective, memory):
            return TaskGraph([task])

        async def replan(self, state, graph, evaluation, memory):
            return graph

    class Scheduler:
        def next_ready(self, graph, budget):
            ready = graph.ready_tasks()
            return ready[0] if ready else None

    class Evaluator:
        async def evaluate(self, task, result, state):
            return Evaluation(task_id=task.id, outcome=TaskOutcome.SUCCESS,
                              replan=ReplanRecommendation.NONE)

    runtime = Runtime(
        planner=Planner(), scheduler=Scheduler(), executor=executor,
        evaluator=Evaluator(), memory=MemoryManager(),
    )
    outcome = await runtime.run(
        None,
        Objective(task_description="strict gateway", budgets=Budget(max_loops=2)),
        Budget(max_loops=2),
    )

    assert outcome.executed_tasks == ["emit-flag"]
    result = await gateway.call("missing_tool", {})
    assert result.success is False
    assert result.exit_code == -1
    assert "not found" in result.stderr.lower()


@pytest.mark.asyncio
async def test_gateway_shell_parser_exit_code_timeout_and_retry(tmp_path):
    gateway = MCPGateway()
    exit_script = tmp_path / "exit_script.py"
    exit_script.write_text("print('shell-output'); raise SystemExit(3)\n", encoding="utf-8")
    gateway.register_shell_tool(
        "shell_exit",
        f'"{sys.executable}" "{exit_script}"',
        "deterministic shell command",
        {},
        parser=lambda stdout: {"first_line": stdout.splitlines()[0] if stdout else ""},
        timeout=2,
        retries=0,
    )
    exited = await gateway.call("shell_exit", {})
    assert exited.success is False
    assert exited.exit_code == 3
    assert exited.parsed_output == {"first_line": "shell-output"}

    slow_script = tmp_path / "slow_script.py"
    slow_script.write_text("import time; time.sleep(0.2)\n", encoding="utf-8")
    gateway.register_shell_argv_tool(
        "argv_timeout",
        [sys.executable, str(slow_script)],
        "deterministic timeout command",
        {},
        timeout=0.05,
        retries=1,
    )
    timed_out = await gateway.call("argv_timeout", {})
    assert timed_out.success is False
    assert timed_out.exit_code == -1
    assert "timed out" in timed_out.stderr.lower()

    gateway.register_shell_tool(
        "shell_timeout",
        f'"{sys.executable}" "{slow_script}"',
        "deterministic shell timeout command",
        {},
        timeout=0.05,
        retries=1,
    )
    shell_timed_out = await gateway.call("shell_timeout", {})
    assert shell_timed_out.success is False
    assert shell_timed_out.exit_code == -1
    assert "timed out" in shell_timed_out.stderr.lower()


@pytest.mark.asyncio
async def test_runtime_replan_persists_memory_metrics_and_cteg(tmp_path):
    """A failed real argv execution must replan into a successful attempt."""
    gateway = MCPGateway()
    gateway.register_shell_argv_tool(
        "emit_result",
        [sys.executable, "-c", "{code}"],
        "emit deterministic test output",
        {"code": {"type": "string"}},
    )
    cteg = CTEG(storage_path=str(tmp_path / "cteg.json"))
    memory = MemoryManager(experience=cteg)
    executor = ToolExecutor(attack_gateway=gateway)
    failed = Task(
        id="attempt-1", type="exploit", goal="recover", action={
            "tool": "emit_result", "params": {"code": "import sys; print('blocked'); sys.exit(2)"}
        }, rationale="initial path",
    )
    replacement = Task(
        id="attempt-2", type="exploit", goal="recover", action={
            "tool": "emit_result", "params": {"code": f"print('{FLAG}')"}
        }, rationale="use a replacement path",
    )

    class Planner:
        def __init__(self):
            self.replan_calls = 0

        async def plan(self, state, objective, memory):
            return TaskGraph([failed])

        async def replan(self, state, graph, evaluation, memory):
            self.replan_calls += 1
            if evaluation.task_id == failed.id and graph.get(replacement.id) is None:
                graph.add(replacement)
            return graph

    class Scheduler:
        def next_ready(self, graph, budget):
            ready = graph.ready_tasks()
            return ready[0] if ready else None

    class Evaluator:
        async def evaluate(self, task, result, state):
            if task.id == failed.id:
                return Evaluation(
                    task_id=task.id, outcome=TaskOutcome.FAILED,
                    failure_type=FailureType.TOOL_ERROR,
                    evidence=[result.stderr], replan=ReplanRecommendation.LOCAL,
                )
            return Evaluation(task_id=task.id, outcome=TaskOutcome.SUCCESS,
                              replan=ReplanRecommendation.NONE)

    planner = Planner()
    runtime = Runtime(
        planner=planner, scheduler=Scheduler(), executor=executor,
        evaluator=Evaluator(), memory=memory,
    )
    outcome = await runtime.run(
        None, Objective(task_description="recover", budgets=Budget(max_loops=4)),
        Budget(max_loops=4),
    )

    assert outcome.executed_tasks == [failed.id, replacement.id]
    assert outcome.replan_count >= 1
    assert planner.replan_calls >= 1
    assert memory.plan.get(failed.id).rationale == "initial path"
    records = memory.execution.recent()
    assert len(records) == 2
    assert records[0].record.success is False
    assert records[1].record.success is True
    assert records[1].importance is ImportanceClass.PRESERVE
    assert cteg.query_exploit_patterns("emit_result")

    report = MetricsCalculator().calculate([
        {"event": "tool_result", "task_id": failed.id, "success": False, "adherence": True},
        {"event": "tool_result", "task_id": replacement.id, "success": True, "adherence": True},
        {"event": "task_evaluated", "task_id": failed.id, "failure_type": FailureType.TOOL_ERROR.value,
         "outcome": TaskOutcome.FAILED.value},
        {"event": "replan_requested", "task_id": failed.id, "action": "replace"},
    ])
    assert report.recovery_rate == 0.0
    assert report.failure_type_counts[FailureType.TOOL_ERROR.value] == 1
    assert report.replan_action_counts == {"replace": 1}


def test_dkg_provenance_round_trip_is_structured(tmp_path):
    dkg = DKG(storage_path=str(tmp_path / "dkg.json"))
    dkg.add_node("Endpoint", "ep-local", {"url": "http://local/flag"},
                 source="integration", evidence="HTTP probe", timestamp="t0")
    node = dkg.query_nodes("Endpoint", with_provenance=True)[0]
    assert node["provenance"] == {"source": "integration", "evidence": "HTTP probe", "timestamp": "t0"}
    assert dkg.get_provenance("ep-local")["source"] == "integration"
    loaded = DKG.load(str(tmp_path / "dkg.json"))
    assert loaded.get_provenance("ep-local")["evidence"] == "HTTP probe"


def test_dpm_detects_waf_from_probe_contract():
    dpm = DefensePerceptionModule()
    probes = [
        SimpleNamespace(probe_class="A", probe_value="<", blocked=True,
                        modified=False, reflected_value=""),
        SimpleNamespace(probe_class="B", probe_value="<script>", blocked=True,
                        modified=False, reflected_value=""),
    ]
    state = dpm.detect(probes, [], use_llm=False)
    assert state.defense_category == DefenseCategory.WAF
    assert state.filter_profile.blocked_chars == ["<"]
    assert state.defense_complexity > 0


@pytest.mark.asyncio
async def test_dave_covers_l1_l4_and_honeypot():
    dave = DAVE(browser_enabled=False)
    valid = ExploitAttempt(
        target_url="http://local/flag",
        http_response=HTTPResponse(
            url="http://local/flag", status_code=200, headers={},
            body=FLAG, elapsed_ms=1.0,
        ),
    )
    accepted = await dave.verify(valid)
    assert accepted.passed is True
    assert accepted.flag_value == FLAG
    assert accepted.layer_results[0].layer == 1
    assert accepted.layer_results[-1].layer == 4

    # A payload echoed back HTML-encoded still counts as impact: verification
    # is decided by L4 (flag extraction), and L3 no longer exists.
    modified = ExploitAttempt(
        target_url="http://local/search", payload="<script>alert(1)</script>",
        http_response=HTTPResponse(
            url="http://local/search", status_code=200, headers={},
            body="&lt;script&gt;alert(1)&lt;/script&gt; " + FLAG, elapsed_ms=1.0,
        ),
    )
    modified_result = await dave.verify(modified)
    assert modified_result.passed is True
    assert modified_result.flag_value == FLAG
    assert modified_result.layer_results[-1].layer == 4

    # A flag returned inside a 403/AccessDenied body must not be discarded by
    # the L1 block heuristics (cloud APIs answer this way routinely).
    forbidden_with_flag = ExploitAttempt(
        target_url="http://local/audit",
        http_response=HTTPResponse(
            url="http://local/audit", status_code=403, headers={},
            body='{"error":"AccessDenied","flag":"%s"}' % FLAG, elapsed_ms=1.0,
        ),
    )
    forbidden_result = await dave.verify(forbidden_with_flag)
    assert forbidden_result.passed is True
    assert forbidden_result.flag_value == FLAG

    blocked = ExploitAttempt(
        target_url="http://local/search?q=%3Cscript%3E",
        http_response=HTTPResponse(
            url="http://local/search", status_code=403, headers={},
            body="blocked by local waf", elapsed_ms=1.0,
        ),
    )
    blocked_result = await dave.verify(blocked)
    assert blocked_result.passed is False
    assert blocked_result.status is VerifyStatus.BLOCKED_BY_WAF
    assert blocked_result.defense_detected is True

    honeypot = ExploitAttempt(
        target_url="http://local/flag",
        tool_stdout="flag{honeypot}",
    )
    rejected = await dave.verify(honeypot)
    assert rejected.passed is False
    assert rejected.is_honeypot_flag is True
    assert rejected.status == VerifyStatus.FAIL
