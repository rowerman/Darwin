"""Tests for evidence-driven adaptive recon and POST/JSON route discovery.

Covers the pure extraction helpers in ``darwin.orchestration.recon`` plus the
coordinator-level ``_adaptive_web_probe`` / ``_api_route_discovery`` behavior
and the empty-vulnerability plan fallback in ``PlanCoordinator``.
"""

import json
import time

import pytest

from darwin.core.contracts import TaskStatus
from darwin.core.task import Task
from darwin.orchestrator import Orchestrator
from darwin.orchestration.recon import (
    _MAX_ROUTE_CANDIDATES,
    _same_origin_candidate,
    extract_json_route_fields,
    extract_openapi_routes,
    extract_route_candidates,
    looks_like_invoke_route,
)
from darwin.tools.mcp_gateway import ToolResult


# ── Pure extraction helpers ───────────────────────────────────────────

class TestCandidateExtraction:
    def test_html_links_and_scripts_are_same_origin_only(self):
        html = (
            '<a href="/login">login</a>'
            '<a href="https://evil.example/x">x</a>'
            '<a href="mailto:a@b.c">mail</a>'
            '<script src="/static/app.js"></script>'
            '<a href="#frag">frag</a>'
        )
        candidates = extract_route_candidates(
            html, {"links": ["/login", "https://evil.example/x", "mailto:a@b.c"],
                   "scripts": ["/static/app.js"]},
            "http://target:8000/",
        )
        urls = [u for u, _ in candidates]
        assert "http://target:8000/login" in urls
        assert "http://target:8000/static/app.js" in urls
        assert "https://evil.example/x" not in urls
        assert "mailto:a@b.c" not in urls
        assert "#frag" not in urls

    def test_js_fetch_xhr_and_api_strings(self):
        js = (
            "fetch('/api/invoke', {method:'POST'});"
            "axios.get('/users?page=1');"
            "xhr.open('GET', '/health');"
            "var u = {url: '/api/v1/objects'};"
            "const p = '/api/items';"
        )
        candidates = extract_route_candidates(js, {}, "http://t:8080/")
        urls = [u for u, _ in candidates]
        for path in ("/api/invoke", "/users?page=1", "/health",
                     "/api/v1/objects", "/api/items"):
            assert f"http://t:8080{path}" in urls, path

    def test_dedupe_preserves_first_source(self):
        html = '<a href="/x">1</a><a href="/x">2</a>'
        candidates = extract_route_candidates(
            html, {"links": ["/x", "/x"]}, "http://t/",
        )
        assert len(candidates) == 1
        assert candidates[0][0] == "http://t/x"

    def test_openapi_doc_paths_only_when_mentioned(self):
        assert extract_route_candidates(
            "no api docs here", {}, "http://t/"
        ) == []
        candidates = extract_route_candidates(
            "swagger UI available at /swagger-ui.html", {}, "http://t/"
        )
        urls = [u for u, _ in candidates]
        assert "http://t/swagger-ui.html" in urls
        assert "http://t/openapi.json" in urls

    def test_plain_text_route_docs(self):
        doc = "POST /api/invoke\nGET /health\nendpoint: /metrics"
        candidates = extract_route_candidates(doc, {}, "http://t:9000/")
        urls = [u for u, _ in candidates]
        assert "http://t:9000/api/invoke" in urls
        assert "http://t:9000/health" in urls
        assert "http://t:9000/metrics" in urls

    def test_same_origin_resolution(self):
        assert _same_origin_candidate(
            "/a", "http://t:8000/x"
        ) == "http://t:8000/a"
        assert _same_origin_candidate(
            "https://t:8000/b", "http://t:8000/x"
        ) == "https://t:8000/b"  # same netloc, scheme switch allowed by resolver
        assert _same_origin_candidate(
            "http://other:8000/c", "http://t:8000/x"
        ) is None
        assert _same_origin_candidate("javascript:void(0)", "http://t/") is None


class TestJsonRouteFields:
    def test_json_url_path_fields(self):
        payload = json.dumps({
            "routes": ["/api/invoke", "/api/status"],
            "links": {"self": "/api/self"},
            "data": {"url": "/api/objects"},
            "description": "/not-a-route-field",
        })
        found = extract_json_route_fields(payload, "http://t:8000/")
        paths = [p for p, _ in found]
        assert "/api/invoke" in paths
        assert "/api/status" in paths
        assert "/api/self" in paths
        assert "/api/objects" in paths
        assert "/not-a-route-field" not in paths

    def test_non_json_returns_empty(self):
        assert extract_json_route_fields("<html>", "http://t/") == []
        assert extract_json_route_fields("", "http://t/") == []


class TestOpenApiExtraction:
    def test_openapi_invoke_route_with_params(self):
        spec = {
            "openapi": "3.0.0",
            "paths": {
                "/invoke": {
                    "post": {
                        "parameters": [{"name": "function", "in": "query"}],
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "code": {"type": "string"},
                                            "language": {"type": "string"},
                                        },
                                    }
                                }
                            }
                        },
                    }
                },
                "/health": {"get": {}},
            },
        }
        routes = extract_openapi_routes(json.dumps(spec))
        by_path = {r["path"]: r for r in routes}
        assert set(by_path) == {"/invoke", "/health"}
        invoke = by_path["/invoke"]
        assert invoke["methods"] == ["POST"]
        assert invoke["body_format"] == "json"
        assert set(invoke["params"]) == {"function", "code", "language"}
        assert by_path["/health"]["methods"] == ["GET"]

    def test_invalid_openapi_returns_empty(self):
        assert extract_openapi_routes("not json") == []
        assert extract_openapi_routes(json.dumps({"paths": "nope"})) == []


class TestInvokeSignal:
    def test_invoke_path_signal(self):
        assert looks_like_invoke_route("/api/invoke", ["POST"], ["code"]) is True
        assert looks_like_invoke_route("/api/users", ["GET"], []) is False
        assert looks_like_invoke_route("/api/run", ["POST"], []) is True
        assert looks_like_invoke_route("/api/status", ["POST"], ["command"]) is True


# ── Coordinator-level behavior ─────────────────────────────────────────

class FakeGateway:
    def __init__(self, responses, schemas=None):
        self.responses = responses
        self.schemas = schemas or {}
        self.calls = []

    def get_tool_names(self):
        return set(self.responses) | set(self.schemas)

    def get_tool_definitions(self):
        return []

    async def call(self, name, params):
        self.calls.append((name, params))
        result = self.responses.get(name)
        if result is None:
            return ToolResult(
                tool_name=name, success=False, stdout="",
                stderr=f"Tool '{name}' not configured", exit_code=-1,
                elapsed_ms=1.0,
            )
        return result


class FakeMCPPool:
    def get_tool_names(self):
        return set()

    def get_tool_definitions(self):
        return []

    async def call_tool(self, name, params):
        return {"isError": True, "content": []}


class FakeCTEG:
    def __init__(self, storage_path="cteg_state.json"):
        self.storage_path = storage_path

    def add_credential(self, **kwargs):
        pass

    def commit_task(self, *args, **kwargs):
        pass

    def get_credentials(self, *args, **kwargs):
        return []

    def get_suggestions(self, *args, **kwargs):
        return {}


class FakeLLM:
    def __init__(self, content="ok"):
        self.content = content
        self.token_count = 100
        self._compressed_count = 0
        self.calls = []

    @property
    def context_load(self):
        return 0.0

    def replace_system_prompt(self, prompt):
        self.calls.append(("replace_system_prompt", prompt))

    def add_context_message(self, content, role="user"):
        self.calls.append(("add_context_message", content))

    def add_tool_result(self, tool_call_id, result):
        self.calls.append(("add_tool_result", tool_call_id, result))

    def generate(self, prompt, system_prompt=None, tools=None,
                 temperature=None, timeout=180.0, stage=None):
        self.calls.append(("generate", prompt))
        return self.content, None

    def compress(self, **kwargs):
        return 0


def _make_orchestrator(llm, recon_gw, attack_gw, monkeypatch):
    monkeypatch.setattr("darwin.orchestrator.create_recon_gateway",
                        lambda: recon_gw)
    monkeypatch.setattr("darwin.orchestrator.create_attack_gateway",
                        lambda: attack_gw)
    monkeypatch.setattr("darwin.orchestrator.MCPClientPool", FakeMCPPool)
    monkeypatch.setattr("darwin.orchestrator.CTEG", FakeCTEG)
    orch = Orchestrator(llm_session=llm, time_budget=1200)
    orch.start_time = time.time()
    return orch


def _http_response(body, status=200, content_type="text/html"):
    return ToolResult(
        tool_name="curl_get", success=True,
        stdout=f"HTTP/1.1 {status} OK\nContent-Type: {content_type}\n\n{body}",
        stderr="", exit_code=0, elapsed_ms=1.0,
        parsed_output={"status": status, "content_type": content_type, "body": body},
    )


@pytest.mark.asyncio
async def test_adaptive_web_probe_records_bounded_deduped_endpoints(monkeypatch):
    html = (
        '<a href="/login">l</a><a href="/login">dup</a>'
        '<a href="https://evil.example/x">x</a>'
        '<script src="/static/app.js"></script>'
    )
    recon_gw = FakeGateway({"curl_get": _http_response("page")})
    orch = _make_orchestrator(FakeLLM(), recon_gw, FakeGateway({}), monkeypatch)
    # pre-existing endpoint is not re-probed
    orch.dkg.add_node("Endpoint", "ep-known", {"url": "http://target:8000/login"})

    parsed = {"links": ["/login", "/login", "https://evil.example/x"],
              "scripts": ["/static/app.js"]}
    await orch.recon._adaptive_web_probe(
        "target", "http://target:8000/", html, parsed,
    )

    eps = orch.dkg.query_nodes("Endpoint")
    probed_urls = {e["url"] for e in eps if e.get("discovered_by") == "adaptive-web-probe"}
    assert "http://target:8000/static/app.js" in probed_urls
    assert "http://target:8000/login" not in probed_urls  # already known
    assert all("evil.example" not in u for u in probed_urls)
    assert len(probed_urls) == 1


@pytest.mark.asyncio
async def test_adaptive_web_probe_respects_candidate_cap(monkeypatch):
    many_links = "".join(f'<a href="/p{i}">{i}</a>' for i in range(80))
    recon_gw = FakeGateway({"curl_get": _http_response("x")})
    orch = _make_orchestrator(FakeLLM(), recon_gw, FakeGateway({}), monkeypatch)
    await orch.recon._adaptive_web_probe(
        "target", "http://target:8000/", many_links, {},
    )
    probed = [c for c in recon_gw.calls if c[0] == "curl_get"]
    assert len(probed) == _MAX_ROUTE_CANDIDATES
    assert len({c[1]["url"] for c in probed}) == _MAX_ROUTE_CANDIDATES


@pytest.mark.asyncio
async def test_api_route_discovery_openapi_records_post_json_and_params(monkeypatch):
    spec = {
        "openapi": "3.0.0",
        "paths": {
            "/invoke": {
                "post": {
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "code": {"type": "string"},
                                        "command": {"type": "string"},
                                    },
                                }
                            }
                        }
                    }
                }
            }
        },
    }
    recon_gw = FakeGateway({
        "http_method_probe": ToolResult(
            tool_name="http_method_probe", success=True,
            stdout="HTTP/1.1 200 OK\nAllow: GET, POST, OPTIONS\n\n",
            stderr="", exit_code=0, elapsed_ms=1.0,
            parsed_output={"status": 200, "allow": "GET, POST, OPTIONS",
                           "content_type": ""},
        )
    })
    orch = _make_orchestrator(FakeLLM(), recon_gw, FakeGateway({}), monkeypatch)
    await orch.recon._api_route_discovery(
        "target", "http://target:8000/", json.dumps(spec),
    )

    eps = orch.dkg.query_nodes("Endpoint")
    post_eps = [e for e in eps if e.get("method") == "POST"
                and e.get("url") == "http://target:8000/invoke"]
    assert post_eps, [e.get("url") for e in eps]
    ep = post_eps[0]
    assert ep["body_format"] == "json"
    assert set(ep["params"].split(",")) == {"code", "command"}
    assert ep["invoke_signal"] is True
    assert ep["discovered_by"] == "adaptive-api-probe"
    assert set(ep["allow_methods"].split(",")) == {"GET", "POST", "OPTIONS"}


@pytest.mark.asyncio
async def test_api_route_discovery_no_schema_does_not_fabricate_params(monkeypatch):
    payload = json.dumps({"routes": ["/invoke"], "links": {"self": "/api/self"}})
    recon_gw = FakeGateway({
        "http_method_probe": ToolResult(
            tool_name="http_method_probe", success=True,
            stdout="HTTP/1.1 405 Method Not Allowed\nAllow: POST\n\n",
            stderr="", exit_code=0, elapsed_ms=1.0,
            parsed_output={"status": 405, "allow": "POST", "content_type": ""},
        )
    })
    orch = _make_orchestrator(FakeLLM(), recon_gw, FakeGateway({}), monkeypatch)
    await orch.recon._api_route_discovery(
        "target", "http://target:8000/", payload,
    )

    eps = orch.dkg.query_nodes("Endpoint")
    post_eps = [e for e in eps if e.get("method") == "POST"]
    assert post_eps
    assert all(e["params"] == "" for e in post_eps), "params must not be invented"
    assert any(e["invoke_signal"] is True for e in post_eps)
    assert all(e["body_format"] == "json" for e in post_eps)


@pytest.mark.asyncio
async def test_api_route_discovery_plain_text_route_docs(monkeypatch):
    doc = "POST /invoke\nGET /health"
    recon_gw = FakeGateway({
        "http_method_probe": ToolResult(
            tool_name="http_method_probe", success=True,
            stdout="HTTP/1.1 200 OK\nAllow: POST\n\n",
            stderr="", exit_code=0, elapsed_ms=1.0,
            parsed_output={"status": 200, "allow": "POST", "content_type": ""},
        )
    })
    orch = _make_orchestrator(FakeLLM(), recon_gw, FakeGateway({}), monkeypatch)
    await orch.recon._api_route_discovery("target", "http://t:9000/", doc)
    urls = {e["url"] for e in orch.dkg.query_nodes("Endpoint")}
    assert "http://t:9000/invoke" in urls
    assert "http://t:9000/health" in urls
    # route-doc POST method is recorded, not guessed
    invoke_eps = [e for e in orch.dkg.query_nodes("Endpoint")
                  if e["url"] == "http://t:9000/invoke"]
    assert {e["method"] for e in invoke_eps} == {"POST"}


@pytest.mark.asyncio
async def test_bootstrap_uses_adaptive_discovery_not_fixed_paths(monkeypatch):
    """Bootstrap probes evidence-driven candidates and never the old fixed list."""
    html = (
        '<html><a href="/login">login</a>'
        '<script src="/app.js"></script></html>'
    )
    nmap_resp = ToolResult(
        tool_name="nmap_full_scan", success=True, stdout="",
        parsed_output={"open_ports": [
            {"port": 8000, "service": "http", "version": ""}
        ]},
        stderr="", exit_code=0, elapsed_ms=1.0,
    )
    curl_root = ToolResult(
        tool_name="curl_get", success=True,
        stdout=f"HTTP/1.1 200 OK\nContent-Type: text/html\n\n{html}",
        stderr="", exit_code=0, elapsed_ms=1.0,
        parsed_output={"status": 200},
    )
    parse_resp = ToolResult(
        tool_name="response_parse", success=True,
        stdout=json.dumps({
            "type": "html", "links": ["/login"], "scripts": ["/app.js"],
            "api_paths": [], "endpoints": [], "forms": 1,
        }),
        stderr="", exit_code=0, elapsed_ms=1.0,
        parsed_output={
            "type": "html", "links": ["/login"], "scripts": ["/app.js"],
            "api_paths": [], "endpoints": [], "forms": 1,
        },
    )
    ww = ToolResult(
        tool_name="whatweb_scan", success=True, stdout="",
        parsed_output={"technologies": []},
        stderr="", exit_code=0, elapsed_ms=1.0,
    )
    recon_gw = FakeGateway({
        "nmap_full_scan": nmap_resp, "curl_get": curl_root,
        "response_parse": parse_resp, "whatweb_scan": ww,
        "http_method_probe": ToolResult(
            tool_name="http_method_probe", success=True,
            stdout="HTTP/1.1 200 OK\nAllow: GET, POST\n\n",
            stderr="", exit_code=0, elapsed_ms=1.0,
            parsed_output={"status": 200, "allow": "GET, POST",
                           "content_type": ""},
        ),
    })
    orch = _make_orchestrator(FakeLLM(), recon_gw, FakeGateway({}), monkeypatch)
    orch._provided_username = None
    orch._provided_password = None
    orch._task_description = "test"

    await orch.recon._bootstrap_scan("http://localhost:8000", port_range="")

    probed = [p for t, p in recon_gw.calls if t == "curl_get"]
    probed_urls = [p["url"] for p in probed]
    assert "http://localhost:8000" in probed_urls
    assert "http://localhost:8000/login" in probed_urls
    assert "http://localhost:8000/app.js" in probed_urls
    # the old fixed path list must not be probed
    for fixed in ("/admin", "/api", "/health", "/metrics", "/console",
                  "/index.html", "/dashboard", "/buckets"):
        assert not any(u.endswith(fixed) for u in probed_urls), fixed


# ── Empty-vulnerability plan fallback ─────────────────────────────────

class TestPlanFallback:
    @pytest.mark.asyncio
    async def test_collect_api_endpoints_dedupes_and_bounds(self, monkeypatch):
        orch = _make_orchestrator(FakeLLM(), FakeGateway({}), FakeGateway({}),
                                  monkeypatch)
        dkg = orch.dkg
        dkg.add_node("Endpoint", "e1", {
            "url": "http://t:8000/invoke", "method": "POST",
            "body_format": "json", "params": "code",
        })
        dkg.add_node("Endpoint", "e2", {
            "url": "http://t:8000/invoke", "method": "POST",
            "body_format": "json", "params": "code",  # duplicate combo
        })
        dkg.add_node("Endpoint", "e3", {
            "url": "http://t:8000/health", "method": "GET",
            "sample_content_type": "application/json",
        })
        dkg.add_node("Endpoint", "e4", {
            "url": "http://t:8000/", "method": "GET",
            "sample_content_type": "text/html",
        })
        collected = orch.planning._collect_api_verification_endpoints()
        combos = {(e["url"], e["method"]) for e in collected}
        assert combos == {("http://t:8000/invoke", "POST"),
                          ("http://t:8000/health", "GET")}

    @pytest.mark.asyncio
    async def test_build_tasks_post_json_without_schema_uses_empty_probe(self, monkeypatch):
        orch = _make_orchestrator(FakeLLM(), FakeGateway({}), FakeGateway({}),
                                  monkeypatch)
        tasks = orch.planning._build_api_verification_tasks([
            {"url": "http://t:8000/invoke", "method": "POST",
             "params": [], "body_format": "json"},
            {"url": "http://t:8000/health", "method": "GET",
             "params": [], "body_format": ""},
        ])
        assert len(tasks) == 2
        post_task = tasks[0]
        assert post_task.action["tool"] == "http_method_probe"
        assert post_task.action["params"]["data"] == "{}"
        assert post_task.action["params"]["method"] == "POST"
        assert post_task.vuln_type == "RouteVerification"
        assert post_task.status is TaskStatus.READY

    @pytest.mark.asyncio
    async def test_build_tasks_uses_known_params_when_schema_exists(self, monkeypatch):
        orch = _make_orchestrator(FakeLLM(), FakeGateway({}), FakeGateway({}),
                                  monkeypatch)
        tasks = orch.planning._build_api_verification_tasks([
            {"url": "http://t:8000/invoke", "method": "POST",
             "params": ["code", "command"], "body_format": "json"},
        ])
        data = json.loads(tasks[0].action["params"]["data"])
        assert data == {"code": "sample_code", "command": "sample_command"}

    @pytest.mark.asyncio
    async def test_empty_plan_generates_verification_tasks(self, monkeypatch):
        llm = FakeLLM(content="no JSON here")
        recon_gw = FakeGateway({})
        attack_gw = FakeGateway({})
        orch = _make_orchestrator(llm, recon_gw, attack_gw, monkeypatch)
        orch.dkg.add_node("Endpoint", "ep-invoke", {
            "url": "http://t:8000/invoke", "method": "POST",
            "body_format": "json", "params": "", "discovered_by": "adaptive-api-probe",
        })

        plan = await orch.planning._generate_exploitation_plan("http://t:8000/")

        assert plan.tasks, "empty analyze output must produce verification tasks"
        assert all(t.source == "api-route-verification" for t in plan.tasks)
        assert all(t.vuln_type == "RouteVerification" for t in plan.tasks)
        assert all(
            t.action["tool"] in ("http_method_probe", "curl_get", "response_parse")
            for t in plan.tasks
        )

    @pytest.mark.asyncio
    async def test_empty_plan_without_api_endpoints_stays_empty(self, monkeypatch):
        llm = FakeLLM(content="no JSON here")
        orch = _make_orchestrator(llm, FakeGateway({}), FakeGateway({}), monkeypatch)
        plan = await orch.planning._generate_exploitation_plan("http://t:8000/")
        assert plan.tasks == []
