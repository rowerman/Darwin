"""A wrong-verb call must be repaired by the framework, not re-planned by an LLM.

cloud-28 sent GET to a route that only answers POST, got ``405 Allow:
OPTIONS, POST``, had that diagnosed twice by the fix LLM — and never sent a
POST, because the fix could only edit parameters of the already-chosen
read-only tool. These tests pin the deterministic replacement rules.
"""

from __future__ import annotations

from darwin.orchestration.execution import ExecutionCoordinator
from darwin.orchestration.planning import PlanCoordinator
from darwin.tools.contracts import (
    capability_family,
    http_tool_can_express,
    http_tools_for,
    request_body_kind,
)
from darwin.tools.mcp_gateway import MCPGateway


def _coordinator(dkg=None):
    orch = type("Orch", (), {
        "attack_gateway": MCPGateway(),
        "recon_gateway": MCPGateway(),
        "dkg": dkg,
        "target_host": "localhost",
    })()
    coord = ExecutionCoordinator.__new__(ExecutionCoordinator)
    object.__setattr__(coord, "_orch", orch)
    return coord


class _FakeDKG:
    def __init__(self, endpoints):
        self._endpoints = endpoints

    def query_nodes(self, node_type=None, filters=None, **_kw):
        if node_type != "Endpoint":
            return []
        if filters:
            return [
                e for e in self._endpoints
                if all(e.get(k) == v for k, v in filters.items())
            ]
        return list(self._endpoints)

    def get_node(self, node_id):
        return next((e for e in self._endpoints if e.get("id") == node_id), None)

    def update_node(self, node_id, props):
        for node in self._endpoints:
            if node.get("id") == node_id:
                node.update(props)
        return True


def test_request_shape_capabilities():
    assert http_tools_for(["POST"], body_kind="json")[0] == "http_post"
    assert http_tools_for(["GET"])[0] == "curl_get"
    assert http_tools_for(["OPTIONS"])[0] == "http_method_probe"
    assert http_tool_can_express("curl_get", ["POST"], "json") is False
    assert request_body_kind({"data": '{"a": 1}'}) == "json"
    assert request_body_kind({"data": {"a": 1}}) == "json"
    assert request_body_kind({"url": "http://x"}) == "none"


def test_capability_family_groups_http_tools():
    assert capability_family("curl_get") == capability_family("http_post")
    assert capability_family("curl_get") != capability_family("sqlmap_test")


def test_documented_post_route_picks_a_write_capable_tool():
    coord = _coordinator(_FakeDKG([{
        "id": "ep-1", "url": "http://localhost:10639/egress",
        "method": "POST", "allow_methods": "OPTIONS, POST",
        "sample_status": 405, "provenance_level": "derived",
    }]))
    assert coord._endpoint_declared_methods(
        "http://localhost:10639/egress") == {"POST"}

    upgrade = coord._method_upgrade_candidate(
        "curl_get",
        {"url": "http://localhost:10639/egress"},
        [{"name": "curl_get", "args": {}, "success": False,
          "stdout": "HTTP/1.1 405 METHOD NOT ALLOWED\nAllow: OPTIONS, POST",
          "method": "GET"}],
    )
    assert upgrade is not None
    tool, params = upgrade
    assert http_tool_can_express(tool, ["POST"])
    assert params["url"] == "http://localhost:10639/egress"
    assert params.get("method") == "POST"


def test_no_upgrade_when_the_planned_tool_can_express_the_verb():
    coord = _coordinator(_FakeDKG([{
        "id": "ep-1", "url": "http://localhost:10639/workflows",
        "method": "POST", "documented_methods": "POST", "sample_status": 200,
        "provenance_level": "verified",
    }]))
    assert coord._method_upgrade_candidate(
        "http_post",
        {"url": "http://localhost:10639/workflows", "method": "POST"},
        [{"name": "http_post", "args": {}, "success": False,
          "stdout": "HTTP 405\nAllow: OPTIONS, POST", "method": "POST"}],
    ) is None


def test_derived_endpoints_are_not_verified():
    coord = _coordinator(_FakeDKG([
        {"id": "ep-1", "url": "http://h/execute", "sample_status": 404,
         "provenance_level": "derived"},
        {"id": "ep-2", "url": "http://h/workflows", "sample_status": 405,
         "provenance_level": "verified"},
    ]))
    assert coord._endpoint_is_verified("http://h/execute") is False
    assert coord._endpoint_is_verified("http://h/workflows") is True
    assert coord._endpoint_is_verified("http://h/never-seen") is False


def test_fix_may_switch_tools_only_inside_one_capability_family():
    assert ExecutionCoordinator._tool_in_same_capability_family(
        "curl_get", "http_post") is True
    assert ExecutionCoordinator._tool_in_same_capability_family(
        "curl_get", "sqlmap_test") is False
    assert ExecutionCoordinator._tool_in_same_capability_family(
        "", "http_post") is False


def test_guess_tool_respects_the_documented_verb():
    coord = PlanCoordinator.__new__(PlanCoordinator)
    assert coord._guess_tool("IDOR") == "curl_get"
    assert coord._guess_tool("IDOR", method="GET") == "curl_get"
    assert coord._guess_tool("IDOR", method="POST") != "curl_get"
    assert coord._guess_tool("LFI", method="POST") != "curl_get"
