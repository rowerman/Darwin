"""Bounded REST route exploration from already-observed identifiers.

A REST API answers 404/405 for a wrong path SHAPE (collection route vs
detail route) even when the verb is right. These helpers derive the
neighbour paths a human would try next — bounded, and built only from
values the target itself disclosed.
"""

from __future__ import annotations

from darwin.orchestration.execution import (
    ExecutionCoordinator,
    _last_http_status,
)
from darwin.orchestration.recon import ReconCoordinator
from darwin.orchestration.research import ResearchCoordinator
from darwin.tools.mcp_gateway import ToolResult
from darwin.utils.urls import (
    ROUTE_VARIANT_MAX,
    observed_identifiers,
    response_body,
    route_variants,
)


def test_route_variants_appends_observed_identifiers():
    variants = route_variants(
        "http://h:1/packages", ["pkg", "1.0.0"]
    )
    assert "http://h:1/packages/pkg" in variants
    assert "http://h:1/packages/pkg/1.0.0" in variants


def test_route_variants_are_bounded_and_exclude_the_original():
    variants = route_variants(
        "http://h:1/packages", ["a", "b", "c", "d", "e", "f", "g"]
    )
    assert len(variants) <= ROUTE_VARIANT_MAX
    assert "http://h:1/packages" not in variants


def test_route_variants_ignore_non_identifier_tokens():
    variants = route_variants(
        "http://h:1/packages", ["not a path segment", "a/b", "Werkzeug/3.1.8"]
    )
    assert variants == []


def test_route_variants_do_nothing_without_identifiers():
    assert route_variants("http://h:1/packages", []) == []


def test_route_variants_stop_on_deep_paths():
    assert route_variants("http://h:1/a/b/c/d/e", ["x"]) == []


def test_observed_identifiers_prefers_json_values():
    body = (
        '{"requirements": [{"name": "pkg", "note": "a sentence here", '
        '"version": "1.0.0"}], "service": "Managed Platform"}'
    )
    assert observed_identifiers(body) == ["pkg", "1.0.0"]


def test_response_body_strips_the_header_block():
    stdout = 'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"a": 1}'
    assert response_body(stdout) == '{"a": 1}'
    assert response_body("no headers here") == "no headers here"


def test_last_http_status_reads_the_executed_calls():
    calls = [
        {"stdout": "HTTP/1.1 404 NOT FOUND\n\nnope"},
        {"stdout": "HTTP/1.1 405 METHOD NOT ALLOWED\n\nnope"},
    ]
    assert _last_http_status(calls) == 405
    assert _last_http_status([]) is None


def _coordinator_with_endpoints(endpoints: list[dict]) -> ExecutionCoordinator:
    dkg = type("DKG", (), {
        "query_nodes": lambda self, kind: list(endpoints) if kind == "Endpoint" else [],
        "add_node": lambda self, *args, **kwargs: None,
    })()
    orch = type("Orch", (), {"target_host": "localhost", "dkg": dkg})()
    coord = ExecutionCoordinator.__new__(ExecutionCoordinator)
    object.__setattr__(coord, "_orch", orch)
    return coord


def test_route_identifiers_read_the_hosts_other_responses():
    coord = _coordinator_with_endpoints([
        {"url": "http://localhost:10637", "sample_response":
            '{"requirements":[{"name":"pkg","version":"1.0.0"}]}'},
        {"url": "http://localhost:10726", "sample_response": '{"packages":[]}'},
    ])
    identifiers = coord._route_identifiers({"url": "http://localhost:10726/packages"})
    assert identifiers == ["pkg", "1.0.0"]


def test_route_identifiers_stay_on_the_target_host():
    coord = _coordinator_with_endpoints([
        {"url": "http://other-host:8080", "sample_response": '{"name":"pkg"}'},
    ])
    assert coord._route_identifiers({}) == []


def _research_coordinator(endpoints: list[dict], services: list[dict]) -> ResearchCoordinator:
    dkg = type("DKG", (), {
        "query_nodes": lambda self, kind: (
            list(endpoints) if kind == "Endpoint"
            else list(services) if kind == "Service"
            else []
        ),
    })()
    orch = type("Orch", (), {
        "target_host": "localhost",
        "target_url": "http://localhost",
        "dkg": dkg,
    })()
    coord = ResearchCoordinator.__new__(ResearchCoordinator)
    object.__setattr__(coord, "_orch", orch)
    return coord


def test_hypothesis_endpoint_port_in_path_is_repaired():
    coord = _research_coordinator(
        [{"url": "http://localhost:10726"}], [{"port": 10726}]
    )
    assert coord._normalize_hypothesis_endpoint("http://localhost/10726") == (
        "http://localhost:10726"
    )


def test_hypothesis_endpoint_on_an_undiscovered_port_is_dropped():
    coord = _research_coordinator(
        [{"url": "http://localhost:10726"}], [{"port": 10726}]
    )
    assert coord._normalize_hypothesis_endpoint("http://localhost:9999") == ""


def test_hypothesis_endpoint_keeps_discovered_and_non_url_values():
    coord = _research_coordinator(
        [{"url": "http://localhost:10726"}], [{"port": 10726}]
    )
    assert coord._normalize_hypothesis_endpoint("http://localhost:10726") == (
        "http://localhost:10726"
    )
    assert coord._normalize_hypothesis_endpoint("/etc/passwd") == "/etc/passwd"


def _recon_coordinator(endpoints: list[dict]):
    added: list[tuple] = []

    class _DKG:
        def query_nodes(self, kind):
            return list(endpoints) if kind == "Endpoint" else []

        def add_node(self, kind, node_id, props):
            added.append((kind, node_id, props))

    orch = type("Orch", (), {"target_host": "localhost", "dkg": _DKG()})()
    coord = ReconCoordinator.__new__(ReconCoordinator)
    object.__setattr__(coord, "_orch", orch)
    return coord, added


async def _stub_probe(_name, args):
    return ToolResult(
        tool_name="http_method_probe", success=True,
        stdout="HTTP 200\nAllow: OPTIONS, PUT, HEAD, GET\n\n{}",
        stderr="", exit_code=0, elapsed_ms=0.0,
        parsed_output={"status": 200, "allow": "OPTIONS, PUT, HEAD, GET"},
    )


def test_collection_child_probe_only_uses_the_safe_verb():
    async def _run():
        coord, added = _recon_coordinator([
            {"url": "http://localhost:10637", "sample_response":
                '{"requirements":[{"name":"pkg","version":"1.0.0"}]}'},
        ])
        calls: list[tuple] = []

        async def _call_tool(name, args):
            calls.append((name, args))
            return await _stub_probe(name, args)

        coord.__dict__["_call_tool"] = _call_tool
        await coord._probe_collection_children("http://localhost:10726/packages", "{}")

        assert calls, "no derived route was probed"
        assert {name for name, _ in calls} == {"http_method_probe"}
        assert {args["method"] for _, args in calls} == {"OPTIONS"}
        urls = [args["url"] for _, args in calls]
        assert "http://localhost:10726/packages/pkg/1.0.0" in urls
        assert any(props.get("discovered_by") == "collection-child-probe"
                   for _, _, props in added)

    import asyncio
    asyncio.run(_run())


def test_collection_child_probe_skips_known_routes():
    import asyncio

    async def _run():
        coord, _ = _recon_coordinator([
            {"url": "http://localhost:10637", "sample_response":
                '{"requirements":[{"name":"pkg"}]}'},
            {"url": "http://localhost:10726/packages/pkg"},
        ])
        calls: list[tuple] = []

        async def _call_tool(name, args):
            calls.append((name, args))
            return await _stub_probe(name, args)

        coord.__dict__["_call_tool"] = _call_tool
        await coord._probe_collection_children("http://localhost:10726/packages", "{}")

        assert all(args["url"] != "http://localhost:10726/packages/pkg"
                   for _, args in calls)

    asyncio.run(_run())
