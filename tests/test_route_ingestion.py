"""Discovery tools must feed the world state, not just the console.

cloud-30 ran ffuf twice (8 KB of results each) and logged "no new state
discovered" both times: `ffuf_fuzz` had no output parser, so the paths it
found never became Endpoint nodes and the planner kept re-probing the root.
"""

from __future__ import annotations

import pytest

from darwin.orchestration.execution import ExecutionCoordinator
from darwin.tools.attack_server import _parse_ffuf_output


_FFUF_OUTPUT = """
        /'___\\  /'___\\           /'___\\
       /\\ \\__/ /\\ \\__/  __  __  /\\ \\__/
       \\ \\ ,__\\\\ \\ ,__\\/\\ \\ \\ \\ \\ \\ ,__\\
        \\ \\ \\_/ \\ \\ \\_/\\ \\ \\_\\ \\ \\ \\ \\ \\_/
         \\ \\_\\   \\ \\_\\  \\ \\____/  \\ \\_\\       /\\/___/
          \\/_/    \\/_/   \\/___/    \\/_/       \\/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://localhost:10641/FUZZ
 :: Progress: [100/100] :: Job [1/1] :: 0 req/sec

deploy                  [Status: 405, Size: 96, Words: 6, Lines: 1, Duration: 1ms]
invoke                  [Status: 200, Size: 42, Words: 3, Lines: 1, Duration: 0ms]
missing                 [Status: 404, Size: 207, Words: 6, Lines: 1, Duration: 0ms]
http://localhost:10641/api/v1 [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 0ms]
"""


def test_ffuf_parser_extracts_paths_and_statuses():
    parsed = _parse_ffuf_output(_FFUF_OUTPUT)
    assert parsed["count"] == 4
    found = {p["path"]: p["code"] for p in parsed["discovered_paths"]}
    assert found["/deploy"] == "405"
    assert found["/invoke"] == "200"
    assert found["/missing"] == "404"
    assert found["/api/v1"] == "301"


def test_ffuf_parser_ignores_banner_and_progress():
    parsed = _parse_ffuf_output("   /'___\\ \n :: Progress: [1/2] :: Job [1/1]\n")
    assert parsed["discovered_paths"] == []


# Real ffuf output: progress is repainted with \r and each repaint is prefixed
# with the ANSI erase sequence, so the match line is glued onto the progress
# line instead of starting one of its own.
_FFUF_REAL_STDOUT = (
    "\x1b[2K:: Progress: [1/4614] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] "
    ":: Errors: 0 ::\r\x1b[2K                        [Status: 200, Size: 67, Words: 4, "
    "Lines: 2, Duration: 2ms]\x1b[0m\r\x1b[2K:: Progress: [40/4614] :: Job [1/1] :: "
    "0 req/sec :: Duration: [0:00:00] :: Errors: 0 ::\r\x1b[2Kdeploy                  "
    "[Status: 405, Size: 153, Words: 16, Lines: 6, Duration: 36ms]\x1b[0m\r"
    "\x1b[2K:: Progress: [4614/4614] :: Job [1/1] :: 1136 req/sec :: "
    "Duration: [0:00:04] :: Errors: 0 ::\r\n"
)


def test_ffuf_parser_survives_ansi_and_carriage_returns():
    parsed = _parse_ffuf_output(_FFUF_REAL_STDOUT)
    assert [p["path"] for p in parsed["discovered_paths"]] == ["/deploy"]
    assert parsed["scan_completed"] is True
    assert parsed["enumeration_error"] == ""


_FFUF_JSON_STDOUT = (
    '{"commandline":"ffuf -u http://t/FUZZ","results":['
    '{"input":{"FFUFHASH":"ab","FUZZ":""},"status":200,"url":"http://t/",'
    '"length":67,"content-type":"application/json"},'
    '{"input":{"FFUFHASH":"cd","FUZZ":"deploy"},"status":405,'
    '"url":"http://t/deploy","length":153}]}'
)


def test_ffuf_parser_prefers_the_json_document():
    parsed = _parse_ffuf_output(_FFUF_JSON_STDOUT)
    # The empty FUZZ word hits the base URL and is not a route discovery.
    assert [p["path"] for p in parsed["discovered_paths"]] == ["/deploy"]
    assert parsed["discovered_paths"][0]["code"] == "405"
    assert parsed["scan_completed"] is True


def test_ffuf_parser_reports_a_scan_that_never_ran():
    parsed = _parse_ffuf_output(
        "Encountered error(s): 1 errors occurred.\n"
        "\t* stat /tmp/common.txt: no such file or directory\n"
    )
    assert parsed["discovered_paths"] == []
    assert parsed["scan_completed"] is False
    assert parsed["enumeration_error"]


class _RecordingDKG:
    def __init__(self):
        self.nodes = {}

    def query_nodes(self, node_type=None, filters=None, **_kw):
        if node_type != "Endpoint":
            return []
        return [{"id": k, **v} for k, v in self.nodes.items()]

    def get_node(self, node_id):
        return self.nodes.get(node_id)

    def add_node(self, node_type, node_id, props=None, **kw):
        self.nodes[node_id] = dict(props or {})
        return node_id

    def update_node(self, node_id, props):
        self.nodes.setdefault(node_id, {}).update(props)
        return True


def _coordinator(dkg):
    orch = type("Orch", (), {
        "attack_gateway": None, "recon_gateway": None,
        "dkg": dkg, "target_host": "",
        "_task_log_event": lambda self, *a, **k: None,
    })()
    coord = ExecutionCoordinator.__new__(ExecutionCoordinator)
    object.__setattr__(coord, "_orch", orch)
    return coord


def _result(parsed):
    return type("R", (), {"parsed_output": parsed, "success": True})()


def test_ingested_routes_become_world_state_with_a_trust_level():
    dkg = _RecordingDKG()
    coord = _coordinator(dkg)
    coord._ingest_observed_routes(
        "ffuf_fuzz",
        {"url": "http://localhost:10641/FUZZ"},
        _result(_parse_ffuf_output(_FFUF_OUTPUT)),
    )
    urls = {v.get("url"): v for v in dkg.nodes.values()}
    assert "http://localhost:10641/deploy" in urls
    assert urls["http://localhost:10641/invoke"]["provenance_level"] == "verified"
    assert urls["http://localhost:10641/missing"]["provenance_level"] == "derived"
    assert coord._orch is not None


def test_ingestion_is_a_noop_without_parsed_paths():
    dkg = _RecordingDKG()
    coord = _coordinator(dkg)
    coord._ingest_observed_routes(
        "ffuf_fuzz", {"url": "http://h/FUZZ"}, _result({}),
    )
    assert dkg.nodes == {}


def test_a_405_fuzz_hit_is_a_route_with_an_unknown_verb():
    """`deploy [Status: 405]` says the route exists; only the verb is missing."""
    dkg = _RecordingDKG()
    coord = _coordinator(dkg)
    coord._ingest_observed_routes(
        "ffuf_fuzz",
        {"url": "http://h:1/FUZZ"},
        _result(_parse_ffuf_output(_FFUF_JSON_STDOUT)),
    )

    node = dkg.nodes["ep-" + __import__("hashlib").sha1(
        b"http://h:1/deploy").hexdigest()[:10]]
    assert node["provenance_level"] == "verified"
    assert node["verb_unknown"] is True
    assert "method" not in node
    assert coord._routes_with_unknown_verb() == ["http://h:1/deploy"]


def test_routes_with_a_known_verb_are_not_probed_again():
    dkg = _RecordingDKG()
    coord = _coordinator(dkg)
    dkg.add_node("Endpoint", "ep-1", {
        "url": "http://h:1/known", "method": "GET", "allow_methods": "GET, POST",
        "methods": {"GET": 200},
    })
    dkg.add_node("Endpoint", "ep-2", {
        "url": "http://h:1/deploy", "methods": {"GET": 405},
        "verb_unknown": True,
    })

    assert coord._routes_with_unknown_verb() == ["http://h:1/deploy"]


@pytest.mark.asyncio
async def test_verb_probe_writes_the_allow_header_back_to_the_route():
    dkg = _RecordingDKG()
    calls: list[dict] = []

    async def _call_tool(name, params):
        calls.append({"name": name, **params})
        return type("R", (), {"parsed_output": {
            "status": 200, "allow": "POST, OPTIONS",
            "headers": {"Allow": "POST, OPTIONS"},
        }, "success": True})()

    dkg.add_node("Endpoint", "ep-1", {
        "url": "http://h:1/deploy", "methods": {"GET": 405},
        "verb_unknown": True,
    })
    orch = type("Orch", (), {
        "attack_gateway": None, "recon_gateway": None,
        "dkg": dkg, "target_host": "",
        "_task_log_event": lambda self, *a, **k: None,
        "_tool_port": type("Port", (), {"call": staticmethod(_call_tool)})(),
        "_remaining_budget": staticmethod(lambda: 100.0),
    })()
    coord = ExecutionCoordinator.__new__(ExecutionCoordinator)
    object.__setattr__(coord, "_orch", orch)

    assert await coord._probe_route_verbs() == 1
    assert calls == [{"name": "http_method_probe", "url": "http://h:1/deploy",
                      "method": "OPTIONS"}]
    assert dkg.nodes["ep-1"]["allow_methods"] == "POST, OPTIONS"
    assert dkg.nodes["ep-1"]["verb_unknown"] is False
