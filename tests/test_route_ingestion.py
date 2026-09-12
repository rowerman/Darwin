"""Discovery tools must feed the world state, not just the console.

cloud-30 ran ffuf twice (8 KB of results each) and logged "no new state
discovered" both times: `ffuf_fuzz` had no output parser, so the paths it
found never became Endpoint nodes and the planner kept re-probing the root.
"""

from __future__ import annotations

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
