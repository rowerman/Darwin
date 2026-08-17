"""Phase 2 hierarchical-knowledge tests."""

import json

from darwin.rag import DarwinRAG, _path_to_collection


def _write(tmp_path, rel, data):
    path = tmp_path / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(data, (list, dict)):
        path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    else:
        path.write_text(data, encoding="utf-8")
    return path


def _build_knowledge_dir(tmp_path):
    _write(
        tmp_path,
        "web/foo.json",
        [
            {
                "id": "scenario-a",
                "title": "XXE SVG Upload",
                "category": "web",
                "subcategory": "xxe",
                "description": "Embed XXE in an SVG document to read server files.",
                "techniques": ["Upload malicious SVG"],
                "tags": ["xxe"],
                "confidence": 0.8,
            },
            {
                "id": "scenario-b",
                "title": "GraphQL IDOR",
                "category": "web",
                "subcategory": "graphql",
                "description": "Introspect GraphQL and abuse object IDs.",
                "confidence": 0.7,
            },
        ],
    )
    _write(
        tmp_path,
        "network/db.json",
        [
            {
                "id": "scenario-db-x",
                "title": "Oracle TNS Poisoning",
                "category": "db",
                "subcategory": "oracle",
                "description": "Poison the Oracle TNS listener and read files via UTL_FILE.",
                "confidence": 0.6,
            }
        ],
    )
    taxonomy = {
        "version": 1,
        "roots": [
            {"name": "web", "children": [{"name": "xxe"}, {"name": "graphql"}]},
            {"name": "db", "children": [{"name": "oracle"}]},
        ],
        "leaves": [
            {
                "id": "scenario-a",
                "guid": "WEB-14",
                "title": "XXE SVG Upload",
                "path": ["web", "xxe"],
            },
            {
                "id": "scenario-b",
                "guid": "WEB-16",
                "title": "GraphQL IDOR",
                "path": ["web", "graphql"],
            },
            {
                "id": "scenario-db-x",
                "guid": "DB-03",
                "title": "Oracle TNS Poisoning",
                "path": ["db", "oracle"],
            },
            {"id": "scenario-missing", "title": "No Entry", "path": ["web", "xxe"]},
        ],
    }
    _write(tmp_path, "taxonomy.json", taxonomy)
    return taxonomy


def _make_rag(tmp_path):
    rag = DarwinRAG()
    assert rag.load(str(tmp_path)) == 3
    # Override the auto-loaded (repo) taxonomy with the test fixture.
    assert rag.load_taxonomy(str(tmp_path / "taxonomy.json")) == 4
    return rag


def test_hierarchical_routes_into_subtree(tmp_path):
    _build_knowledge_dir(tmp_path)
    rag = _make_rag(tmp_path)
    results = rag.search_hierarchical(
        "XXE SVG upload file disclosure", top_k=5, route_k=1
    )
    ids = {r["id"] for r in results}
    assert "scenario-a" in ids
    assert results[0]["path"] == ["web", "xxe"]
    assert results[0]["guid"] == "WEB-14"


def test_hierarchical_falls_back_without_route(tmp_path):
    _build_knowledge_dir(tmp_path)
    rag = _make_rag(tmp_path)
    results = rag.search_hierarchical(
        "zzzz totally unrelated nonsense", top_k=5, route_k=2
    )
    flat = rag.search("zzzz totally unrelated nonsense", top_k=5)
    # No leaf routes → flat fallback; both should agree on the result set.
    assert isinstance(results, list)
    assert {r["id"] for r in results} == {r["id"] for r in flat}


def test_hierarchical_falls_back_without_taxonomy(tmp_path):
    _build_knowledge_dir(tmp_path)
    rag = DarwinRAG()
    rag.load(str(tmp_path))
    rag.load_taxonomy(str(tmp_path / "no-such-taxonomy.json"))
    assert rag.taxonomy_loaded is False
    results = rag.search_hierarchical("XXE SVG upload", top_k=3)
    flat = rag.search("XXE SVG upload", top_k=3)
    assert {r["id"] for r in results} == {r["id"] for r in flat}


def test_scenario_collection_mapping():
    assert _path_to_collection(__import__("pathlib").Path("knowledge/scenarios/k8s/x.json")) == "cloud"
    assert _path_to_collection(__import__("pathlib").Path("knowledge/scenarios/db/x.json")) == "network"
    assert _path_to_collection(__import__("pathlib").Path("knowledge/scenarios/web/x.json")) == "web"
