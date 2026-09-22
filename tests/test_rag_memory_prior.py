"""RAG behaviour with cross-task precedents and structural preconditions."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from darwin.dkg import DKG
from darwin.graph_fingerprint import build_snapshot
from darwin.rag import DarwinRAG, RagConfig, set_graph_context
from darwin.rag_corpus import build_corpus, write_corpus
from darwin.rag_embedder import HashEmbedder, TokenOverlapReranker

QUERY = "union select payload extraction bypass filter encoding evasion"


def _entry(entry_id: str, title: str, capability: str, techniques, **extra) -> dict:
    return {
        "id": entry_id, "title": title, "capability": capability,
        "domains": ["web"], "requires_environment": [],
        "applies_when": ["url parameter reaches the database layer"],
        "signals": [], "technique_class": techniques,
        "verification": "replay the payload and compare responses",
        "failure_boundary": [], "tools": [], "confidence": 0.7,
        **extra,
    }


def _rag_with(tmp_path: Path, entries: list) -> DarwinRAG:
    root = tmp_path / "knowledge"
    (root / "capabilities").mkdir(parents=True)
    (root / "capabilities" / "entries.json").write_text(
        json.dumps(entries, ensure_ascii=False), encoding="utf-8",
    )
    build = build_corpus(root)
    write_corpus(build.entries, root, build)
    instance = DarwinRAG(
        knowledge_dir=str(root), embedder=HashEmbedder(),
        reranker=TokenOverlapReranker(),
        config=RagConfig(max_results=3, use_cache=False),
    )
    instance.load()
    return instance


@pytest.fixture(autouse=True)
def _reset_graph_context():
    set_graph_context(None)
    yield
    set_graph_context(None)


def test_absent_or_empty_prior_keeps_retrieval_unchanged(tmp_path: Path):
    rag = _rag_with(tmp_path, [
        _entry("cap-strong", "union select payload extraction bypass filter encoding evasion",
               "sql_injection", ["union select payload"]),
        _entry("cap-weak", "payload extraction hardening checklist",
               "sql_hardening", ["checklist"]),
    ])
    baseline = [r["id"] for r in rag.retrieve(QUERY)]
    assert baseline == ["cap-strong"]
    assert [r["id"] for r in rag.retrieve(QUERY, prior={})] == baseline


def test_prior_cannot_admit_a_gate_rejected_entry(tmp_path: Path):
    rag = _rag_with(tmp_path, [
        _entry("cap-strong", "union select payload extraction bypass filter encoding evasion",
               "sql_injection", ["union select payload"]),
        _entry("cap-weak", "payload extraction hardening checklist",
               "sql_hardening", ["checklist"]),
    ])
    baseline = [r["id"] for r in rag.retrieve(QUERY)]
    assert "cap-weak" not in baseline, "precondition: the weak entry must fail the gate"
    boosted = [r["id"] for r in rag.retrieve(QUERY, prior={"cap-weak": 10.0})]
    assert "cap-weak" not in boosted


def test_graph_pattern_precondition_gates_on_the_current_snapshot(tmp_path: Path):
    pattern = {"nodes": [{"type": "K8sPod", "where": "privileged=true"}],
               "requires_subgraph": True}
    rag = _rag_with(tmp_path, [
        _entry("cap-priv-escape", "union select payload extraction bypass filter encoding evasion",
               "container_escape", ["privileged pod escape"], graph_pattern=pattern),
    ])
    # No snapshot published yet: the filter stays out of the way.
    assert [r["id"] for r in rag.retrieve(QUERY)] == ["cap-priv-escape"]

    set_graph_context(build_snapshot(_web_graph()))
    assert rag.retrieve(QUERY) == []

    set_graph_context(build_snapshot(_k8s_graph()))
    assert [r["id"] for r in rag.retrieve(QUERY)] == ["cap-priv-escape"]


def _web_graph() -> DKG:
    dkg = DKG()
    dkg.add_node("Host", "host-web", {"ip": "10.1.0.1"})
    dkg.add_node("Endpoint", "ep-web", {"url": "http://web:8080/", "method": "GET"})
    dkg.add_edge("host-web", "ep-web", "host_has_endpoint")
    return dkg


def _k8s_graph() -> DKG:
    dkg = DKG()
    dkg.add_node("Host", "host-k8s", {"ip": "10.2.0.1"})
    dkg.add_node("K8sPod", "pod-1", {"name": "escape", "privileged": True})
    dkg.add_node("K8sSA", "sa-1", {"name": "default"})
    dkg.add_edge("host-k8s", "pod-1", "node_hosts_pod")
    dkg.add_edge("pod-1", "sa-1", "pod_mounts_sa")
    return dkg
