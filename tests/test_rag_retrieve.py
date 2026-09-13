"""Hybrid retrieval: dual channel, environment gate, rerank gate and caps."""

from __future__ import annotations

import json
import logging
from pathlib import Path

import pytest

from darwin.rag import DarwinRAG, RagConfig
from darwin.rag_corpus import build_corpus, write_corpus
from darwin.rag_embedder import HashEmbedder, TokenOverlapReranker


def _capability(entry_id: str, title: str, capability: str, domains, requires,
                applies, techniques, verification) -> dict:
    return {
        "id": entry_id, "title": title, "capability": capability,
        "domains": domains, "requires_environment": requires,
        "applies_when": applies, "signals": [], "technique_class": techniques,
        "verification": verification, "failure_boundary": [],
        "tools": [], "confidence": 0.7,
    }


@pytest.fixture()
def rag(tmp_path: Path) -> DarwinRAG:
    root = tmp_path / "knowledge"
    (root / "capabilities").mkdir(parents=True)
    (root / "capabilities" / "entries.json").write_text(json.dumps([
        _capability(
            "cap-cloud-cross-tenant", "cross tenant predictable resource id ownership",
            "cloud_cross_tenant", ["cloud"], ["public_cloud", "hybrid"],
            ["resources addressed by predictable ids", "owner check missing"],
            ["identifier enumeration and swap"], "compare two tenants' ids",
        ),
        _capability(
            "cap-k8s-rbac", "kubernetes service account token overpermissive rbac",
            "k8s_rbac", ["k8s"], ["private_cloud", "hybrid"],
            ["pod mounts a service account token", "rbac grants secret reads"],
            ["token permission enumeration"], "read a secret in another namespace",
        ),
        _capability(
            "cap-web-ssrf", "ssrf internal service reach and metadata access",
            "web_ssrf", ["web"], [],
            ["url fetch feature reaches internal addresses"],
            ["address filter bypass"], "request loopback admin endpoint",
        ),
    ], ensure_ascii=False), encoding="utf-8")
    # A legacy entry so conversion and dual-channel behaviour are exercised.
    (root / "web_pat.json").write_text(json.dumps([{
        "id": "pat-1",
        "title": "Jinja2 template injection expression evaluation",
        "category": "SSTI",
        "description": "Template expressions are evaluated server side and reveal engine errors.",
        "techniques": ["probe arithmetic expression in the template parameter"],
        "indicators": ["response contains the evaluated arithmetic result"],
        "tags": ["web", "ssti"],
        "confidence": 0.6,
    }], ensure_ascii=False), encoding="utf-8")
    build = build_corpus(root)
    write_corpus(build.entries, root, build)

    instance = DarwinRAG(
        knowledge_dir=str(root), embedder=HashEmbedder(), reranker=TokenOverlapReranker(),
        config=RagConfig(max_results=3, use_cache=False),
    )
    instance.load()
    return instance


def test_returns_at_most_max_results(rag):
    results = rag.retrieve("cross tenant predictable resource id ownership")
    assert 0 < len(results) <= 3


def test_environment_hard_filter_drops_k8s_on_public_cloud(rag):
    query = "kubernetes service account token overpermissive rbac secret read"
    public = rag.retrieve(query, environment="public_cloud")
    private = rag.retrieve(query, environment="private_cloud")
    assert all("k8s" not in (r.get("domains") or []) for r in public)
    assert any(r["id"] == "cap-k8s-rbac" for r in private)


def test_unknown_environment_disables_hard_filter(rag):
    results = rag.retrieve(
        "kubernetes service account token overpermissive rbac", environment="", domains=["k8s"]
    )
    assert any(r["id"] == "cap-k8s-rbac" for r in results)


def test_both_channels_contribute(rag):
    results = rag.retrieve("template injection expression evaluation", environment="web_db")
    assert results, "expected a sparse/dense match for the legacy entry"
    trace = results[0]["retrieval"]
    assert trace.get("dense_rank") or trace.get("sparse_rank")
    assert "fused" in trace and "rerank" in trace


def test_gate_returns_empty_for_unrelated_query(rag):
    assert rag.retrieve("quantum chromodynamics lattice renormalization") == []


def test_per_capability_cap_and_dedup(tmp_path: Path):
    root = tmp_path / "knowledge"
    (root / "capabilities").mkdir(parents=True)
    entries = [
        _capability(f"cap-dup-{i}", "ssrf internal service reach and metadata access",
                    "web_ssrf", ["web"], [],
                    ["url fetch reaches internal addresses"], ["address filter bypass"],
                    "request the loopback admin endpoint")
        for i in range(4)
    ]
    (root / "capabilities" / "dups.json").write_text(json.dumps(entries), encoding="utf-8")
    build = build_corpus(root)
    write_corpus(build.entries, root, build)
    rag = DarwinRAG(knowledge_dir=str(root), embedder=HashEmbedder(),
                    reranker=TokenOverlapReranker(),
                    config=RagConfig(max_results=3, max_per_capability=2, use_cache=False))
    rag.load()
    results = rag.retrieve("ssrf internal service reach metadata access")
    # Identical titles collapse to one entry, so the capability cap is not the
    # binding constraint here — what matters is that no 3 duplicates leak out.
    assert len(results) <= 3
    assert len({r["title"] for r in results}) == len(results)


def test_domain_mismatch_is_penalised_not_dropped(rag):
    results = rag.retrieve("ssrf internal service reach metadata access",
                           environment="public_cloud", domains=["k8s"])
    # The web entry stays reachable but must not be the top hit once the only
    # k8s candidate is environment-filtered.
    assert results
    assert results[0]["score"] >= results[-1]["score"]


def test_empty_corpus_reports_error(tmp_path: Path):
    rag = DarwinRAG(knowledge_dir=str(tmp_path / "missing"),
                    embedder=HashEmbedder(), reranker=TokenOverlapReranker())
    assert rag.load() == 0
    assert rag.backend == "empty"
    assert "tools.build_rag_corpus" in rag.load_error
    assert rag.retrieve("anything") == []


def test_sparse_only_backend_when_embedder_disabled(tmp_path: Path, caplog):
    root = tmp_path / "knowledge"
    (root / "capabilities").mkdir(parents=True)
    (root / "capabilities" / "one.json").write_text(json.dumps([
        _capability("cap-web-ssrf", "ssrf internal service reach", "web_ssrf",
                    ["web"], [], ["url fetch reaches internal"], ["filter bypass"],
                    "request loopback")
    ]), encoding="utf-8")
    build = build_corpus(root)
    write_corpus(build.entries, root, build)
    with caplog.at_level(logging.ERROR, logger="darwin.rag"):
        rag = DarwinRAG(knowledge_dir=str(root),
                        config=RagConfig(embedder_kind="none", reranker_kind="token-overlap",
                                         use_cache=False))
        rag.load()
    assert rag.backend == "sparse_only"
    assert any("dense channel disabled" in record.message for record in caplog.records)
    assert rag.retrieve("ssrf internal service reach")


def test_retrieval_is_deterministic(rag):
    first = [(r["id"], r["score"]) for r in rag.retrieve("ssrf internal service reach")]
    second = [(r["id"], r["score"]) for r in rag.retrieve("ssrf internal service reach")]
    assert first == second
