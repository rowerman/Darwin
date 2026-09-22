"""Cross-task graph memory: projection, fingerprint, store and credentials."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from darwin.credential_memory import CredentialMemory
from darwin.dkg import NODE_TYPES, DKG
from darwin.graph_fingerprint import (
    SNAPSHOT_EXCLUDED_TYPES, build_snapshot, coarse_class, fingerprint,
    match_graph_pattern, similarity,
)
from darwin.memory_config import MemoryConfig
from darwin.precedent_store import (
    PrecedentStore, build_knowledge_record, clear_prior, current_prior, publish_prior,
)


def k8s_graph(seed: int, extra_flag: str = "") -> DKG:
    dkg = DKG()
    dkg.add_node("Host", f"host-{seed}", {"ip": f"10.0.{seed}.1"})
    dkg.add_node("K8sCluster", f"cluster-{seed}", {"name": "kind"})
    dkg.add_node("K8sNamespace", f"ns-{seed}", {"name": "default"})
    dkg.add_node("K8sPod", f"pod-{seed}", {"name": "escape", "privileged": True})
    dkg.add_node("K8sSA", f"sa-{seed}", {"name": "default"})
    dkg.add_node("Endpoint", f"ep-{seed}", {"url": f"http://t{seed}:8080/fetch", "method": "GET"})
    dkg.add_node("Flag", f"flag-{seed}", {"value": extra_flag or f"flag{{secret-{seed}}}",
                                          "verified": True})
    dkg.add_node("Credential", f"cred-{seed}", {"username": "admin", "password": "hunter2"})
    dkg.add_node("ExploitPrimitive", f"prim-{seed}", {"request": "GET /fetch?url=file:///etc/passwd"})
    dkg.add_edge(f"cluster-{seed}", f"ns-{seed}", "cluster_contains_namespace")
    dkg.add_edge(f"ns-{seed}", f"pod-{seed}", "namespace_contains_pod")
    dkg.add_edge(f"host-{seed}", f"pod-{seed}", "node_hosts_pod")
    dkg.add_edge(f"pod-{seed}", f"sa-{seed}", "pod_mounts_sa")
    dkg.add_edge(f"host-{seed}", f"ep-{seed}", "host_has_endpoint")
    return dkg


def web_graph(seed: int) -> DKG:
    dkg = DKG()
    dkg.add_node("Host", f"host-{seed}", {"ip": f"10.9.{seed}.1"})
    dkg.add_node("Service", f"svc-{seed}", {"port": 8080, "service_name": "http"})
    dkg.add_node("Endpoint", f"ep-{seed}", {"url": f"http://w{seed}:8080/", "method": "GET"})
    dkg.add_edge(f"host-{seed}", f"svc-{seed}", "host_has_service")
    dkg.add_edge(f"host-{seed}", f"ep-{seed}", "host_has_endpoint")
    return dkg


@pytest.fixture(autouse=True)
def _clean_prior():
    clear_prior()
    yield
    clear_prior()


def test_snapshot_never_carries_flags_credentials_or_primitives():
    snapshot = build_snapshot(k8s_graph(1))
    types = {node["type"] for node in snapshot["nodes"]}
    assert types & SNAPSHOT_EXCLUDED_TYPES == set()
    blob = json.dumps(snapshot, ensure_ascii=False)
    assert "flag{" not in blob
    assert "hunter2" not in blob
    assert "file:///etc/passwd" not in blob


def test_coarse_vocabulary_covers_every_dkg_node_type():
    assert [t for t in NODE_TYPES if coarse_class(t) == "unknown"] == []


def test_similarity_is_symmetric_bounded_and_family_separating():
    left = fingerprint(build_snapshot(k8s_graph(1)))
    right = fingerprint(build_snapshot(k8s_graph(2)))
    other = fingerprint(build_snapshot(web_graph(3)))

    same = similarity(left, right)
    cross = similarity(left, other)
    assert 0.0 <= cross["score"] <= same["score"] <= 1.0
    assert same["score"] == similarity(right, left)["score"]
    assert set(same["components"]) == {"node", "edge", "schema", "path"}


def test_projection_stops_at_max_hops():
    dkg = k8s_graph(4)
    dkg.add_node("RDS", "far-db", {"name": "far"})
    dkg.add_edge("host-4", "far-db", "resource_reaches_resource")
    assert "far-db" in {n["id"] for n in build_snapshot(dkg, max_hops=3)["nodes"]}
    assert "far-db" not in {n["id"] for n in build_snapshot(dkg, max_hops=0)["nodes"]}


def test_graph_pattern_containment():
    snapshot = build_snapshot(k8s_graph(5))
    assert match_graph_pattern(
        {"nodes": [{"type": "K8sPod", "where": "privileged=true"}],
         "edges": [{"type": "pod_mounts_sa"}]},
        snapshot,
    )
    assert not match_graph_pattern(
        {"nodes": [{"type": "K8sPod", "where": "privileged=false"}]}, snapshot,
    )
    assert not match_graph_pattern({"nodes": [{"type": "RDS"}]}, snapshot)
    assert match_graph_pattern({"nodes": [{"type": "RDS"}], "requires_subgraph": False},
                               snapshot)


def test_precedent_store_ranks_similar_graphs_and_falls_back_to_json(tmp_path: Path):
    config = MemoryConfig(
        storage_dir=str(tmp_path / "graphs"),
        credentials_path=str(tmp_path / "creds.json"),
    )
    store = PrecedentStore(config)
    store.record_task_snapshot(
        "task-k8s", fingerprint=fingerprint(build_snapshot(k8s_graph(6))),
        knowledge=[build_knowledge_record("cap-k8s", surfaced=True, used=True,
                                          verified_success=True)],
    )
    store.record_task_snapshot(
        "task-web", fingerprint=fingerprint(build_snapshot(web_graph(7))),
        knowledge=[build_knowledge_record("cap-web", surfaced=True, used=True,
                                          verified_success=True)],
    )
    assert (tmp_path / "graphs" / "task-k8s.json").exists()

    hits = store.query(fingerprint(build_snapshot(k8s_graph(8))))
    assert [hit["task_id"] for hit in hits] == ["task-k8s"]
    # The other family is not retrieved: same-family hits only.
    web_hits = store.query(fingerprint(build_snapshot(web_graph(9))))
    assert [hit["task_id"] for hit in web_hits] == ["task-web"]


def test_prior_credits_only_verified_successes(tmp_path: Path):
    config = MemoryConfig(storage_dir=str(tmp_path / "graphs"),
                          credentials_path=str(tmp_path / "creds.json"))
    store = PrecedentStore(config)
    store.record_task_snapshot(
        "task-1", fingerprint=fingerprint(build_snapshot(k8s_graph(10))),
        knowledge=[
            build_knowledge_record("cap-worked", surfaced=True, used=True,
                                   verified_success=True),
            build_knowledge_record("cap-untried", surfaced=True, used=False),
            build_knowledge_record("cap-failed", surfaced=True, used=True, failed=True),
        ],
    )
    prior = store.prior(fingerprint(build_snapshot(k8s_graph(11))))
    assert "cap-worked" in prior
    assert "cap-untried" not in prior
    assert "cap-failed" not in prior
    publish_prior(prior)
    assert set(current_prior()) == {"cap-worked"}


def test_credential_memory_requires_full_identity(tmp_path: Path):
    memory = CredentialMemory(str(tmp_path / "creds.json"))
    memory.record(host="localhost", port=10601, service_type="mssql",
                  username="sa", password="pw", scope="http://localhost",
                  environment="web_db")

    def lookup(**overrides):
        kwargs = dict(host="localhost", port=10601, service_type="mssql",
                      scope="http://localhost", environment="web_db")
        kwargs.update(overrides)
        return memory.lookup(**kwargs)

    assert lookup()
    assert lookup(service_type="http") == []          # same port, other service
    assert lookup(port=10602) == []                   # other port
    assert lookup(scope="http://other") == []         # other scope
    assert lookup(environment="public_cloud") == []   # other environment
