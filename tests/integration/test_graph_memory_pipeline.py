"""Cross-module coverage for the graph-precedent memory path.

Fully local: no ports, no network, no LLM.  It drives the real
``LifecycleCoordinator`` memory hooks against a real DKG, fingerprint, store and
RAG prior registry, which is the chain that runs inside ``Orchestrator.run()``.
"""

from __future__ import annotations

import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from darwin.core.task import Task
from darwin.dkg import DKG
from darwin.data_model import OrchestratorPhase
from darwin.memory_config import MemoryConfig
from darwin.orchestration.lifecycle import LifecycleCoordinator
from darwin.precedent_store import (
    PrecedentStore, clear_prior, current_prior,
)
from darwin.rag import note_surfaced, reset_surfaced

pytestmark = pytest.mark.integration

KNOWLEDGE_ID = "cap-k8s-overbroad-rbac-serviceaccount"


def _k8s_graph(seed: int) -> DKG:
    dkg = DKG()
    dkg.add_node("Host", f"host-{seed}", {"ip": f"10.0.{seed}.1"})
    dkg.add_node("K8sNamespace", f"ns-{seed}", {"name": "default"})
    dkg.add_node("K8sPod", f"pod-{seed}", {"name": "app"})
    dkg.add_node("K8sSA", f"sa-{seed}", {"name": "app-sa"})
    dkg.add_node("IAMRole", f"role-{seed}", {"name": "node"})
    dkg.add_node("Endpoint", f"ep-{seed}", {"url": f"http://t{seed}:8080/", "method": "GET"})
    dkg.add_edge(f"ns-{seed}", f"pod-{seed}", "namespace_contains_pod")
    dkg.add_edge(f"host-{seed}", f"pod-{seed}", "node_hosts_pod")
    dkg.add_edge(f"pod-{seed}", f"sa-{seed}", "pod_mounts_sa")
    dkg.add_edge(f"sa-{seed}", f"role-{seed}", "sa_bound_to_role")
    dkg.add_edge(f"host-{seed}", f"ep-{seed}", "host_has_endpoint")
    return dkg


def _web_graph(seed: int) -> DKG:
    dkg = DKG()
    dkg.add_node("Host", f"host-{seed}", {"ip": f"10.9.{seed}.1"})
    dkg.add_node("Service", f"svc-{seed}", {"port": 8080, "service_name": "http"})
    dkg.add_node("Endpoint", f"ep-{seed}", {"url": f"http://w{seed}:8080/", "method": "GET"})
    dkg.add_edge(f"host-{seed}", f"svc-{seed}", "host_has_service")
    dkg.add_edge(f"host-{seed}", f"ep-{seed}", "host_has_endpoint")
    return dkg


def _coordinator(tmp_path: Path, dkg: DKG, scope: str) -> LifecycleCoordinator:
    config = MemoryConfig(
        storage_dir=str(tmp_path / "graphs"),
        credentials_path=str(tmp_path / "credentials.json"),
    )
    stub = SimpleNamespace(
        dkg=dkg,
        precedent=PrecedentStore(config),
        memory_config=config,
        target_host="target",
        start_time=time.time(),
        exploitation_plan=SimpleNamespace(tasks=[]),
        _task_log=[],
        phase=OrchestratorPhase.RECON,
    )
    stub.memory_scope = lambda: scope
    stub.memory_environment = lambda: ""
    return LifecycleCoordinator(stub)


def _executed_task() -> Task:
    return Task(
        id="task-1", type="task", goal="escalate",
        instruction=f"use {KNOWLEDGE_ID} technique to read the service account token",
        attempt_count=1,
        source_knowledge_ids=[KNOWLEDGE_ID],
    )


@pytest.fixture(autouse=True)
def _reset_memory_registries(monkeypatch):
    clear_prior()
    reset_surfaced()
    monkeypatch.setattr(
        "darwin.rag.get_rag",
        lambda: SimpleNamespace(_entries=[{
            "id": KNOWLEDGE_ID, "title": "rbac serviceaccount overpermissive",
            "technique_class": ["token permission enumeration"],
        }]),
    )
    yield
    clear_prior()
    reset_surfaced()


def test_snapshot_is_recorded_then_reused_by_a_similar_graph(tmp_path: Path):
    first = _coordinator(tmp_path, _k8s_graph(1), "http://bench-a")
    first._publish_knowledge_prior()
    assert current_prior() == {}, "no history yet → retrieval is unchanged"

    note_surfaced([KNOWLEDGE_ID])
    first.exploitation_plan = SimpleNamespace(tasks=[_executed_task()])
    first._record_task_memory(SimpleNamespace(success=True, flag="flag{ok}"))
    assert list((tmp_path / "graphs").glob("*.json")), "snapshot must be persisted"

    # Same environment shape, different resources: the verified knowledge is
    # prior-boosted for the next task.
    second = _coordinator(tmp_path, _k8s_graph(2), "http://bench-b")
    second._publish_knowledge_prior()
    assert KNOWLEDGE_ID in current_prior()

    # Unrelated environment: strict fallback to plain RAG.
    third = _coordinator(tmp_path, _web_graph(3), "http://bench-c")
    third._publish_knowledge_prior()
    assert current_prior() == {}


def test_failed_task_earns_no_credit(tmp_path: Path):
    first = _coordinator(tmp_path, _k8s_graph(4), "http://bench-d")
    note_surfaced([KNOWLEDGE_ID])
    first.exploitation_plan = SimpleNamespace(tasks=[_executed_task()])
    first._record_task_memory(SimpleNamespace(success=False, flag=""))

    second = _coordinator(tmp_path, _k8s_graph(5), "http://bench-e")
    second._publish_knowledge_prior()
    assert current_prior() == {}
