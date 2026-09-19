"""Recon/hypothesis guards for the KIND-benchmark failure mode.

Covers three defects observed on 2026-09-19 (experiment/result/k8s-0*.md):
the CMS probe registering ten bogus endpoints on a Kubernetes API server,
the numeric-id heuristic firing on host/port digits, and an unbounded deep
recon phase starving the exploit window.
"""

from __future__ import annotations

import asyncio
import time
from types import SimpleNamespace

import pytest

from darwin.data_model import PipelineState, TopologyNode, TopologySnapshot
from darwin.orchestration.lifecycle import LifecycleCoordinator
from darwin.orchestration.planning import (
    exec_body_fields,
    registry_signal,
)
from darwin.orchestration.recon import (
    _has_cms_marker,
    _looks_like_html,
    parse_k8s_access,
)
from darwin.orchestration.research import numeric_object_path
from darwin.reachability import is_host_reachable

_K8S_403_BODY = (
    'HTTP/2 403\r\nContent-Type: application/json\r\n\r\n'
    '{"kind":"Status","apiVersion":"v1","status":"Failure","message":'
    '"forbidden: User \\"system:anonymous\\" cannot get path /wp-admin/"}\n'
)


def test_cms_probe_skips_json_apis():
    """A JSON root must never be path-probed for CMS entry points."""
    assert not _looks_like_html({
        "sample_content_type": "application/json",
        "sample_response": '{"service":"Managed Automation"}\n',
    })
    assert not _looks_like_html({
        "sample_response": 'HTTP/1.1 200 OK\n\n{"kind":"Status"}\n',
    })
    assert _looks_like_html({
        "sample_content_type": "text/html; charset=utf-8",
        "sample_response": "<html><body>hi</body></html>",
    })


def test_cms_marker_rejects_uniform_auth_wall():
    """A Kubernetes Status 403 is not evidence of a CMS endpoint."""
    assert not _has_cms_marker(_K8S_403_BODY, 403)
    assert _has_cms_marker(
        "HTTP/1.1 200 OK\n\n<link rel='stylesheet' href='/wp-content/a.css'>", 200
    )
    assert _has_cms_marker(
        'HTTP/1.1 200 OK\n\n<form><input type="password" name="p"></form>', 200
    )


def test_cluster_internal_endpoints_are_not_host_reachable():
    """ClusterIP/derived endpoints reach the planner as facts, not as probes."""
    cluster_ip = {
        "url": "https://10.96.0.1:443",
        "discovered_by": "relation_analyzer:service_spec",
        "virtual": True,
    }
    api_server = {
        "url": "https://127.0.0.1:45889",
        "discovered_by": "k8s-cluster-discovery",
    }
    assert not is_host_reachable(cluster_ip)
    assert is_host_reachable(api_server)


def test_kubectl_access_tags_drive_the_attack_surface():
    """The kubectl identity's rights decide which cluster paths are possible."""
    admin = [
        "Resources                                Non-Resource URLs   Resource Names   Verbs",
        "*.*                                      []                  []               [*]",
        "selfsubjectreviews.authentication.k8s.io []                  []               [create]",
    ]
    limited = [
        "Resources   Non-Resource URLs   Resource Names   Verbs",
        "pods        []                  []               [get list watch]",
        "pods/log    []                  []               [get list]",
        "configmaps  []                  []               [get]",
    ]
    assert parse_k8s_access(admin) == ["cluster-admin"]
    assert parse_k8s_access(limited) == ["read-pod-logs"]
    # A '*' inside the resource column must not be read as a wildcard verb.
    assert parse_k8s_access(["*.*   []   []   [get]"]) == []


def test_numeric_id_heuristic_matches_path_segments_only():
    """Host/port digits must not manufacture an IDOR hypothesis."""
    assert not numeric_object_path("https://127.0.0.1:45889/wp-admin/")
    assert not numeric_object_path("http://10.96.0.10:53")
    assert not numeric_object_path("https://127.0.0.1:45889/api/v1/namespaces")
    assert numeric_object_path("http://127.0.0.1:10642/runbooks/1")
    # A recorded 404/403 probe is an observation, not an object route.
    assert not numeric_object_path("http://127.0.0.1:10642/runbooks/1", 404)


def test_registry_signal_needs_registry_evidence():
    """A '/v2/' path segment is not a Docker Registry signal."""
    assert not registry_signal(
        "{\"kind\":\"status\"} https://127.0.0.1:45889/wp-json/wp/v2/"
    )
    assert registry_signal("server: docker-distribution registry/2.0")


def test_exec_body_fields_detects_server_side_execution():
    assert exec_body_fields("script,attacker_url") == ["script"]
    assert exec_body_fields("command;timeout") == ["command"]
    assert exec_body_fields("username,password") == []
    assert exec_body_fields(None) == []


def test_phase_ratios_reserve_the_exploit_window():
    ratios = LifecycleCoordinator._PHASE_RATIOS
    assert pytest.approx(sum(ratios.values()), abs=1e-6) == 1.0
    assert {"deep_recon", "defense"} <= set(ratios)
    # Deep recon used to run unbounded and leave ~110s for exploitation.
    assert ratios["exploit"] >= 0.45
    assert ratios["deep_recon"] <= 0.15


@pytest.mark.asyncio
async def test_phase_budget_cancels_a_stalled_phase():
    """A hung deep_recon must not consume the run's remaining budget."""
    stub = SimpleNamespace(
        time_budget=600.0,
        _PHASE_RATIOS={"deep_recon": 0.001},
        start_time=time.time(),
        _run_deadline=time.monotonic() + 600.0,
        _orch=SimpleNamespace(_phase_used={"deep_recon": 0.0}, _phase_carryover=0.0),
        _task_log_event=lambda *args, **kwargs: None,
    )
    stub._remaining_budget = lambda: max(0.0, stub._run_deadline - time.monotonic())

    async def _stall():
        await asyncio.sleep(5)
        return "never"

    ok, value = await LifecycleCoordinator._run_phase_with_budget(
        stub, "deep_recon", _stall()
    )
    assert ok is False and value is None
    # 0.6s allowance: the stalled phase is cut off, not allowed to run to 5s.
    assert stub._orch._phase_used["deep_recon"] < 3


def test_cluster_access_facts_reach_the_prompt():
    """Cluster identity/rights must be rendered, not buried in dropped notes."""
    state = PipelineState()
    state.hosts.append({
        "ip": "172.18.0.2",
        "k8s_access_summary": "kubectl identity: cluster-admin, create-pods",
    })
    state.topology = TopologySnapshot(nodes=[
        TopologyNode(
            id="k8s-cluster-x", node_type="K8sCluster",
            properties={"name": "cve-cluster", "api_url": "https://127.0.0.1:45889"},
        ),
        TopologyNode(
            id="k8s-pod-default-poc", node_type="K8sPod",
            properties={
                "name": "runc-escape-poc", "namespace": "default", "phase": "Failed",
                "images": ["localhost/runc-escape:latest"],
            },
        ),
    ])
    context = state.to_prompt_context()
    assert "## Cluster & Access Facts" in context
    assert "cluster-admin" in context
    assert "default/runc-escape-poc [Failed]" in context
