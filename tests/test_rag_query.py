"""Query construction, runtime context and tool contract for DarwinRAG."""

from __future__ import annotations

from pathlib import Path

from darwin.rag import RagConfig, DarwinRAG, get_environment, reset_rag, set_environment
from darwin.rag_query import (
    active_domains,
    build_capability_query,
    domains_from_dkg,
    environment_from_dkg,
)


class _FakeDKG:
    def __init__(self, nodes: dict):
        self._nodes = nodes

    def query_nodes(self, node_type: str = ""):
        if node_type:
            return self._nodes.get(node_type, [])
        return [n for group in self._nodes.values() for n in group]


class _FakeVuln:
    def __init__(self, vuln_type: str, endpoint: str = ""):
        self.vuln_type = vuln_type
        self.endpoint = endpoint


class _FakeService:
    def __init__(self, version: str = "", banner: str = ""):
        self.version = version
        self.banner = banner


def test_query_maps_vulnerability_class_to_canonical_terms():
    query = build_capability_query(
        services=[_FakeService(version="Werkzeug httpd 3.1.8 (Python/3.11)")],
        vulns=[_FakeVuln("SSTI", "http://target/render"), _FakeVuln("AuthBypass")],
    )
    assert "Werkzeug httpd 3.1.8" in query
    assert "server-side template injection" in query
    assert "authentication bypass" in query
    assert "http://target/render" in query
    assert query.count("Werkzeug httpd 3.1.8") == 1


def test_query_accepts_extra_terms_and_dedupes():
    query = build_capability_query(extra_terms=["redis", "REDIS", "weak credentials"])
    assert query == "redis weak credentials"


def test_active_domains_detects_environment_families():
    assert "k8s" in active_domains(["kubelet 10250 exposed", "etcd keys readable"])
    assert "cloud" in active_domains(["Azure service tag spoofing via IMDS"])
    assert "db" in active_domains(["postgres 14 listening"])
    assert active_domains(["nothing familiar here"]) == []


def test_environment_and_domains_from_dkg():
    dkg = _FakeDKG({
        "Analysis": [{"classification": {"kind": "public_cloud", "provider": "aws"}}],
        "Service": [{"banner": "S3-compatible object store", "version": ""}],
        "Endpoint": [{"url": "http://target/api", "sample_response": "iam role"}],
    })
    assert environment_from_dkg(dkg) == "public_cloud"
    domains = domains_from_dkg(dkg)
    assert "cloud" in domains
    assert environment_from_dkg(None) == ""
    assert domains_from_dkg(None) == []


def test_environment_state_round_trip():
    reset_rag()
    set_environment("private_cloud")
    assert get_environment() == "private_cloud"
    reset_rag()
    assert get_environment() == ""


def test_config_from_repo_yaml():
    rag = DarwinRAG(config_path="config/darwin.yaml")
    assert rag._config.max_results == 3
    assert rag._config.model_dir.endswith("paraphrase-multilingual-MiniLM-L12-v2")
    assert rag._config.reranker_dir.endswith("mmarco-mMiniLMv2-L12-H384-v1")


def test_config_mapping_overrides_defaults():
    cfg = RagConfig.from_mapping({
        "max_results": 2, "rerank_candidates": 5, "domain_penalty": 0.3,
        "gate": {"score_min": 1.5, "score_window": 0.5},
    })
    assert cfg.max_results == 2
    assert cfg.rerank_candidates == 5
    assert cfg.domain_penalty == 0.3
    assert cfg.score_min == 1.5 and cfg.score_window == 0.5


def test_knowledge_search_tool_contract():
    from darwin.tools.attack_server import create_attack_gateway

    definition = next(
        d for d in create_attack_gateway().get_tool_definitions()
        if d["function"]["name"] == "knowledge_search"
    )
    params = definition["function"]["parameters"]["properties"]
    assert "domain" in params and "environment" in params
    assert "category" not in params
    assert "at most 3" in definition["function"]["description"]
    assert "empty result means" in definition["function"]["description"]
