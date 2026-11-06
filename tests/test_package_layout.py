"""Package layout and legacy import compatibility."""

from importlib import import_module
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent

MODULE_EXPORTS = {
    "orchestrator": ("orchestrator", "Orchestrator"),
    "runner": ("runner", "Orchestrator"),
    "dkg": ("dkg", "DKG"),
    "data_model": ("data_model", "PipelineState"),
    "environment": ("environment", "EnvironmentKind"),
    "reachability": ("reachability", "is_host_reachable"),
    "response_evidence": ("response_evidence", "detect_response_anomalies"),
    "topology_analysis": ("topology_analysis", "RelationAnalyzer"),
    "cloud_topology": ("cloud_topology", "CloudTopologyMapper"),
    "cloud_attack_path": ("cloud_attack_path", "compute_attack_paths"),
    "rag": ("rag", "DarwinRAG"),
    "rag_corpus": ("rag_corpus", "build_corpus"),
    "rag_embedder": ("rag_embedder", "HashEmbedder"),
    "rag_query": ("rag_query", "environment_from_dkg"),
    "search_evidence": ("search_evidence", "format_rag_evidence"),
    "cteg": ("cteg", "CTEG"),
    "credential_memory": ("credential_memory", "CredentialMemory"),
    "graph_fingerprint": ("graph_fingerprint", "fingerprint"),
    "memory_config": ("memory_config", "MemoryConfig"),
    "precedent_store": ("precedent_store", "PrecedentStore"),
    "dpm": ("dpm", "DefensePerceptionModule"),
    "dave": ("dave", "DAVE"),
}

DOMAIN_PACKAGES = {
    "orchestrator": "app",
    "runner": "app",
    "dkg": "world",
    "data_model": "world",
    "environment": "world",
    "reachability": "world",
    "response_evidence": "world",
    "topology_analysis": "world",
    "cloud_topology": "world",
    "cloud_attack_path": "world",
    "rag": "knowledge",
    "rag_corpus": "knowledge",
    "rag_embedder": "knowledge",
    "rag_query": "knowledge",
    "search_evidence": "knowledge",
    "cteg": "memory",
    "credential_memory": "memory",
    "graph_fingerprint": "memory",
    "memory_config": "memory",
    "precedent_store": "memory",
    "dpm": "security",
    "dave": "verification",
}


@pytest.mark.parametrize("legacy_name", sorted(MODULE_EXPORTS))
def test_legacy_imports_resolve_to_canonical_objects(legacy_name):
    module_name, export_name = MODULE_EXPORTS[legacy_name]
    domain = DOMAIN_PACKAGES[legacy_name]
    legacy = import_module(f"darwin.{legacy_name}")
    canonical = import_module(f"darwin.{domain}.{module_name}")
    assert getattr(legacy, export_name) is getattr(canonical, export_name)


def test_generated_reports_are_not_tracked_at_repository_root():
    assert not (ROOT / "BENCHMARK_SUMMARY_CLOUD_K8S.md").exists()
    assert not (ROOT / "CLOUD_BENCHMARK_DETAIL.md").exists()
    assert not (ROOT / "TOOL_COVERAGE_AUDIT.md").exists()
    assert not (ROOT / "cteg_state.json").exists()
    assert not list((ROOT / "darwin").glob("*.bak-*"))
