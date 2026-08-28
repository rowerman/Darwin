"""Tests for Dynamic Knowledge Graph operations."""

import pytest
from darwin.dkg import DKG, NODE_TYPES, EDGE_TYPES


class TestDKGNodeOperations:
    """Node CRUD operations."""

    def test_add_node_basic(self):
        dkg = DKG()
        node_id = dkg.add_node("Host", "host-1", {"ip": "192.168.1.1"})
        assert node_id == "host-1"

    def test_add_node_invalid_type(self):
        dkg = DKG()
        with pytest.raises(ValueError, match="Unknown node type"):
            dkg.add_node("InvalidType", "test-1")

    def test_get_node_exists(self):
        dkg = DKG()
        dkg.add_node("Host", "host-1", {"ip": "10.0.0.1", "os": "linux"})
        node = dkg.get_node("host-1")
        assert node is not None
        assert node["ip"] == "10.0.0.1"
        assert node["os"] == "linux"
        assert node["type"] == "Host"

    def test_get_node_missing(self):
        dkg = DKG()
        assert dkg.get_node("nonexistent") is None

    def test_query_nodes_by_type(self):
        dkg = DKG()
        dkg.add_node("Host", "h1", {"ip": "10.0.0.1"})
        dkg.add_node("Host", "h2", {"ip": "10.0.0.2"})
        dkg.add_node("Domain", "d1", {"name": "test.local"})

        hosts = dkg.query_nodes("Host")
        assert len(hosts) == 2

        domains = dkg.query_nodes("Domain")
        assert len(domains) == 1

    def test_query_nodes_with_filters(self):
        dkg = DKG()
        dkg.add_node("Host", "h1", {"ip": "10.0.0.1", "is_internal": True})
        dkg.add_node("Host", "h2", {"ip": "10.0.0.2", "is_internal": False})

        internal = dkg.query_nodes("Host", {"is_internal": True})
        assert len(internal) == 1
        assert internal[0]["id"] == "h1"

    def test_query_nodes_all_types(self):
        dkg = DKG()
        dkg.add_node("Host", "h1", {"ip": "10.0.0.1"})
        dkg.add_node("Service", "s1", {"port": 80})

        all_nodes = dkg.query_nodes()
        assert len(all_nodes) == 2

    def test_update_node_existing(self):
        dkg = DKG()
        dkg.add_node("Vulnerability", "vuln-1", {"severity": "low"})
        result = dkg.update_node("vuln-1", {"severity": "critical"})
        assert result is True
        node = dkg.get_node("vuln-1")
        assert node["severity"] == "critical"

    def test_update_node_missing(self):
        dkg = DKG()
        result = dkg.update_node("nonexistent", {"key": "value"})
        assert result is False


class TestDKGEdgeOperations:
    """Edge operations."""

    def test_add_edge_basic(self):
        dkg = DKG()
        dkg.add_node("Host", "h1")
        dkg.add_node("Service", "s1")
        dkg.add_edge("h1", "s1", "host_has_service", port=80)
        edges = dkg.query_edges()
        assert len(edges) == 1
        assert edges[0]["from"] == "h1"
        assert edges[0]["to"] == "s1"
        assert edges[0]["type"] == "host_has_service"
        assert edges[0]["port"] == 80

    def test_add_edge_invalid_type(self):
        dkg = DKG()
        dkg.add_node("Host", "h1")
        dkg.add_node("Host", "h2")
        with pytest.raises(ValueError, match="Unknown edge type"):
            dkg.add_edge("h1", "h2", "invalid_edge_type")

    def test_query_edges_by_type(self):
        dkg = DKG()
        dkg.add_node("Host", "h1")
        dkg.add_node("Service", "s1")
        dkg.add_node("Domain", "d1")
        dkg.add_edge("h1", "s1", "host_has_service")
        dkg.add_edge("h1", "d1", "host_in_domain")

        service_edges = dkg.query_edges(edge_type="host_has_service")
        assert len(service_edges) == 1

        all_edges = dkg.query_edges()
        assert len(all_edges) == 2

    def test_query_edges_by_from_type(self):
        dkg = DKG()
        dkg.add_node("Host", "h1")
        dkg.add_node("Service", "s1")
        dkg.add_node("Vulnerability", "e1")
        dkg.add_edge("h1", "s1", "host_has_service")
        dkg.add_edge("s1", "e1", "service_has_vuln")

        from_host = dkg.query_edges(from_type="Host")
        assert len(from_host) == 1

    def test_get_neighbors(self):
        dkg = DKG()
        dkg.add_node("Host", "h1")
        dkg.add_node("Service", "s1", {"port": 80})
        dkg.add_node("Service", "s2", {"port": 443})
        dkg.add_edge("h1", "s1", "host_has_service")
        dkg.add_edge("h1", "s2", "host_has_service")

        neighbors = dkg.get_neighbors("h1")
        assert len(neighbors) == 2

        neighbors_filtered = dkg.get_neighbors("h1", "host_has_service")
        assert len(neighbors_filtered) == 2

    def test_get_neighbors_nonexistent(self):
        dkg = DKG()
        neighbors = dkg.get_neighbors("nonexistent")
        assert neighbors == []

    def test_upsert_edge_merges_observations_without_parallel_edges(self):
        dkg = DKG()
        dkg.add_node("Host", "h1")
        dkg.add_node("Service", "s1")
        dkg.upsert_edge("h1", "s1", "host_has_service",
                         source="nmap", evidence="tcp/80", confidence=0.5)
        first_revision = dkg.revision
        changed = dkg.upsert_edge("h1", "s1", "host_has_service",
                                   source="curl", evidence="HTTP 200", confidence=0.9)
        assert changed is True
        assert len(dkg.query_edges()) == 1
        edge = dkg.query_edges()[0]
        assert set(edge["provenance"]["sources"]) == {"nmap", "curl"}
        assert set(edge["evidence"]) == {"tcp/80", "HTTP 200"}
        assert edge["confidence"] == 0.9
        stable_revision = dkg.revision
        assert dkg.upsert_edge("h1", "s1", "host_has_service",
                               source="curl", evidence="HTTP 200", confidence=0.9) is False
        assert dkg.revision == stable_revision
        assert stable_revision > first_revision


class TestDKGPersistence:
    """Serialization round-trip."""

    def test_to_dict_empty(self):
        dkg = DKG()
        data = dkg.to_dict()
        assert data["nodes"] == []
        assert data["edges"] == []
        assert "created_at" in data

    def test_to_dict_with_data(self):
        dkg = DKG()
        dkg.add_node("Host", "h1", {"ip": "10.0.0.1"})
        dkg.add_node("Service", "s1", {"port": 80})
        dkg.add_edge("h1", "s1", "host_has_service")

        data = dkg.to_dict()
        assert len(data["nodes"]) == 2
        assert len(data["edges"]) == 1

    def test_from_dict_roundtrip(self):
        dkg = DKG()
        dkg.add_node("Host", "h1", {"ip": "10.0.0.1", "is_internal": True})
        dkg.add_node("Host", "h2", {"ip": "10.0.0.2"})
        dkg.add_node("Domain", "d1", {"name": "internal"})
        dkg.add_node("Domain", "d2", {"name": "trusted"})
        dkg.add_edge("d1", "d2", "domain_trusts", type="bidirectional")

        data = dkg.to_dict()
        restored = DKG.from_dict(data)

        assert len(restored.query_nodes("Host")) == 2
        node = restored.get_node("h1")
        assert node["ip"] == "10.0.0.1"
        assert node["is_internal"] is True

    def test_save_load(self, tmp_path):
        dkg = DKG()
        dkg.add_node("Host", "h1", {"ip": "10.0.0.1"})
        dkg.add_node("Vulnerability", "vuln-1", {"severity": "critical", "cve_id": "CVE-2022-28512"})

        path = str(tmp_path / "test_dkg.json")
        dkg.save(path)

        loaded = DKG.load(path)
        assert len(loaded.query_nodes()) == 2
        assert loaded.get_node("vuln-1")["severity"] == "critical"
        assert loaded.get_node("vuln-1")["cve_id"] == "CVE-2022-28512"


class TestDKGSummary:
    """Summary and high-level queries."""

    def test_summary_empty(self):
        dkg = DKG()
        assert dkg.summary() == "DKG is empty"

    def test_summary_with_data(self):
        dkg = DKG()
        dkg.add_node("Host", "h1", {"ip": "10.0.0.1"})
        summary = dkg.summary()
        assert "Host: 1" in summary
        assert "h1" in summary

    def test_get_defense_context(self):
        dkg = DKG()
        dkg.add_node("Host", "h1")
        dkg.add_node("Host", "h2")
        dkg.add_node("Vulnerability", "v1")
        dkg.add_node("Flag", "f1", {"verified": True})
        dkg.add_node("Flag", "f2", {"verified": False})

        ctx = dkg.get_defense_context()
        assert ctx["n_hosts"] == 2
        assert ctx["n_vulns"] == 1
        assert ctx["n_flags"] == 2
        assert len(ctx["flags_captured"]) == 1


class TestDKGReset:
    """Reset behavior."""

    def test_reset_clears_all(self):
        dkg = DKG()
        dkg.add_node("Host", "h1")
        dkg.add_node("Vulnerability", "v1")
        assert len(dkg.query_nodes()) == 2

        dkg.reset()
        assert len(dkg.query_nodes()) == 0
        assert dkg.summary() == "DKG is empty"


class TestDKGProvenance:
    """P12: source/evidence/timestamp provenance metadata."""

    def test_add_node_with_provenance(self):
        dkg = DKG()
        dkg.add_node(
            "Endpoint",
            "e1",
            {"url": "http://x/login"},
            source="curl_get",
            evidence="HTTP 200 with login form",
            timestamp="2026-08-13T10:00:00",
        )
        prov = dkg.get_provenance("e1")
        assert prov["source"] == "curl_get"
        assert prov["evidence"] == "HTTP 200 with login form"
        assert prov["timestamp"] == "2026-08-13T10:00:00"

    def test_provenance_does_not_collide_with_flat_source_property(self):
        dkg = DKG()
        # Existing call sites already use a flat "source" domain property.
        dkg.add_node("Credential", "c1", {"source": "partial_success"})
        node = dkg.get_node("c1")
        assert node["source"] == "partial_success"
        assert node.get("provenance") is None
        assert dkg.get_provenance("c1")["source"] == "unknown"

    def test_legacy_node_reports_unknown_provenance(self):
        dkg = DKG()
        dkg.add_node("Host", "h1", {"ip": "10.0.0.1"})
        prov = dkg.get_provenance("h1")
        assert prov == {"source": "unknown", "evidence": "", "timestamp": ""}

    def test_get_provenance_missing_node_returns_none(self):
        dkg = DKG()
        assert dkg.get_provenance("nonexistent") is None

    def test_query_nodes_with_provenance_fills_unknown(self):
        dkg = DKG()
        dkg.add_node("Host", "h1", {"ip": "10.0.0.1"})
        dkg.add_node("Host", "h2", {"ip": "10.0.0.2"}, source="nmap_scan")

        rows = dkg.query_nodes("Host", with_provenance=True)
        by_id = {r["id"]: r["provenance"] for r in rows}
        assert by_id["h1"] == {"source": "unknown", "evidence": "", "timestamp": ""}
        assert by_id["h2"]["source"] == "nmap_scan"

        # Without the flag, legacy nodes simply have no provenance key.
        plain = dkg.query_nodes("Host")
        assert "provenance" not in plain[0]

    def test_provenance_survives_roundtrip(self):
        dkg = DKG()
        dkg.add_node(
            "Vulnerability",
            "v1",
            {"severity": "critical"},
            source="sqlmap_test",
            evidence="error-based injection confirmed",
        )
        data = dkg.to_dict()
        restored = DKG.from_dict(data)
        prov = restored.get_provenance("v1")
        assert prov["source"] == "sqlmap_test"
        assert prov["evidence"] == "error-based injection confirmed"

    def test_update_node_preserves_provenance(self):
        dkg = DKG()
        dkg.add_node("Host", "h1", {"ip": "10.0.0.1"}, source="nmap_scan")
        dkg.update_node("h1", {"os": "linux"})
        assert dkg.get_provenance("h1")["source"] == "nmap_scan"


class TestDKGAllNodeTypes:
    """All 8 node types can be created."""

    @pytest.mark.parametrize("ntype", NODE_TYPES)
    def test_create_each_node_type(self, ntype):
        dkg = DKG()
        node_id = dkg.add_node(ntype, f"{ntype.lower()}-test", {})
        node = dkg.get_node(node_id)
        assert node is not None
        assert node["type"] == ntype


class TestDKGAllEdgeTypes:
    """All 9 edge types can be created."""

    @pytest.mark.parametrize("etype", EDGE_TYPES)
    def test_create_each_edge_type(self, etype):
        dkg = DKG()
        dkg.add_node("Host", "source")
        # The target is intentionally left untyped: this test only verifies
        # registration of every edge name. Typed compatibility is covered by
        # the dedicated semantic validation tests below.
        dkg.add_edge("source", "target", etype)
        edges = dkg.query_edges()
        assert len(edges) == 1
        assert edges[0]["type"] == etype

    def test_typed_edge_rejects_wrong_endpoints(self):
        dkg = DKG()
        dkg.add_node("Host", "h1")
        dkg.add_node("Flag", "flag-1")
        with pytest.raises(ValueError, match="host_has_service.*Host -> Service"):
            dkg.add_edge("h1", "flag-1", "host_has_service")

    def test_semantic_violations_audit_legacy_edges(self):
        dkg = DKG.from_dict({
            "nodes": [
                {"id": "h1", "type": "Host"},
                {"id": "flag-1", "type": "Flag"},
            ],
            "edges": [{"from": "h1", "to": "flag-1", "type": "host_has_service"}],
        })
        violations = dkg.semantic_violations()
        assert len(violations) == 1
        assert violations[0]["type"] == "host_has_service"
