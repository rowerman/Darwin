"""Dynamic Knowledge Graph — shared structured state for all agents.

Reference:
  - Cochise src/cochise/knowledge.py:73 — incremental knowledge accumulation
  - AWE MemoryStorage (SQLite) — node/edge schema design
  - VulnBot db/models/ — relational model for pentest entities
"""

from __future__ import annotations

import json
import threading
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

import networkx as nx


# Node types
NODE_TYPES = [
    "Host",          # IP, OS, open_ports, is_reachable, is_internal
    "Service",        # port, protocol, version, banner
    "Endpoint",       # URL, method, params, auth_required
    "Vulnerability",  # type, endpoint, parameter, severity, cve_id
    "Credential",     # user, password, hash, type, source_host
    "Session",        # host, user, access_level, shell_type
    "Domain",         # name, functional_level, trusts
    "Flag",           # value, location, verified, is_honeypot_flag
]

# Edge types
EDGE_TYPES = [
    "host_has_service",      # Host → Service
    "host_has_endpoint",     # Host → Endpoint
    "service_has_vuln",      # Service → Vulnerability
    "endpoint_has_vuln",     # Endpoint → Vulnerability
    "session_on_host",       # Session → Host
    "credential_for",        # Credential → Host
    "host_in_domain",        # Host → Domain
    "domain_trusts",         # Domain → Domain (type: trust_direction)
    "vuln_exploited_by",     # Vulnerability → Credential/Session
]


class DKG:
    """Dynamic Knowledge Graph with JSON persistence.

    Thread-safe for multi-agent concurrent reads/writes.
    """

    def __init__(self, storage_path: str | None = None):
        self.graph = nx.MultiDiGraph()
        self.storage_path = storage_path
        self._lock = threading.RLock()
        self._created_at = datetime.now().isoformat()

    # ── Node Operations ─────────────────────────────────────────────

    def add_node(
        self, node_type: str, node_id: str, properties: Dict[str, Any] | None = None
    ) -> str:
        """Add or update a typed node. Returns node_id."""
        if node_type not in NODE_TYPES:
            raise ValueError(f"Unknown node type: {node_type}. Valid: {NODE_TYPES}")
        with self._lock:
            props = properties or {}
            props["type"] = node_type
            props.setdefault("created_at", datetime.now().isoformat())
            props["updated_at"] = datetime.now().isoformat()
            self.graph.add_node(node_id, **props)
            self._persist()
        return node_id

    def get_node(self, node_id: str) -> Dict[str, Any] | None:
        """Get a single node by ID."""
        with self._lock:
            if node_id in self.graph:
                return dict(self.graph.nodes[node_id])
        return None

    def query_nodes(
        self, node_type: str | None = None, filters: Dict[str, Any] | None = None
    ) -> List[Dict[str, Any]]:
        """Query nodes by type and optional property filters."""
        results = []
        with self._lock:
            for nid, data in self.graph.nodes(data=True):
                if node_type and data.get("type") != node_type:
                    continue
                if filters and not all(
                    data.get(k) == v for k, v in filters.items()
                ):
                    continue
                results.append({"id": nid, **data})
        return results

    def update_node(self, node_id: str, properties: Dict[str, Any]) -> bool:
        """Update node properties. Returns True if node exists."""
        with self._lock:
            if node_id not in self.graph:
                return False
            for k, v in properties.items():
                self.graph.nodes[node_id][k] = v
            self.graph.nodes[node_id]["updated_at"] = datetime.now().isoformat()
            self._persist()
        return True

    # ── Edge Operations ─────────────────────────────────────────────

    def add_edge(
        self, from_id: str, to_id: str, edge_type: str, **properties
    ) -> None:
        """Add a typed edge between two nodes."""
        if edge_type not in EDGE_TYPES:
            raise ValueError(f"Unknown edge type: {edge_type}. Valid: {EDGE_TYPES}")
        with self._lock:
            props = properties or {}
            props["type"] = edge_type
            props.setdefault("created_at", datetime.now().isoformat())
            self.graph.add_edge(from_id, to_id, **props)
            self._persist()

    def query_edges(
        self,
        from_type: str | None = None,
        to_type: str | None = None,
        edge_type: str | None = None,
    ) -> List[Dict[str, Any]]:
        """Query edges with optional type filters."""
        results = []
        with self._lock:
            for u, v, data in self.graph.edges(data=True):
                if edge_type and data.get("type") != edge_type:
                    continue
                if from_type and self.graph.nodes[u].get("type") != from_type:
                    continue
                if to_type and self.graph.nodes[v].get("type") != to_type:
                    continue
                results.append({"from": u, "to": v, **data})
        return results

    def get_neighbors(
        self, node_id: str, edge_type: str | None = None
    ) -> List[Dict[str, Any]]:
        """Get neighboring nodes (outgoing edges)."""
        results = []
        with self._lock:
            if node_id not in self.graph:
                return results
            for _, target, data in self.graph.out_edges(node_id, data=True):
                if edge_type and data.get("type") != edge_type:
                    continue
                target_data = dict(self.graph.nodes[target])
                results.append({"id": target, "edge_type": data.get("type"), **target_data})
        return results

    # ── High-Level Queries ──────────────────────────────────────────

    def get_defense_context(self) -> Dict[str, Any]:
        """Extract defense-relevant information from DKG."""
        hosts = self.query_nodes("Host")
        vulns = self.query_nodes("Vulnerability")
        flags = self.query_nodes("Flag")
        endpoints = self.query_nodes("Endpoint")

        return {
            "n_hosts": len(hosts),
            "n_vulns": len(vulns),
            "n_flags": len(flags),
            "n_endpoints": len(endpoints),
            "hosts": hosts,
            "vulnerabilities": vulns,
            "flags_captured": [f for f in flags if f.get("verified")],
        }

    def compute_task_breadth(self) -> float:
        """Compute B (Task Breadth) dimension from current DKG state.

        B = 0.4 * N_norm + 0.3 * M_domain + 0.3 * L_move
        """
        hosts = self.query_nodes("Host")
        domains = self.query_nodes("Domain")
        credentials = self.query_nodes("Credential")

        n_targets = len(hosts)
        is_multi_domain = len(domains) > 1

        internal_hosts = [h for h in hosts if h.get("is_internal", False)]
        needs_lateral = len(internal_hosts) > 0 and len(credentials) > 0

        N_norm = min(n_targets / 5.0, 1.0)
        M_domain = 1.0 if is_multi_domain else 0.0
        L_move = 1.0 if needs_lateral else 0.0

        return 0.4 * N_norm + 0.3 * M_domain + 0.3 * L_move

    def summary(self) -> str:
        """Human-readable summary of current DKG state."""
        lines = []
        for ntype in NODE_TYPES:
            nodes = self.query_nodes(ntype)
            if nodes:
                lines.append(f"{ntype}: {len(nodes)}")
                for n in nodes[:3]:  # show first 3
                    key_props = {k: v for k, v in n.items()
                                 if k not in ("id", "type", "created_at", "updated_at")}
                    lines.append(f"  - {n['id']}: {key_props}")
                if len(nodes) > 3:
                    lines.append(f"  ... and {len(nodes) - 3} more")
        return "\n".join(lines) if lines else "DKG is empty"

    # ── Persistence ─────────────────────────────────────────────────

    def _persist(self) -> None:
        """Save to JSON file if storage_path is set."""
        if self.storage_path:
            with open(self.storage_path, "w", encoding="utf-8") as f:
                json.dump(self.to_dict(), f, indent=2, default=str)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize graph to JSON-serializable dict."""
        with self._lock:
            return {
                "nodes": [
                    {"id": nid, **data}
                    for nid, data in self.graph.nodes(data=True)
                ],
                "edges": [
                    {"from": u, "to": v, **data}
                    for u, v, data in self.graph.edges(data=True)
                ],
                "created_at": self._created_at,
            }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DKG":
        """Deserialize from dict."""
        dkg = cls()
        for node in data.get("nodes", []):
            nid = node.pop("id")
            dkg.graph.add_node(nid, **node)
        for edge in data.get("edges", []):
            u = edge.pop("from")
            v = edge.pop("to")
            dkg.graph.add_edge(u, v, **edge)
        dkg._created_at = data.get("created_at", datetime.now().isoformat())
        return dkg

    def save(self, path: str) -> None:
        """Save to a specific path."""
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2, default=str)

    @classmethod
    def load(cls, path: str) -> "DKG":
        """Load from a JSON file."""
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return cls.from_dict(data)

    def reset(self) -> None:
        """Clear all nodes and edges."""
        with self._lock:
            self.graph.clear()
            self._created_at = datetime.now().isoformat()
