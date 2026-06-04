"""Dynamic Knowledge Graph — shared structured state for all agents.

Reference:
  - Cochise src/cochise/knowledge.py:73 — incremental knowledge accumulation
  - AWE MemoryStorage (SQLite) — node/edge schema design
  - VulnBot db/models/ — relational model for pentest entities

v2: Added asyncio.Event notification per node type for real-time
    multi-agent coordination. Agents can await wait_for_nodes()
    instead of polling.
"""

from __future__ import annotations

import asyncio
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
    "Plan",           # plan_id, phase, goal, total_tasks, completed, failed, status
    "Task",           # plan_id, instruction, tool, params, status, dependencies, attempts
    "PlanSummary",    # source_plan_id, phase, completed_tasks, key_findings, failed_approaches
    "Analysis",       # phase, type, content — application understanding from analyze phase
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
    "plan_contains_task",    # Plan → Task
    "task_depends_on",       # Task → Task
    "plan_successor",        # Plan → PlanSummary
]


class DKG:
    """Dynamic Knowledge Graph with JSON persistence + async notifications.

    Thread-safe for multi-agent concurrent reads/writes.
    Agents can subscribe to node type changes via asyncio.Event notifications.
    """

    def __init__(self, storage_path: str | None = None):
        self.graph = nx.MultiDiGraph()
        self.storage_path = storage_path
        self._lock = threading.RLock()
        self._created_at = datetime.now().isoformat()

        # Notification system: one asyncio.Event per node type
        self._events: dict[str, asyncio.Event] = {
            nt: asyncio.Event() for nt in NODE_TYPES
        }
        # Track node counts per type for change detection
        self._node_counts: dict[str, int] = {nt: 0 for nt in NODE_TYPES}

    # ── Node Operations ─────────────────────────────────────────────

    def add_node(
        self, node_type: str, node_id: str, properties: Dict[str, Any] | None = None
    ) -> str:
        """Add or update a typed node. Returns node_id.

        Triggers asyncio.Event notification for the node type,
        enabling real-time multi-agent coordination.
        New nodes start at _version=1; updates increment the counter.
        """
        if node_type not in NODE_TYPES:
            raise ValueError(f"Unknown node type: {node_type}. Valid: {NODE_TYPES}")
        with self._lock:
            is_new = node_id not in self.graph
            props = properties or {}
            props["type"] = node_type
            props.setdefault("created_at", datetime.now().isoformat())
            props["updated_at"] = datetime.now().isoformat()
            if is_new:
                props["_version"] = 1
            else:
                props["_version"] = self.graph.nodes[node_id].get("_version", 0) + 1
            self.graph.add_node(node_id, **props)
            self._persist()

        # Notify subscribers when new nodes appear.
        # Event stays set (no clear) so late subscribers don't miss notifications.
        # The _node_counts counter lets waiters detect new nodes without resetting.
        if is_new:
            self._node_counts[node_type] = self._node_counts.get(node_type, 0) + 1
            event = self._events.get(node_type)
            if event:
                event.set()

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
            self.graph.nodes[node_id]["_version"] = (
                self.graph.nodes[node_id].get("_version", 0) + 1
            )
            self.graph.nodes[node_id]["updated_at"] = datetime.now().isoformat()
            self._persist()
        return True

    def update_node_if_current(
        self, node_id: str, expected_version: int, properties: Dict[str, Any],
    ) -> bool:
        """Optimistic locking: update only if node version matches expected.

        Returns True if update succeeded, False if version mismatch (stale read).
        Prevents lost updates when multiple agents modify the same node.
        """
        with self._lock:
            if node_id not in self.graph:
                return False
            current = self.graph.nodes[node_id].get("_version", 0)
            if current != expected_version:
                return False
            for k, v in properties.items():
                self.graph.nodes[node_id][k] = v
            self.graph.nodes[node_id]["_version"] = current + 1
            self.graph.nodes[node_id]["updated_at"] = datetime.now().isoformat()
            self._persist()
        return True

    def get_node_version(self, node_id: str) -> int | None:
        """Get the current version of a node (for optimistic locking)."""
        with self._lock:
            if node_id not in self.graph:
                return None
            return self.graph.nodes[node_id].get("_version", 0)

    # ── Endpoint Claiming (Agent Dedup) ───────────────────────────────

    def claim_endpoint(self, agent_id: str, endpoint_url: str) -> bool:
        """Register an agent as working on a specific endpoint.

        Returns True if claim succeeded, False if already claimed by another agent.
        Uses a dedicated Claim node type in the graph.
        """
        claim_id = f"claim-{endpoint_url}"
        with self._lock:
            if claim_id in self.graph:
                existing = self.graph.nodes[claim_id].get("claimed_by", "")
                if existing and existing != agent_id:
                    return False  # Another agent already owns this
            self.graph.add_node(claim_id,
                type="_claim", claimed_by=agent_id, endpoint=endpoint_url,
                claimed_at=datetime.now().isoformat(),
            )
            self._node_counts["_claim"] = self._node_counts.get("_claim", 0) + 1
        return True

    def release_endpoint(self, agent_id: str, endpoint_url: str) -> None:
        """Release an agent's claim on an endpoint."""
        claim_id = f"claim-{endpoint_url}"
        with self._lock:
            if claim_id in self.graph:
                existing = self.graph.nodes[claim_id].get("claimed_by", "")
                if existing == agent_id:
                    self.graph.remove_node(claim_id)

    def is_endpoint_claimed(self, endpoint_url: str) -> tuple[bool, str]:
        """Check if an endpoint is claimed. Returns (claimed, agent_id)."""
        claim_id = f"claim-{endpoint_url}"
        with self._lock:
            if claim_id in self.graph:
                return True, self.graph.nodes[claim_id].get("claimed_by", "")
        return False, ""

    def get_claimed_endpoints(self, agent_id: str) -> list[str]:
        """Get all endpoints claimed by a specific agent."""
        results = []
        with self._lock:
            for nid, data in self.graph.nodes(data=True):
                if (data.get("type") == "_claim"
                        and data.get("claimed_by") == agent_id):
                    results.append(data.get("endpoint", ""))
        return results

    # ── Scoped Views ──────────────────────────────────────────────────

    def get_scoped_view(
        self,
        agent_type: str,
        target_hosts: list[str] | None = None,
        max_nodes: int = 50,
    ) -> dict:
        """Return a scoped DKG view tailored to an agent's role.

        ReconAgent sees: Host, Service, Endpoint within its target hosts.
        ExploitAgent sees: Vulnerability, Endpoint, Service within its targets.
        PivotAgent sees: Host, Credential, Session across all hosts.

        Args:
            agent_type: 'recon', 'exploit', or 'pivot'
            target_hosts: host IPs/IDs the agent is responsible for
            max_nodes: cap on returned nodes per type
        """
        agent_type = agent_type.lower()
        target_set = set(target_hosts or [])

        # Filter functions per agent type
        def _in_targets(node: dict) -> bool:
            if not target_set:
                return True
            ep = node.get("endpoint", "") or node.get("url", "") or node.get("ip", "")
            nid = node.get("id", "")
            # Substring match: endpoint URL contains the target host
            return any(
                t in ep or t in nid
                for t in target_set
            )

        node_types: list[str]
        if agent_type in ("recon", "reconagent"):
            node_types = ["Host", "Service", "Endpoint"]
        elif agent_type in ("exploit", "exploitagent"):
            node_types = ["Vulnerability", "Endpoint", "Service", "Flag"]
        elif agent_type in ("pivot", "pivotagent"):
            node_types = ["Host", "Credential", "Session"]
        else:
            node_types = NODE_TYPES

        view: dict[str, list[dict]] = {}
        with self._lock:
            for nt in node_types:
                nodes = []
                for nid, data in self.graph.nodes(data=True):
                    if data.get("type") != nt:
                        continue
                    node = {"id": nid, **dict(data)}
                    if _in_targets(node):
                        nodes.append(node)
                        if len(nodes) >= max_nodes:
                            break
                view[nt] = nodes
        return view

    def get_relevant_vulnerabilities(self, host_or_service: str) -> list[dict]:
        """Get vulnerabilities relevant to a specific host or service."""
        vulns = []
        with self._lock:
            for nid, data in self.graph.nodes(data=True):
                if data.get("type") != "Vulnerability":
                    continue
                ep = data.get("endpoint", "")
                if host_or_service in ep or host_or_service in nid:
                    vulns.append({"id": nid, **dict(data)})
        return vulns

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

    def summary(self) -> str:
        """Human-readable summary of current DKG state."""
        lines = []
        for ntype in NODE_TYPES:
            nodes = self.query_nodes(ntype)
            if nodes:
                lines.append(f"{ntype}: {len(nodes)}")
                for n in nodes[:8]:  # show up to 8 per type for LLM analysis
                    key_props = {k: v for k, v in n.items()
                                 if k not in ("id", "type", "created_at", "updated_at", "discovered_by")}
                    lines.append(f"  - id={n['id']}: {key_props}")
                if len(nodes) > 8:
                    lines.append(f"  ... and {len(nodes) - 8} more")
        return "\n".join(lines) if lines else "DKG is empty"

        # ── Async Notification API ────────────────────────────────────────

    async def wait_for_nodes(
        self, node_type: str, min_count: int = 1, timeout: float = 60.0,
    ) -> bool:
        """Wait until at least min_count nodes of node_type exist.

        Returns True if the condition was met, False on timeout.
        Used by the orchestrator to react to agent discoveries in real-time.
        """
        deadline = asyncio.get_event_loop().time() + timeout
        while True:
            current = len(self.query_nodes(node_type))
            if current >= min_count:
                return True
            remaining = deadline - asyncio.get_event_loop().time()
            if remaining <= 0:
                return False
            try:
                await asyncio.wait_for(
                    self._events[node_type].wait(), timeout=min(remaining, 5.0),
                )
            except asyncio.TimeoutError:
                continue

    async def wait_for_new_nodes(
        self, node_type: str, since_count: int, timeout: float = 30.0,
    ) -> bool:
        """Wait until the count of node_type exceeds since_count.

        Returns True if new nodes appeared, False on timeout.
        """
        return await self.wait_for_nodes(node_type, since_count + 1, timeout)

    def get_node_count(self, node_type: str) -> int:
        """Get the current count of nodes of the given type."""
        return len(self.query_nodes(node_type))

    def subscribe(self, node_type: str) -> asyncio.Event:
        """Get the asyncio.Event for a node type (for custom wait logic)."""
        return self._events.get(node_type, asyncio.Event())

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
        import os
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
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
