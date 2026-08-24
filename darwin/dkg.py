"""Dynamic Knowledge Graph — shared structured state.

Reference:
  - Cochise src/cochise/knowledge.py:73 — incremental knowledge accumulation
  - AWE MemoryStorage (SQLite) — node/edge schema design
  - VulnBot db/models/ — relational model for pentest entities
"""

from __future__ import annotations

import json
import logging
import threading
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

import networkx as nx

log = logging.getLogger(__name__)


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
    "PlanSummary",    # source_plan_id, phase, completed_tasks, key_findings, failed_approaches
    "Analysis",       # phase, type, content — application understanding from analyze phase

    # ── Cloud-native node types (CTAGE module) ──────────────────────
    "CloudAccount",     # provider, account_id, region — cloud account entity
    "IAMRole",          # name, arn, trust_policy, permissions_boundary
    "IAMPolicy",        # name, arn, actions, resources, effect
    "K8sCluster",       # name, api_url, version, node_count
    "K8sNode",          # LEGACY — host machines are unified as Host; kept for old checkpoints
    "K8sNamespace",     # name, cluster, labels
    "K8sPod",           # name, namespace, node, sa_name, privileged, capabilities, host_pid, phase
    "K8sSA",            # name, namespace, secrets, annotations
    "TrustRelationship",# source_account, target_account, principal, condition, type
    # Explicit cloud resources and Kubernetes control-plane resources.
    "VPC", "Subnet", "RouteTable", "SecurityGroup", "ENI", "EC2",  # EC2/ENI legacy; new writes use Host
    "EKS", "LoadBalancer", "RDS", "S3",
    "Deployment", "StatefulSet", "DaemonSet", "EndpointSlice", "Ingress",
    "NetworkPolicy", "Role", "ClusterRole", "RoleBinding",
    "ClusterRoleBinding", "Secret", "ConfigMap",
    "AttackPath",
]

# Canonical property fields per node type, with accepted alias names.
# ``add_node`` renames aliases to the canonical field and logs unknown keys
# (debug level) so writers converge on one vocabulary. Host is intentionally
# free-form: cloud/AD/K8s discovery modules attach arbitrary metadata without
# touching this table.
NODE_PROPERTY_SCHEMAS: Dict[str, Dict[str, Tuple[str, ...]]] = {
    "Endpoint": {
        "url": ("uri",),
        "params": (),  # DKG layer stores a comma-joined string; typed layer splits
    },
    "Vulnerability": {
        "parameter": ("param",),
    },
    "Credential": {
        "username": ("user",),
    },
}

_FREE_FORM_NODE_TYPES = {"Host"}

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

    # ── Cloud-native edge types (CTAGE module) ──────────────────────
    # K8s hierarchy
    "cluster_contains_node",       # K8sCluster → K8sNode
    "cluster_contains_namespace",  # K8sCluster → K8sNamespace
    "namespace_contains_pod",      # K8sNamespace → K8sPod
    "node_hosts_pod",              # K8sNode → K8sPod
    # K8s RBAC
    "pod_mounts_sa",               # K8sPod → K8sSA
    "sa_bound_to_role",            # K8sSA → IAMRole (via RBAC binding)
    # Cloud IAM
    "role_has_policy",             # IAMRole → IAMPolicy
    "policy_grants_access",        # IAMPolicy → CloudAccount (or resource)
    "role_can_assume",             # IAMRole → IAMRole (trust chain)
    # Cross-account / cross-layer
    "account_contains_role",       # CloudAccount → IAMRole
    "account_trusts",              # CloudAccount → CloudAccount (via TrustRelationship)
    # Session / credential access
    "session_has_cloud_cred",      # Session → Credential (cloud-specific: IAM keys, SA tokens)
    "credential_for_role",         # Credential → IAMRole
    # Service/resource and network relations used by topology analysis.
    "service_targets_pod",          # Service → K8sPod
    "workload_owns_pod",            # Deployment/StatefulSet/DaemonSet → K8sPod
    "binding_subject",              # RoleBinding/ClusterRoleBinding → K8sSA
    "binding_targets_role",          # RoleBinding/ClusterRoleBinding → Role/ClusterRole
    "role_grants_permission",        # Role/ClusterRole → K8sNamespace
    "ingress_routes_service",        # Ingress → Service
    "endpoint_slice_backed_by_service",  # EndpointSlice → Service
    "account_contains_resource",    # CloudAccount → AWS resource
    "resource_in_subnet",            # ENI/EC2 → Subnet
    "route_table_routes_to",         # RouteTable → Subnet/ENI
    "security_group_attaches",       # SecurityGroup → ENI/EC2
    "policy_grants_resource",        # IAMPolicy → AWS resource
    "eks_links_k8s_cluster",          # EKS → K8sCluster
    "resource_reaches_resource",      # network resource → resource
    "service_exposes_endpoint",    # Service → Endpoint
    "endpoint_backed_by_service",  # Endpoint → Service
    "host_reaches_host",            # Host → Host
    "service_calls_service",        # Service → Service
    "resource_contains",            # resource → resource
    "resource_exposed_via",         # resource → Endpoint/Service
    "resource_depends_on",          # resource → resource
    "network_policy_allows",        # NetworkPolicy → resource
    "network_policy_denies",        # NetworkPolicy → resource
]

EDGE_STATUS_VALUES = {"observed", "inferred", "hypothesized", "stale"}

# Canonical relationship semantics.  New collectors must use an existing
# semantic name instead of introducing a synonym with a different spelling.
EDGE_SEMANTICS: Dict[str, Dict[str, str]] = {
    "host_has_service": {"from": "Host", "to": "Service"},
    "host_has_endpoint": {"from": "Host", "to": "Endpoint"},
    "node_hosts_pod": {"from": "Host", "to": "K8sPod"},
    "cluster_contains_node": {"from": "K8sCluster", "to": "Host"},
    "pod_mounts_sa": {"from": "K8sPod", "to": "K8sSA"},
    "sa_bound_to_role": {"from": "K8sSA", "to": "IAMRole"},
    "role_has_policy": {"from": "IAMRole", "to": "IAMPolicy"},
    "credential_for": {"from": "Credential", "to": "Host"},
    "credential_for_role": {"from": "Credential", "to": "IAMRole"},
    "service_targets_pod": {"from": "Service", "to": "K8sPod"},
    "workload_owns_pod": {"from": "Workload", "to": "K8sPod"},
    "binding_subject": {"from": "Binding", "to": "K8sSA"},
    "binding_targets_role": {"from": "Binding", "to": "Role"},
    "role_grants_permission": {"from": "Role", "to": "K8sNamespace"},
    "ingress_routes_service": {"from": "Ingress", "to": "Service"},
    "endpoint_slice_backed_by_service": {"from": "EndpointSlice", "to": "Service"},
    "account_contains_resource": {"from": "CloudAccount", "to": "Resource"},
    "resource_in_subnet": {"from": "Host", "to": "Subnet"},
    "route_table_routes_to": {"from": "RouteTable", "to": "Resource"},
    "security_group_attaches": {"from": "SecurityGroup", "to": "Host"},
    "policy_grants_resource": {"from": "IAMPolicy", "to": "Resource"},
    "eks_links_k8s_cluster": {"from": "EKS", "to": "K8sCluster"},
    "resource_reaches_resource": {"from": "Resource", "to": "Resource"},
    "service_exposes_endpoint": {"from": "Service", "to": "Endpoint"},
    "endpoint_backed_by_service": {"from": "Endpoint", "to": "Service"},
    "host_reaches_host": {"from": "Host", "to": "Host"},
    "service_calls_service": {"from": "Service", "to": "Service"},
    "resource_contains": {"from": "Resource", "to": "Resource"},
    "resource_exposed_via": {"from": "Resource", "to": "Endpoint"},
    "resource_depends_on": {"from": "Resource", "to": "Resource"},
    "network_policy_allows": {"from": "NetworkPolicy", "to": "Resource"},
    "network_policy_denies": {"from": "NetworkPolicy", "to": "Resource"},
}


class DKG:
    """Dynamic Knowledge Graph with JSON persistence + async notifications.

    Thread-safe for multi-agent concurrent reads/writes.
    Agents can subscribe to node type changes via asyncio.Event notifications.
    """

    CHANGE_JOURNAL_LIMIT = 512

    def __init__(self, storage_path: str | None = None,
                 scope: Dict[str, Any] | None = None):
        self.graph = nx.MultiDiGraph()
        self.storage_path = storage_path
        self._lock = threading.RLock()
        self._created_at = datetime.now().isoformat()
        self._revision = 0
        self._attack_path_cache: tuple[int, list] | None = None
        self.scope: Dict[str, Any] = dict(scope or {})
        self._change_journal: list[dict[str, Any]] = []
        self._attack_path_states: Dict[str, Dict[str, Any]] = {}

    @property
    def revision(self) -> int:
        """Monotonic revision for consumers that cache graph snapshots."""
        with self._lock:
            return self._revision

    def _touch(self, change: Dict[str, Any] | None = None) -> None:
        self._revision += 1
        if change is not None:
            self._change_journal.append({"revision": self._revision, **change})
            if len(self._change_journal) > self.CHANGE_JOURNAL_LIMIT:
                del self._change_journal[:-self.CHANGE_JOURNAL_LIMIT]

    def set_scope(self, *, engagement_id: str = "", target_scope: str = "",
                  environment_scope: str = "") -> None:
        """Set checkpoint scope metadata without changing graph revision."""
        with self._lock:
            self.scope = {
                "engagement_id": str(engagement_id or ""),
                "target_scope": str(target_scope or ""),
                "environment_scope": str(environment_scope or ""),
            }
            self._persist()

    def validate_scope(self, expected: Dict[str, Any] | None) -> bool:
        """Return whether all supplied non-empty scope fields match."""
        expected = expected or {}
        with self._lock:
            return all(
                not value or self.scope.get(key, "") == value
                for key, value in expected.items()
            )

    def upsert_attack_path(self, path_id: str, *, confidence: float,
                           evidence: Any = None, status: str = "active",
                           updated_revision: int | None = None,
                           path: Any = None) -> Dict[str, Any]:
        """Persist stable attack-path state without adding graph noise."""
        if status not in {"active", "rejected", "stale"}:
            raise ValueError(f"Unknown attack path status: {status}")
        with self._lock:
            state = dict(self._attack_path_states.get(str(path_id), {}))
            state.update({
                "path_id": str(path_id),
                "confidence": max(0.0, min(1.0, float(confidence))),
                "status": status,
                "evidence": list(evidence or []) if isinstance(evidence, (list, tuple)) else evidence,
                "updated_revision": self._revision if updated_revision is None else int(updated_revision),
            })
            if path is not None:
                state["path"] = path
            self._attack_path_states[str(path_id)] = state
            self._persist()
            return dict(state)

    def attack_path_states(self) -> list[Dict[str, Any]]:
        with self._lock:
            return [dict(v) for v in self._attack_path_states.values()]

    # ── Node Operations ─────────────────────────────────────────────

    # P12: provenance for nodes written without provenance metadata.
    _UNKNOWN_PROVENANCE = {"source": "unknown", "evidence": "", "timestamp": ""}

    def add_node(
        self,
        node_type: str,
        node_id: str,
        properties: Dict[str, Any] | None = None,
        *,
        source: str = "",
        evidence: str = "",
        timestamp: str | None = None,
    ) -> str:
        """Add or update a typed node. Returns node_id.

        New nodes start at _version=1; updates increment the counter.

        P12: optional ``source`` / ``evidence`` / ``timestamp`` record who
        discovered this fact and why. They are stored under a nested
        ``provenance`` dict so they never collide with domain properties
        (some call sites already use a flat "source" key).
        """
        if node_type not in NODE_TYPES:
            raise ValueError(f"Unknown node type: {node_type}. Valid: {NODE_TYPES}")
        with self._lock:
            is_new = node_id not in self.graph
            props = self._normalize_properties(node_type, properties or {})
            if source or evidence or timestamp:
                provenance: Dict[str, str] = {}
                if source:
                    provenance["source"] = str(source)
                if evidence:
                    provenance["evidence"] = str(evidence)
                if timestamp:
                    provenance["timestamp"] = str(timestamp)
                props["provenance"] = provenance
            props["type"] = node_type
            props.setdefault("created_at", datetime.now().isoformat())
            props["updated_at"] = datetime.now().isoformat()
            if is_new:
                props["_version"] = 1
            else:
                props["_version"] = self.graph.nodes[node_id].get("_version", 0) + 1
            self.graph.add_node(node_id, **props)
            self._touch({
                "op": "node_upsert", "id": str(node_id),
                "data": {"id": str(node_id), **dict(props)},
            })
            self._persist()

        return node_id

    @staticmethod
    def _normalize_properties(
        node_type: str, props: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Canonicalize alias fields and DKG-layer storage types.

        - Renames declared aliases to their canonical field (e.g.
          Vulnerability ``param`` → ``parameter``, Credential ``user`` →
          ``username``).
        - Endpoint ``params`` is stored as a comma-joined string at the DKG
          layer; lists are joined here so readers never see two shapes.
        - Unknown keys are preserved (never dropped) but logged at debug so
          drift is visible without breaking discovery modules.
        - Host nodes are free-form by design (cloud/AD/K8s metadata).
        """
        schema = NODE_PROPERTY_SCHEMAS.get(node_type)
        if node_type in _FREE_FORM_NODE_TYPES or not schema:
            return props
        alias_to_canonical = {
            alias: canonical
            for canonical, aliases in schema.items()
            for alias in aliases
        }
        out: Dict[str, Any] = {}
        for key, value in props.items():
            canonical = alias_to_canonical.get(key)
            if canonical:
                if canonical not in out:
                    out[canonical] = value
                else:
                    log.debug(
                        "DKG %s: alias '%s' ignored (canonical '%s' already set)",
                        node_type, key, canonical,
                    )
                continue
            if node_type == "Endpoint" and key == "params" and isinstance(value, list):
                out[key] = ", ".join(str(p) for p in value)
                continue
            if key not in schema:
                log.debug("DKG %s node: unknown property '%s' (kept)", node_type, key)
            out[key] = value
        return out

    def get_provenance(self, node_id: str) -> Dict[str, str] | None:
        """Return the provenance dict for a node.

        Nodes written before P12 (or without provenance metadata) report
        ``{"source": "unknown", ...}`` instead of failing; a missing node
        returns None.
        """
        with self._lock:
            if node_id not in self.graph:
                return None
            prov = self.graph.nodes[node_id].get("provenance")
            if isinstance(prov, dict) and prov:
                return dict(prov)
            return dict(self._UNKNOWN_PROVENANCE)

    def get_node(self, node_id: str) -> Dict[str, Any] | None:
        """Get a single node by ID."""
        with self._lock:
            if node_id in self.graph:
                return dict(self.graph.nodes[node_id])
        return None

    def query_nodes(
        self,
        node_type: str | None = None,
        filters: Dict[str, Any] | None = None,
        *,
        with_provenance: bool = False,
    ) -> List[Dict[str, Any]]:
        """Query nodes by type and optional property filters.

        P12: ``with_provenance=True`` guarantees every result carries a
        ``provenance`` dict (unknown-shape for legacy nodes).
        """
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
        if with_provenance:
            for result in results:
                prov = result.get("provenance")
                if not (isinstance(prov, dict) and prov):
                    result["provenance"] = dict(self._UNKNOWN_PROVENANCE)
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
            self._touch({
                "op": "node_update", "id": str(node_id),
                "data": {"id": str(node_id), **dict(self.graph.nodes[node_id])},
            })
            self._persist()
        return True

    # ── Edge Operations ─────────────────────────────────────────────

    @staticmethod
    def _as_unique_values(value: Any, limit: int = 12) -> list[str]:
        if value in (None, ""):
            return []
        values = value if isinstance(value, (list, tuple, set)) else [value]
        out: list[str] = []
        for item in values:
            text = str(item)
            if text and text not in out:
                out.append(text)
            if len(out) >= limit:
                break
        return out

    def upsert_edge(
        self,
        from_id: str,
        to_id: str,
        edge_type: str,
        *,
        properties: Dict[str, Any] | None = None,
        confidence: float | None = None,
        source: str = "",
        evidence: str = "",
        status: str = "observed",
    ) -> bool:
        """Insert or merge one canonical typed edge.

        Returns True when the graph changed.  Historical parallel edges with
        the same ``(from, to, type)`` key are folded into the surviving edge.
        """
        if edge_type not in EDGE_TYPES:
            raise ValueError(f"Unknown edge type: {edge_type}. Valid: {EDGE_TYPES}")
        if status not in EDGE_STATUS_VALUES:
            raise ValueError(f"Unknown edge status: {status}")
        with self._lock:
            now = datetime.now().isoformat()
            incoming = dict(properties or {})
            incoming.pop("type", None)
            source = source or str(incoming.pop("source", "") or "")
            evidence = evidence or str(incoming.pop("evidence", "") or "")
            incoming.setdefault("status", status)
            if confidence is not None:
                incoming["confidence"] = float(confidence)
            existing_keys = [
                key for key, data in self.graph.get_edge_data(from_id, to_id, default={}).items()
                if data.get("type") == edge_type
            ]
            merged: Dict[str, Any] = {}
            for key in existing_keys:
                merged.update(dict(self.graph.edges[from_id, to_id, key]))
            merged.update(incoming)
            merged["type"] = edge_type
            merged.setdefault("created_at", now)
            merged.setdefault("first_seen", merged.get("created_at", now))
            merged["last_seen"] = now
            prior_status = str(merged.get("status", "") or "")
            incoming_status = str(incoming.get("status", status) or status)
            if incoming_status == "observed" and prior_status in {"inferred", "hypothesized"}:
                incoming_status = prior_status
            merged["status"] = incoming_status
            if source:
                prior = merged.get("provenance", {})
                prior_sources = self._as_unique_values(
                    prior.get("sources", prior.get("source", ""))
                ) if isinstance(prior, dict) else []
                if source not in prior_sources:
                    prior_sources.append(str(source))
                merged["provenance"] = {
                    "sources": prior_sources[:12],
                    "last_timestamp": now,
                }
            elif "provenance" not in merged:
                merged["provenance"] = {"sources": [], "last_timestamp": now}
            if evidence:
                prior_ev = merged.get("evidence", [])
                evs = self._as_unique_values(prior_ev)
                if evidence not in evs:
                    evs.append(str(evidence))
                merged["evidence"] = evs[:12]

            # Compare semantic data while ignoring observation time fields.
            comparable = {k: v for k, v in merged.items()
                          if k not in {"last_seen", "created_at", "first_seen"}}
            old_comparable: Dict[str, Any] = {}
            if existing_keys:
                old = dict(self.graph.edges[from_id, to_id, existing_keys[0]])
                old_comparable = {k: v for k, v in old.items()
                                  if k not in {"last_seen", "created_at", "first_seen"}}
            changed = (not existing_keys) or comparable != old_comparable or len(existing_keys) > 1
            if existing_keys:
                for key in existing_keys:
                    self.graph.remove_edge(from_id, to_id, key)
            self.graph.add_edge(from_id, to_id, **merged)
            if changed:
                self._touch({
                    "op": "edge_upsert",
                    "key": [str(from_id), str(to_id), str(edge_type)],
                    "data": {"from": str(from_id), "to": str(to_id), **dict(merged)},
                })
            self._persist()
            return changed

    def add_edge(
        self, from_id: str, to_id: str, edge_type: str, **properties
    ) -> None:
        """Backward-compatible wrapper around :meth:`upsert_edge`."""
        self.upsert_edge(from_id, to_id, edge_type, properties=properties)

    def query_edges(
        self,
        from_type: str | None = None,
        to_type: str | None = None,
        edge_type: str | None = None,
    ) -> List[Dict[str, Any]]:
        """Query edges with optional type filters."""
        results = []
        with self._lock:
            seen: set[tuple[str, str, str]] = set()
            for u, v, data in self.graph.edges(data=True):
                if edge_type and data.get("type") != edge_type:
                    continue
                if from_type and self.graph.nodes[u].get("type") != from_type:
                    continue
                if to_type and self.graph.nodes[v].get("type") != to_type:
                    continue
                key = (str(u), str(v), str(data.get("type", "")))
                if key in seen:
                    continue
                seen.add(key)
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

    def topology_snapshot(
        self,
        anchor_ids: list[str] | None = None,
        *,
        max_hops: int = 2,
        max_nodes: int = 48,
        max_edges: int = 96,
    ) -> Dict[str, Any]:
        """Return a deterministic, bounded local topology snapshot."""
        with self._lock:
            all_ids = sorted(str(nid) for nid in self.graph.nodes)
            anchors = [str(nid) for nid in (anchor_ids or []) if nid in self.graph]
            if not anchors:
                preferred = {"Session", "Host", "Service", "Endpoint"}
                anchors = [
                    nid for nid in all_ids
                    if self.graph.nodes[nid].get("type") in preferred
                ][:max_nodes]
            if not anchors:
                anchors = all_ids[:max_nodes]

            selected = set(anchors)
            frontier = set(anchors)
            undirected = self.graph.to_undirected(as_view=True)
            for _ in range(max(0, int(max_hops))):
                if len(selected) >= max_nodes:
                    break
                next_frontier: set[str] = set()
                for nid in sorted(frontier):
                    next_frontier.update(str(x) for x in undirected.neighbors(nid))
                next_frontier -= selected
                room = max_nodes - len(selected)
                selected.update(sorted(next_frontier)[:room])
                frontier = next_frontier

            nodes = []
            for nid in sorted(selected):
                nodes.append({"id": nid, **dict(self.graph.nodes[nid])})
            # Canonical edge view: dedupe parallel edges with the same
            # (from, to, type), keeping the first (earliest) record in
            # deterministic order, then apply the max_edges bound.
            edge_rows = sorted(
                self.graph.edges(keys=True, data=True),
                key=lambda item: (
                    str(item[0]), str(item[1]), str(item[2]),
                    str(item[3].get("type", "")),
                ),
            )
            seen_edges: set[tuple[str, str, str]] = set()
            edges = []
            for src, dst, _key, data in edge_rows:
                if str(src) in selected and str(dst) in selected:
                    edge_type = str(data.get("type", ""))
                    edge_key = (str(src), str(dst), edge_type)
                    if edge_key in seen_edges:
                        continue
                    seen_edges.add(edge_key)
                    edges.append({"from": str(src), "to": str(dst), **dict(data)})
                    if len(edges) >= max_edges:
                        break
            return {
                "revision": self._revision,
                "anchors": sorted(set(anchors)),
                "nodes": nodes,
                "edges": edges,
            }

    def topology_context(
        self,
        *,
        view: str = "cloud",
        anchors: list[str] | None = None,
        relation_types: list[str] | None = None,
        max_hops: int = 2,
        max_nodes: int = 48,
        max_edges: int = 96,
        since_revision: int | None = None,
    ) -> Dict[str, Any]:
        """Return bounded LLM context without truncating the raw DKG."""
        with self._lock:
            snapshot = self.topology_snapshot(
                anchor_ids=anchors,
                max_hops=max_hops,
                max_nodes=max_nodes,
                max_edges=max_edges,
            )
            if relation_types:
                allowed = {str(x) for x in relation_types}
                snapshot["edges"] = [
                    e for e in snapshot["edges"] if e.get("type") in allowed
                ]

            type_counts: Dict[str, int] = {}
            for _nid, data in self.graph.nodes(data=True):
                ntype = str(data.get("type", "unknown"))
                type_counts[ntype] = type_counts.get(ntype, 0) + 1
            total_nodes = self.graph.number_of_nodes()
            total_edges = len({
                (str(u), str(v), str(data.get("type", "")))
                for u, v, data in self.graph.edges(data=True)
            })

            journal = list(self._change_journal)
            history_complete = True
            changes: list[dict] = []
            if since_revision is not None:
                since = int(since_revision)
                if journal and since < journal[0].get("revision", 0) - 1:
                    history_complete = False
                changes = [
                    dict(item) for item in journal
                    if int(item.get("revision", 0)) > since
                ]

            included_nodes = len(snapshot.get("nodes", []))
            included_edges = len(snapshot.get("edges", []))
            coverage = {
                "total_nodes": total_nodes,
                "total_edges": total_edges,
                "included_nodes": included_nodes,
                "included_edges": included_edges,
                "omitted_nodes": max(0, total_nodes - included_nodes),
                "omitted_edges": max(0, total_edges - included_edges),
                "view": view,
                "complete": (
                    included_nodes >= total_nodes
                    and included_edges >= total_edges
                    and history_complete
                ),
            }
            return {
                "revision": self._revision,
                "view": view,
                "scope": dict(self.scope),
                "environment": dict(self.scope),
                "summary": {
                    "node_counts": type_counts,
                    "total_nodes": total_nodes,
                    "total_edges": total_edges,
                },
                "local": snapshot,
                "changes": changes,
                "coverage": coverage,
                "history_complete": history_complete,
                "omitted_count": {
                    "nodes": coverage["omitted_nodes"],
                    "edges": coverage["omitted_edges"],
                },
            }

    def attack_path_summary(
        self,
        max_paths: int = 12,
        *,
        affected_node_ids: set[str] | None = None,
        affected_edge_keys: set[tuple[str, str, str]] | None = None,
    ) -> list:
        """Return a bounded attack-path summary, gated and cached by revision.

        Only computes cloud/K8s attack paths when the graph actually contains
        the node types the four finders depend on; the result is cached for
        the current revision so repeated ``normalize_dkg_state()`` calls do
        not re-run the BFS analyses.
        """
        with self._lock:
            affected_node_ids = {str(x) for x in (affected_node_ids or set())}
            affected_edge_keys = {
                (str(a), str(b), str(c)) for a, b, c in (affected_edge_keys or set())
            }
            partial = bool(affected_node_ids or affected_edge_keys)
            if (
                self._attack_path_cache is not None
                and self._attack_path_cache[0] == self._revision
                and not partial
            ):
                return list(self._attack_path_cache[1])

            gate_types = {"IAMRole", "K8sPod", "K8sSA", "TrustRelationship"}
            if not any(
                data.get("type") in gate_types
                for _nid, data in self.graph.nodes(data=True)
            ):
                self._attack_path_cache = (self._revision, [])
                return []

            # Lazy import avoids a circular dependency: cloud_attack_path
            # imports DKG at module level.
            from darwin.cloud_attack_path import compute_attack_paths
            from darwin.cloud_attack_path import index_attack_path

            try:
                old_paths = list(self._attack_path_cache[1]) if self._attack_path_cache else []
                categories = None
                if partial and old_paths:
                    categories = set()
                    for node_id in affected_node_ids:
                        node_type = str(self.graph.nodes[node_id].get("type", "")) if node_id in self.graph else ""
                        categories.update({
                            "privilege_escalation", "cross_account"
                        } if node_type in {"IAMRole", "IAMPolicy", "CloudAccount", "EKS"} else set())
                        categories.update({
                            "container_escape", "lateral_move"
                        } if node_type in {"K8sPod", "K8sSA", "NetworkPolicy", "SecurityGroup", "Host"} else set())
                    for src, dst, edge_type in affected_edge_keys:
                        if edge_type in {"role_can_assume", "role_has_policy", "policy_grants_resource"}:
                            categories.update({"privilege_escalation", "cross_account"})
                        else:
                            categories.add("lateral_move")
                    if not categories:
                        return old_paths[: max(0, int(max_paths))]
                report = (
                    compute_attack_paths(self, categories=categories)
                    if categories is not None
                    else compute_attack_paths(self)
                )
                if categories is not None:
                    paths = [p for p in old_paths if p.category not in categories] + list(report.paths)
                else:
                    paths = list(report.paths)
                paths = paths[: max(0, int(max_paths))]
                for path in paths:
                    path_id = str(getattr(path, "path_id", "") or "")
                    if not path_id:
                        continue
                    node_ids, edge_keys = index_attack_path(self, path)
                    path.node_ids = node_ids
                    path.edge_keys = edge_keys
                    prior = self._attack_path_states.get(path_id, {})
                    self._attack_path_states[path_id] = {
                        **prior,
                        "path_id": path_id,
                        "confidence": float(prior.get("confidence", getattr(path, "confidence", 0.0))),
                        "status": prior.get("status", "active"),
                        "node_ids": node_ids,
                        "edge_keys": edge_keys,
                        "path": {
                            "category": getattr(path, "category", ""),
                            "description": getattr(path, "description", ""),
                            "steps": list(getattr(path, "steps", []) or []),
                        },
                        "updated_revision": self._revision,
                    }
                self._persist()
            except Exception:
                # Keep the previous silent-fallback behavior; do not cache
                # failures so a later call can retry.
                return []
            self._attack_path_cache = (self._revision, paths)
            return list(paths)

    @staticmethod
    def topology_diff(
        before: Dict[str, Any] | None,
        after: Dict[str, Any] | None,
    ) -> Dict[str, Any]:
        """Compute stable added/removed/updated node and edge records."""
        before = before or {}
        after = after or {}
        bnodes = {
            str(n.get("id")): n for n in before.get("nodes", [])
            if n.get("id") is not None
        }
        anodes = {
            str(n.get("id")): n for n in after.get("nodes", [])
            if n.get("id") is not None
        }
        edge_key = lambda e: (
            str(e.get("from")), str(e.get("to")), str(e.get("type", ""))
        )
        bedges = {edge_key(e): e for e in before.get("edges", [])}
        aedges = {edge_key(e): e for e in after.get("edges", [])}
        return {
            "from_revision": before.get("revision", 0),
            "to_revision": after.get("revision", 0),
            "added_nodes": [anodes[k] for k in sorted(set(anodes) - set(bnodes))],
            "removed_nodes": [bnodes[k] for k in sorted(set(bnodes) - set(anodes))],
            "updated_nodes": [
                anodes[k] for k in sorted(set(anodes) & set(bnodes))
                if anodes[k] != bnodes[k]
            ],
            "added_edges": [aedges[k] for k in sorted(set(aedges) - set(bedges))],
            "removed_edges": [bedges[k] for k in sorted(set(bedges) - set(aedges))],
        }

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
                "revision": self._revision,
                "scope": dict(self.scope),
                "change_journal": list(self._change_journal),
                "attack_path_states": list(self._attack_path_states.values()),
            }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DKG":
        """Deserialize from dict."""
        dkg = cls()
        for node in data.get("nodes", []):
            node_copy = dict(node)
            nid = node_copy.pop("id")
            dkg.graph.add_node(nid, **node_copy)
        # Fold legacy parallel edges without changing the persisted revision.
        for edge in data.get("edges", []):
            edge_copy = dict(edge)
            u = edge_copy.pop("from")
            v = edge_copy.pop("to")
            etype = edge_copy.get("type", "")
            if not etype:
                continue
            existing = [
                key for key, current in dkg.graph.get_edge_data(u, v, default={}).items()
                if current.get("type") == etype
            ]
            if not existing:
                dkg.graph.add_edge(u, v, **edge_copy)
                continue
            current = dict(dkg.graph.edges[u, v, existing[0]])
            for key in ("source", "evidence"):
                vals = DKG._as_unique_values(current.get(key)) + DKG._as_unique_values(edge_copy.get(key))
                if vals:
                    edge_copy[key] = vals[:12]
            if "confidence" in edge_copy:
                edge_copy["confidence"] = max(
                    float(current.get("confidence", 0.0) or 0.0),
                    float(edge_copy.get("confidence", 0.0) or 0.0),
                )
            current.update(edge_copy)
            for key in existing:
                dkg.graph.remove_edge(u, v, key)
            dkg.graph.add_edge(u, v, **current)
        dkg._created_at = data.get("created_at", datetime.now().isoformat())
        dkg._revision = int(data.get("revision", 0) or 0)
        dkg.scope = dict(data.get("scope", {}) or {})
        dkg._change_journal = list(data.get("change_journal", []) or [])[-dkg.CHANGE_JOURNAL_LIMIT:]
        dkg._attack_path_states = {
            str(item.get("path_id")): dict(item)
            for item in data.get("attack_path_states", [])
            if item.get("path_id")
        }
        dkg._attack_path_cache = None
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
            self._attack_path_cache = None
            self._attack_path_states.clear()
            self._change_journal.clear()
            self._touch({"op": "reset"})
