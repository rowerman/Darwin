"""Attack-surface graph projection, two-level vocabulary and similarity.

The DKG is the per-run world model.  This module turns it into a *portable*
representation that can be compared across tasks:

    DKG ──project_attack_surface──> snapshot ──fingerprint──> vector-ish dict
                                                        └──similarity──> score

Only the externally reachable subgraph is compared.  Local RBAC noise (a
single KIND cluster produces hundreds of ``role_grants_permission`` edges)
otherwise dominates every histogram and makes unrelated targets look alike.

Secrets never leave the DKG: ``Flag`` / ``Credential`` / ``ExploitPrimitive``
nodes are dropped entirely and the remaining properties are passed through the
same redaction used for prompt-facing views.
"""

from __future__ import annotations

import math
from typing import Any, Dict, Iterable, List, Sequence, Tuple

from darwin.dkg import EDGE_TYPES, DKG

# Node types that must never enter a cross-task snapshot: flags and credential
# material would leak one challenge's answer into the next run.
SNAPSHOT_EXCLUDED_TYPES = frozenset({"Flag", "Credential", "ExploitPrimitive"})

#: Where an attacker actually enters.  Everything else is only interesting if
#: it is reachable from one of these.
ANCHOR_TYPES = frozenset({"Host", "Endpoint", "LoadBalancer", "Ingress"})

COARSE_CLASSES = (
    "compute", "identity", "storage", "network",
    "control_plane", "orchestration", "web", "unknown",
)

#: Two-level vocabulary: fine-grained DKG type -> coarse resource class.  The
#: coarse layer is what gets compared (resource ids and counts differ across
#: targets); the fine layer explains a match to a human or an LLM.
_COARSE_BY_TYPE: Dict[str, str] = {
    # compute
    "Host": "compute", "EC2": "compute", "K8sNode": "compute", "K8sPod": "compute",
    "ENI": "compute",
    # identity
    "CloudAccount": "identity", "IAMRole": "identity", "IAMPolicy": "identity",
    "K8sSA": "identity", "Role": "identity", "ClusterRole": "identity",
    "RoleBinding": "identity", "ClusterRoleBinding": "identity",
    "TrustRelationship": "identity", "Domain": "identity", "Session": "identity",
    "Credential": "identity",
    # storage
    "S3": "storage", "RDS": "storage", "Secret": "storage", "ConfigMap": "storage",
    # network
    "VPC": "network", "Subnet": "network", "RouteTable": "network",
    "SecurityGroup": "network", "LoadBalancer": "network", "Ingress": "network",
    "NetworkPolicy": "network",
    # control plane
    "K8sCluster": "control_plane", "K8sNamespace": "control_plane",
    "EKS": "control_plane", "Deployment": "control_plane",
    "StatefulSet": "control_plane", "DaemonSet": "control_plane",
    "EndpointSlice": "control_plane",
    # application surface
    "Service": "web", "Endpoint": "web", "Vulnerability": "web",
    "ExploitPrimitive": "web", "Flag": "web", "Analysis": "web",
    "Plan": "web", "PlanSummary": "web", "AttackPath": "web",
}

#: Properties that describe *when we looked*, not *what is there*.  Two runs of
#: the same target must produce the same fingerprint.
_VOLATILE_KEYS = frozenset({
    "created_at", "updated_at", "first_seen", "last_seen", "timestamp",
    "_version", "provenance",
})

DEFAULT_WEIGHTS: Dict[str, float] = {
    "node": 0.30, "edge": 0.35, "schema": 0.15, "path": 0.20,
}

MAX_PATH_DEPTH = 4
MAX_PATH_SIGNATURES = 300


def coarse_class(node_type: str) -> str:
    """Coarse resource class for a DKG node type."""
    return _COARSE_BY_TYPE.get(str(node_type or ""), "unknown")


def _redact_and_strip(props: Dict[str, Any]) -> Dict[str, Any]:
    """Drop observation-time fields and redact credential-shaped values."""
    return {
        key: value for key, value in DKG._redact_sensitive(dict(props)).items()
        if key not in _VOLATILE_KEYS
    }


def _as_nodes(dkg: Any) -> List[Dict[str, Any]]:
    return [
        node for node in dkg.query_nodes()
        if node.get("type") not in SNAPSHOT_EXCLUDED_TYPES
    ]


def _as_edges(dkg: Any, allowed_ids: set) -> List[Dict[str, Any]]:
    return [
        edge for edge in dkg.query_edges()
        if str(edge.get("from")) in allowed_ids
        and str(edge.get("to")) in allowed_ids
        and str(edge.get("type", "")) in EDGE_TYPES
    ]


def attack_surface_ids(dkg: Any, *, max_hops: int = 3, max_nodes: int = 400) -> List[str]:
    """Ids reachable from an entry point within ``max_hops``."""
    nodes = _as_nodes(dkg)
    known = {str(node.get("id")) for node in nodes}
    adjacency: Dict[str, set] = {}
    for edge in dkg.query_edges():
        src, dst = str(edge.get("from")), str(edge.get("to"))
        if src not in known or dst not in known:
            continue
        adjacency.setdefault(src, set()).add(dst)
        adjacency.setdefault(dst, set()).add(src)

    anchors = sorted(
        str(node.get("id")) for node in nodes
        if node.get("type") in ANCHOR_TYPES
    )
    if not anchors:
        anchors = sorted(known)
    selected, frontier = set(anchors), set(anchors)
    for _ in range(max(0, int(max_hops))):
        if len(selected) >= max_nodes:
            break
        nxt: set = set()
        for node_id in frontier:
            nxt.update(adjacency.get(node_id, ()))
        nxt -= selected
        selected.update(sorted(nxt)[: max(0, max_nodes - len(selected))])
        frontier = nxt
    return sorted(selected)


def build_snapshot(
    dkg: Any,
    *,
    max_hops: int = 3,
    max_nodes: int = 400,
    labels: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    """Portable attack-surface snapshot of the current DKG."""
    all_nodes = {str(node.get("id")): node for node in _as_nodes(dkg)}
    all_edges = _as_edges(dkg, set(all_nodes))
    selected = set(attack_surface_ids(dkg, max_hops=max_hops, max_nodes=max_nodes))
    nodes = [
        {
            "id": str(node.get("id")),
            "type": str(node.get("type", "")),
            "coarse": coarse_class(str(node.get("type", ""))),
            "properties": _redact_and_strip({
                key: value for key, value in node.items() if key != "id"
            }),
        }
        for node in all_nodes.values() if str(node.get("id")) in selected
    ]
    nodes.sort(key=lambda item: item["id"])
    allowed = {item["id"] for item in nodes}
    all_keys = {
        (str(edge.get("from")), str(edge.get("to")), str(edge.get("type", "")))
        for edge in all_edges
    }
    edges, seen = [], set()
    for edge in all_edges:
        if str(edge.get("from")) not in allowed:
            continue
        key = (str(edge.get("from")), str(edge.get("to")), str(edge.get("type", "")))
        if key in seen:
            continue
        seen.add(key)
        edges.append({
            "from": key[0], "to": key[1], "type": key[2],
            "properties": _redact_and_strip({
                key_name: value for key_name, value in edge.items()
                if key_name not in {"from", "to", "type"}
            }),
        })
    edges.sort(key=lambda item: (item["from"], item["to"], item["type"]))

    return {
        "nodes": nodes,
        "edges": edges,
        "labels": dict(labels or {}),
        "coverage": {
            "nodes": len(nodes),
            "edges": len(edges),
            "total_nodes": len(all_nodes),
            "total_edges": len(all_keys),
            "complete": len(nodes) >= len(all_nodes) and len(seen) >= len(all_keys),
        },
    }


def _type_of(node: Dict[str, Any]) -> str:
    return str(node.get("coarse") or coarse_class(str(node.get("type", ""))))


def _path_signatures(
    nodes: Sequence[Dict[str, Any]], edges: Sequence[Dict[str, Any]]
) -> List[str]:
    """Typed walk signatures starting at entry points."""
    by_id = {str(node["id"]): node for node in nodes}
    out: Dict[str, List[Tuple[str, str]]] = {}
    for edge in edges:
        out.setdefault(str(edge.get("from")), []).append(
            (str(edge.get("type", "")), str(edge.get("to")))
        )
    for value in out.values():
        value.sort()

    signatures: set = set()

    def walk(node_id: str, trail: List[str], depth: int) -> None:
        if len(signatures) >= MAX_PATH_SIGNATURES:
            return
        for edge_type, target in out.get(node_id, ()):
            target_node = by_id.get(target)
            if target_node is None:
                continue
            step = f"-{edge_type}->{_type_of(target_node)}"
            current = trail + [step]
            signatures.add("".join(current))
            if depth + 1 < MAX_PATH_DEPTH:
                walk(target, current, depth + 1)

    for node in nodes:
        if str(node.get("type")) in ANCHOR_TYPES or str(node.get("type")) == "Host":
            walk(str(node["id"]), [_type_of(node)], 0)
    return sorted(signatures)[:MAX_PATH_SIGNATURES]


def fingerprint(subject: Any, *, labels: Dict[str, Any] | None = None) -> Dict[str, Any]:
    """Fingerprint a DKG instance or an existing snapshot."""
    snapshot = subject if isinstance(subject, dict) else build_snapshot(subject)
    nodes = list(snapshot.get("nodes", []))
    edges = list(snapshot.get("edges", []))

    node_hist: Dict[str, int] = {}
    detail_hist: Dict[str, int] = {}
    for node in nodes:
        node_hist[_type_of(node)] = node_hist.get(_type_of(node), 0) + 1
        fine = str(node.get("type", ""))
        detail_hist[fine] = detail_hist.get(fine, 0) + 1

    by_id = {str(node["id"]): node for node in nodes}
    edge_hist: Dict[str, int] = {}
    detail_edge_hist: Dict[str, int] = {}
    for edge in edges:
        src, dst = by_id.get(str(edge.get("from"))), by_id.get(str(edge.get("to")))
        if src is None or dst is None:
            continue
        key = f"{_type_of(src)}|{edge.get('type', '')}|{_type_of(dst)}"
        edge_hist[key] = edge_hist.get(key, 0) + 1
        fine_key = f"{src.get('type', '')}|{edge.get('type', '')}|{dst.get('type', '')}"
        detail_edge_hist[fine_key] = detail_edge_hist.get(fine_key, 0) + 1

    return {
        "schema": sorted(node_hist),
        "node_hist": node_hist,
        "edge_hist": edge_hist,
        "path_signatures": _path_signatures(nodes, edges),
        "detail": {"node_types": detail_hist, "edge_triples": detail_edge_hist},
        "totals": {"nodes": len(nodes), "edges": len(edges)},
        "coverage": dict(snapshot.get("coverage", {})),
        "labels": dict(labels if labels is not None else snapshot.get("labels", {})),
    }


def _cosine(left: Dict[str, float], right: Dict[str, float]) -> float:
    if not left or not right:
        return 0.0
    keys = set(left) | set(right)
    dot = sum(left.get(key, 0.0) * right.get(key, 0.0) for key in keys)
    norm_left = math.sqrt(sum(value * value for value in left.values()))
    norm_right = math.sqrt(sum(value * value for value in right.values()))
    if norm_left == 0.0 or norm_right == 0.0:
        return 0.0
    return dot / (norm_left * norm_right)


def _jaccard(left: Iterable[Any], right: Iterable[Any]) -> float:
    left_set, right_set = set(left), set(right)
    if not left_set and not right_set:
        return 1.0
    if not left_set or not right_set:
        return 0.0
    return len(left_set & right_set) / len(left_set | right_set)


def similarity(
    left: Dict[str, Any],
    right: Dict[str, Any],
    weights: Dict[str, float] | None = None,
) -> Dict[str, Any]:
    """Weighted similarity between two fingerprints, with components."""
    resolved = dict(DEFAULT_WEIGHTS)
    resolved.update({k: float(v) for k, v in (weights or {}).items() if k in resolved})
    total_weight = sum(resolved.values()) or 1.0
    components = {
        "node": _cosine(left.get("node_hist", {}), right.get("node_hist", {})),
        "edge": _cosine(left.get("edge_hist", {}), right.get("edge_hist", {})),
        "schema": _jaccard(left.get("schema", []), right.get("schema", [])),
        "path": _jaccard(left.get("path_signatures", []), right.get("path_signatures", [])),
    }
    score = sum(resolved[key] * value for key, value in components.items()) / total_weight
    return {
        "score": round(float(score), 6),
        "components": {key: round(float(value), 6) for key, value in components.items()},
        "weights": resolved,
    }


def shared_node_types(left: Dict[str, Any], right: Dict[str, Any]) -> List[str]:
    """Fine-grained node types present in both snapshots — used for explanations."""
    left_types = set((left.get("detail") or {}).get("node_types", {}))
    right_types = set((right.get("detail") or {}).get("node_types", {}))
    return sorted(left_types & right_types)


def _node_matches(condition: Dict[str, Any], node: Dict[str, Any]) -> bool:
    if str(node.get("type", "")) != str(condition.get("type", "")):
        return False
    where = condition.get("where")
    if not where:
        return True
    key, _, expected = str(where).partition("=")
    key = key.strip()
    properties = node.get("properties") if isinstance(node.get("properties"), dict) else {}
    if key not in properties:
        return False
    actual = properties[key]
    if not expected.strip():
        return bool(actual)
    if isinstance(actual, bool):
        return actual == (expected.strip().lower() in ("true", "1", "yes"))
    return str(actual).strip().lower() == expected.strip().lower()


def _edge_matches(
    condition: Dict[str, Any], edge: Dict[str, Any], by_id: Dict[str, Dict[str, Any]]
) -> bool:
    if str(edge.get("type", "")) != str(condition.get("type", "")):
        return False
    source = by_id.get(str(edge.get("from")))
    target = by_id.get(str(edge.get("to")))
    if source is None or target is None:
        return False
    from_types = condition.get("from_types")
    to_types = condition.get("to_types")
    if from_types and source.get("type") not in set(from_types):
        return False
    if to_types and target.get("type") not in set(to_types):
        return False
    return True


def match_graph_pattern(pattern: Dict[str, Any], snapshot: Dict[str, Any]) -> bool:
    """Whether ``snapshot`` contains the subgraph a corpus entry requires.

    Declared nodes/edges are containment conditions, not a bijection: the entry
    applies when *some* node/edge satisfies each condition.  Entries without a
    pattern, or with ``requires_subgraph: false``, always match.
    """
    if not isinstance(pattern, dict):
        return True
    if not pattern.get("requires_subgraph", True):
        return True
    nodes = list(snapshot.get("nodes") or [])
    edges = list(snapshot.get("edges") or [])
    by_id = {str(node.get("id")): node for node in nodes}
    for condition in pattern.get("nodes") or []:
        if not any(_node_matches(condition, node) for node in nodes):
            return False
    for condition in pattern.get("edges") or []:
        if not any(_edge_matches(condition, edge, by_id) for edge in edges):
            return False
    return True
