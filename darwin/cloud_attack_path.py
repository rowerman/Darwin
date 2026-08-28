"""Cloud Attack Path Reasoner (CTAGE Phase 2).

Given the DKG's cloud topology (populated by CloudTopologyMapper),
computes and ranks attack paths across four dimensions:

1. **Privilege Escalation Paths**: From current IAM role → higher-privilege roles
   via CAN_ASSUME edges (trust chain BFS).

2. **Container Escape Paths**: Match pod security profiles to escape methods,
   rank by risk score and ease of exploitation.

3. **Lateral Movement Paths**: Cross-namespace RBAC bindings enabling
   access from current namespace to target namespaces.

4. **Cross-Account Paths**: Trust relationships enabling movement between
   cloud accounts.

The output is a ranked list of AttackPath objects, each with a recommended
tool, difficulty estimate, and prerequisite chain.
"""

from __future__ import annotations

import logging
from collections import deque
from dataclasses import dataclass, field
from typing import Any

from darwin.dkg import DKG

log = logging.getLogger(__name__)


# ── Data structures ──────────────────────────────────────────────────────

@dataclass
class AttackPath:
    """A discovered attack path from current position to a target."""
    path_id: str
    category: str  # "privilege_escalation", "container_escape", "lateral_move", "cross_account"
    description: str
    steps: list[dict] = field(default_factory=list)
    difficulty: str = "unknown"  # "easy", "medium", "hard"
    estimated_time: str = "unknown"
    recommended_tools: list[str] = field(default_factory=list)
    prerequisites: list[str] = field(default_factory=list)
    confidence: float = 1.0  # 0.0–1.0, reduced for indirect paths
    node_ids: list[str] = field(default_factory=list)
    edge_keys: list[tuple[str, str, str]] = field(default_factory=list)

    def to_prompt_context(self) -> str:
        """Format as LLM-friendly prompt injection."""
        lines = [
            f"### [{self.category.upper()}] {self.description}",
            f"Difficulty: {self.difficulty} | Confidence: {self.confidence:.0%}",
        ]
        if self.prerequisites:
            lines.append(f"Prerequisites: {', '.join(self.prerequisites)}")
        if self.steps:
            lines.append("Steps:")
            for i, step in enumerate(self.steps, 1):
                tool = step.get("tool", "")
                target = step.get("target", "")
                lines.append(f"  {i}. {tool} → {target}")
        if self.recommended_tools:
            lines.append(f"Recommended tools: {', '.join(self.recommended_tools)}")
        return "\n".join(lines)


@dataclass
class AttackPathReport:
    """Complete attack path analysis result."""
    paths: list[AttackPath] = field(default_factory=list)
    summary: str = ""

    def to_prompt_context(self) -> str:
        """Format all paths as LLM prompt injection."""
        if not self.paths:
            return "## Cloud Attack Path Analysis\nNo viable attack paths found in current topology."

        lines = ["## Cloud Attack Path Analysis (CTAGE)"]
        lines.append(f"Total paths found: {len(self.paths)}")
        lines.append(self.summary)
        lines.append("")

        by_category: dict[str, list[AttackPath]] = {}
        for p in self.paths:
            by_category.setdefault(p.category, []).append(p)

        for category, paths in by_category.items():
            cat_label = {
                "privilege_escalation": "Privilege Escalation",
                "container_escape": "Container Escape",
                "lateral_move": "Lateral Movement",
                "cross_account": "Cross-Account",
            }.get(category, category)
            lines.append(f"### {cat_label} Paths ({len(paths)})")
            for p in paths[:5]:  # Top 5 per category
                lines.append(p.to_prompt_context())
                lines.append("")

        return "\n".join(lines)


def index_attack_path(dkg: DKG, path: AttackPath) -> tuple[list[str], list[tuple[str, str, str]]]:
    """Derive stable graph indexes from path steps and known node names."""
    node_ids: set[str] = set()
    searchable = " ".join([
        path.description,
        *path.prerequisites,
        *[str(step.get("target", "")) for step in path.steps],
    ])
    for node_id, data in dkg.graph.nodes(data=True):
        name = str(data.get("name", "") or "")
        if str(node_id) in searchable or (name and name in searchable):
            node_ids.add(str(node_id))
    edge_keys: set[tuple[str, str, str]] = set()
    for src in sorted(node_ids):
        if src not in dkg.graph:
            continue
        for _src, dst, key, data in dkg.graph.out_edges(src, keys=True, data=True):
            if str(dst) in node_ids:
                edge_keys.add((str(src), str(dst), str(data.get("type", ""))))
    return sorted(node_ids), sorted(edge_keys)


# ── Graph Queries ────────────────────────────────────────────────────────

def _get_outgoing_edges(dkg: DKG, node_id: str) -> list[tuple[str, str]]:
    """Get (target_id, edge_type) for all outgoing edges from node_id."""
    if node_id not in dkg.graph:
        return []
    return [
        (target, dkg.graph.edges[node_id, target, key].get("type", ""))
        for (src, target, key) in dkg.graph.out_edges(node_id, keys=True)
    ]


def _get_nodes_by_type(dkg: DKG, node_type: str) -> list[dict]:
    """Get all nodes of a given type with their properties."""
    return [
        {"id": nid, **dkg.graph.nodes[nid]}
        for nid in dkg.graph.nodes
        if dkg.graph.nodes[nid].get("type") == node_type
    ]


# ── Path Finder — Privilege Escalation ───────────────────────────────────

def find_privilege_escalation_paths(dkg: DKG, max_depth: int = 4) -> list[AttackPath]:
    """Find IAM privilege escalation paths via role assumption chains.

    BFS from each IAM role, following role_can_assume edges.
    """
    paths: list[AttackPath] = []
    iam_roles = _get_nodes_by_type(dkg, "IAMRole")

    # Build adjacency: role → [(target_role, edge_props)]
    adj: dict[str, list[tuple[str, dict]]] = {}
    for role in iam_roles:
        rid = role["id"]
        adj.setdefault(rid, [])
        for target_id, edge_type in _get_outgoing_edges(dkg, rid):
            if edge_type == "role_can_assume":
                target_node = dkg.graph.nodes.get(target_id, {})
                if target_node.get("type") == "IAMRole":
                    adj[rid].append((target_id, target_node))

    # BFS from each source role
    visited_global: set[tuple[str, str]] = set()
    for src_role in iam_roles:
        src_id = src_role["id"]
        src_name = src_role.get("name", src_id)
        queue: deque[tuple[str, list[dict], int]] = deque()
        queue.append((src_id, [], 0))
        visited: set[str] = {src_id}

        while queue:
            current_id, prefix_steps, depth = queue.popleft()
            if depth >= max_depth:
                continue

            for next_id, next_role in adj.get(current_id, []):
                if next_id in visited:
                    continue
                if (src_id, next_id) in visited_global:
                    continue

                visited.add(next_id)
                visited_global.add((src_id, next_id))
                next_name = next_role.get("name", next_id)

                step = {
                    "action": "assume_role",
                    "from_role": current_id,
                    "to_role": next_name,
                    "tool": "aws_iam_federation",
                    "target": next_name,
                }
                full_steps = prefix_steps + [step]

                difficulty = "easy" if depth == 0 else ("medium" if depth <= 2 else "hard")
                confidence = max(0.3, 1.0 - depth * 0.2)

                paths.append(AttackPath(
                    path_id=f"priv-esc-{src_name}-to-{next_name}",
                    category="privilege_escalation",
                    description=f"AssumeRole chain: {src_name} → {next_name}",
                    steps=list(full_steps),
                    difficulty=difficulty,
                    recommended_tools=["aws_iam_federation", "aws_cli"],
                    prerequisites=[f"IAM role: {src_name}"],
                    confidence=confidence,
                ))
                queue.append((next_id, full_steps, depth + 1))

    # Sort: easiest first, highest confidence first
    paths.sort(key=lambda p: (
        {"easy": 0, "medium": 1, "hard": 2}.get(p.difficulty, 3),
        -p.confidence,
    ))
    return paths


# ── Path Finder — Container Escape ───────────────────────────────────────

# Escape vector → recommended tool mapping
ESCAPE_TOOL_MAP = {
    "privileged_container": "nsenter_exec",
    "cap_sys_admin_cgroup": "container_escape_cgroup",
    "cap_dac_read_search": "container_escape_cap_dac",
    "cap_sys_ptrace": "container_escape_procfs",
    "cap_net_raw_mitm": "tcpdump_capture",
    "hostpid_procfs": "container_escape_procfs",
    "hostpath_escape": "container_escape_mount_disk",
    "docker_socket": "container_escape_docker_sock",
    "containerd_socket": "crictl_cmd",
    "crio_socket": "crictl_cmd",
}

ESCAPE_DIFFICULTY = {
    "privileged_container": "easy",
    "cap_sys_admin_cgroup": "easy",
    "docker_socket": "easy",
    "containerd_socket": "medium",
    "crio_socket": "medium",
    "hostpid_procfs": "medium",
    "hostpath_escape": "medium",
    "cap_dac_read_search": "medium",
    "cap_sys_ptrace": "hard",
    "cap_net_raw_mitm": "hard",
}


def find_container_escape_paths(dkg: DKG) -> list[AttackPath]:
    """Find container escape paths based on pod security profiles.

    Reads K8sPod nodes and their security attributes, matches escape
    vectors to tools, and ranks by risk score.
    """
    paths: list[AttackPath] = []
    pods = _get_nodes_by_type(dkg, "K8sPod")

    for pod in pods:
        pid = pod["id"]
        pod_name = pod.get("name", pid)
        namespace = pod.get("namespace", "")
        sa_name = "default"

        # Get SA via pod_mounts_sa edge
        for target_id, edge_type in _get_outgoing_edges(dkg, pid):
            if edge_type == "pod_mounts_sa":
                sa_node = dkg.graph.nodes.get(target_id, {})
                if sa_node.get("type") == "K8sSA":
                    sa_name = sa_node.get("name", sa_name)

        # Determine escape vectors from pod properties
        vectors = []
        if pod.get("host_pid"):
            vectors.append("hostpid_procfs")

        # Also check via JSON-encoded security data if present
        # (The pod node may have additional security metadata)

        if vectors:
            for vector in vectors:
                tool = ESCAPE_TOOL_MAP.get(vector, "check_capabilities")
                difficulty = ESCAPE_DIFFICULTY.get(vector, "medium")

                paths.append(AttackPath(
                    path_id=f"escape-{namespace}-{pod_name}-{vector}",
                    category="container_escape",
                    description=f"Escape {namespace}/{pod_name} via {vector}",
                    steps=[{
                        "action": "escape",
                        "vector": vector,
                        "pod": f"{namespace}/{pod_name}",
                        "tool": tool,
                        "target": f"{namespace}/{pod_name}",
                    }],
                    difficulty=difficulty,
                    recommended_tools=[tool, "check_capabilities", "check_mounts"],
                    prerequisites=[f"Access to pod {namespace}/{pod_name}",
                                   f"ServiceAccount: {sa_name}"],
                    confidence=0.9 if difficulty == "easy" else 0.7,
                ))

    # Sort by difficulty
    paths.sort(key=lambda p: {"easy": 0, "medium": 1, "hard": 2}.get(p.difficulty, 3))
    return paths


# ── Path Finder — Lateral Movement ───────────────────────────────────────

def find_lateral_movement_paths(dkg: DKG) -> list[AttackPath]:
    """Find cross-namespace lateral movement paths via RBAC bindings.

    For each SA→Role binding, check if the role grants access to resources
    in other namespaces.
    """
    paths: list[AttackPath] = []
    sas = _get_nodes_by_type(dkg, "K8sSA")

    for sa in sas:
        said = sa["id"]
        sa_name = sa.get("name", said)
        sa_ns = sa.get("namespace", "")

        # Follow SA → Role via sa_bound_to_role edges
        for target_id, edge_type in _get_outgoing_edges(dkg, said):
            if edge_type == "sa_bound_to_role":
                role = dkg.graph.nodes.get(target_id, {})
                role_name = role.get("name", target_id)
                role_ns = role.get("namespace", "cluster")

                is_cross_ns = role_ns not in ("", "cluster", sa_ns)

                if is_cross_ns or role_ns == "cluster":
                    move_type = "cross-namespace" if is_cross_ns else "cluster-scoped"
                    paths.append(AttackPath(
                        path_id=f"lateral-{sa_ns}-{sa_name}-to-{role_ns}",
                        category="lateral_move",
                        description=f"SA {sa_ns}/{sa_name} → {move_type} role {role_name}",
                        steps=[{
                            "action": "use_sa_token",
                            "sa": f"{sa_ns}/{sa_name}",
                            "role": role_name,
                            "scope": role_ns,
                            "tool": "k8s_sa_token_steal",
                        }],
                        difficulty="easy" if is_cross_ns else "medium",
                        recommended_tools=["k8s_sa_token_steal", "kubectl_get_secrets",
                                          "kubectl_get_pods"],
                        prerequisites=[f"SA token: {sa_ns}/{sa_name}"],
                        confidence=0.9 if is_cross_ns else 0.7,
                    ))

    # Sort: cross-namespace first (easier)
    paths.sort(key=lambda p: 0 if "cross-namespace" in p.description else 1)
    return paths


# ── Path Finder — Cross-Account ──────────────────────────────────────────

def find_cross_account_paths(dkg: DKG) -> list[AttackPath]:
    """Find cross-account attack paths via trust relationships."""
    paths: list[AttackPath] = []
    trusts = _get_nodes_by_type(dkg, "TrustRelationship")

    for trust in trusts:
        tid = trust["id"]
        principal = trust.get("principal", "")
        effect = trust.get("effect", "Allow")
        condition = trust.get("condition", "{}")

        # Get connected accounts
        connected_accounts = []
        for target_id, edge_type in _get_outgoing_edges(dkg, tid):
            if edge_type == "account_trusts":
                acct = dkg.graph.nodes.get(target_id, {})
                if acct.get("type") == "CloudAccount":
                    connected_accounts.append(acct.get("account_id", target_id))

        # Get source role
        source_role = ""
        for src_id, edge_type in _get_incoming_edges(dkg, tid):
            if edge_type == "role_can_assume":
                role = dkg.graph.nodes.get(src_id, {})
                source_role = role.get("name", src_id)

        for acct_id in connected_accounts:
            has_condition = condition and condition != "{}"
            difficulty = "hard" if has_condition else "medium"

            paths.append(AttackPath(
                path_id=f"cross-acct-{source_role}-to-{acct_id}",
                category="cross_account",
                description=f"Cross-account: {source_role} → account {acct_id}",
                steps=[{
                    "action": "assume_role_cross_account",
                    "from_role": source_role,
                    "target_account": acct_id,
                    "principal": principal,
                    "condition": condition,
                    "tool": "aws_iam_federation",
                }],
                difficulty=difficulty,
                recommended_tools=["aws_iam_federation", "aws_cli"],
                prerequisites=[f"Role: {source_role}",
                               f"Trust to account: {acct_id}"],
                confidence=0.6 if has_condition else 0.8,
            ))

    paths.sort(key=lambda p: {"medium": 0, "hard": 1}.get(p.difficulty, 2))
    return paths


def find_cloud_data_plane_paths(dkg: DKG) -> list[AttackPath]:
    """Find data-plane chains from SSRF through IMDS credentials to a flag."""
    paths: list[AttackPath] = []
    vulnerabilities = _get_nodes_by_type(dkg, "Vulnerability")
    credentials = _get_nodes_by_type(dkg, "Credential")
    roles = _get_nodes_by_type(dkg, "IAMRole")
    resources = [
        *(_get_nodes_by_type(dkg, "S3")),
        *(_get_nodes_by_type(dkg, "RDS")),
    ]
    flags = _get_nodes_by_type(dkg, "Flag")
    if not vulnerabilities or not credentials or not resources:
        return paths

    ssrf_vulns = [
        vuln for vuln in vulnerabilities
        if "ssrf" in str(vuln.get("vuln_type", "")).lower()
        or "server-side request" in str(vuln.get("vuln_type", "")).lower()
    ]
    if not ssrf_vulns:
        return paths

    for vuln in ssrf_vulns:
        vuln_id = str(vuln["id"])
        endpoint_text = str(vuln.get("endpoint", ""))

        for credential in credentials:
            cid = str(credential["id"])
            role_ids = {
                target for target, edge_type in _get_outgoing_edges(dkg, cid)
                if edge_type == "credential_for_role"
            }
            if roles and not role_ids:
                continue
            policy_ids = {
                policy_id
                for role_id in role_ids
                for policy_id, edge_type in _get_outgoing_edges(dkg, role_id)
                if edge_type == "role_has_policy"
            }
            for resource in resources:
                rid = str(resource["id"])
                resource_edges = {
                    source for source, edge_type in _get_incoming_edges(dkg, rid)
                    if edge_type == "policy_grants_resource"
                }
                if not policy_ids.intersection(resource_edges):
                    continue
                flag_ids = {
                    target for target, edge_type in _get_outgoing_edges(dkg, rid)
                    if edge_type == "resource_contains"
                }
                flag_ids &= {str(flag["id"]) for flag in flags}
                target_name = str(resource.get("BucketName", resource.get("name", rid)))
                path_id = f"data-plane-{vuln_id}-{cid}-{rid}"
                steps = [
                    {"action": "exploit_ssrf", "tool": "ssrf_probe", "target": endpoint_text or vuln_id},
                    {"action": "read_imds_credentials", "tool": "ssrf_probe", "target": "169.254.169.254/latest/meta-data/iam/security-credentials/"},
                    {"action": "use_cloud_credential", "tool": "aws_cli", "target": target_name},
                ]
                if flag_ids:
                    steps.append({"action": "retrieve_flag", "tool": "aws_cli", "target": ",".join(sorted(flag_ids))})
                paths.append(AttackPath(
                    path_id=path_id,
                    category="cloud_data_plane",
                    description=f"SSRF → IMDS credentials → cloud resource {target_name}",
                    steps=steps,
                    difficulty="easy",
                    recommended_tools=["ssrf_probe", "curl_get", "aws_cli"],
                    prerequisites=["Unauthenticated or exploitable SSRF endpoint", f"IAM role credential: {credential.get('username', cid)}"],
                    confidence=0.95 if flag_ids else 0.8,
                ))
    return paths


# ── Helper ───────────────────────────────────────────────────────────────

def _get_incoming_edges(dkg: DKG, node_id: str) -> list[tuple[str, str]]:
    """Get (source_id, edge_type) for all incoming edges to node_id."""
    if node_id not in dkg.graph:
        return []
    return [
        (src, dkg.graph.edges[src, node_id, key].get("type", ""))
        for (src, tgt, key) in dkg.graph.in_edges(node_id, keys=True)
    ]


# ── Main API ─────────────────────────────────────────────────────────────

def compute_attack_paths(dkg: DKG, categories: set[str] | None = None) -> AttackPathReport:
    """Compute all attack paths from the current DKG cloud topology.

    Returns a ranked AttackPathReport suitable for LLM prompt injection.
    """
    all_paths: list[AttackPath] = []

    categories = set(categories or {
        "privilege_escalation", "container_escape", "lateral_move", "cross_account",
        "cloud_data_plane",
    })

    # 1. Privilege escalation
    if "privilege_escalation" in categories:
        try:
            priv_paths = find_privilege_escalation_paths(dkg)
            all_paths.extend(priv_paths)
            log.info("CTAGE Reasoner: found %d privilege escalation paths", len(priv_paths))
        except Exception as e:
            log.debug("CTAGE Reasoner: privilege escalation analysis failed: %s", e)

    # 2. Container escape
    if "container_escape" in categories:
        try:
            escape_paths = find_container_escape_paths(dkg)
            all_paths.extend(escape_paths)
            log.info("CTAGE Reasoner: found %d container escape paths", len(escape_paths))
        except Exception as e:
            log.debug("CTAGE Reasoner: container escape analysis failed: %s", e)

    # 3. Lateral movement
    if "lateral_move" in categories:
        try:
            lateral_paths = find_lateral_movement_paths(dkg)
            all_paths.extend(lateral_paths)
            log.info("CTAGE Reasoner: found %d lateral movement paths", len(lateral_paths))
        except Exception as e:
            log.debug("CTAGE Reasoner: lateral movement analysis failed: %s", e)

    # 4. Cross-account
    if "cross_account" in categories:
        try:
            cross_paths = find_cross_account_paths(dkg)
            all_paths.extend(cross_paths)
            log.info("CTAGE Reasoner: found %d cross-account paths", len(cross_paths))
        except Exception as e:
            log.debug("CTAGE Reasoner: cross-account analysis failed: %s", e)

    if "cloud_data_plane" in categories:
        try:
            data_paths = find_cloud_data_plane_paths(dkg)
            all_paths.extend(data_paths)
            log.info("CTAGE Reasoner: found %d cloud data-plane paths", len(data_paths))
        except Exception as e:
            log.debug("CTAGE Reasoner: cloud data-plane analysis failed: %s", e)

    # Sort: easy first, high confidence first, then by category priority
    category_priority = {
        "container_escape": 0,
        "lateral_move": 1,
        "privilege_escalation": 2,
        "cross_account": 3,
        "cloud_data_plane": 1,
    }
    all_paths.sort(key=lambda p: (
        {"easy": 0, "medium": 1, "hard": 2, "unknown": 3}.get(p.difficulty, 3),
        -p.confidence,
        category_priority.get(p.category, 4),
    ))

    # Build summary
    by_cat: dict[str, int] = {}
    for p in all_paths:
        by_cat[p.category] = by_cat.get(p.category, 0) + 1

    summary_parts = []
    if by_cat:
        cat_labels = {
            "privilege_escalation": "privilege escalation",
            "container_escape": "container escape",
            "lateral_move": "lateral movement",
            "cross_account": "cross-account",
            "cloud_data_plane": "cloud data-plane",
        }
        summary_parts.append("Attack surface analysis complete. ")
        summary_parts.append(", ".join(
            f"{cnt} {cat_labels.get(cat, cat)} paths" for cat, cnt in sorted(by_cat.items())
        ))
    else:
        summary_parts.append(
            "No cloud/K8s topology data found in DKG. "
            "Run CloudTopologyMapper first to populate K8s/cloud nodes."
        )

    return AttackPathReport(
        paths=all_paths,
        summary="".join(summary_parts),
    )
