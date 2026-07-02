"""Cloud Topology & Attack Graph Engine (CTAGE) — Cloud Topology Mapper.

Maps Kubernetes cluster topology and cloud IAM relationships into the DKG
as first-class node types (K8sCluster, K8sNode, K8sPod, K8sSA, IAMRole, etc.)
with typed edges representing RBAC bindings, container hierarchies, and
cloud trust relationships.

This extends the orchestrator's existing ``_k8s_cluster_discovery()`` with:
- Fine-grained pod security context analysis
- RBAC relationship graph construction (Role→RoleBinding→SA→Pod)
- IAM role enumeration (via IMDS or AWS API)
- Cross-account trust relationship detection

Reference: BloodHound graph-based attack path analysis adapted for K8s/cloud.
"""

from __future__ import annotations

import asyncio
import json as _json
import logging
import re
from dataclasses import dataclass, field
from typing import Any

from darwin.dkg import DKG

log = logging.getLogger(__name__)


# ── Data structures ──────────────────────────────────────────────────────

@dataclass
class K8sRBACBinding:
    """Represents a K8s RBAC binding (RoleBinding or ClusterRoleBinding)."""
    name: str
    namespace: str  # "" for cluster-scoped
    kind: str  # "RoleBinding" or "ClusterRoleBinding"
    role_name: str
    role_kind: str  # "Role" or "ClusterRole"
    subjects: list[dict] = field(default_factory=list)  # [{kind, name, namespace}]


@dataclass
class PodSecurityProfile:
    """Security-relevant properties extracted from a pod spec."""
    pod_name: str
    namespace: str
    privileged: bool = False
    capabilities_add: list[str] = field(default_factory=list)
    host_pid: bool = False
    host_network: bool = False
    host_ipc: bool = False
    host_path_mounts: list[str] = field(default_factory=list)
    mounted_sockets: list[str] = field(default_factory=list)
    service_account: str = "default"
    run_as_user: int | None = None
    run_as_group: int | None = None

    @property
    def escape_vectors(self) -> list[str]:
        """Return list of applicable escape vectors based on security profile."""
        vectors = []
        if self.privileged:
            vectors.append("privileged_container")
        if "SYS_ADMIN" in self.capabilities_add:
            vectors.append("cap_sys_admin_cgroup")
        if "CAP_DAC_READ_SEARCH" in self.capabilities_add:
            vectors.append("cap_dac_read_search")
        if "CAP_SYS_PTRACE" in self.capabilities_add:
            vectors.append("cap_sys_ptrace")
        if "CAP_NET_RAW" in self.capabilities_add:
            vectors.append("cap_net_raw_mitm")
        if self.host_pid:
            vectors.append("hostpid_procfs")
        if self.host_path_mounts:
            vectors.append("hostpath_escape")
        if any("docker.sock" in s for s in self.mounted_sockets):
            vectors.append("docker_socket")
        if any("containerd.sock" in s for s in self.mounted_sockets):
            vectors.append("containerd_socket")
        if any("crio.sock" in s for s in self.mounted_sockets):
            vectors.append("crio_socket")
        return vectors

    @property
    def risk_score(self) -> float:
        """0.0 (safe) to 1.0 (critical). Weighted by escape vector severity."""
        score = 0.0
        if self.privileged:
            score += 0.40
        if "SYS_ADMIN" in self.capabilities_add:
            score += 0.30
        if self.host_pid:
            score += 0.20
        if self.host_path_mounts:
            score += 0.15
        if self.mounted_sockets:
            score += 0.25
        if "CAP_DAC_READ_SEARCH" in self.capabilities_add:
            score += 0.15
        if "CAP_SYS_PTRACE" in self.capabilities_add:
            score += 0.10
        return min(score, 1.0)


@dataclass
class CloudTopology:
    """Aggregated cloud/K8s topology snapshot."""
    clusters: list[dict] = field(default_factory=list)
    nodes: list[dict] = field(default_factory=list)
    namespaces: list[str] = field(default_factory=list)
    pods: list[dict] = field(default_factory=list)
    pod_security_profiles: list[PodSecurityProfile] = field(default_factory=list)
    rbac_bindings: list[K8sRBACBinding] = field(default_factory=list)
    service_accounts: list[dict] = field(default_factory=list)
    iam_roles: list[dict] = field(default_factory=list)
    cross_account_trusts: list[dict] = field(default_factory=list)
    high_risk_pods: list[PodSecurityProfile] = field(default_factory=list)


# ── K8s Topology Discovery ──────────────────────────────────────────────

class CloudTopologyMapper:
    """Discovers K8S cluster topology + cloud IAM and writes to DKG."""

    def __init__(self, dkg: DKG):
        self.dkg = dkg

    async def discover(self) -> CloudTopology:
        """Run full cloud topology discovery and populate DKG.

        Returns a CloudTopology snapshot for downstream reasoning.
        """
        topology = CloudTopology()

        # Phase 1: K8s cluster topology
        await self._discover_clusters(topology)
        if topology.clusters:
            await self._discover_nodes(topology)
            await self._discover_namespaces(topology)
            await self._discover_pods(topology)
            await self._discover_service_accounts(topology)
            await self._discover_rbac(topology)

        # Phase 2: Pod security analysis
        topology.pod_security_profiles = self._analyze_pod_security(topology.pods)
        topology.high_risk_pods = [
            p for p in topology.pod_security_profiles if p.risk_score > 0.3
        ]

        # Phase 3: Cloud IAM (only if IMDS/cloud metadata reachable)
        await self._discover_iam(topology)

        # Phase 4: Write to DKG
        self._write_to_dkg(topology)

        return topology

    # ── Phase 1: K8s cluster topology ─────────────────────────────────

    async def _discover_clusters(self, topology: CloudTopology) -> None:
        """Discover K8s cluster(s) via kubectl."""
        try:
            proc = await asyncio.create_subprocess_shell(
                "kubectl cluster-info 2>&1",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=8)
            out = stdout.decode("utf-8", errors="replace")
            if proc.returncode != 0 or "is running at" not in out:
                return

            api_match = re.search(r"is running at (https?://\S+)", out)
            api_url = api_match.group(1) if api_match else ""

            # Get cluster name from current context
            cluster_name = "default"
            try:
                proc2 = await asyncio.create_subprocess_shell(
                    "kubectl config current-context 2>&1",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout2, _ = await asyncio.wait_for(proc2.communicate(), timeout=5)
                if proc2.returncode == 0:
                    cluster_name = stdout2.decode("utf-8", errors="replace").strip()
            except Exception:
                pass

            # Get server version
            version = ""
            try:
                proc3 = await asyncio.create_subprocess_shell(
                    "kubectl version --short 2>&1",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout3, _ = await asyncio.wait_for(proc3.communicate(), timeout=5)
                if proc3.returncode == 0:
                    out3 = stdout3.decode("utf-8", errors="replace")
                    vm = re.search(r"Server Version: v?(\S+)", out3)
                    if vm:
                        version = vm.group(1)
            except Exception:
                pass

            topology.clusters.append({
                "name": cluster_name,
                "api_url": api_url,
                "version": version,
            })
            log.info("CloudTopologyMapper: discovered cluster '%s' at %s", cluster_name, api_url)
        except Exception as e:
            log.debug("CloudTopologyMapper: cluster discovery failed: %s", e)

    async def _discover_nodes(self, topology: CloudTopology) -> None:
        """Enumerate K8s nodes."""
        try:
            proc = await asyncio.create_subprocess_shell(
                "kubectl get nodes -o json 2>&1",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=8)
            out = stdout.decode("utf-8", errors="replace")
            if proc.returncode != 0 or not out.strip().startswith("{"):
                return

            data = _json.loads(out)
            for item in data.get("items", []):
                meta = item.get("metadata", {})
                status = item.get("status", {})
                spec = item.get("spec", {})

                internal_ip = ""
                for addr in status.get("addresses", []):
                    if addr.get("type") == "InternalIP":
                        internal_ip = addr.get("address", "")
                        break

                is_cp = any(
                    "control-plane" in l or l == "node-role.kubernetes.io/master"
                    for l in meta.get("labels", {})
                )

                taints = [
                    f"{t.get('key','')}={t.get('value','')}:{t.get('effect','')}"
                    for t in spec.get("taints", [])
                ]

                topology.nodes.append({
                    "name": meta.get("name", ""),
                    "internal_ip": internal_ip,
                    "is_control_plane": is_cp,
                    "labels": meta.get("labels", {}),
                    "taints": taints,
                    "cluster": topology.clusters[0]["name"] if topology.clusters else "",
                })
        except Exception as e:
            log.debug("CloudTopologyMapper: node discovery failed: %s", e)

    async def _discover_namespaces(self, topology: CloudTopology) -> None:
        """Enumerate K8s namespaces."""
        try:
            proc = await asyncio.create_subprocess_shell(
                "kubectl get namespaces -o json 2>&1",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=8)
            out = stdout.decode("utf-8", errors="replace")
            if proc.returncode == 0 and out.strip().startswith("{"):
                data = _json.loads(out)
                topology.namespaces = [
                    i.get("metadata", {}).get("name", "")
                    for i in data.get("items", [])
                ]
        except Exception as e:
            log.debug("CloudTopologyMapper: namespace discovery failed: %s", e)

    async def _discover_pods(self, topology: CloudTopology) -> None:
        """Enumerate K8s pods with full security context."""
        try:
            proc = await asyncio.create_subprocess_shell(
                "kubectl get pods -A -o json 2>&1",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
            out = stdout.decode("utf-8", errors="replace")
            if proc.returncode != 0 or not out.strip().startswith("{"):
                return

            data = _json.loads(out)
            for item in data.get("items", []):
                meta = item.get("metadata", {})
                spec = item.get("spec", {})
                status = item.get("status", {})

                pod_info = {
                    "name": meta.get("name", ""),
                    "namespace": meta.get("namespace", ""),
                    "node_name": spec.get("nodeName", ""),
                    "service_account": spec.get("serviceAccountName", "default"),
                    "phase": status.get("phase", "Unknown"),
                    "host_network": spec.get("hostNetwork", False),
                    "host_pid": spec.get("hostPID", False),
                    "host_ipc": spec.get("hostIPC", False),
                    "labels": meta.get("labels", {}),
                    "containers": [],
                    "volumes": [],
                }

                # Extract volume info
                for vol in spec.get("volumes", []):
                    vol_info = {"name": vol.get("name", "")}
                    if "hostPath" in vol:
                        vol_info["type"] = "hostPath"
                        vol_info["path"] = vol["hostPath"].get("path", "")
                    elif "persistentVolumeClaim" in vol:
                        vol_info["type"] = "pvc"
                    elif "emptyDir" in vol:
                        vol_info["type"] = "emptyDir"
                    elif "secret" in vol:
                        vol_info["type"] = "secret"
                    elif "configMap" in vol:
                        vol_info["type"] = "configMap"
                    elif "projected" in vol:
                        vol_info["type"] = "projected"
                        # Check for SA token projection
                        for src in vol["projected"].get("sources", []):
                            if "serviceAccountToken" in src:
                                vol_info["type"] = "projected_sa_token"
                    pod_info["volumes"].append(vol_info)

                # Extract container security contexts
                for container in spec.get("containers", []):
                    ctx = container.get("securityContext", {})
                    cont_info = {
                        "name": container.get("name", ""),
                        "image": container.get("image", ""),
                        "privileged": ctx.get("privileged", False),
                        "capabilities_add": ctx.get("capabilities", {}).get("add", []),
                        "capabilities_drop": ctx.get("capabilities", {}).get("drop", []),
                        "run_as_user": ctx.get("runAsUser"),
                        "run_as_group": ctx.get("runAsGroup"),
                        "read_only_root_fs": ctx.get("readOnlyRootFilesystem", False),
                        "allow_privilege_escalation": ctx.get("allowPrivilegeEscalation"),
                        "volume_mounts": [
                            {"name": vm.get("name", ""), "mount_path": vm.get("mountPath", ""),
                             "read_only": vm.get("readOnly", False)}
                            for vm in container.get("volumeMounts", [])
                        ],
                    }
                    pod_info["containers"].append(cont_info)

                topology.pods.append(pod_info)
        except Exception as e:
            log.debug("CloudTopologyMapper: pod discovery failed: %s", e)

    async def _discover_service_accounts(self, topology: CloudTopology) -> None:
        """Enumerate K8s service accounts."""
        try:
            proc = await asyncio.create_subprocess_shell(
                "kubectl get serviceaccounts -A -o json 2>&1",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=8)
            out = stdout.decode("utf-8", errors="replace")
            if proc.returncode != 0 or not out.strip().startswith("{"):
                return

            data = _json.loads(out)
            for item in data.get("items", []):
                meta = item.get("metadata", {})
                sa_info = {
                    "name": meta.get("name", ""),
                    "namespace": meta.get("namespace", ""),
                    "secrets": [
                        s.get("name", "") for s in item.get("secrets", [])
                    ],
                    "annotations": meta.get("annotations", {}),
                }
                topology.service_accounts.append(sa_info)
        except Exception as e:
            log.debug("CloudTopologyMapper: SA discovery failed: %s", e)

    async def _discover_rbac(self, topology: CloudTopology) -> None:
        """Enumerate K8s RBAC bindings (Roles + RoleBindings + ClusterRoles + ClusterRoleBindings)."""
        # ClusterRoleBindings
        try:
            proc = await asyncio.create_subprocess_shell(
                "kubectl get clusterrolebindings -o json 2>&1",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=8)
            out = stdout.decode("utf-8", errors="replace")
            if proc.returncode == 0 and out.strip().startswith("{"):
                data = _json.loads(out)
                for item in data.get("items", []):
                    rb = item.get("roleRef", {})
                    topology.rbac_bindings.append(K8sRBACBinding(
                        name=item.get("metadata", {}).get("name", ""),
                        namespace="",
                        kind="ClusterRoleBinding",
                        role_name=rb.get("name", ""),
                        role_kind=rb.get("kind", "ClusterRole"),
                        subjects=item.get("subjects", []),
                    ))
        except Exception as e:
            log.debug("CloudTopologyMapper: CRB discovery failed: %s", e)

        # RoleBindings (per namespace)
        try:
            proc = await asyncio.create_subprocess_shell(
                "kubectl get rolebindings -A -o json 2>&1",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
            out = stdout.decode("utf-8", errors="replace")
            if proc.returncode == 0 and out.strip().startswith("{"):
                data = _json.loads(out)
                for item in data.get("items", []):
                    meta = item.get("metadata", {})
                    rb = item.get("roleRef", {})
                    topology.rbac_bindings.append(K8sRBACBinding(
                        name=meta.get("name", ""),
                        namespace=meta.get("namespace", ""),
                        kind="RoleBinding",
                        role_name=rb.get("name", ""),
                        role_kind=rb.get("kind", "Role"),
                        subjects=item.get("subjects", []),
                    ))
        except Exception as e:
            log.debug("CloudTopologyMapper: RB discovery failed: %s", e)

    # ── Phase 2: Pod security analysis ─────────────────────────────────

    def _analyze_pod_security(self, pods: list[dict]) -> list[PodSecurityProfile]:
        """Extract security profiles and compute escape vectors for each pod."""
        profiles = []
        for pod in pods:
            for container in pod.get("containers", []):
                profile = PodSecurityProfile(
                    pod_name=pod["name"],
                    namespace=pod["namespace"],
                    privileged=container.get("privileged", False),
                    capabilities_add=container.get("capabilities_add", []),
                    host_pid=pod.get("host_pid", False),
                    host_network=pod.get("host_network", False),
                    host_ipc=pod.get("host_ipc", False),
                    service_account=pod.get("service_account", "default"),
                    run_as_user=container.get("run_as_user"),
                    run_as_group=container.get("run_as_group"),
                )

                # Detect mounted sockets and host paths
                for vm in container.get("volume_mounts", []):
                    mp = vm.get("mount_path", "")
                    if "docker.sock" in mp:
                        profile.mounted_sockets.append(mp)
                    elif "containerd.sock" in mp or "crio.sock" in mp:
                        profile.mounted_sockets.append(mp)
                    if "/host-" in mp or "/host_" in mp:
                        profile.host_path_mounts.append(mp)

                # Also check volumes for hostPath
                for vol in pod.get("volumes", []):
                    if vol.get("type") == "hostPath":
                        path = vol.get("path", "")
                        for vm in container.get("volume_mounts", []):
                            if vm.get("name") == vol.get("name"):
                                profile.host_path_mounts.append(path)

                profiles.append(profile)

        return profiles

    # ── Phase 3: Cloud IAM discovery ───────────────────────────────────

    async def _discover_iam(self, topology: CloudTopology) -> None:
        """Enumerate cloud IAM roles via IMDS or cloud metadata endpoints.

        For AWS: probe 169.254.169.254 for IAM role name and credentials.
        For GCP/Azure: probe respective metadata endpoints.
        """
        # Try AWS IMDSv2 first (more secure, requires token)
        imds_creds = await self._probe_aws_imds()
        if imds_creds:
            topology.iam_roles.append(imds_creds)

        # Try AWS CLI if credentials are available
        await self._discover_aws_roles(topology)

    async def _probe_aws_imds(self) -> dict | None:
        """Probe AWS IMDS for IAM role info. Returns dict or None."""
        # Try IMDSv2 token
        try:
            proc = await asyncio.create_subprocess_shell(
                "curl -s -m 3 -X PUT 'http://169.254.169.254/latest/api/token' "
                "-H 'X-aws-ec2-metadata-token-ttl-seconds: 21600' 2>&1",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5)
            token = stdout.decode("utf-8", errors="replace").strip()

            if token and not token.startswith("<?") and len(token) > 10:
                # IMDSv2 — get role name
                proc2 = await asyncio.create_subprocess_shell(
                    f"curl -s -m 3 -H 'X-aws-ec2-metadata-token: {token}' "
                    "'http://169.254.169.254/latest/meta-data/iam/security-credentials/' 2>&1",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout2, _ = await asyncio.wait_for(proc2.communicate(), timeout=5)
                role_name = stdout2.decode("utf-8", errors="replace").strip()
            else:
                # IMDSv1 fallback
                proc2 = await asyncio.create_subprocess_shell(
                    "curl -s -m 3 'http://169.254.169.254/latest/meta-data/iam/security-credentials/' 2>&1",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout2, _ = await asyncio.wait_for(proc2.communicate(), timeout=5)
                role_name = stdout2.decode("utf-8", errors="replace").strip()

            if role_name and not role_name.startswith("<?") and len(role_name) < 256:
                # Get credentials
                creds_url = (
                    f"http://169.254.169.254/latest/meta-data/iam/security-credentials/{role_name}"
                )
                if token and len(token) > 10:
                    creds_cmd = (
                        f"curl -s -m 3 -H 'X-aws-ec2-metadata-token: {token}' '{creds_url}' 2>&1"
                    )
                else:
                    creds_cmd = f"curl -s -m 3 '{creds_url}' 2>&1"

                proc3 = await asyncio.create_subprocess_shell(
                    creds_cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout3, _ = await asyncio.wait_for(proc3.communicate(), timeout=5)
                creds_out = stdout3.decode("utf-8", errors="replace")

                if creds_out.strip().startswith("{"):
                    try:
                        creds = _json.loads(creds_out)
                        return {
                            "role_name": role_name,
                            "account_id": creds.get("AccountId", ""),
                            "access_key_id": creds.get("AccessKeyId", ""),
                            "provider": "aws",
                            "source": "imds",
                            "imds_version": 2 if (token and len(token) > 10) else 1,
                        }
                    except Exception:
                        pass
        except Exception:
            pass
        return None

    async def _discover_aws_roles(self, topology: CloudTopology) -> None:
        """Enumerate IAM roles via AWS CLI (requires working credentials)."""
        try:
            # List roles
            proc = await asyncio.create_subprocess_shell(
                "aws iam list-roles --max-items 50 --output json 2>&1",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
            out = stdout.decode("utf-8", errors="replace")
            if proc.returncode != 0 or not out.strip().startswith("["):
                # Try with --query
                proc2 = await asyncio.create_subprocess_shell(
                    "aws iam list-roles --max-items 50 --query 'Roles[*].[RoleName,Arn,AssumeRolePolicyDocument]' --output json 2>&1",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout2, _ = await asyncio.wait_for(proc2.communicate(), timeout=10)
                out = stdout2.decode("utf-8", errors="replace")

            if out.strip().startswith("[") or out.strip().startswith("{"):
                data = _json.loads(out)
                items = data if isinstance(data, list) else data.get("Roles", [])
                for role in items:
                    role_info = {
                        "role_name": role[0] if isinstance(role, list) else role.get("RoleName", ""),
                        "arn": role[1] if isinstance(role, list) else role.get("Arn", ""),
                        "provider": "aws",
                        "source": "aws_cli",
                    }

                    # Extract trust policy for cross-account analysis
                    trust_policy = None
                    if isinstance(role, list) and len(role) > 2:
                        trust_policy = role[2]
                    elif isinstance(role, dict):
                        trust_policy = role.get("AssumeRolePolicyDocument")

                    if trust_policy:
                        role_info["trust_policy"] = trust_policy
                        # Detect cross-account trust
                        trusts = self._extract_cross_account_trusts(trust_policy)
                        for trust in trusts:
                            trust["source_role"] = role_info["role_name"]
                            topology.cross_account_trusts.append(trust)

                    topology.iam_roles.append(role_info)
        except Exception as e:
            log.debug("CloudTopologyMapper: AWS IAM discovery failed: %s", e)

    def _extract_cross_account_trusts(self, trust_policy: dict | str) -> list[dict]:
        """Extract cross-account trust relationships from a trust policy."""
        trusts = []
        try:
            if isinstance(trust_policy, str):
                trust_policy = _json.loads(trust_policy)

            for statement in trust_policy.get("Statement", []):
                principal = statement.get("Principal", {})
                aws_principals = principal.get("AWS", [])
                if isinstance(aws_principals, str):
                    aws_principals = [aws_principals]

                for p in aws_principals:
                    if ":" in p and not p.startswith("*"):
                        # arn:aws:iam::ACCOUNT_ID:root or arn:aws:iam::ACCOUNT_ID:role/ROLE
                        parts = p.split(":")
                        if len(parts) >= 5:
                            target_account = parts[4]
                            condition = statement.get("Condition", {})
                            trusts.append({
                                "principal": p,
                                "target_account": target_account,
                                "effect": statement.get("Effect", "Allow"),
                                "action": statement.get("Action", ""),
                                "condition": condition,
                            })
        except Exception:
            pass
        return trusts

    # ── Phase 4: Write to DKG ──────────────────────────────────────────

    def _write_to_dkg(self, topology: CloudTopology) -> None:
        """Populate DKG with structured cloud/K8s topology nodes and edges."""

        # ── K8s Clusters ──
        for cluster in topology.clusters:
            cid = f"k8s-cluster-{cluster['name']}"
            self.dkg.add_node("K8sCluster", cid, {
                "name": cluster["name"],
                "api_url": cluster.get("api_url", ""),
                "version": cluster.get("version", ""),
            })

            # ── K8s Nodes ──
            for node in topology.nodes:
                if node.get("cluster") == cluster["name"]:
                    nid = f"k8s-node-{node['name']}"
                    self.dkg.add_node("K8sNode", nid, {
                        "name": node["name"],
                        "internal_ip": node.get("internal_ip", ""),
                        "is_control_plane": node.get("is_control_plane", False),
                        "labels": _json.dumps(node.get("labels", {})),
                        "taints": _json.dumps(node.get("taints", [])),
                    })
                    self.dkg.add_edge(cid, nid, "cluster_contains_node")

            # ── Namespaces ──
            for ns in topology.namespaces:
                nsid = f"k8s-ns-{ns}"
                self.dkg.add_node("K8sNamespace", nsid, {
                    "name": ns,
                })
                self.dkg.add_edge(cid, nsid, "cluster_contains_namespace")

            # ── Pods ──
            for pod in topology.pods:
                pid = f"k8s-pod-{pod['namespace']}-{pod['name']}"
                self.dkg.add_node("K8sPod", pid, {
                    "name": pod["name"],
                    "namespace": pod["namespace"],
                    "node_name": pod.get("node_name", ""),
                    "phase": pod.get("phase", ""),
                    "host_network": pod.get("host_network", False),
                    "host_pid": pod.get("host_pid", False),
                    "service_account": pod.get("service_account", "default"),
                })

                # Pod → Namespace
                nsid = f"k8s-ns-{pod['namespace']}"
                if nsid in self.dkg.graph:
                    self.dkg.add_edge(nsid, pid, "namespace_contains_pod")

                # Pod → Node
                if pod.get("node_name"):
                    nid = f"k8s-node-{pod['node_name']}"
                    if nid in self.dkg.graph:
                        self.dkg.add_edge(nid, pid, "node_hosts_pod")

            # ── Service Accounts ──
            for sa in topology.service_accounts:
                said = f"k8s-sa-{sa['namespace']}-{sa['name']}"
                self.dkg.add_node("K8sSA", said, {
                    "name": sa["name"],
                    "namespace": sa["namespace"],
                    "secrets": _json.dumps(sa.get("secrets", [])),
                    "annotations": _json.dumps(sa.get("annotations", {})),
                })

            # ── Pod → SA edges ──
            for pod in topology.pods:
                pid = f"k8s-pod-{pod['namespace']}-{pod['name']}"
                said = f"k8s-sa-{pod['namespace']}-{pod.get('service_account', 'default')}"
                if pid in self.dkg.graph and said in self.dkg.graph:
                    self.dkg.add_edge(pid, said, "pod_mounts_sa")

            # ── RBAC Bindings ──
            for binding in topology.rbac_bindings:
                for subject in binding.subjects:
                    if subject.get("kind") == "ServiceAccount":
                        subj_ns = subject.get("namespace", binding.namespace)
                        subj_name = subject.get("name", "")
                        said = f"k8s-sa-{subj_ns}-{subj_name}"
                        if said in self.dkg.graph:
                            # Create a Role node for the bound role
                            role_ns = binding.namespace if binding.kind == "RoleBinding" else "cluster"
                            rid = f"iam-role-k8s-{role_ns}-{binding.role_name}"
                            self.dkg.add_node("IAMRole", rid, {
                                "name": binding.role_name,
                                "kind": binding.role_kind,
                                "namespace": role_ns,
                                "source": "k8s_rbac",
                            })
                            self.dkg.add_edge(said, rid, "sa_bound_to_role")

        # ── Cloud IAM ──
        for role in topology.iam_roles:
            rid = f"iam-role-{role.get('role_name', 'unknown')}"
            self.dkg.add_node("IAMRole", rid, {
                "name": role.get("role_name", ""),
                "arn": role.get("arn", ""),
                "provider": role.get("provider", ""),
                "account_id": role.get("account_id", ""),
                "source": role.get("source", ""),
            })

        # ── Cross-account trusts ──
        for trust in topology.cross_account_trusts:
            src_role_id = f"iam-role-{trust.get('source_role', 'unknown')}"
            tgt_acct_id = f"cloud-acct-{trust.get('target_account', 'unknown')}"
            self.dkg.add_node("CloudAccount", tgt_acct_id, {
                "account_id": trust.get("target_account", ""),
                "provider": "aws",
            })
            tid = f"trust-{trust.get('source_role','')}-{trust.get('target_account','')}"
            self.dkg.add_node("TrustRelationship", tid, {
                "principal": trust.get("principal", ""),
                "effect": trust.get("effect", "Allow"),
                "condition": _json.dumps(trust.get("condition", {})),
            })
            if src_role_id in self.dkg.graph:
                self.dkg.add_edge(src_role_id, tid, "role_can_assume")
            if tgt_acct_id in self.dkg.graph:
                self.dkg.add_edge(tid, tgt_acct_id, "account_trusts")

        # ── High-risk analysis ──
        if topology.high_risk_pods:
            analysis_lines = [f"High-risk pods ({len(topology.high_risk_pods)}):"]
            for profile in topology.high_risk_pods:
                vectors = profile.escape_vectors
                analysis_lines.append(
                    f"  {profile.namespace}/{profile.pod_name}: "
                    f"risk={profile.risk_score:.2f}, "
                    f"vectors={vectors}, "
                    f"sa={profile.service_account}"
                )
            self.dkg.add_node("Analysis", "cloud-topology-high-risk", {
                "phase": "recon",
                "type": "cloud_topology",
                "content": "\n".join(analysis_lines),
            })

        log.info(
            "CloudTopologyMapper: wrote %d clusters, %d nodes, %d pods, %d SAs, %d RBAC bindings, %d IAM roles to DKG",
            len(topology.clusters), len(topology.nodes), len(topology.pods),
            len(topology.service_accounts), len(topology.rbac_bindings), len(topology.iam_roles),
        )


# ── Convenience function ────────────────────────────────────────────────

async def discover_cloud_topology(dkg: DKG) -> CloudTopology:
    """Discover cloud/K8s topology and populate DKG.

    Safe to call even when no K8s cluster exists — fails silently in <2s.
    """
    mapper = CloudTopologyMapper(dkg)
    return await mapper.discover()
