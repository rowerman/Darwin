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
    services: list[dict] = field(default_factory=list)
    workloads: list[dict] = field(default_factory=list)
    endpoint_slices: list[dict] = field(default_factory=list)
    ingresses: list[dict] = field(default_factory=list)
    network_policies: list[dict] = field(default_factory=list)
    rbac_roles: list[dict] = field(default_factory=list)
    rbac_resources: list[dict] = field(default_factory=list)
    secrets: list[dict] = field(default_factory=list)
    configmaps: list[dict] = field(default_factory=list)
    pod_security_profiles: list[PodSecurityProfile] = field(default_factory=list)
    rbac_bindings: list[K8sRBACBinding] = field(default_factory=list)
    service_accounts: list[dict] = field(default_factory=list)
    iam_roles: list[dict] = field(default_factory=list)
    cross_account_trusts: list[dict] = field(default_factory=list)
    aws_resources: dict[str, list[dict]] = field(default_factory=dict)
    aws_iam_policies: list[dict] = field(default_factory=list)
    aws_coverage: dict[str, Any] = field(default_factory=dict)
    aws_warnings: list[str] = field(default_factory=list)
    high_risk_pods: list[PodSecurityProfile] = field(default_factory=list)


# ── K8s Topology Discovery ──────────────────────────────────────────────

class CloudTopologyMapper:
    """Discovers K8S cluster topology + cloud IAM and writes to DKG."""

    def __init__(self, dkg: DKG, tool_port=None, environment=None):
        self.dkg = dkg
        self.tool_port = tool_port
        self.environment = environment

    async def _run_discovery(self, command: str, *, timeout: float = 8.0):
        """Run a discovery command through the injected tool port."""
        if self.tool_port is not None:
            result = await self.tool_port("cloud_discovery_command", {"command": command})
            return bool(getattr(result, "success", False)), getattr(result, "stdout", "") or ""
        # Direct subprocess execution is intentionally disabled.  Discovery
        # must be invoked from the orchestrator with the gateway port.
        return False, ""

    async def _run_aws_discovery(self, service: str, action: str, *, resource: str = "",
                                 region: str = "", endpoint_url: str = "", timeout: float = 15.0):
        if self.tool_port is None:
            return False, {}, "AWS discovery requires the injected gateway port"
        try:
            result = await self.tool_port("cloud_discovery_aws", {
                "service": service, "action": action, "resource": resource,
                "region": region, "endpoint_url": endpoint_url,
            })
            parsed = getattr(result, "parsed_output", {}) or {}
            if not isinstance(parsed, dict):
                parsed = {"items": parsed}
            if not parsed and getattr(result, "stdout", ""):
                try:
                    parsed = _json.loads(result.stdout)
                except Exception:
                    parsed = {}
            return bool(getattr(result, "success", False)), parsed, getattr(result, "stderr", "") or ""
        except Exception as exc:
            return False, {}, str(exc)

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
            await self._discover_services(topology)
            await self._discover_workloads(topology)
            await self._discover_endpoint_slices(topology)
            await self._discover_ingresses(topology)
            await self._discover_network_policies(topology)
            await self._discover_service_accounts(topology)
            await self._discover_rbac(topology)
            await self._discover_rbac_resources(topology)
            await self._discover_sensitive_metadata(topology)

        # Phase 2: Pod security analysis
        topology.pod_security_profiles = self._analyze_pod_security(topology.pods)
        topology.high_risk_pods = [
            p for p in topology.pod_security_profiles if p.risk_score > 0.3
        ]

        # Phase 3: Cloud IAM (only if IMDS/cloud metadata reachable)
        await self._discover_iam(topology)

        # Phase 4: Public-cloud resources are explicitly gated by the
        # classifier; ordinary Web/DB runs never issue AWS API calls.
        provider = str(getattr(self.environment, "provider", "") or "").lower()
        cloud_enabled = bool(getattr(self.environment, "cloud_enabled", False))
        if cloud_enabled and (provider in {"", "aws", "aws+"} or "aws" in provider):
            await self._discover_aws_resources(topology)

        # Phase 5: Write to DKG
        self._write_to_dkg(topology)

        return topology

    # ── Phase 1: K8s cluster topology ─────────────────────────────────

    async def _discover_clusters(self, topology: CloudTopology) -> None:
        """Discover K8s cluster(s) via kubectl."""
        try:
            ok, out = await self._run_discovery("kubectl cluster-info")
            if not ok or "is running at" not in out:
                return

            api_match = re.search(r"is running at (https?://\S+)", out)
            api_url = api_match.group(1) if api_match else ""

            # Get cluster name from current context
            cluster_name = "default"
            try:
                ok2, stdout2 = await self._run_discovery("kubectl config current-context", timeout=5)
                if ok2:
                    cluster_name = stdout2.strip()
            except Exception:
                pass

            # Get server version
            version = ""
            try:
                ok3, out3 = await self._run_discovery("kubectl version --short", timeout=5)
                if ok3:
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
            ok, out = await self._run_discovery("kubectl get nodes -o json")
            if not ok or not out.strip().startswith("{"):
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
            ok, out = await self._run_discovery("kubectl get namespaces -o json")
            if ok and out.strip().startswith("{"):
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
            ok, out = await self._run_discovery("kubectl get pods -A -o json", timeout=10)
            if not ok or not out.strip().startswith("{"):
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
                        vol_info["config_map_name"] = vol["configMap"].get("name", "")
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
            ok, out = await self._run_discovery("kubectl get serviceaccounts -A -o json")
            if not ok or not out.strip().startswith("{"):
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

    async def _json_items(self, command: str, *, timeout: float = 10) -> list[dict]:
        """Read an allow-listed Kubernetes JSON list, returning empty on failure."""
        try:
            ok, out = await self._run_discovery(command, timeout=timeout)
            if not ok or not out.strip().startswith("{"):
                return []
            payload = _json.loads(out)
            return [item for item in payload.get("items", []) if isinstance(item, dict)]
        except Exception as exc:
            log.debug("CloudTopologyMapper: %s failed: %s", command, exc)
            return []

    async def _discover_services(self, topology: CloudTopology) -> None:
        for item in await self._json_items("kubectl get svc -A -o json"):
            meta = item.get("metadata", {})
            spec = item.get("spec", {})
            topology.services.append({
                "name": meta.get("name", ""),
                "namespace": meta.get("namespace", ""),
                "selector": spec.get("selector", {}),
                "type": spec.get("type", "ClusterIP"),
                "ports": spec.get("ports", []),
                "cluster_ip": spec.get("clusterIP", ""),
            })

    async def _discover_workloads(self, topology: CloudTopology) -> None:
        commands = (
            ("kubectl get deployments -A -o json", "Deployment"),
            ("kubectl get statefulsets -A -o json", "StatefulSet"),
            ("kubectl get daemonsets -A -o json", "DaemonSet"),
        )
        for command, kind in commands:
            for item in await self._json_items(command):
                meta = item.get("metadata", {})
                topology.workloads.append({
                    "kind": kind,
                    "name": meta.get("name", ""),
                    "namespace": meta.get("namespace", ""),
                    "labels": meta.get("labels", {}),
                    "owner_references": meta.get("ownerReferences", []),
                    "selector": item.get("spec", {}).get("selector", {}).get("matchLabels", {}),
                })

    async def _discover_endpoint_slices(self, topology: CloudTopology) -> None:
        for item in await self._json_items("kubectl get endpointslices -A -o json"):
            meta = item.get("metadata", {})
            labels = meta.get("labels", {})
            topology.endpoint_slices.append({
                "name": meta.get("name", ""),
                "namespace": meta.get("namespace", ""),
                "service_name": labels.get("kubernetes.io/service-name", ""),
                "address_type": item.get("addressType", ""),
                "endpoints": item.get("endpoints", []),
                "ports": item.get("ports", []),
            })

    async def _discover_ingresses(self, topology: CloudTopology) -> None:
        for item in await self._json_items("kubectl get ingress -A -o json"):
            meta = item.get("metadata", {})
            spec = item.get("spec", {})
            backend_services: list[dict] = []
            default_backend = spec.get("defaultBackend", {}).get("service", {})
            if default_backend.get("name"):
                backend_services.append({"name": default_backend["name"], "port": default_backend.get("port", {})})
            for rule in spec.get("rules", []):
                for path in rule.get("http", {}).get("paths", []):
                    service = path.get("backend", {}).get("service", {})
                    if service.get("name"):
                        backend_services.append({"name": service["name"], "port": service.get("port", {})})
            topology.ingresses.append({
                "name": meta.get("name", ""),
                "namespace": meta.get("namespace", ""),
                "class_name": spec.get("ingressClassName", ""),
                "backend_services": backend_services,
                "tls_hosts": [host for tls in spec.get("tls", []) for host in tls.get("hosts", [])],
            })

    async def _discover_network_policies(self, topology: CloudTopology) -> None:
        for item in await self._json_items("kubectl get networkpolicies -A -o json"):
            meta = item.get("metadata", {})
            spec = item.get("spec", {})
            topology.network_policies.append({
                "name": meta.get("name", ""),
                "namespace": meta.get("namespace", ""),
                "pod_selector": spec.get("podSelector", {}),
                "policy_types": spec.get("policyTypes", []),
                "ingress": spec.get("ingress", []),
                "egress": spec.get("egress", []),
            })

    async def _discover_sensitive_metadata(self, topology: CloudTopology) -> None:
        for item in await self._json_items("kubectl get secrets -A -o json"):
            meta = item.get("metadata", {})
            topology.secrets.append({
                "name": meta.get("name", ""), "namespace": meta.get("namespace", ""),
                "type": item.get("type", ""), "data_keys": sorted(item.get("data", {}).keys()),
            })
        for item in await self._json_items("kubectl get configmaps -A -o json"):
            meta = item.get("metadata", {})
            raw_data = item.get("data", {}) if isinstance(item.get("data"), dict) else {}
            _SENSITIVE_KEY_HINTS = ("password", "secret", "token", "key", "credential", "apikey", "api_key")
            safe_data = {}
            for key, value in raw_data.items():
                lowered = str(key).lower()
                if any(hint in lowered for hint in _SENSITIVE_KEY_HINTS):
                    continue
                text = str(value)
                safe_data[key] = text[:200]
            topology.configmaps.append({
                "name": meta.get("name", ""), "namespace": meta.get("namespace", ""),
                "data_keys": sorted(item.get("data", {}).keys()),
                "data": safe_data,
            })

    async def _discover_rbac(self, topology: CloudTopology) -> None:
        """Enumerate K8s RBAC bindings (Roles + RoleBindings + ClusterRoles + ClusterRoleBindings)."""
        # ClusterRoleBindings
        try:
            ok, out = await self._run_discovery("kubectl get clusterrolebindings -o json")
            if ok and out.strip().startswith("{"):
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
            ok, out = await self._run_discovery("kubectl get rolebindings -A -o json", timeout=10)
            if ok and out.strip().startswith("{"):
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

    async def _discover_rbac_resources(self, topology: CloudTopology) -> None:
        for command, kind in (
            ("kubectl get roles -A -o json", "Role"),
            ("kubectl get clusterroles -o json", "ClusterRole"),
        ):
            for item in await self._json_items(command):
                meta = item.get("metadata", {})
                topology.rbac_roles.append({
                    "kind": kind,
                    "name": meta.get("name", ""),
                    "namespace": meta.get("namespace", ""),
                    "rules": item.get("rules", []),
                })
        for command, kind in (
            ("kubectl get rolebindings -A -o json", "RoleBinding"),
            ("kubectl get clusterrolebindings -o json", "ClusterRoleBinding"),
        ):
            for item in await self._json_items(command):
                meta = item.get("metadata", {})
                role_ref = item.get("roleRef", {})
                topology.rbac_resources.append({
                    "kind": kind,
                    "name": meta.get("name", ""),
                    "namespace": meta.get("namespace", ""),
                    "role_name": role_ref.get("name", ""),
                    "role_kind": role_ref.get("kind", "Role"),
                    "subjects": item.get("subjects", []),
                })

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
            ok, token_out = await self._run_discovery(
                "curl -s -m 3 -X PUT http://169.254.169.254/latest/api/token"
            )
            token = token_out.strip() if ok else ""

            if token and not token.startswith("<?") and len(token) > 10:
                # IMDSv2 — get role name
                ok2, role_out = await self._run_discovery(
                    f"curl -s -m 3 -H 'X-aws-ec2-metadata-token: {token}' "
                    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                    timeout=5,
                )
                role_name = role_out.strip() if ok2 else ""
            else:
                # IMDSv1 fallback
                ok2, role_out = await self._run_discovery(
                    "curl -s -m 3 http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                    timeout=5,
                )
                role_name = role_out.strip() if ok2 else ""

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

                _ok3, creds_out = await self._run_discovery(creds_cmd, timeout=5)

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
            ok, out = await self._run_discovery(
                "aws iam list-roles --max-items 50 --output json", timeout=10
            )
            if not ok or not out.strip().startswith("["):
                # Try with --query
                _ok2, out = await self._run_discovery(
                    "aws iam list-roles --max-items 50 --query 'Roles[*].[RoleName,Arn,AssumeRolePolicyDocument]' --output json",
                    timeout=10,
                )

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

    @staticmethod
    def _aws_items(payload: dict, *keys: str) -> list[dict]:
        for key in keys:
            value = payload.get(key)
            if isinstance(value, list):
                return [row for row in value if isinstance(row, dict)]
        for value in payload.values():
            if isinstance(value, list) and all(isinstance(row, dict) for row in value):
                return list(value)
        return []

    @staticmethod
    def _aws_id(resource_type: str, row: dict, account_id: str = "", region: str = "") -> str:
        arn = str(row.get("Arn", row.get("arn", "")) or "").strip()
        if arn:
            return f"aws:{arn}"
        candidates = (
            row.get("VpcId"), row.get("SubnetId"), row.get("RouteTableId"),
            row.get("GroupId"), row.get("NetworkInterfaceId"), row.get("InstanceId"),
            row.get("ClusterArn"), row.get("ClusterName"), row.get("LoadBalancerArn"),
            row.get("DBInstanceArn"), row.get("DBInstanceIdentifier"),
            row.get("Name"), row.get("BucketName"), row.get("PolicyName"),
            row.get("RoleName"), row.get("PolicyArn"),
        )
        identifier = next((str(value) for value in candidates if value), "unknown")
        return f"aws:{account_id}:{region}:{resource_type}:{identifier}"

    async def _discover_aws_resources(self, topology: CloudTopology) -> None:
        """Collect bounded AWS metadata through the dedicated read-only port."""
        specs = (
            ("ec2", "describe-vpcs", "VPCs", "VPC"),
            ("ec2", "describe-subnets", "Subnets", "Subnet"),
            ("ec2", "describe-route-tables", "RouteTables", "RouteTable"),
            ("ec2", "describe-security-groups", "SecurityGroups", "SecurityGroup"),
            ("ec2", "describe-network-interfaces", "NetworkInterfaces", "ENI"),
            ("ec2", "describe-instances", "Reservations", "EC2"),
            ("elbv2", "describe-load-balancers", "LoadBalancers", "LoadBalancer"),
            ("rds", "describe-db-instances", "DBInstances", "RDS"),
            ("s3api", "list-buckets", "Buckets", "S3"),
            ("iam", "list-roles", "Roles", "IAMRole"),
            ("iam", "list-policies", "Policies", "IAMPolicy"),
        )
        account_id = ""
        ok, identity, err = await self._run_aws_discovery("sts", "get-caller-identity")
        if ok:
            account_id = str(identity.get("Account", "") or "")
            topology.aws_resources.setdefault("CloudAccount", []).append({
                "account_id": account_id, "arn": identity.get("Arn", ""),
                "user_id": identity.get("UserId", ""), "provider": "aws",
            })
        elif err:
            topology.aws_warnings.append(f"sts:get-caller-identity: {err}")

        for service, action, key, node_type in specs:
            ok, payload, err = await self._run_aws_discovery(service, action)
            if not ok:
                topology.aws_warnings.append(f"{service}:{action}: {err or 'discovery failed'}")
                continue
            rows = self._aws_items(payload, key)
            # describe-instances nests instances under Reservations.
            if node_type == "EC2":
                rows = [instance for reservation in rows
                        for instance in reservation.get("Instances", [])
                        if isinstance(instance, dict)]
            bucket = topology.aws_resources.setdefault(node_type, [])
            for row in rows[:200]:
                row = dict(row)
                row["provider"] = "aws"
                row["account_id"] = account_id
                row["resource_id"] = self._aws_id(node_type, row, account_id)
                bucket.append(row)
                if node_type == "IAMRole":
                    trust = row.get("AssumeRolePolicyDocument") or row.get("assume_role_policy")
                    if trust:
                        row["trust_policy"] = trust
                        for trust_row in self._extract_cross_account_trusts(trust):
                            trust_row["source_role"] = row.get("RoleName", row.get("role_name", ""))
                            topology.cross_account_trusts.append(trust_row)
                if node_type == "IAMPolicy":
                    policy_arn = row.get("Arn", row.get("PolicyArn", ""))
                    if policy_arn:
                        ok_policy, detail, _ = await self._run_aws_discovery(
                            "iam", "get-policy", resource=f"--policy-arn {policy_arn}"
                        )
                        if ok_policy:
                            policy = detail.get("Policy", detail)
                            row["policy_detail"] = policy
                            version_id = policy.get("DefaultVersionId", "")
                            if version_id:
                                ok_version, version_detail, version_err = await self._run_aws_discovery(
                                    "iam", "get-policy-version",
                                    resource=f"--policy-arn {policy_arn} --version-id {version_id}",
                                )
                                if ok_version:
                                    document = version_detail.get("PolicyVersion", {}).get("Document", {})
                                    if document:
                                        row["policy_document"] = document
                                else:
                                    topology.aws_warnings.append(
                                        f"iam:get-policy-version:{policy_arn}: {version_err or 'discovery failed'}"
                                    )
                if node_type == "S3":
                    bucket_name = row.get("Name", row.get("BucketName", ""))
                    if bucket_name:
                        ok_loc, loc, loc_err = await self._run_aws_discovery(
                            "s3api", "get-bucket-location", resource=f"--bucket {bucket_name}"
                        )
                        if ok_loc:
                            row["region"] = loc.get("LocationConstraint") or "us-east-1"
                        else:
                            topology.aws_warnings.append(
                                f"s3api:get-bucket-location:{bucket_name}: {loc_err or 'discovery failed'}"
                            )

        eks_ok, eks_payload, eks_err = await self._run_aws_discovery("eks", "list-clusters")
        if eks_ok:
            names = eks_payload.get("clusters", []) if isinstance(eks_payload, dict) else []
            for name in names[:50]:
                ok_cluster, detail, _ = await self._run_aws_discovery(
                    "eks", "describe-cluster", resource=f"--name {name}"
                )
                cluster = detail.get("cluster", {}) if ok_cluster else {"name": name}
                cluster["provider"] = "aws"
                cluster["account_id"] = account_id
                cluster["resource_id"] = self._aws_id("EKS", cluster, account_id)
                topology.aws_resources.setdefault("EKS", []).append(cluster)
        elif eks_err:
            topology.aws_warnings.append(f"eks:list-clusters: {eks_err}")

        topology.aws_coverage = {
            "resource_counts": {key: len(rows) for key, rows in topology.aws_resources.items()},
            "warnings": list(topology.aws_warnings),
            "complete": not bool(topology.aws_warnings),
        }

    # ── Phase 4: Write to DKG ──────────────────────────────────────────

    def _find_host_by_ip(self, ip: str) -> str | None:
        """Return an existing Host node id whose ip/internal_ip equals ``ip``."""
        if not ip:
            return None
        for row in self.dkg.query_nodes("Host"):
            if str(row.get("ip", "") or "") == ip or str(row.get("internal_ip", "") or "") == ip:
                return str(row.get("id", ""))
        return None

    def _write_to_dkg(self, topology: CloudTopology) -> None:
        """Populate DKG with structured cloud/K8s topology nodes and edges."""

        # ── K8s Clusters ──
        k8s_host_ids: dict[str, str] = {}
        for cluster in topology.clusters:
            cid = f"k8s-cluster-{cluster['name']}"
            self.dkg.add_node("K8sCluster", cid, {
                "name": cluster["name"],
                "api_url": cluster.get("api_url", ""),
                "version": cluster.get("version", ""),
            })

            # ── K8s Nodes → unified Host nodes ──
            for node in topology.nodes:
                if node.get("cluster") == cluster["name"]:
                    internal_ip = str(node.get("internal_ip", "") or "")
                    nid = self._find_host_by_ip(internal_ip) or f"host-k8s-{node['name']}"
                    self.dkg.add_node("Host", nid, {
                        "name": node["name"],
                        "cluster": cluster["name"],
                        "internal_ip": internal_ip,
                        "is_control_plane": node.get("is_control_plane", False),
                        "labels": _json.dumps(node.get("labels", {})),
                        "taints": _json.dumps(node.get("taints", [])),
                        "provider": "k8s",
                    }, source="cloud_discovery:k8s_node")
                    k8s_host_ids[str(node["name"])] = nid
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
                    "labels": pod.get("labels", {}),
                })

                # Pod → Namespace
                nsid = f"k8s-ns-{pod['namespace']}"
                if nsid in self.dkg.graph:
                    self.dkg.add_edge(nsid, pid, "namespace_contains_pod")

                # Pod → Node
                if pod.get("node_name"):
                    nid = k8s_host_ids.get(str(pod.get("node_name", "")))
                    if nid and nid in self.dkg.graph:
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

            # ── Service selector → Pod edges ──
            pod_rows = [
                (f"k8s-pod-{pod.get('namespace','')}-{pod.get('name','')}", pod)
                for pod in topology.pods
            ]
            for service in self.dkg.query_nodes("Service"):
                selector = service.get("k8s_selector", {})
                if isinstance(selector, str):
                    try:
                        selector = _json.loads(selector)
                    except Exception:
                        selector = {}
                if not isinstance(selector, dict) or not selector:
                    continue
                for pid, pod in pod_rows:
                    labels = pod.get("labels", {}) or {}
                    if pod.get("namespace") != service.get("k8s_namespace"):
                        continue
                    if all(labels.get(str(k)) == v for k, v in selector.items()):
                        self.dkg.add_edge(
                            service["id"], pid, "service_targets_pod",
                            source="k8s_selector", evidence=_json.dumps(selector),
                            confidence=0.95, status="inferred",
                        )

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

        # ── Services and first-class Kubernetes resources ──
        for service in topology.services:
            sid = f"k8s-service-{service.get('namespace', '')}-{service.get('name', '')}"
            self.dkg.add_node("Service", sid, {
                "name": service.get("name", ""),
                "k8s_namespace": service.get("namespace", ""),
                "k8s_selector": service.get("selector", {}),
                "k8s_type": service.get("type", "ClusterIP"),
                "ports": service.get("ports", []),
                "cluster_ip": service.get("cluster_ip", ""),
            }, source="cloud_discovery:k8s_service")

        for workload in topology.workloads:
            kind = str(workload.get("kind", "Deployment"))
            wid = f"k8s-{kind.lower()}-{workload.get('namespace', '')}-{workload.get('name', '')}"
            self.dkg.add_node(kind, wid, {
                "name": workload.get("name", ""),
                "namespace": workload.get("namespace", ""),
                "labels": workload.get("labels", {}),
                "selector": workload.get("selector", {}),
                "owner_references": workload.get("owner_references", []),
            }, source="cloud_discovery:k8s_workload")

        for endpoint_slice in topology.endpoint_slices:
            eid = f"k8s-endpointslice-{endpoint_slice.get('namespace', '')}-{endpoint_slice.get('name', '')}"
            self.dkg.add_node("EndpointSlice", eid, {
                "name": endpoint_slice.get("name", ""),
                "namespace": endpoint_slice.get("namespace", ""),
                "service_name": endpoint_slice.get("service_name", ""),
                "address_type": endpoint_slice.get("address_type", ""),
                "endpoints": endpoint_slice.get("endpoints", []),
                "ports": endpoint_slice.get("ports", []),
            }, source="cloud_discovery:k8s_endpointslice")

        for ingress in topology.ingresses:
            iid = f"k8s-ingress-{ingress.get('namespace', '')}-{ingress.get('name', '')}"
            self.dkg.add_node("Ingress", iid, {
                "name": ingress.get("name", ""),
                "namespace": ingress.get("namespace", ""),
                "class_name": ingress.get("class_name", ""),
                "backend_services": ingress.get("backend_services", []),
                "tls_hosts": ingress.get("tls_hosts", []),
            }, source="cloud_discovery:k8s_ingress")

        for policy in topology.network_policies:
            pid = f"k8s-networkpolicy-{policy.get('namespace', '')}-{policy.get('name', '')}"
            self.dkg.add_node("NetworkPolicy", pid, {
                "name": policy.get("name", ""),
                "namespace": policy.get("namespace", ""),
                "pod_selector": policy.get("pod_selector", {}),
                "policy_types": policy.get("policy_types", []),
                "ingress": policy.get("ingress", []),
                "egress": policy.get("egress", []),
            }, source="cloud_discovery:k8s_networkpolicy")

        for role in topology.rbac_roles:
            kind = str(role.get("kind", "Role"))
            rid = f"k8s-{kind.lower()}-{role.get('namespace', 'cluster')}-{role.get('name', '')}"
            self.dkg.add_node(kind, rid, {
                "name": role.get("name", ""),
                "namespace": role.get("namespace", ""),
                "rules": role.get("rules", []),
            }, source="cloud_discovery:k8s_rbac")

        for binding in topology.rbac_resources:
            kind = str(binding.get("kind", "RoleBinding"))
            bid = f"k8s-{kind.lower()}-{binding.get('namespace', 'cluster')}-{binding.get('name', '')}"
            self.dkg.add_node(kind, bid, {
                "name": binding.get("name", ""),
                "namespace": binding.get("namespace", ""),
                "role_name": binding.get("role_name", ""),
                "role_kind": binding.get("role_kind", "Role"),
                "subjects": binding.get("subjects", []),
            }, source="cloud_discovery:k8s_rbac")

        for item in topology.secrets:
            sid = f"k8s-secret-{item.get('namespace', '')}-{item.get('name', '')}"
            self.dkg.add_node("Secret", sid, item, source="cloud_discovery:k8s_secret_metadata")
        for item in topology.configmaps:
            cid = f"k8s-configmap-{item.get('namespace', '')}-{item.get('name', '')}"
            self.dkg.add_node("ConfigMap", cid, item, source="cloud_discovery:k8s_configmap_metadata")

        # ── AWS resources ──
        account_rows = topology.aws_resources.get("CloudAccount", [])
        account_id = str((account_rows[0] if account_rows else {}).get("account_id", "") or "")
        account_node_id = f"cloud-acct-{account_id}" if account_id else ""
        if account_id:
            self.dkg.add_node("CloudAccount", account_node_id, {
                "account_id": account_id, "provider": "aws",
                "arn": (account_rows[0] if account_rows else {}).get("arn", ""),
            }, source="cloud_discovery_aws:sts")

        aws_ids: dict[str, dict[str, str]] = {}
        for node_type, rows in topology.aws_resources.items():
            if node_type in {"CloudAccount", "EC2", "ENI"}:
                continue
            for row in rows:
                rid = str(row.get("resource_id", "") or "")
                if not rid:
                    continue
                node_id = rid
                props = {
                    key: value for key, value in row.items()
                    if key not in {"resource_id", "SecretAccessKey", "AccessKeyId", "Token"}
                }
                props.setdefault("resource_id", rid)
                self.dkg.add_node(node_type, node_id, props, source="cloud_discovery_aws")
                key_fields = {
                    "VPC": "VpcId", "Subnet": "SubnetId", "RouteTable": "RouteTableId",
                    "SecurityGroup": "GroupId", "ENI": "NetworkInterfaceId", "EC2": "InstanceId",
                    "EKS": "ClusterName", "LoadBalancer": "LoadBalancerArn", "RDS": "DBInstanceIdentifier",
                    "S3": "BucketName", "IAMRole": "RoleName", "IAMPolicy": "PolicyArn",
                }
                lookup_key = str(row.get(key_fields.get(node_type, ""), "") or row.get("Name", "") or rid)
                aws_ids.setdefault(node_type, {})[lookup_key] = {
                    "id": node_id, "arn": str(row.get("Arn", row.get("arn", "")) or "")
                }
                if node_type == "EKS":
                    name = str(row.get("name", "") or "")
                    if name:
                        aws_ids["EKS"].setdefault(name, {"id": node_id, "arn": str(row.get("Arn", row.get("arn", "")) or "")})
                if account_node_id:
                    self.dkg.add_edge(
                        account_node_id, node_id, "account_contains_resource",
                        source="cloud_discovery_aws", evidence=node_type,
                        confidence=1.0, status="observed",
                    )

        # ── EC2 instances → unified Host nodes; ENIs fold into Host props ──
        eni_by_instance: dict[str, list[dict]] = {}
        eni_by_ip: dict[str, list[dict]] = {}
        for row in topology.aws_resources.get("ENI", []):
            attachment = row.get("Attachment", {}) if isinstance(row.get("Attachment"), dict) else {}
            instance_id = str(attachment.get("InstanceId", "") or "")
            private_ip = str(row.get("PrivateIpAddress", row.get("private_ip", "")) or "")
            if instance_id:
                eni_by_instance.setdefault(instance_id, []).append(row)
            if private_ip:
                eni_by_ip.setdefault(private_ip, []).append(row)

        ec2_host_ids: dict[str, str] = {}
        for row in topology.aws_resources.get("EC2", []):
            instance_id = str(row.get("InstanceId", "") or "")
            private_ip = str(row.get("PrivateIpAddress", row.get("private_ip", "")) or "")
            nid = self._find_host_by_ip(private_ip)
            if not nid and instance_id:
                nid = f"host-ec2-{instance_id}"
            if not nid:
                topology.aws_warnings.append(f"EC2 instance without id/ip skipped: {row}")
                continue
            props = {
                "ip": private_ip,
                "instance_id": instance_id,
                "arn": row.get("Arn", row.get("arn", "")),
                "provider": "aws",
                "account_id": row.get("account_id", ""),
                "region": row.get("region", ""),
                "subnet_id": row.get("SubnetId", ""),
                "groups": row.get("Groups", []),
            }
            props = {key: value for key, value in props.items() if value not in (None, "")}
            enis = eni_by_instance.get(instance_id, []) or eni_by_ip.get(private_ip, [])
            if enis:
                props["network_interfaces"] = [
                    {
                        "id": eni.get("NetworkInterfaceId", ""),
                        "subnet_id": eni.get("SubnetId", ""),
                        "groups": [
                            str(group.get("GroupId", ""))
                            for group in eni.get("Groups", []) if isinstance(group, dict)
                        ],
                        "private_ip": eni.get("PrivateIpAddress", ""),
                    }
                    for eni in enis
                ]
            self.dkg.add_node("Host", nid, props, source="cloud_discovery_aws:ec2")
            ec2_host_ids[instance_id] = nid
            if account_node_id:
                self.dkg.add_edge(
                    account_node_id, nid, "account_contains_resource",
                    source="cloud_discovery_aws", evidence="EC2",
                    confidence=1.0, status="observed",
                )
        orphan_enis = [
            row for row in topology.aws_resources.get("ENI", [])
            if not str(
                (row.get("Attachment") if isinstance(row.get("Attachment"), dict) else {}).get("InstanceId", "") or ""
            )
        ]
        if orphan_enis:
            topology.aws_warnings.append(f"orphan ENIs without instance skipped: {len(orphan_enis)}")

        # Stable AWS relationship joins by IDs returned by the APIs.
        for row in topology.aws_resources.get("Subnet", []):
            subnet_id = aws_ids.get("Subnet", {}).get(str(row.get("SubnetId", "")), {}).get("id", "")
            vpc_id = aws_ids.get("VPC", {}).get(str(row.get("VpcId", "")), {}).get("id", "")
            if subnet_id and vpc_id:
                self.dkg.add_edge(vpc_id, subnet_id, "resource_contains", source="cloud_discovery_aws", evidence="VpcId", confidence=1.0)
        for row in topology.aws_resources.get("EC2", []):
            nid = ec2_host_ids.get(str(row.get("InstanceId", "")), "")
            subnet_id = aws_ids.get("Subnet", {}).get(str(row.get("SubnetId", "")), {}).get("id", "")
            if nid and subnet_id:
                self.dkg.add_edge(nid, subnet_id, "resource_in_subnet", source="cloud_discovery_aws", evidence="SubnetId", confidence=1.0)
            for group in row.get("Groups", []) if isinstance(row.get("Groups"), list) else []:
                group_id = aws_ids.get("SecurityGroup", {}).get(str(group.get("GroupId", "")), {}).get("id", "")
                if group_id and nid:
                    self.dkg.add_edge(group_id, nid, "security_group_attaches", source="cloud_discovery_aws", evidence="Groups", confidence=0.9, status="inferred")

        for row in topology.aws_resources.get("RouteTable", []):
            route_table_id = aws_ids.get("RouteTable", {}).get(str(row.get("RouteTableId", "")), {}).get("id", "")
            for assoc in row.get("Associations", []) if isinstance(row.get("Associations"), list) else []:
                subnet_id = aws_ids.get("Subnet", {}).get(str(assoc.get("SubnetId", "")), {}).get("id", "")
                if route_table_id and subnet_id:
                    self.dkg.add_edge(
                        route_table_id, subnet_id, "route_table_routes_to",
                        source="cloud_discovery_aws", evidence="Associations",
                        confidence=1.0, status="observed",
                    )

        for row in topology.aws_resources.get("EKS", []):
            cluster_name = str(row.get("name", row.get("ClusterName", "")) or "")
            eks_id = aws_ids.get("EKS", {}).get(cluster_name, {}).get("id", "")
            k8s_id = f"k8s-cluster-{cluster_name}"
            if eks_id and k8s_id in self.dkg.graph:
                self.dkg.add_edge(eks_id, k8s_id, "eks_links_k8s_cluster", source="aws_k8s_crosswalk", evidence=cluster_name, confidence=0.95, status="inferred")

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

async def discover_cloud_topology(dkg: DKG, tool_port=None, environment=None) -> CloudTopology:
    """Discover cloud/K8s topology and populate DKG.

    Safe to call even when no K8s cluster exists — fails silently in <2s.
    """
    mapper = CloudTopologyMapper(dkg, tool_port=tool_port, environment=environment)
    return await mapper.discover()
