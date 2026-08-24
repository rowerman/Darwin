"""Deterministic relationship analysis for collected Kubernetes topology."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

from darwin.dkg import DKG


@dataclass
class TopologyAnalysisResult:
    """Summary of one idempotent relationship-analysis pass."""

    before_revision: int
    after_revision: int
    added_relations: int = 0
    updated_relations: int = 0
    affected_path_ids: list[str] = field(default_factory=list)
    coverage: dict[str, Any] = field(default_factory=dict)
    priority_hints: dict[str, float] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)


class RelationAnalyzer:
    """Infer only relationships supported by explicit DKG resource facts."""

    _WORKLOAD_TYPES = {"Deployment", "StatefulSet", "DaemonSet"}
    _BINDING_TYPES = {"RoleBinding", "ClusterRoleBinding"}

    @staticmethod
    def _json(value: Any, default: Any) -> Any:
        if isinstance(value, (dict, list)):
            return value
        if isinstance(value, str) and value.strip():
            try:
                return json.loads(value)
            except (TypeError, ValueError):
                return default
        return default

    @staticmethod
    def _nodes(dkg: DKG, node_type: str) -> list[dict[str, Any]]:
        return list(dkg.query_nodes(node_type))

    @staticmethod
    def _node_id(node: dict[str, Any]) -> str:
        return str(node.get("id", ""))

    @staticmethod
    def _changed_paths(dkg: DKG, changed_ids: set[str]) -> list[str]:
        if not changed_ids:
            return []
        affected: list[str] = []
        for state in dkg.attack_path_states():
            path_id = str(state.get("path_id", ""))
            path = state.get("path", {})
            text = json.dumps(path, default=str)
            if any(node_id and node_id in text for node_id in changed_ids):
                affected.append(path_id)
        return sorted(set(x for x in affected if x))

    def _edge(
        self,
        dkg: DKG,
        result: TopologyAnalysisResult,
        changed_ids: set[str],
        source: str,
        evidence: str,
        confidence: float,
        status: str,
        from_id: str,
        to_id: str,
        edge_type: str,
    ) -> None:
        if not from_id or not to_id or dkg.get_node(from_id) is None or dkg.get_node(to_id) is None:
            return
        existed = any(
            row.get("from") == from_id and row.get("to") == to_id and row.get("type") == edge_type
            for row in dkg.query_edges()
        )
        changed = dkg.upsert_edge(
            from_id,
            to_id,
            edge_type,
            source=source,
            evidence=evidence,
            confidence=confidence,
            status=status,
        )
        if changed:
            if existed:
                result.updated_relations += 1
            else:
                result.added_relations += 1
            changed_ids.update((from_id, to_id))
            result.priority_hints[f"{from_id}->{to_id}:{edge_type}"] = (
                0.9 if status == "observed" else 0.6
            )

    def _analyze_iam(self, dkg: DKG, result: TopologyAnalysisResult, changed_ids: set[str]) -> None:
        roles = self._nodes(dkg, "IAMRole")
        policies = self._nodes(dkg, "IAMPolicy")
        role_by_arn = {str(r.get("arn", "")): self._node_id(r) for r in roles if r.get("arn")}
        role_by_name = {str(r.get("name", r.get("RoleName", ""))): self._node_id(r) for r in roles}
        policy_by_arn = {
            str(p.get("arn", p.get("Arn", p.get("PolicyArn", "")))): self._node_id(p)
            for p in policies if p.get("arn", p.get("Arn", p.get("PolicyArn", "")))
        }
        for role in roles:
            role_id = self._node_id(role)
            attached = self._json(role.get("AttachedPolicies", role.get("attached_policies", [])), [])
            for item in attached if isinstance(attached, list) else []:
                arn = str(item.get("PolicyArn", item.get("arn", ""))) if isinstance(item, dict) else str(item)
                policy_id = policy_by_arn.get(arn)
                if policy_id:
                    self._edge(dkg, result, changed_ids, "relation_analyzer:iam_attachment", arn, 1.0, "observed", role_id, policy_id, "role_has_policy")
            trust = self._json(role.get("trust_policy", role.get("AssumeRolePolicyDocument", {})), {})
            for statement in trust.get("Statement", []) if isinstance(trust, dict) else []:
                principal = statement.get("Principal", {}) if isinstance(statement, dict) else {}
                principals = principal.get("AWS", []) if isinstance(principal, dict) else []
                if isinstance(principals, str):
                    principals = [principals]
                for arn in principals if isinstance(principals, list) else []:
                    source_id = role_by_arn.get(str(arn)) or role_by_name.get(str(arn).split("/")[-1])
                    if source_id:
                        self._edge(dkg, result, changed_ids, "relation_analyzer:iam_trust", str(arn), 1.0, "observed", source_id, role_id, "role_can_assume")

        resource_by_arn = {
            str(node.get("arn", node.get("Arn", ""))): self._node_id(node)
            for node_type in ("S3", "EC2", "RDS", "EKS", "LoadBalancer", "VPC")
            for node in self._nodes(dkg, node_type)
            if node.get("arn", node.get("Arn", ""))
        }
        for policy in policies:
            policy_id = self._node_id(policy)
            document = self._json(
                policy.get("policy_document", policy.get("policy_detail", policy.get("document", policy.get("PolicyDocument", {})))),
                {},
            )
            for statement in document.get("Statement", []) if isinstance(document, dict) else []:
                resources = statement.get("Resource", []) if isinstance(statement, dict) else []
                if isinstance(resources, str):
                    resources = [resources]
                for arn in resources if isinstance(resources, list) else []:
                    target = resource_by_arn.get(str(arn))
                    if target:
                        self._edge(dkg, result, changed_ids, "relation_analyzer:iam_permission", str(arn), 1.0, "observed", policy_id, target, "policy_grants_resource")

    def _analyze_network(self, dkg: DKG, result: TopologyAnalysisResult, changed_ids: set[str]) -> None:
        groups = self._nodes(dkg, "SecurityGroup")
        resources = [node for node_type in ("ENI", "EC2") for node in self._nodes(dkg, node_type)]
        group_ids = {str(group.get("GroupId", group.get("group_id", ""))): self._node_id(group) for group in groups}
        for group in groups:
            source_id = self._node_id(group)
            for permission in group.get("IpPermissions", group.get("ingress", [])) or []:
                for pair in permission.get("UserIdGroupPairs", []) if isinstance(permission, dict) else []:
                    target_id = group_ids.get(str(pair.get("GroupId", "")))
                    if target_id:
                        self._edge(dkg, result, changed_ids, "relation_analyzer:security_group", str(pair.get("GroupId")), 0.8, "inferred", source_id, target_id, "resource_reaches_resource")
        for resource in resources:
            subnet = str(resource.get("SubnetId", "") or "")
            if not subnet:
                continue
            for other in resources:
                if self._node_id(other) == self._node_id(resource):
                    continue
                if subnet == str(other.get("SubnetId", "") or ""):
                    self._edge(dkg, result, changed_ids, "relation_analyzer:subnet_reachability", subnet, 0.55, "hypothesized", self._node_id(resource), self._node_id(other), "resource_reaches_resource")

    @staticmethod
    def _endpoint_url(host: str, port: int) -> str:
        scheme = "https" if port == 443 else "http"
        return f"{scheme}://{host}:{port}"

    def _analyze_service_endpoints(
        self, dkg: DKG, result: TopologyAnalysisResult, changed_ids: set[str],
        services: list[dict[str, Any]],
    ) -> None:
        """Link K8s Service clusterIP/ports to Endpoint nodes."""
        endpoints = self._nodes(dkg, "Endpoint")
        endpoint_by_url = {str(row.get("url", "")).rstrip("/"): self._node_id(row) for row in endpoints}
        for service in services:
            sid = self._node_id(service)
            cluster_ip = str(service.get("cluster_ip", service.get("clusterIP", "")) or "")
            ports = self._json(service.get("ports", []), [])
            for port_row in ports if isinstance(ports, list) else []:
                if not isinstance(port_row, dict):
                    continue
                port = port_row.get("port", port_row.get("targetPort"))
                if not port:
                    continue
                eid = f"endpoint-svc-{service.get('k8s_namespace', service.get('namespace', ''))}-{service.get('name', '')}-{port}"
                url = self._endpoint_url(cluster_ip or "cluster.local", int(port))
                if eid not in dkg.graph:
                    dkg.add_node(
                        "Endpoint", eid,
                        {"url": url, "params": "", "discovered_by": "relation_analyzer:service_spec"},
                        source="relation_analyzer:service_spec",
                    )
                if sid and eid:
                    self._edge(dkg, result, changed_ids, "relation_analyzer:service_spec", url, 0.95, "observed", sid, eid, "service_exposes_endpoint")
                    self._edge(dkg, result, changed_ids, "relation_analyzer:service_spec", url, 0.95, "observed", eid, sid, "endpoint_backed_by_service")
                # Match an already-scanned endpoint by URL when clusterIP is absent.
                if not cluster_ip:
                    for ep_url, ep_id in endpoint_by_url.items():
                        if str(port) in ep_url and service.get("name") in ep_url:
                            self._edge(dkg, result, changed_ids, "relation_analyzer:endpoint_match", ep_url, 0.7, "inferred", sid, ep_id, "service_exposes_endpoint")
                            self._edge(dkg, result, changed_ids, "relation_analyzer:endpoint_match", ep_url, 0.7, "inferred", ep_id, sid, "endpoint_backed_by_service")

    def _analyze_service_calls(
        self, dkg: DKG, result: TopologyAnalysisResult, changed_ids: set[str],
        services: list[dict[str, Any]], pods: list[dict[str, Any]],
    ) -> None:
        """Infer Service→Service calls from ConfigMap references mounted by Pods."""
        configmaps = self._nodes(dkg, "ConfigMap")
        service_by_key = {
            (str(s.get("k8s_namespace", s.get("namespace", ""))), str(s.get("name", ""))): self._node_id(s)
            for s in services
        }
        pod_by_id = {self._node_id(p): p for p in pods}
        for configmap in configmaps:
            cm_ns = str(configmap.get("namespace", ""))
            data = self._json(configmap.get("data", {}), {})
            if not isinstance(data, dict):
                continue
            refs: set[tuple[str, str]] = set()
            for value in data.values():
                text = str(value)
                for match in re.finditer(r"https?://([a-z0-9.-]+)(?::(\d+))?", text, re.I):
                    refs.add((match.group(1).lower(), match.group(2) or ""))
                for match in re.finditer(r"\b([a-z0-9-]+):(\d{1,5})\b", text):
                    refs.add((match.group(1).lower(), match.group(2)))
            if not refs:
                continue
            # Consumers: Services selecting Pods that mount this ConfigMap.
            consumers: set[str] = set()
            for service in services:
                selector = self._json(service.get("k8s_selector", {}), {})
                if not isinstance(selector, dict) or not selector:
                    continue
                for pod in pods:
                    if str(pod.get("namespace", "")) != cm_ns:
                        continue
                    mounted = self._json(pod.get("volumes", []), [])
                    names = {
                        str(v.get("config_map_name", "")) for v in mounted if isinstance(v, dict)
                    }
                    if str(configmap.get("name", "")) not in names:
                        continue
                    labels = self._json(pod.get("labels", {}), {})
                    if isinstance(labels, dict) and all(labels.get(str(k)) == v for k, v in selector.items()):
                        consumers.add(self._node_id(service))
            for target_name, _port in refs:
                target_id = service_by_key.get((cm_ns, target_name))
                if not target_id:
                    continue
                for source_id in consumers:
                    if source_id == target_id:
                        continue
                    self._edge(dkg, result, changed_ids, "relation_analyzer:configmap_ref", target_name, 0.7, "inferred", source_id, target_id, "service_calls_service")

    def _analyze_host_reachability(
        self, dkg: DKG, result: TopologyAnalysisResult, changed_ids: set[str],
    ) -> None:
        """Link AWS EC2/ENI private IPs to Host nodes and infer host reachability."""
        hosts = self._nodes(dkg, "Host")
        host_by_ip = {str(h.get("ip", "")): self._node_id(h) for h in hosts}
        aws_nodes = [n for node_type in ("EC2", "ENI") for n in self._nodes(dkg, node_type)]
        host_to_resource: dict[str, list[dict[str, Any]]] = {}
        for node in aws_nodes:
            private_ip = str(node.get("PrivateIpAddress", node.get("private_ip", "")) or "")
            host_id = host_by_ip.get(private_ip)
            if host_id:
                host_to_resource.setdefault(host_id, []).append(node)
                self._edge(dkg, result, changed_ids, "relation_analyzer:private_ip", private_ip, 1.0, "observed", self._node_id(node), host_id, "resource_reaches_resource")
                self._edge(dkg, result, changed_ids, "relation_analyzer:private_ip", private_ip, 1.0, "observed", host_id, self._node_id(node), "resource_reaches_resource")
        host_ids = list(host_to_resource)
        for i, source_host in enumerate(host_ids):
            for target_host in host_ids[i + 1:]:
                shared_subnet = False
                shared_group = False
                for source_node in host_to_resource[source_host]:
                    for target_node in host_to_resource[target_host]:
                        if source_node.get("SubnetId") and source_node.get("SubnetId") == target_node.get("SubnetId"):
                            shared_subnet = True
                        source_groups = {
                            str(g.get("GroupId", "")) for g in source_node.get("Groups", []) if isinstance(g, dict)
                        }
                        target_groups = {
                            str(g.get("GroupId", "")) for g in target_node.get("Groups", []) if isinstance(g, dict)
                        }
                        if source_groups & target_groups:
                            shared_group = True
                if shared_subnet or shared_group:
                    evidence = "shared_subnet" if shared_subnet else "shared_security_group"
                    self._edge(
                        dkg, result, changed_ids, "relation_analyzer:host_reachability",
                        evidence, 0.7, "inferred", source_host, target_host, "host_reaches_host",
                    )

    def _analyze_resource_exposure(
        self, dkg: DKG, result: TopologyAnalysisResult, changed_ids: set[str],
    ) -> None:
        """Create Endpoint nodes for exposed AWS resources."""
        for node_type in ("LoadBalancer", "RDS"):
            for row in self._nodes(dkg, node_type):
                host = ""
                port = 80
                if node_type == "LoadBalancer":
                    host = str(row.get("DNSName", row.get("dns_name", "")) or "")
                else:
                    endpoint = self._json(row.get("Endpoint", {}), {})
                    if isinstance(endpoint, dict):
                        host = str(endpoint.get("Address", "") or "")
                        port = int(endpoint.get("Port", 5432) or 5432)
                if not host:
                    continue
                eid = f"endpoint-aws-{node_type.lower()}-{self._node_id(row).split(':')[-1]}"
                url = self._endpoint_url(host, port)
                if eid not in dkg.graph:
                    dkg.add_node(
                        "Endpoint", eid,
                        {"url": url, "params": "", "discovered_by": "relation_analyzer:aws_exposure"},
                        source="relation_analyzer:aws_exposure",
                    )
                self._edge(dkg, result, changed_ids, "relation_analyzer:aws_exposure", url, 0.9, "observed", self._node_id(row), eid, "resource_exposed_via")
        for row in self._nodes(dkg, "S3"):
            bucket = str(row.get("BucketName", row.get("Name", "")) or "")
            region = str(row.get("region", "") or "")
            if not bucket or not region:
                continue
            host = f"{bucket}.s3.{region}.amazonaws.com"
            eid = f"endpoint-aws-s3-{bucket}"
            url = self._endpoint_url(host, 443)
            if eid not in dkg.graph:
                dkg.add_node(
                    "Endpoint", eid,
                    {"url": url, "params": "", "discovered_by": "relation_analyzer:aws_exposure"},
                    source="relation_analyzer:aws_exposure",
                )
            self._edge(dkg, result, changed_ids, "relation_analyzer:aws_exposure", url, 0.9, "observed", self._node_id(row), eid, "resource_exposed_via")

    def _analyze_resource_dependencies(
        self, dkg: DKG, result: TopologyAnalysisResult, changed_ids: set[str],
    ) -> None:
        subnets = self._nodes(dkg, "Subnet")
        groups = self._nodes(dkg, "SecurityGroup")
        subnet_by_id = {str(s.get("SubnetId", s.get("subnet_id", ""))): self._node_id(s) for s in subnets}
        group_by_id = {str(g.get("GroupId", g.get("group_id", ""))): self._node_id(g) for g in groups}
        for row in self._nodes(dkg, "RDS"):
            rid = self._node_id(row)
            subnet_group = self._json(row.get("DBSubnetGroup", {}), {})
            subnets_meta = self._json(subnet_group.get("Subnets", []), []) if isinstance(subnet_group, dict) else []
            for item in subnets_meta if isinstance(subnets_meta, list) else []:
                target = subnet_by_id.get(str(item.get("SubnetIdentifier", "")) if isinstance(item, dict) else "")
                if target:
                    self._edge(dkg, result, changed_ids, "relation_analyzer:rds_subnet", str(item.get("SubnetIdentifier")), 0.75, "inferred", rid, target, "resource_depends_on")
            vpc_groups = self._json(row.get("VpcSecurityGroups", []), [])
            for item in vpc_groups if isinstance(vpc_groups, list) else []:
                target = group_by_id.get(str(item.get("VpcSecurityGroupId", "")) if isinstance(item, dict) else "")
                if target:
                    self._edge(dkg, result, changed_ids, "relation_analyzer:rds_sg", str(item.get("VpcSecurityGroupId")), 0.75, "inferred", rid, target, "resource_depends_on")
        for row in self._nodes(dkg, "LoadBalancer"):
            rid = self._node_id(row)
            zones = self._json(row.get("AvailabilityZones", []), [])
            for item in zones if isinstance(zones, list) else []:
                target = subnet_by_id.get(str(item.get("SubnetId", "")) if isinstance(item, dict) else "")
                if target:
                    self._edge(dkg, result, changed_ids, "relation_analyzer:lb_subnet", str(item.get("SubnetId")), 0.75, "inferred", rid, target, "resource_depends_on")
            security_groups = self._json(row.get("SecurityGroups", []), [])
            for group_id in security_groups if isinstance(security_groups, list) else []:
                target = group_by_id.get(str(group_id))
                if target:
                    self._edge(dkg, result, changed_ids, "relation_analyzer:lb_sg", str(group_id), 0.75, "inferred", rid, target, "resource_depends_on")

    def _analyze_rbac_permissions(
        self, dkg: DKG, result: TopologyAnalysisResult, changed_ids: set[str],
    ) -> None:
        namespaces = self._nodes(dkg, "K8sNamespace")
        ns_by_name = {str(n.get("name", "")): self._node_id(n) for n in namespaces}
        for node_type in ("Role", "ClusterRole"):
            for role in self._nodes(dkg, node_type):
                rules = self._json(role.get("rules", []), [])
                if not rules:
                    continue
                verbs: list[str] = []
                resources: list[str] = []
                api_groups: list[str] = []
                for rule in rules if isinstance(rules, list) else []:
                    if not isinstance(rule, dict):
                        continue
                    verbs.extend(rule.get("verbs", []))
                    resources.extend(rule.get("resources", []))
                    api_groups.extend(rule.get("apiGroups", []))
                summary = {
                    "verbs": sorted(set(str(v) for v in verbs)),
                    "resources": sorted(set(str(r) for r in resources)),
                    "api_groups": sorted(set(str(g) for g in api_groups)),
                }
                role_id = self._node_id(role)
                if node_type == "Role":
                    target_ns = ns_by_name.get(str(role.get("namespace", "")))
                else:
                    target_ns = None
                targets = [target_ns] if target_ns else list(ns_by_name.values())
                for ns_id in targets:
                    self._edge(
                        dkg, result, changed_ids, "relation_analyzer:rbac_rules",
                        json.dumps(summary, sort_keys=True), 1.0, "observed",
                        role_id, ns_id, "role_grants_permission",
                    )

    def _analyze_route_tables(
        self, dkg: DKG, result: TopologyAnalysisResult, changed_ids: set[str],
    ) -> None:
        subnets = self._nodes(dkg, "Subnet")
        subnet_by_id = {str(s.get("SubnetId", s.get("subnet_id", ""))): self._node_id(s) for s in subnets}
        cidr_to_id = {str(s.get("CidrBlock", s.get("cidr_block", ""))): self._node_id(s) for s in subnets if s.get("CidrBlock", s.get("cidr_block", ""))}
        for route_table in self._nodes(dkg, "RouteTable"):
            rt_id = self._node_id(route_table)
            associations = self._json(route_table.get("Associations", []), [])
            source_subnets = [
                subnet_by_id.get(str(a.get("SubnetId", ""))) for a in associations if isinstance(a, dict)
            ]
            routes = self._json(route_table.get("Routes", []), [])
            for route in routes if isinstance(routes, list) else []:
                if not isinstance(route, dict):
                    continue
                destination = str(route.get("DestinationCidrBlock", "") or "")
                target = cidr_to_id.get(destination)
                if not target:
                    continue
                for source in source_subnets:
                    if source and source != target:
                        self._edge(dkg, result, changed_ids, "relation_analyzer:route_table", destination, 0.6, "inferred", source, target, "resource_reaches_resource")

    def analyze(self, dkg: DKG, environment: Any | None = None) -> TopologyAnalysisResult:
        """Build K8s relationships from facts already present in ``dkg``."""
        before = dkg.revision
        result = TopologyAnalysisResult(before_revision=before, after_revision=before)
        changed_ids: set[str] = set()

        pods = self._nodes(dkg, "K8sPod")
        services = self._nodes(dkg, "Service")
        workloads = [
            node for node_type in self._WORKLOAD_TYPES
            for node in self._nodes(dkg, node_type)
        ]

        # Service selectors are explicit inferred relationships.
        for service in services:
            selector = self._json(service.get("k8s_selector", {}), {})
            namespace = str(service.get("k8s_namespace", service.get("namespace", "")))
            if not isinstance(selector, dict) or not selector:
                continue
            for pod in pods:
                labels = self._json(pod.get("labels", {}), {})
                if namespace and str(pod.get("namespace", "")) != namespace:
                    continue
                if isinstance(labels, dict) and all(labels.get(str(k)) == v for k, v in selector.items()):
                    self._edge(
                        dkg, result, changed_ids, "relation_analyzer:service_selector",
                        json.dumps(selector, sort_keys=True), 0.95, "inferred",
                        self._node_id(service), self._node_id(pod), "service_targets_pod",
                    )

        # Owner references connect workload controllers to their pods.
        workload_by_key = {
            (str(node.get("namespace", "")), str(node.get("name", "")), node.get("type")): self._node_id(node)
            for node in workloads
        }
        for pod in pods:
            refs = self._json(pod.get("owner_references", pod.get("ownerReferences", [])), [])
            for ref in refs if isinstance(refs, list) else []:
                kind = str(ref.get("kind", ""))
                if kind not in self._WORKLOAD_TYPES:
                    continue
                owner_id = workload_by_key.get((
                    str(pod.get("namespace", "")), str(ref.get("name", "")), kind
                ), "")
                self._edge(
                    dkg, result, changed_ids, "relation_analyzer:owner_reference",
                    str(ref.get("uid", ref.get("name", ""))), 1.0, "observed",
                    owner_id, self._node_id(pod), "workload_owns_pod",
                )

        # EndpointSlice and Ingress records carry explicit backend references.
        for endpoint_slice in self._nodes(dkg, "EndpointSlice"):
            service_name = str(endpoint_slice.get("service_name", endpoint_slice.get("service", "")))
            namespace = str(endpoint_slice.get("namespace", ""))
            target = next((s for s in services if str(s.get("name", "")) == service_name and
                           (not namespace or str(s.get("k8s_namespace", s.get("namespace", ""))) == namespace)), None)
            if target:
                self._edge(
                    dkg, result, changed_ids, "relation_analyzer:endpoint_slice",
                    service_name, 1.0, "observed", self._node_id(endpoint_slice),
                    self._node_id(target), "endpoint_slice_backed_by_service",
                )
        for ingress in self._nodes(dkg, "Ingress"):
            backends = self._json(ingress.get("backend_services", ingress.get("backends", [])), [])
            for backend in backends if isinstance(backends, list) else []:
                name = str(backend.get("name", backend.get("service", ""))) if isinstance(backend, dict) else str(backend)
                target = next((s for s in services if str(s.get("name", "")) == name), None)
                if target:
                    self._edge(
                        dkg, result, changed_ids, "relation_analyzer:ingress_backend",
                        name, 1.0, "observed", self._node_id(ingress),
                        self._node_id(target), "ingress_routes_service",
                    )

        # Binding nodes connect ServiceAccounts to Role/ClusterRole nodes.
        roles = self._nodes(dkg, "Role") + self._nodes(dkg, "ClusterRole")
        bindings = self._nodes(dkg, "RoleBinding") + self._nodes(dkg, "ClusterRoleBinding")
        for binding in bindings:
            role_name = str(binding.get("role_name", binding.get("roleRef_name", "")))
            role_kind = str(binding.get("role_kind", binding.get("roleRef_kind", "Role")))
            role = next((r for r in roles if str(r.get("name", "")) == role_name and
                         (not role_kind or str(r.get("type", "")) == role_kind)), None)
            if role:
                self._edge(
                    dkg, result, changed_ids, "relation_analyzer:rbac_binding",
                    role_name, 1.0, "observed", self._node_id(binding),
                    self._node_id(role), "binding_targets_role",
                )
            subjects = self._json(binding.get("subjects", []), [])
            for subject in subjects if isinstance(subjects, list) else []:
                if not isinstance(subject, dict) or subject.get("kind") != "ServiceAccount":
                    continue
                sa_id = f"k8s-sa-{subject.get('namespace', binding.get('namespace', ''))}-{subject.get('name', '')}"
                self._edge(
                    dkg, result, changed_ids, "relation_analyzer:rbac_subject",
                    str(subject.get("name", "")), 1.0, "observed",
                    self._node_id(binding), sa_id, "binding_subject",
                )

        # NetworkPolicy selectors are explicit observed policy scope.  The
        # policy action remains conservative: only declared deny entries are
        # marked as denies; selector coverage is an allow candidate.
        for policy in self._nodes(dkg, "NetworkPolicy"):
            selector = self._json(policy.get("pod_selector", {}), {})
            namespace = str(policy.get("namespace", ""))
            for pod in pods:
                labels = self._json(pod.get("labels", {}), {})
                if namespace and str(pod.get("namespace", "")) != namespace:
                    continue
                if isinstance(selector, dict) and isinstance(labels, dict) and all(
                    labels.get(str(k)) == v for k, v in selector.items()
                ):
                    edge_type = "network_policy_denies" if policy.get("denies") else "network_policy_allows"
                    self._edge(
                        dkg, result, changed_ids, "relation_analyzer:network_policy",
                        json.dumps(selector, sort_keys=True), 0.85, "inferred",
                        self._node_id(policy), self._node_id(pod), edge_type,
                    )

        self._analyze_iam(dkg, result, changed_ids)
        self._analyze_network(dkg, result, changed_ids)
        self._analyze_service_endpoints(dkg, result, changed_ids, services)
        self._analyze_service_calls(dkg, result, changed_ids, services, pods)
        self._analyze_host_reachability(dkg, result, changed_ids)
        self._analyze_resource_exposure(dkg, result, changed_ids)
        self._analyze_resource_dependencies(dkg, result, changed_ids)
        self._analyze_rbac_permissions(dkg, result, changed_ids)
        self._analyze_route_tables(dkg, result, changed_ids)

        if changed_ids:
            try:
                dkg.attack_path_summary(affected_node_ids=changed_ids)
            except Exception as exc:
                result.warnings.append(f"attack path refresh failed: {exc}")
        result.after_revision = dkg.revision
        result.affected_path_ids = self._changed_paths(dkg, changed_ids)
        result.coverage = {
            "pods": len(pods),
            "services": len(services),
            "workloads": len(workloads),
            "endpoint_slices": len(self._nodes(dkg, "EndpointSlice")),
            "ingresses": len(self._nodes(dkg, "Ingress")),
            "network_policies": len(self._nodes(dkg, "NetworkPolicy")),
            "rbac_bindings": len(bindings),
            "configmaps": len(self._nodes(dkg, "ConfigMap")),
            "route_tables": len(self._nodes(dkg, "RouteTable")),
            "roles": len(roles),
        }
        if environment is not None and not getattr(environment, "cloud_enabled", False):
            result.warnings.append("cloud analysis skipped for non-cloud classification")
        return result


__all__ = ["RelationAnalyzer", "TopologyAnalysisResult"]
