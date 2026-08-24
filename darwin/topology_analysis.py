"""Deterministic relationship analysis for collected Kubernetes topology."""

from __future__ import annotations

import json
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
        }
        if environment is not None and not getattr(environment, "cloud_enabled", False):
            result.warnings.append("cloud analysis skipped for non-cloud classification")
        return result


__all__ = ["RelationAnalyzer", "TopologyAnalysisResult"]
