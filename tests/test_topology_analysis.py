from darwin.dkg import DKG
from darwin.cloud_topology import CloudTopology, CloudTopologyMapper
from darwin.topology_analysis import RelationAnalyzer


def test_relation_analyzer_builds_k8s_relationships_idempotently():
    dkg = DKG()
    dkg.add_node("Service", "svc-web", {
        "name": "web", "k8s_namespace": "default", "k8s_selector": {"app": "web"},
    })
    dkg.add_node("K8sPod", "pod-web", {
        "name": "web-1", "namespace": "default", "labels": {"app": "web"},
        "owner_references": [{"kind": "Deployment", "name": "web", "uid": "dep-1"}],
    })
    dkg.add_node("Deployment", "dep-web", {"name": "web", "namespace": "default"})
    dkg.add_node("EndpointSlice", "eps-web", {
        "name": "web-abc", "namespace": "default", "service_name": "web",
    })
    dkg.add_node("Ingress", "ing-web", {
        "name": "web-ing", "namespace": "default", "backend_services": [{"name": "web"}],
    })
    dkg.add_node("K8sSA", "k8s-sa-default-web", {"name": "web", "namespace": "default"})
    dkg.add_node("Role", "role-web", {"name": "reader", "namespace": "default"})
    dkg.add_node("RoleBinding", "rb-web", {
        "name": "web-reader", "namespace": "default", "role_name": "reader",
        "role_kind": "Role", "subjects": [{"kind": "ServiceAccount", "name": "web", "namespace": "default"}],
    })
    dkg.add_node("NetworkPolicy", "np-web", {
        "name": "web-policy", "namespace": "default", "pod_selector": {"app": "web"},
    })

    analyzer = RelationAnalyzer()
    first = analyzer.analyze(dkg)
    second = analyzer.analyze(dkg)

    edges = {(row["from"], row["to"], row["type"]) for row in dkg.query_edges()}
    assert ("svc-web", "pod-web", "service_targets_pod") in edges
    assert ("dep-web", "pod-web", "workload_owns_pod") in edges
    assert ("eps-web", "svc-web", "endpoint_slice_backed_by_service") in edges
    assert ("ing-web", "svc-web", "ingress_routes_service") in edges
    assert ("rb-web", "role-web", "binding_targets_role") in edges
    assert ("rb-web", "k8s-sa-default-web", "binding_subject") in edges
    assert ("np-web", "pod-web", "network_policy_allows") in edges
    assert first.added_relations >= 7
    assert second.added_relations == 0


def test_relation_analyzer_reports_non_cloud_skip_warning():
    dkg = DKG()
    result = RelationAnalyzer().analyze(dkg, environment=type("Env", (), {"cloud_enabled": False})())
    assert result.warnings == ["cloud analysis skipped for non-cloud classification"]


def test_cloud_mapper_writes_extended_k8s_resources_without_secret_values():
    dkg = DKG()
    topology = CloudTopology(
        services=[{"name": "web", "namespace": "default", "selector": {"app": "web"}}],
        workloads=[{"kind": "Deployment", "name": "web", "namespace": "default", "labels": {"app": "web"}}],
        endpoint_slices=[{"name": "web-1", "namespace": "default", "service_name": "web"}],
        ingresses=[{"name": "web", "namespace": "default", "backend_services": [{"name": "web"}]}],
        network_policies=[{"name": "web", "namespace": "default", "pod_selector": {"app": "web"}}],
        rbac_roles=[{"kind": "Role", "name": "reader", "namespace": "default", "rules": [{"verbs": ["get"]}]}],
        rbac_resources=[{"kind": "RoleBinding", "name": "web-reader", "namespace": "default", "role_name": "reader", "role_kind": "Role", "subjects": []}],
        secrets=[{"name": "db", "namespace": "default", "type": "Opaque", "data_keys": ["password"]}],
        configmaps=[{"name": "app", "namespace": "default", "data_keys": ["url"]}],
    )

    CloudTopologyMapper(dkg)._write_to_dkg(topology)

    assert dkg.get_node("k8s-deployment-default-web")["type"] == "Deployment"
    assert dkg.get_node("k8s-endpointslice-default-web-1")["type"] == "EndpointSlice"
    assert dkg.get_node("k8s-secret-default-db")["data_keys"] == ["password"]
    assert "data" not in dkg.get_node("k8s-secret-default-db")
