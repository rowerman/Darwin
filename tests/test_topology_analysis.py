from darwin.dkg import DKG
from darwin.cloud_topology import (
    CloudTopology,
    CloudTopologyMapper,
    PodSecurityProfile,
    write_k8s_service_nodes,
)
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


def test_analyzer_generates_service_endpoint_and_configmap_call_relations():
    dkg = DKG()
    dkg.add_node("Service", "svc-web", {
        "name": "web", "k8s_namespace": "default",
        "cluster_ip": "10.0.0.10", "ports": [{"port": 80}],
        "k8s_selector": {"app": "web"},
    })
    dkg.add_node("Service", "svc-db", {
        "name": "db", "k8s_namespace": "default", "k8s_selector": {"app": "db"},
    })
    dkg.add_node("K8sPod", "pod-web", {
        "name": "web-1", "namespace": "default", "labels": {"app": "web"},
        "volumes": [{"type": "configMap", "config_map_name": "app-config"}],
    })
    dkg.add_node("ConfigMap", "cm-app", {
        "name": "app-config", "namespace": "default",
        "data": {"db_url": "http://db:5432"},
    })

    RelationAnalyzer().analyze(dkg)
    edges = {(row["from"], row["to"], row["type"]) for row in dkg.query_edges()}

    assert any(e[2] == "service_exposes_endpoint" for e in edges)
    assert any(e[2] == "endpoint_backed_by_service" for e in edges)
    assert ("svc-web", "svc-db", "service_calls_service") in edges


def test_analyzer_generates_host_resource_and_rbac_permission_relations():
    dkg = DKG()
    dkg.add_node("Host", "host-a", {
        "ip": "10.0.0.5", "subnet_id": "subnet-1", "groups": [{"GroupId": "sg-1"}],
    })
    dkg.add_node("Host", "host-b", {
        "ip": "10.0.0.6", "subnet_id": "subnet-1", "groups": [{"GroupId": "sg-1"}],
    })
    dkg.add_node("K8sNamespace", "k8s-ns-default", {"name": "default"})
    dkg.add_node("Role", "role-reader", {
        "name": "reader", "namespace": "default",
        "rules": [{"verbs": ["get", "list"], "resources": ["pods"], "apiGroups": [""]}],
    })

    RelationAnalyzer().analyze(dkg)
    edges = {(row["from"], row["to"], row["type"]) for row in dkg.query_edges()}

    assert ("host-a", "host-b", "host_reaches_host") in edges
    assert ("role-reader", "k8s-ns-default", "role_grants_permission") in edges


def test_analyzer_generates_aws_exposure_dependency_and_route_relations():
    dkg = DKG()
    dkg.add_node("LoadBalancer", "aws:lb-1", {
        "LoadBalancerArn": "arn:aws:elasticloadbalancing:us-east-1:123:loadbalancer/app/web",
        "DNSName": "web-123.elb.amazonaws.com", "AvailabilityZones": [{"SubnetId": "subnet-1"}],
    })
    dkg.add_node("RDS", "aws:rds-1", {
        "DBInstanceIdentifier": "db-1",
        "Endpoint": {"Address": "db-1.abc.us-east-1.rds.amazonaws.com", "Port": 5432},
        "DBSubnetGroup": {"Subnets": [{"SubnetIdentifier": "subnet-1"}]},
    })
    dkg.add_node("Subnet", "aws:subnet-1", {"SubnetId": "subnet-1", "CidrBlock": "10.0.1.0/24"})
    dkg.add_node("Subnet", "aws:subnet-2", {"SubnetId": "subnet-2", "CidrBlock": "10.0.2.0/24"})
    dkg.add_node("RouteTable", "aws:rt-1", {
        "RouteTableId": "rt-1",
        "Associations": [{"SubnetId": "subnet-1"}],
        "Routes": [{"DestinationCidrBlock": "10.0.2.0/24"}],
    })
    dkg.add_node("S3", "aws:s3-bucket", {"BucketName": "bucket", "region": "us-east-1"})

    RelationAnalyzer().analyze(dkg)
    edges = {(row["from"], row["to"], row["type"]) for row in dkg.query_edges()}

    assert any(e[2] == "resource_exposed_via" for e in edges)
    assert ("aws:rds-1", "aws:subnet-1", "resource_depends_on") in edges
    assert ("aws:lb-1", "aws:subnet-1", "resource_depends_on") in edges
    assert ("aws:subnet-1", "aws:subnet-2", "resource_reaches_resource") in edges


def test_iam_policy_document_is_preferred_over_detail():
    dkg = DKG()
    dkg.add_node("IAMPolicy", "policy-a", {
        "arn": "arn:aws:iam::123:policy/a",
        "policy_detail": {"Statement": []},
        "policy_document": {"Statement": [{"Effect": "Allow", "Resource": "arn:aws:s3:::bucket"}]},
    })
    dkg.add_node("S3", "bucket", {"arn": "arn:aws:s3:::bucket", "BucketName": "bucket"})

    RelationAnalyzer().analyze(dkg)
    edges = {(row["from"], row["to"], row["type"]) for row in dkg.query_edges()}
    assert ("policy-a", "bucket", "policy_grants_resource") in edges


def test_k8s_service_writer_emits_one_canonical_node_per_port():
    """A Service node carries the scalar contract every consumer reads."""
    dkg = DKG()
    services = [{
        "name": "metadata", "namespace": "default", "cluster_ip": "10.96.202.38",
        "selector": {"app": "metadata"}, "type": "ClusterIP",
        "ports": [{"port": 5000, "protocol": "TCP", "target_port": 5000}],
    }, {
        "name": "kube-dns", "namespace": "kube-system", "cluster_ip": "10.96.0.10",
        "selector": {"k8s-app": "kube-dns"}, "type": "ClusterIP",
        "ports": [{"port": 53, "protocol": "UDP"}, {"port": 9153, "protocol": "TCP"}],
    }, {
        "name": "no-ports", "namespace": "default", "ports": [{"target_port": "named"}],
    }]

    write_k8s_service_nodes(dkg, services)
    write_k8s_service_nodes(dkg, services)  # repeated discovery stays idempotent

    nodes = {node["id"]: node for node in dkg.query_nodes("Service")}
    assert set(nodes) == {
        "svc-k8s-default-metadata-5000",
        "svc-k8s-kube-system-kube-dns-53",
        "svc-k8s-kube-system-kube-dns-9153",
    }
    for node in nodes.values():
        assert isinstance(node["port"], int)
        assert node["protocol"] in {"tcp", "udp"}
    dns = nodes["svc-k8s-kube-system-kube-dns-53"]
    assert dns["protocol"] == "udp"
    assert dns["name"] == "kube-dns"
    assert dns["cluster_ip"] == "10.96.0.10"
    assert dns["k8s_selector"] == {"k8s-app": "kube-dns"}


def test_analyzer_links_per_port_service_nodes_to_in_cluster_endpoints():
    dkg = DKG()
    write_k8s_service_nodes(dkg, [{
        "name": "metadata", "namespace": "default", "cluster_ip": "10.96.202.38",
        "selector": {"app": "metadata"}, "type": "ClusterIP",
        "ports": [{"port": 5000, "protocol": "TCP"}],
    }])
    # Host-side services are scanned where they listen; no cluster alias.
    dkg.add_node("Service", "svc-localhost-8080", {
        "port": 8080, "protocol": "tcp", "service_name": "http",
    })

    RelationAnalyzer().analyze(dkg)

    endpoint_id = "endpoint-svc-default-metadata-5000"
    assert dkg.get_node(endpoint_id)["url"] == "http://10.96.202.38:5000"
    edges = {(row["from"], row["to"], row["type"]) for row in dkg.query_edges()}
    assert ("svc-k8s-default-metadata-5000", endpoint_id, "service_exposes_endpoint") in edges
    assert (endpoint_id, "svc-k8s-default-metadata-5000", "endpoint_backed_by_service") in edges
    assert not any(
        str(row.get("url", "")).startswith("http://cluster.local") for row in dkg.query_nodes("Endpoint")
    )


def test_pod_capabilities_rank_and_reach_the_world_model():
    """K8s writes bare capability names; they must rank like libcap names."""
    profile = PodSecurityProfile(
        pod_name="attacker", namespace="default", capabilities_add=["NET_RAW"],
    )
    assert profile.escape_vectors == ["cap_net_raw_mitm"]
    assert profile.risk_score > 0
    assert profile.is_high_risk
    assert PodSecurityProfile(
        pod_name="victim", namespace="default",
    ).is_high_risk is False

    dkg = DKG()
    CloudTopologyMapper(dkg)._write_to_dkg(CloudTopology(
        clusters=[{"name": "kind-test", "api_url": "https://127.0.0.1:42087"}],
        pods=[{
            "name": "attacker", "namespace": "default", "phase": "Running",
            "containers": [{"privileged": False, "capabilities_add": ["NET_RAW"]}],
        }],
    ))
    pod = dkg.get_node("k8s-pod-default-attacker")
    assert pod["capabilities"] == ["NET_RAW"]
    assert pod["privileged"] is False
