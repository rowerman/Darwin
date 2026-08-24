"""Host-unified model: EC2/K8sNode become Host; bug fixes from the review."""

import pytest

from darwin.cloud_topology import CloudTopology, CloudTopologyMapper
from darwin.core.belief import render_belief_snapshot
from darwin.dkg import DKG
from darwin.topology_analysis import RelationAnalyzer


def test_k8s_nodes_are_written_as_host_and_linked_to_cluster_and_pods():
    dkg = DKG()
    topology = CloudTopology(
        clusters=[{"name": "prod", "api_url": "https://x", "version": "1.27"}],
        nodes=[{
            "name": "node-1", "cluster": "prod", "internal_ip": "10.0.0.10",
            "is_control_plane": True, "labels": {"role": "master"}, "taints": [],
        }],
        pods=[{
            "name": "web-1", "namespace": "default", "node_name": "node-1",
            "phase": "Running", "service_account": "default", "labels": {},
        }],
    )

    CloudTopologyMapper(dkg)._write_to_dkg(topology)

    hosts = dkg.query_nodes("Host")
    assert len(hosts) == 1
    assert hosts[0]["provider"] == "k8s"
    assert hosts[0]["internal_ip"] == "10.0.0.10"
    assert dkg.query_nodes("K8sNode") == []
    edges = {(row["from"], row["to"], row["type"]) for row in dkg.query_edges()}
    assert ("k8s-cluster-prod", "host-k8s-node-1", "cluster_contains_node") in edges
    assert ("host-k8s-node-1", "k8s-pod-default-web-1", "node_hosts_pod") in edges


def test_k8s_node_merges_into_existing_host_by_internal_ip():
    dkg = DKG()
    dkg.add_node("Host", "host-10.0.0.10", {"ip": "10.0.0.10", "os": "linux"})
    topology = CloudTopology(
        clusters=[{"name": "prod", "api_url": "https://x", "version": "1.27"}],
        nodes=[{"name": "node-1", "cluster": "prod", "internal_ip": "10.0.0.10"}],
    )

    CloudTopologyMapper(dkg)._write_to_dkg(topology)

    hosts = dkg.query_nodes("Host")
    assert len(hosts) == 1
    assert hosts[0]["id"] == "host-10.0.0.10"
    assert hosts[0]["provider"] == "k8s"
    assert hosts[0]["os"] == "linux"  # existing properties preserved


def test_ec2_instances_are_written_as_host_with_eni_aggregation():
    dkg = DKG()
    topology = CloudTopology(aws_resources={
        "CloudAccount": [{"account_id": "123", "arn": "arn:aws:iam::123:root", "provider": "aws"}],
        "EC2": [{
            "InstanceId": "i-1", "PrivateIpAddress": "10.0.0.20", "SubnetId": "subnet-1",
            "Groups": [{"GroupId": "sg-1"}], "Arn": "arn:aws:ec2:us-east-1:123:instance/i-1",
        }],
        "ENI": [{
            "NetworkInterfaceId": "eni-1", "SubnetId": "subnet-1", "PrivateIpAddress": "10.0.0.20",
            "Attachment": {"InstanceId": "i-1"}, "Groups": [{"GroupId": "sg-1"}],
        }],
        "Subnet": [{"SubnetId": "subnet-1", "VpcId": "vpc-1", "resource_id": "aws:subnet-1"}],
        "VPC": [{"VpcId": "vpc-1", "resource_id": "aws:vpc-1"}],
        "SecurityGroup": [{"GroupId": "sg-1", "resource_id": "aws:sg-1"}],
    })

    CloudTopologyMapper(dkg)._write_to_dkg(topology)

    hosts = dkg.query_nodes("Host")
    assert len(hosts) == 1
    assert hosts[0]["id"] == "host-ec2-i-1"
    assert hosts[0]["provider"] == "aws"
    assert hosts[0]["network_interfaces"][0]["id"] == "eni-1"
    assert dkg.query_nodes("EC2") == []
    assert dkg.query_nodes("ENI") == []
    edges = {(row["from"], row["to"], row["type"]) for row in dkg.query_edges()}
    assert ("cloud-acct-123", "host-ec2-i-1", "account_contains_resource") in edges
    assert ("host-ec2-i-1", "aws:subnet-1", "resource_in_subnet") in edges
    assert ("aws:sg-1", "host-ec2-i-1", "security_group_attaches") in edges


def test_ec2_merges_into_existing_host_by_private_ip():
    dkg = DKG()
    dkg.add_node("Host", "host-10.0.0.20", {"ip": "10.0.0.20"})
    topology = CloudTopology(aws_resources={
        "EC2": [{"InstanceId": "i-1", "PrivateIpAddress": "10.0.0.20", "Arn": "arn:aws:ec2:us-east-1:123:instance/i-1"}],
    })

    CloudTopologyMapper(dkg)._write_to_dkg(topology)

    hosts = dkg.query_nodes("Host")
    assert len(hosts) == 1
    assert hosts[0]["id"] == "host-10.0.0.20"
    assert hosts[0]["provider"] == "aws"


def test_same_k8s_cluster_hosts_reach_each_other_as_hypothesized():
    dkg = DKG()
    dkg.add_node("Host", "host-a", {"provider": "k8s", "cluster": "prod"})
    dkg.add_node("Host", "host-b", {"provider": "k8s", "cluster": "prod"})

    RelationAnalyzer().analyze(dkg)
    edges = {(row["from"], row["to"], row["type"]) for row in dkg.query_edges()}

    assert ("host-a", "host-b", "host_reaches_host") in edges


def test_virtual_endpoint_nodes_are_rendered_with_marker():
    dkg = DKG()
    dkg.add_node("Endpoint", "ep-virtual", {
        "url": "http://cluster.local:80", "virtual": True,
    })
    from darwin.data_model import normalize_dkg_state

    text = render_belief_snapshot(normalize_dkg_state(dkg))
    assert "Endpoint:ep-virtual (http://cluster.local:80) [virtual]" in text


def test_dirty_rds_port_does_not_crash_analyzer():
    dkg = DKG()
    dkg.add_node("RDS", "aws:rds:bad", {
        "DBInstanceIdentifier": "bad",
        "Endpoint": {"Address": "bad.rds.amazonaws.com", "Port": "not-a-number"},
    })

    result = RelationAnalyzer().analyze(dkg)

    assert result.after_revision >= result.before_revision
    assert not any("Port" in warning for warning in result.warnings)


def test_configmap_ip_port_reference_is_not_misparsed():
    dkg = DKG()
    dkg.add_node("Service", "svc-db", {
        "name": "5", "k8s_namespace": "default", "k8s_selector": {"app": "db"},
    })
    dkg.add_node("K8sPod", "pod-web", {
        "name": "web-1", "namespace": "default", "labels": {"app": "web"},
        "volumes": [{"type": "configMap", "config_map_name": "cfg"}],
    })
    dkg.add_node("Service", "svc-web", {
        "name": "web", "k8s_namespace": "default", "k8s_selector": {"app": "web"},
    })
    dkg.add_node("ConfigMap", "cm", {
        "name": "cfg", "namespace": "default",
        "data": {"endpoint": "10.0.0.5:8080"},
    })

    RelationAnalyzer().analyze(dkg)
    edges = {(row["from"], row["to"], row["type"]) for row in dkg.query_edges()}

    assert not any(e[2] == "service_calls_service" for e in edges)


@pytest.mark.asyncio
async def test_task_anchor_ids_exact_ip_match_avoids_prefix_collision(
    make_orchestrator, fake_llm, fake_gateway
):
    orch = make_orchestrator(fake_llm(content="[]"), fake_gateway({}), fake_gateway({}))
    orch.dkg.add_node("Host", "host-10.0.0.5", {"ip": "10.0.0.5"})
    orch.dkg.add_node("Host", "host-10.0.0.50", {"ip": "10.0.0.50"})
    orch.dkg.add_node("Endpoint", "ep-5", {"url": "http://10.0.0.5:80/"})
    orch.dkg.add_node("Endpoint", "ep-50", {"url": "http://10.0.0.50:80/"})
    from darwin.core.task import Task

    task = Task(
        id="t", type="task", goal="g",
        action={"tool": "curl_get", "params": {"url": "http://10.0.0.5:80/flag"}},
    )

    anchors = orch.execution._task_anchor_ids(task)

    assert "host-10.0.0.5" in anchors
    assert "host-10.0.0.50" not in anchors
    assert "ep-5" in anchors
    assert "ep-50" not in anchors
