import pytest

from darwin.cloud_attack_path import AttackPath, AttackPathReport
from darwin.cloud_topology import CloudTopology, CloudTopologyMapper
from darwin.dkg import DKG
from darwin.core.task import Task
from darwin.core.task_graph import TaskGraph
from darwin.tools.mcp_gateway import MCPGateway, ToolResult
from darwin.tools.recon_server import register_recon_tools
from darwin.topology_analysis import RelationAnalyzer


@pytest.mark.asyncio
async def test_aws_discovery_rejects_mutating_actions_without_spawning():
    gateway = MCPGateway()
    register_recon_tools(gateway)

    result = await gateway.call("cloud_discovery_aws", {
        "service": "iam", "action": "attach-role-policy", "resource": "role/demo",
    })

    assert result.success is False
    assert result.exit_code == 2
    assert "read-only" in result.stderr


def test_hybrid_mapper_deduplicates_eks_crosswalk_and_adds_aws_edges():
    dkg = DKG()
    dkg.add_node("K8sCluster", "k8s-cluster-prod", {"name": "prod"})
    topology = CloudTopology(aws_resources={
        "CloudAccount": [{"account_id": "123", "arn": "arn:aws:iam::123:root", "provider": "aws"}],
        "EKS": [{"name": "prod", "ClusterName": "prod", "arn": "arn:aws:eks:us-east-1:123:cluster/prod", "resource_id": "aws:eks:prod"}],
        "VPC": [{"VpcId": "vpc-1", "Arn": "arn:aws:ec2:us-east-1:123:vpc/vpc-1", "resource_id": "aws:vpc-1"}],
        "Subnet": [{"SubnetId": "subnet-1", "VpcId": "vpc-1", "resource_id": "aws:subnet-1"}],
    })

    CloudTopologyMapper(dkg)._write_to_dkg(topology)

    assert len(dkg.query_nodes("K8sCluster")) == 1
    assert len(dkg.query_nodes("EKS")) == 1
    assert any(edge["type"] == "eks_links_k8s_cluster" for edge in dkg.query_edges())
    assert any(edge["type"] == "resource_contains" for edge in dkg.query_edges())


@pytest.mark.asyncio
async def test_aws_mapper_normalizes_fixture_resources_through_gateway_port():
    payloads = {
        ("sts", "get-caller-identity"): {"Account": "123", "Arn": "arn:aws:iam::123:root"},
        ("ec2", "describe-vpcs"): {"Vpcs": [{"VpcId": "vpc-1"}]},
        ("ec2", "describe-subnets"): {"Subnets": [{"SubnetId": "subnet-1", "VpcId": "vpc-1"}]},
        ("eks", "list-clusters"): {"clusters": ["prod"]},
        ("eks", "describe-cluster"): {"cluster": {"name": "prod", "arn": "arn:aws:eks:us-east-1:123:cluster/prod"}},
    }

    async def fake_port(name, params):
        payload = payloads.get((params.get("service"), params.get("action")), {})
        return ToolResult(
            tool_name=name, success=True, stdout="", stderr="", exit_code=0,
            elapsed_ms=1, parsed_output=payload,
        )

    env = type("Env", (), {"cloud_enabled": True, "provider": "aws"})()
    topology = CloudTopology()
    mapper = CloudTopologyMapper(DKG(), tool_port=fake_port, environment=env)
    await mapper._discover_aws_resources(topology)

    assert topology.aws_resources["CloudAccount"][0]["account_id"] == "123"
    assert topology.aws_resources["VPC"][0]["resource_id"].startswith("aws:123")
    assert topology.aws_resources["EKS"][0]["name"] == "prod"
    assert topology.aws_coverage["complete"] is True


def test_relation_analyzer_handles_iam_policy_trust_and_network_edges():
    dkg = DKG()
    dkg.add_node("IAMRole", "role-source", {
        "name": "source", "arn": "arn:aws:iam::123:role/source",
        "trust_policy": {"Statement": [{"Principal": {"AWS": "arn:aws:iam::123:role/target"}}]},
        "AttachedPolicies": [{"PolicyArn": "arn:aws:iam::123:policy/read"}],
    })
    dkg.add_node("IAMRole", "role-target", {"name": "target", "arn": "arn:aws:iam::123:role/target"})
    dkg.add_node("IAMPolicy", "policy-read", {
        "arn": "arn:aws:iam::123:policy/read",
        "policy_detail": {"Statement": [{"Effect": "Allow", "Resource": "arn:aws:s3:::bucket"}]},
    })
    dkg.add_node("S3", "bucket", {"arn": "arn:aws:s3:::bucket", "BucketName": "bucket"})
    dkg.add_node("SecurityGroup", "sg-a", {"GroupId": "sg-a", "IpPermissions": [{"UserIdGroupPairs": [{"GroupId": "sg-b"}]}]})
    dkg.add_node("SecurityGroup", "sg-b", {"GroupId": "sg-b"})

    RelationAnalyzer().analyze(dkg)
    edges = {(row["from"], row["to"], row["type"]) for row in dkg.query_edges()}

    assert ("role-source", "policy-read", "role_has_policy") in edges
    assert ("role-target", "role-source", "role_can_assume") in edges
    assert ("policy-read", "bucket", "policy_grants_resource") in edges
    assert ("sg-a", "sg-b", "resource_reaches_resource") in edges


def test_partial_attack_path_refresh_recomputes_only_affected_categories(monkeypatch):
    import darwin.cloud_attack_path as attack_path

    calls = []

    def fake_compute(dkg, categories=None):
        calls.append(categories)
        paths = [AttackPath(path_id="priv-1", category="privilege_escalation", description="role")]
        if categories is None or "lateral_move" in categories:
            paths.append(AttackPath(path_id="lat-1", category="lateral_move", description="network"))
        return AttackPathReport(paths=paths)

    monkeypatch.setattr(attack_path, "compute_attack_paths", fake_compute)
    dkg = DKG()
    dkg.add_node("IAMRole", "role-a", {})
    assert {p.path_id for p in dkg.attack_path_summary()} == {"priv-1", "lat-1"}
    dkg.add_node("IAMPolicy", "policy-a", {})

    refreshed = dkg.attack_path_summary(affected_node_ids={"role-a"})

    assert calls[0] is None
    assert calls[-1] == {"privilege_escalation", "cross_account"}
    assert {p.path_id for p in refreshed} == {"priv-1", "lat-1"}


def test_attack_path_dependency_blocks_stale_path_tasks():
    task = Task(
        id="follow", type="task", goal="follow path",
        dependencies=[{"type": "requires_attack_path", "path_id": "p1"}],
    )
    graph = TaskGraph([task])

    assert graph.ready_tasks({"attack_paths": [{"path_id": "p1", "status": "active"}]}) == [task]
    task.status = task.status.CREATED
    assert graph.ready_tasks({"attack_paths": [{"path_id": "p1", "status": "stale"}]}) == []
    assert task.status.value == "blocked"
