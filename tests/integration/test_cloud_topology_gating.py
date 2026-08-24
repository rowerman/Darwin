"""Cloud/K8s discovery gating through the injected tool-call port.

These tests exercise the real ``Orchestrator`` + ``ReconCoordinator`` path
with a deterministic tool port: the port records every invocation and
returns local JSON payloads for the AWS discovery allowlist.  They verify
that ordinary Web/DB runs never trigger cloud discovery and that AWS
classifications map resources and relations into the DKG.
"""

from __future__ import annotations

import pytest

from darwin.dkg import DKG
from darwin.tools.mcp_gateway import ToolResult


pytestmark = pytest.mark.integration


class RecordingToolPort:
    """Replacement for ``GatewayToolCallPort`` with scripted cloud results."""

    def __init__(self, *, aws_payloads=None, open_ports=None,
                 kubectl_stdout=None, kubectl_payloads=None):
        self.calls = []
        self.aws_payloads = aws_payloads or {}
        self.open_ports = open_ports or []
        self.kubectl_stdout = kubectl_stdout or {}
        self.kubectl_payloads = kubectl_payloads or {}

    @staticmethod
    def _result(name, payload=None, *, success=True, stdout=""):
        return ToolResult(
            tool_name=name, success=success, stdout=stdout, stderr="",
            exit_code=0 if success else 1, elapsed_ms=1.0,
            parsed_output=payload or {},
        )

    async def call(self, name, params):
        self.calls.append((name, dict(params or {})))
        if name == "nmap_port_range" or name == "nmap_full_scan":
            return self._result(name, {"open_ports": list(self.open_ports)})
        if name == "cloud_discovery_aws":
            payload = self.aws_payloads.get(
                (params.get("service"), params.get("action"))
            )
            if payload is None:
                return self._result(name, success=False, stdout="")
            return self._result(name, payload)
        if name == "cloud_discovery_command":
            command = str(params.get("command", ""))
            if command in self.kubectl_stdout:
                return self._result(name, success=True, stdout=self.kubectl_stdout[command])
            if command in self.kubectl_payloads:
                return self._result(name, self.kubectl_payloads[command])
            # IMDS / unhandled probes fail silently so the mapper continues.
            return self._result(name, success=False, stdout="")
        return self._result(name, success=False, stdout="")


@pytest.fixture
def aws_environment(monkeypatch):
    monkeypatch.setattr(
        "darwin.rag.get_rag", lambda: None,
    )


@pytest.mark.asyncio
async def test_web_db_classification_never_calls_cloud_tools(
    make_orchestrator, fake_llm, fake_gateway, aws_environment
):
    orch = make_orchestrator(fake_llm(content="[]"), fake_gateway({}), fake_gateway({}))
    port = RecordingToolPort(open_ports=[{"port": 8080, "service": "http", "state": "open"}])
    orch._tool_port = port
    orch._provided_username = ""
    orch._provided_password = ""

    await orch.recon._bootstrap_scan("http://127.0.0.1:8080", port_range="8080")

    called_names = [name for name, _ in port.calls]
    assert "cloud_discovery_command" not in called_names
    assert "cloud_discovery_aws" not in called_names
    assert orch.dkg.query_nodes("VPC") == []
    assert orch.dkg.query_nodes("Subnet") == []
    assert orch.dkg.query_nodes("EKS") == []
    assert orch._scan_classification.kind.value == "web_db"


@pytest.mark.asyncio
async def test_aws_classification_maps_resources_and_relations(
    make_orchestrator, fake_llm, fake_gateway, aws_environment
):
    orch = make_orchestrator(fake_llm(content="[]"), fake_gateway({}), fake_gateway({}))
    aws_payloads = {
        ("sts", "get-caller-identity"): {"Account": "123", "Arn": "arn:aws:iam::123:root"},
        ("ec2", "describe-vpcs"): {
            "Vpcs": [{"VpcId": "vpc-1", "Arn": "arn:aws:ec2:us-east-1:123:vpc/vpc-1"}],
        },
        ("ec2", "describe-subnets"): {
            "Subnets": [{"SubnetId": "subnet-1", "VpcId": "vpc-1"}],
        },
        ("ec2", "describe-route-tables"): {"RouteTables": []},
        ("ec2", "describe-security-groups"): {"SecurityGroups": []},
        ("ec2", "describe-network-interfaces"): {"NetworkInterfaces": []},
        ("ec2", "describe-instances"): {"Reservations": []},
        ("elbv2", "describe-load-balancers"): {"LoadBalancers": []},
        ("rds", "describe-db-instances"): {"DBInstances": []},
        ("s3api", "list-buckets"): {"Buckets": []},
        ("iam", "list-roles"): {"Roles": []},
        ("iam", "list-policies"): {"Policies": []},
        ("eks", "list-clusters"): {"clusters": []},
    }
    port = RecordingToolPort(
        aws_payloads=aws_payloads,
        open_ports=[{"port": 443, "service": "aws eks", "state": "open"}],
    )
    orch._tool_port = port
    orch._provided_username = ""
    orch._provided_password = ""

    await orch.recon._bootstrap_scan("http://127.0.0.1:443", port_range="443")

    aws_calls = {
        (params.get("service"), params.get("action"))
        for name, params in port.calls if name == "cloud_discovery_aws"
    }
    assert ("sts", "get-caller-identity") in aws_calls
    assert ("ec2", "describe-vpcs") in aws_calls
    assert ("eks", "list-clusters") in aws_calls

    vpcs = orch.dkg.query_nodes("VPC")
    subnets = orch.dkg.query_nodes("Subnet")
    accounts = orch.dkg.query_nodes("CloudAccount")
    assert vpcs and subnets and accounts
    assert vpcs[0]["id"].startswith("aws:arn:aws:ec2:")

    edge_types = {row["type"] for row in orch.dkg.query_edges()}
    assert "account_contains_resource" in edge_types
    assert "resource_contains" in edge_types
    assert orch._scan_classification.kind.value == "public_cloud"
    assert orch._topology_analysis is not None
    assert "vpcs" in orch._topology_analysis.coverage or orch._topology_analysis.coverage


@pytest.mark.asyncio
async def test_aws_mapper_without_port_never_spawns():
    """The mapper must refuse to discover when no gateway port is injected."""
    from darwin.cloud_topology import CloudTopologyMapper

    mapper = CloudTopologyMapper(DKG(), tool_port=None)
    ok, out = await mapper._run_discovery("kubectl cluster-info")
    assert ok is False and out == ""


@pytest.mark.asyncio
async def test_hybrid_classification_maps_k8s_and_aws_without_duplication(
    make_orchestrator, fake_llm, fake_gateway, aws_environment
):
    orch = make_orchestrator(fake_llm(content="[]"), fake_gateway({}), fake_gateway({}))
    aws_payloads = {
        ("sts", "get-caller-identity"): {"Account": "123", "Arn": "arn:aws:iam::123:root"},
        ("ec2", "describe-vpcs"): {
            "Vpcs": [{"VpcId": "vpc-1", "Arn": "arn:aws:ec2:us-east-1:123:vpc/vpc-1"}],
        },
        ("ec2", "describe-subnets"): {
            "Subnets": [{"SubnetId": "subnet-1", "VpcId": "vpc-1"}],
        },
        ("ec2", "describe-route-tables"): {"RouteTables": []},
        ("ec2", "describe-security-groups"): {"SecurityGroups": []},
        ("ec2", "describe-network-interfaces"): {"NetworkInterfaces": []},
        ("ec2", "describe-instances"): {"Reservations": []},
        ("elbv2", "describe-load-balancers"): {"LoadBalancers": []},
        ("rds", "describe-db-instances"): {"DBInstances": []},
        ("s3api", "list-buckets"): {"Buckets": []},
        ("iam", "list-roles"): {"Roles": []},
        ("iam", "list-policies"): {"Policies": []},
        ("eks", "list-clusters"): {"clusters": ["prod"]},
        ("eks", "describe-cluster"): {
            "cluster": {"name": "prod", "arn": "arn:aws:eks:us-east-1:123:cluster/prod"},
        },
    }
    port = RecordingToolPort(
        aws_payloads=aws_payloads,
        open_ports=[
            {"port": 6443, "service": "kubernetes", "state": "open"},
            {"port": 443, "service": "aws eks", "state": "open"},
        ],
        kubectl_stdout={
            "kubectl cluster-info": "Kubernetes control plane is running at https://10.0.0.1:6443\n",
            "kubectl config current-context": "prod\n",
        },
        kubectl_payloads={
            "kubectl get namespaces -o json": {"items": [{"metadata": {"name": "default"}}]},
            "kubectl get pods -A -o json": {"items": []},
        },
    )
    orch._tool_port = port
    orch._provided_username = ""
    orch._provided_password = ""

    await orch.recon._bootstrap_scan("http://127.0.0.1:6443", port_range="6443,443")

    assert orch._scan_classification.kind.value == "hybrid"
    assert orch._scan_classification.provider == "aws"
    assert len(orch.dkg.query_nodes("K8sCluster")) == 1
    assert len(orch.dkg.query_nodes("EKS")) == 1
    eks_edges = [
        row for row in orch.dkg.query_edges() if row["type"] == "eks_links_k8s_cluster"
    ]
    assert len(eks_edges) == 1
    aws_calls = {
        (params.get("service"), params.get("action"))
        for name, params in port.calls if name == "cloud_discovery_aws"
    }
    assert ("eks", "describe-cluster") in aws_calls
    assert ("ec2", "describe-vpcs") in aws_calls
    assert orch._topology_analysis is not None
