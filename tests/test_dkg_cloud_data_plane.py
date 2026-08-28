"""Regression coverage for cloud data-plane DKG facts."""

from darwin.cloud_attack_path import compute_attack_paths
from darwin.cloud_topology import CloudTopology, CloudTopologyMapper
from darwin.dkg import DKG


def test_imds_mapper_persists_credential_and_redacts_prompt_views():
    dkg = DKG()
    topology = CloudTopology(iam_roles=[{
        "role_name": "ec2-role",
        "account_id": "123456789012",
        "access_key_id": "AKIAEXAMPLE",
        "secret_access_key": "secret-value",
        "session_token": "session-value",
        "expiration": "2026-08-28T13:24:40Z",
        "provider": "aws",
        "source": "imds",
        "imds_version": 1,
    }])

    CloudTopologyMapper(dkg)._write_to_dkg(topology)

    credential = dkg.get_node("credential-imds-ec2-role")
    assert credential["secret_access_key"] == "secret-value"
    assert credential["session_token"] == "session-value"
    assert dkg.query_edges(edge_type="credential_for_role")[0]["to"] == "iam-role-ec2-role"
    snapshot = dkg.topology_snapshot(anchor_ids=["credential-imds-ec2-role"], max_hops=1)
    rendered = str(snapshot)
    assert "secret-value" not in rendered
    assert "session-value" not in rendered
    assert "<redacted>" in rendered


def test_cloud_data_plane_path_follows_imds_credential_to_flag():
    dkg = DKG()
    dkg.add_node("Endpoint", "ep-fetch", {"url": "/fetch?url={url}"})
    dkg.add_node("Vulnerability", "vuln-ssrf", {"vuln_type": "SSRF", "endpoint": "/fetch"})
    dkg.add_node("Credential", "cred-imds", {"username": "ec2-role", "type": "aws_temporary_credentials"})
    dkg.add_node("IAMRole", "role-ec2", {"name": "ec2-role"})
    dkg.add_node("IAMPolicy", "policy-s3", {"name": "s3-read"})
    dkg.add_node("S3", "s3-protected", {"BucketName": "protected"})
    dkg.add_node("Flag", "flag-1", {"value": "flag{cloud-01-imds-s3}", "verified": True})
    dkg.add_edge("ep-fetch", "vuln-ssrf", "endpoint_has_vuln")
    dkg.add_edge("cred-imds", "role-ec2", "credential_for_role")
    dkg.add_edge("role-ec2", "policy-s3", "role_has_policy")
    dkg.add_edge("policy-s3", "s3-protected", "policy_grants_resource")
    dkg.add_edge("s3-protected", "flag-1", "resource_contains")

    report = compute_attack_paths(dkg)
    paths = [path for path in report.paths if path.category == "cloud_data_plane"]
    assert len(paths) == 1
    assert paths[0].confidence == 0.95
    assert "IMDS credentials" in paths[0].description


def test_docker_cloud_evidence_links_url_fetcher_to_imds():
    dkg = DKG()
    dkg.add_node("Host", "host-target", {"ip": "169.254.0.10"})
    dkg.add_node("Service", "svc-target-10601", {"port": 10601})
    dkg.add_node("Endpoint", "ep-root", {
        "url": "http://target/",
        "sample_response": "<h1>Cloud Dashboard</h1>",
    })
    dkg.add_node("Endpoint", "ep-fetch", {
        "url": "http://target/fetch", "params": "url",
    })
    dkg.add_edge("host-target", "svc-target-10601", "host_has_service")
    dkg.add_edge("host-target", "ep-root", "host_has_endpoint")
    dkg.add_edge("host-target", "ep-fetch", "host_has_endpoint")

    CloudTopologyMapper(dkg)._write_docker_cloud_evidence()

    assert dkg.get_node("host-imds-169.254.169.254")
    assert dkg.query_edges(edge_type="host_reaches_host")[0]["to"] == "host-imds-169.254.169.254"
    assert dkg.query_edges(edge_type="service_calls_service")[0]["to"] == "service-imds-http"
