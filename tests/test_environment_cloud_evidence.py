from darwin.dkg import DKG
from darwin.environment import EnvironmentKind, classify_environment
from darwin.rag import DarwinRAG


def test_endpoint_cloud_evidence_enables_cloud_classification():
    dkg = DKG()
    dkg.add_node("Endpoint", "ep-http://localhost:10630/run", {
        "url": "http://localhost:10630/run",
        "sample_response": "inference pod read cluster secrets with node role",
    })

    classification = classify_environment([{
        "port": 10630,
        "service": "Werkzeug httpd",
    }], dkg)

    assert classification.kind is EnvironmentKind.PUBLIC_CLOUD
    assert classification.cloud_enabled is True


def test_discovered_k8s_host_keeps_k8s_knowledge_in_scope():
    """A KIND cluster is a K8s engagement, not a public-cloud one.

    Cluster discovery tags the node host with ``provider=k8s``; without that
    signal the classifier reads the K8s analysis text as public-cloud evidence
    and retrieval drops every K8s knowledge entry.
    """
    dkg = DKG()
    dkg.add_node("Host", "host-k8s-kind-control-plane", {
        "ip": "172.18.0.2", "is_reachable": True, "is_internal": True,
        "provider": "k8s", "k8s_node_name": "kind-control-plane",
    })
    dkg.add_node("Service", "svc-k8s-default-metadata-5000", {
        "port": 5000, "protocol": "tcp", "service_name": "k8s-metadata",
        "k8s_namespace": "default", "cluster_ip": "10.96.202.38",
    })
    dkg.add_node("Analysis", "analysis-k8s-cluster", {
        "phase": "recon", "content": "K8S cluster discovered with 1 node(s)\n3 pod(s) running:",
    })

    classification = classify_environment([], dkg)

    assert classification.kind is EnvironmentKind.HYBRID
    assert classification.cloud_enabled is True
    assert "dkg:k8s-host" in classification.signals
    k8s_entry = {"requires_environment": ["private_cloud", "hybrid"]}
    assert DarwinRAG._environment_allows(k8s_entry, classification.environment_scope)
