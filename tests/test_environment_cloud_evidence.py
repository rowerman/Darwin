from darwin.dkg import DKG
from darwin.environment import EnvironmentKind, classify_environment


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
