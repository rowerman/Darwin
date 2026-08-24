from darwin.dkg import DKG
from darwin.environment import EnvironmentKind, classify_environment


def test_web_db_classification_does_not_enable_cloud():
    result = classify_environment([{"port": 80, "service": "http", "version": "nginx"}])
    assert result.kind is EnvironmentKind.WEB_DB
    assert result.cloud_enabled is False


def test_k8s_and_public_signals_classify_hybrid():
    result = classify_environment([
        {"port": 6443, "service": "kubernetes", "version": "api"},
        {"port": 443, "service": "aws", "version": "eks"},
    ])
    assert result.kind is EnvironmentKind.HYBRID
    assert result.cloud_enabled is True
    assert result.provider == "aws"


def test_dkg_cloud_nodes_classify_public_cloud():
    dkg = DKG()
    dkg.add_node("IAMRole", "role-a", {"name": "read-only", "provider": "aws"})
    result = classify_environment([], dkg)
    assert result.kind is EnvironmentKind.PUBLIC_CLOUD
    assert result.cloud_enabled is True
