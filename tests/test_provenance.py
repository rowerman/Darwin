"""P15 G2: DKG provenance consumption tests."""

import pytest


@pytest.mark.asyncio
async def test_provenance_summary_format(fake_llm, fake_gateway, make_orchestrator):
    orch = make_orchestrator(fake_llm(), fake_gateway({}), fake_gateway({}))
    orch.dkg.add_node(
        "Credential",
        "c1",
        {"username": "admin", "host": "x"},
        source="partial_success",
        evidence="auth ok",
    )
    orch.dkg.add_node(  # legacy flat source fallback
        "Credential", "c2", {"username": "legacy", "host": "x"}, source="cteg_memory"
    )
    orch.dkg.add_node("Endpoint", "e1", {"url": "http://x/login"})  # no provenance

    summary = orch.provenance_summary()

    assert "source: partial_success" in summary
    assert "evidence: auth ok" in summary
    assert "source: cteg_memory" in summary
    assert "source: unknown" in summary
    assert "[Credential] admin" in summary
    assert "[Endpoint] http://x/login" in summary


@pytest.mark.asyncio
async def test_provenance_summary_caps_and_orders(
    fake_llm, fake_gateway, make_orchestrator
):
    orch = make_orchestrator(fake_llm(), fake_gateway({}), fake_gateway({}))
    for i in range(12):
        orch.dkg.add_node("Credential", f"c{i}", {"username": f"u{i}", "host": "x"})
    orch.dkg.add_node(
        "Credential",
        "real",
        {"username": "u-real", "host": "x"},
        source="ssh_exec",
        evidence="login ok",
    )

    summary = orch.provenance_summary(max_items=5)

    rows = [l for l in summary.splitlines() if l.startswith("- [Credential]")]
    assert len(rows) <= 5
    # Provenanced facts sort first.
    assert summary.splitlines()[0].startswith("- [Credential] u-real (source: ssh_exec)")
