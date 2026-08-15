"""Tests for the unified cognition snapshot (O1).

Covers the pure renderer (facts / beliefs / plan / defense / rationale),
the per-task discovery diff, and the snapshot marker contract used by
compression (O3.2).
"""

from types import SimpleNamespace

from darwin.core.belief import (
    SNAPSHOT_MARKER,
    node_ids_by_type,
    render_belief_snapshot,
    render_new_discoveries,
)
from darwin.data_model import (
    EndpointInfo,
    ExploitationPlan,
    PipelineState,
    ServiceInfo,
    VulnerabilityHypothesis,
)
from darwin.dkg import DKG


def _state(**kw) -> PipelineState:
    state = PipelineState()
    for key, value in kw.items():
        setattr(state, key, value)
    return state


def _plan(tasks=None) -> ExploitationPlan:
    return ExploitationPlan(
        plan_id="p1",
        phase="exploit",
        goal="capture flag",
        tasks=tasks or [],
    )


class TestRenderBeliefSnapshot:
    def test_empty_world_returns_empty(self):
        assert render_belief_snapshot(PipelineState()) == ""

    def test_renders_all_sections(self):
        state = _state(
            endpoints=[EndpointInfo(url="http://t/login", method="POST", params=["user"])],
            services=[ServiceInfo(port=8080, protocol="tcp", version="Apache 2.4")],
            credentials=[SimpleNamespace(username="admin", source_host="t")],
            sessions=[{"user": "root", "host": "t", "access_level": "user"}],
            flags=["flag{abc}"],
        )
        vulns = [
            VulnerabilityHypothesis(
                vuln_type="SQLI",
                endpoint="http://t/login",
                param="user",
                confidence=0.7,
                evidence="quote caused error",
                research_cves=["CVE-2020-0001"],
            )
        ]
        defense = SimpleNamespace(waf_type="cloudflare", defense_complexity=0.8)
        rationale = [
            SimpleNamespace(
                task_id="t1",
                goal="probe login",
                hypothesis="SQLI on user",
                evidence=["error observed"],
            )
        ]
        text = render_belief_snapshot(
            state, vulns, _plan(
                [
                    {"id": "t1", "instruction": "probe login",
                     "status": "pending", "dependent_task_ids": []},
                    {"id": "t2", "instruction": "done task", "status": "done"},
                ]
            ),
            defense,
            rationale,
        )

        assert SNAPSHOT_MARKER in text
        assert "Current Cognition" in text
        assert "Flags: flag{abc}" in text
        assert "Services: :8080/tcp Apache 2.4" in text
        assert "POST http://t/login params=user" in text
        assert "Beliefs (vulnerability hypotheses):" in text
        assert "[SQLI] http://t/login param=user conf=70%" in text
        assert "CVE-2020-0001" in text
        assert "Plan: 1/2 done, 0 failed, 1 pending" in text
        assert "Defense: WAF=cloudflare, complexity=0.80" in text
        assert "Preserved rationale" in text

    def test_caps_limit_items(self):
        state = _state(
            endpoints=[EndpointInfo(url=f"http://t/{i}") for i in range(50)],
            services=[ServiceInfo(port=i) for i in range(20)],
        )
        text = render_belief_snapshot(state, compact=False)
        # default endpoint cap is 8, service cap is 6
        assert text.count("http://t/") == 8
        assert text.count("/tcp") == 6

    def test_compact_is_shorter(self):
        state = _state(
            endpoints=[EndpointInfo(url=f"http://t/{i}") for i in range(20)],
            services=[ServiceInfo(port=i, version="x") for i in range(20)],
        )
        full = render_belief_snapshot(state, compact=False)
        compact = render_belief_snapshot(state, compact=True)
        assert full
        assert compact
        assert len(compact) < len(full)

    def test_defense_none_omitted(self):
        state = _state(endpoints=[EndpointInfo(url="http://t/")])
        assert "Defense:" not in render_belief_snapshot(state, defense=None)


class TestDiscoveryDiff:
    def test_node_ids_by_type(self):
        dkg = DKG()
        dkg.add_node("Endpoint", "ep-1", {"url": "http://t/"})
        snap = node_ids_by_type(dkg)
        assert snap["Endpoint"] == {"ep-1"}
        assert snap["Vulnerability"] == set()

    def test_render_new_discoveries_only_new_nodes(self):
        dkg = DKG()
        dkg.add_node("Endpoint", "ep-old", {"url": "http://t/old"})
        dkg.add_node("Vulnerability", "vuln-old", {"vuln_type": "XSS", "endpoint": "http://t/"})
        before = node_ids_by_type(dkg)

        dkg.add_node("Endpoint", "ep-new", {"url": "http://t/new"})
        dkg.add_node("Vulnerability", "vuln-new", {
            "vuln_type": "SQLI", "endpoint": "http://t/login", "parameter": "user",
        })

        text = render_new_discoveries(before, dkg)
        assert "New This Task" in text
        assert "Endpoint (1):" in text
        assert "http://t/new" in text
        assert "Vulnerability (1):" in text
        assert "[SQLI] http://t/login param=user" in text
        assert "http://t/old" not in text

    def test_no_baseline_returns_empty(self):
        dkg = DKG()
        dkg.add_node("Endpoint", "ep-1", {"url": "http://t/"})
        assert render_new_discoveries(None, dkg) == ""

    def test_no_changes_returns_empty(self):
        dkg = DKG()
        dkg.add_node("Endpoint", "ep-1", {"url": "http://t/"})
        before = node_ids_by_type(dkg)
        assert render_new_discoveries(before, dkg) == ""
