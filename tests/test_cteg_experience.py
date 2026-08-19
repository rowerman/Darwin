"""Unit tests for the P13 Execution Memory -> CTEG bridge."""

from types import SimpleNamespace

from darwin.cteg import (
    CTEG,
    BypassPattern,
    ExploitPattern,
    ScenarioProfile,
    build_scenario_profile,
    match_score,
)
from darwin.core.executor import ExecutionResult
from darwin.core.memory import MemoryManager


def result(**overrides):
    base = dict(
        task_id="t1",
        tool="sqlmap_test",
        planned_tool="sqlmap_test",
        adherence=True,
        success=True,
        stdout="injectable: yes",
        stderr="",
        exit_code=0,
        elapsed_ms=10.0,
    )
    base.update(overrides)
    return ExecutionResult(**base)


def test_cteg_record_execution_creates_exploit_pattern(tmp_path):
    cteg = CTEG(storage_path=str(tmp_path / "cteg.json"))
    new_count = cteg.record_execution(result())

    assert new_count >= 1
    assert "ep-sqli-t1" in cteg.graph
    node = cteg.graph.nodes["ep-sqli-t1"]
    assert node["type"] == "ExploitPattern"
    assert node["total_attempts"] == 1
    assert node["total_successes"] == 1


def test_cteg_record_execution_merges_duplicate(tmp_path):
    cteg = CTEG(storage_path=str(tmp_path / "cteg.json"))
    rec = result()
    cteg.record_execution(rec)

    assert cteg.record_execution(rec) == 0  # merged, not a new pattern
    node = cteg.graph.nodes["ep-sqli-t1"]
    assert node["total_attempts"] >= 2
    assert node["total_successes"] >= 2


def test_cteg_record_execution_failure_outcome(tmp_path):
    cteg = CTEG(storage_path=str(tmp_path / "cteg.json"))
    cteg.record_execution(result(success=False, stdout="", stderr="internal error"))

    node = cteg.graph.nodes["ep-sqli-t1"]
    assert node["total_attempts"] == 1
    assert node["total_successes"] == 0


def test_cteg_record_execution_ignores_empty_tool(tmp_path):
    cteg = CTEG(storage_path=str(tmp_path / "cteg.json"))
    assert cteg.record_execution(result(tool="")) == 0
    assert len(list(cteg.graph.nodes)) == 0


def test_cteg_persists_after_record_execution(tmp_path):
    path = str(tmp_path / "cteg.json")
    cteg = CTEG(storage_path=path)
    cteg.record_execution(result())

    reloaded = CTEG(storage_path=path)
    assert "ep-sqli-t1" in reloaded.graph


def test_execution_to_hints_roundtrip(tmp_path):
    """P15 G3 closure: ExecutionRecord -> CTEG pattern -> next-round hints."""
    cteg = CTEG(storage_path=str(tmp_path / "cteg.json"))
    manager = MemoryManager(experience=cteg)
    manager.record_execution(result())  # sqlmap_test success -> shared

    hints = manager.experience_hints(vuln_type="sqli")
    strategies = hints.get("exploit_strategies") or []
    assert any(s.get("mechanism") == "sqlmap_test" for s in strategies)


# ── P4 scenario matching ───────────────────────────────────────────


def _bypass(**kw):
    base = dict(
        pattern_id="bp-1",
        mechanism="double_encode",
        abstract_description="double URL encoding",
        applicable_defense_types=[],
        applicable_vuln_types=[],
    )
    base.update(kw)
    return BypassPattern(**base)


def _exploit(**kw):
    base = dict(
        pattern_id="ep-1",
        mechanism="sqlmap_test",
        abstract_description="sql injection via sqlmap",
        vulnerability_type="sqli",
    )
    base.update(kw)
    return ExploitPattern(**base)


def test_match_score_exact_primary_match_passes_gate():
    profile = ScenarioProfile(vuln_types={"sqli"}, defense_types={"waf"})
    pat = _bypass(applicable_defense_types=["waf"], applicable_vuln_types=["sqli"])
    assert match_score(pat, profile) >= 0.5


def test_match_score_vuln_only_passes_and_tech_only_fails():
    profile = ScenarioProfile(
        vuln_types={"sqli"}, tech_stack={"wordpress"}, domains=set()
    )
    vuln_only = _bypass(applicable_vuln_types=["sqli"])
    assert match_score(vuln_only, profile) >= 0.5
    tech_only = _exploit(vulnerability_type="xss", technology_stack=["wordpress"])
    assert match_score(tech_only, profile) < 0.5


def test_match_score_any_wildcard_counts_only_when_dimension_present():
    no_defense = ScenarioProfile(vuln_types={"sqli"})
    pat = _bypass(applicable_defense_types=["any"], applicable_vuln_types=["sqli"])
    assert match_score(pat, no_defense) == 1.0  # vuln exact + "any" def ignored
    with_defense = ScenarioProfile(vuln_types={"sqli"}, defense_types={"waf"})
    assert match_score(pat, with_defense) == 1.5  # +0.5 wildcard defense


def test_tech_stack_boosts_exploit_pattern():
    profile = ScenarioProfile(vuln_types={"sqli"}, tech_stack={"wordpress"})
    pat = _exploit(technology_stack=["wordpress"])
    assert match_score(pat, profile) > 1.0


def test_get_suggestions_gates_unrelated_patterns(tmp_path):
    cteg = CTEG(storage_path=str(tmp_path / "cteg.json"))
    cteg.add_exploit_pattern(_exploit(pattern_id="ep-sqli"))
    cteg.add_exploit_pattern(_exploit(pattern_id="ep-xss", vulnerability_type="xss"))

    hints = cteg.get_suggestions(profile=ScenarioProfile(vuln_types={"sqli"}))
    assert len(hints["exploit_strategies"]) == 1
    assert hints["exploit_strategies"][0]["mechanism"] == "sqlmap_test"
    assert hints["exploit_strategies"][0]["overlap"] >= 0.5


def test_get_suggestions_no_match_returns_empty(tmp_path):
    cteg = CTEG(storage_path=str(tmp_path / "cteg.json"))
    cteg.add_exploit_pattern(_exploit(vulnerability_type="xss"))
    hints = cteg.get_suggestions(profile=ScenarioProfile(vuln_types={"sqli"}))
    assert hints == {"bypass_strategies": [], "exploit_strategies": []}


def test_get_suggestions_legacy_scalars_backward_compatible(tmp_path):
    cteg = CTEG(storage_path=str(tmp_path / "cteg.json"))
    cteg.add_exploit_pattern(_exploit())
    hints = cteg.get_suggestions(vuln_type="sqli")
    assert hints["exploit_strategies"]
    assert hints["exploit_strategies"][0]["overlap"] >= 0.5


def test_get_suggestions_top_k_caps_results(tmp_path):
    cteg = CTEG(storage_path=str(tmp_path / "cteg.json"))
    for i in range(5):
        cteg.add_exploit_pattern(
            _exploit(pattern_id=f"ep-{i}", mechanism=f"m{i}")
        )
    hints = cteg.get_suggestions(profile=ScenarioProfile(vuln_types={"sqli"}), top_k=2)
    assert len(hints["exploit_strategies"]) == 2


def test_build_scenario_profile_from_state():
    state = SimpleNamespace(
        vulnerabilities=[SimpleNamespace(vuln_type="SQLI")],
        services=[
            SimpleNamespace(port=80, protocol="tcp", version="Apache WordPress", banner="")
        ],
        analysis_notes=["WordPress 6.7 detected on /wp-login"],
        endpoints=[],
        credentials=[],
        flags=[],
        sessions=[],
        hosts=[],
        domains=[],
    )
    defense = SimpleNamespace(waf_type="Cloudflare")
    profile = build_scenario_profile(state, [], defense)
    assert "sqli" in profile.vuln_types
    assert "cloudflare" in profile.defense_types
    assert "wordpress" in profile.tech_stack
    assert "web" in profile.domains


def test_build_scenario_profile_tolerates_broken_inputs():
    profile = build_scenario_profile(None, None, None)
    assert isinstance(profile, ScenarioProfile)
    assert not profile.vuln_types and not profile.defense_types
