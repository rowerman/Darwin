"""Tests for dynamic_scaling module — complexity hints and seed_votes."""

import pytest
from darwin.dkg import DKG
from darwin.dynamic_scaling import (
    DynamicScalingEngine,
    ScalingLevel,
    detect_complexity_hints,
    compute_task_breadth,
)
from darwin.dpm import DefenseStateVector


def _make_dkg_with_services(ports: list[int]) -> DKG:
    """Helper: create a DKG with a host and the given service ports."""
    dkg = DKG()
    dkg.add_node("Host", "host1", {"ip": "10.0.0.1"})
    for port in ports:
        dkg.add_node("Service", f"svc_{port}",
                     {"port": port, "service_name": f"svc-{port}"})
    return dkg


def _make_defense(complexity: float = 0.0) -> DefenseStateVector:
    """Helper: create a DefenseStateVector with given complexity."""
    return DefenseStateVector(defense_complexity=complexity)


class TestDetectComplexityHints:
    """Tests for detect_complexity_hints()."""

    def test_empty_dkg_returns_none(self):
        """Empty DKG — no complexity signal, return None."""
        dkg = DKG()
        result = detect_complexity_hints(dkg)
        assert result is None

    def test_single_service_returns_none(self):
        """Single service — too simple for hints, return None."""
        dkg = _make_dkg_with_services([80])
        result = detect_complexity_hints(dkg)
        assert result is None

    def test_two_services_returns_none(self):
        """2 services — borderline, let hysteresis decide."""
        dkg = _make_dkg_with_services([80, 443])
        result = detect_complexity_hints(dkg)
        assert result is None

    def test_three_services_returns_none(self):
        """3 services — still borderline without other indicators."""
        dkg = _make_dkg_with_services([80, 443, 8080])
        result = detect_complexity_hints(dkg)
        assert result is None

    def test_four_services_returns_coordinated(self):
        """4 services — clear multi-service target."""
        dkg = _make_dkg_with_services([80, 443, 8080, 3306])
        result = detect_complexity_hints(dkg)
        assert result == "coordinated"

    def test_six_services_returns_distributed(self):
        """6 services — large target, distributed."""
        dkg = _make_dkg_with_services([80, 443, 8080, 3306, 5432, 6379])
        result = detect_complexity_hints(dkg)
        assert result == "distributed"

    def test_ad_ports_returns_coordinated(self):
        """AD ports (445+389) — immediate coordinated regardless of count."""
        dkg = _make_dkg_with_services([445, 389])
        result = detect_complexity_hints(dkg)
        assert result == "coordinated"

    def test_ad_domain_node_returns_coordinated(self):
        """Domain node in DKG — immediate coordinated."""
        dkg = _make_dkg_with_services([80])
        dkg.add_node("Domain", "test.local", {"domain_name": "test.local"})
        result = detect_complexity_hints(dkg)
        assert result == "coordinated"

    def test_k8s_api_port_returns_coordinated(self):
        """K8s API server port (6443) — immediate coordinated."""
        dkg = _make_dkg_with_services([6443, 10250])
        result = detect_complexity_hints(dkg)
        assert result == "coordinated"

    def test_kubelet_port_returns_coordinated(self):
        """Kubelet port (10250) alone — immediate coordinated."""
        dkg = _make_dkg_with_services([10250, 80])
        result = detect_complexity_hints(dkg)
        assert result == "coordinated"

    def test_multi_host_with_creds_returns_coordinated(self):
        """Multiple hosts + credentials — coordinated."""
        dkg = _make_dkg_with_services([80, 22])
        dkg.add_node("Host", "host2", {"ip": "10.0.0.2", "is_internal": True})
        dkg.add_node("Credential", "cred1",
                     {"username": "admin", "password": "test", "service": "ssh"})
        result = detect_complexity_hints(dkg)
        assert result == "coordinated"

    def test_defense_plus_three_services_returns_coordinated(self):
        """Defense present + 3 services — coordinated."""
        dkg = _make_dkg_with_services([80, 443, 8080])
        defense = _make_defense(complexity=0.5)
        result = detect_complexity_hints(dkg, defense)
        assert result == "coordinated"

    def test_defense_low_complexity_ignored(self):
        """Defense complexity <= 0.1 — ignored."""
        dkg = _make_dkg_with_services([80, 443, 8080])
        defense = _make_defense(complexity=0.05)
        result = detect_complexity_hints(dkg, defense)
        assert result is None

    def test_none_defense_state(self):
        """None defense_state with 3 services — still borderline."""
        dkg = _make_dkg_with_services([80, 443, 8080])
        result = detect_complexity_hints(dkg, None)
        assert result is None

    def test_non_int_ports_handled(self):
        """Non-integer port values should not crash."""
        dkg = DKG()
        dkg.add_node("Host", "host1", {"ip": "10.0.0.1"})
        dkg.add_node("Service", "svc1", {"port": "http", "service_name": "web"})
        dkg.add_node("Service", "svc2", {"port": "ssh", "service_name": "ssh"})
        dkg.add_node("Service", "svc3", {"port": "mysql", "service_name": "db"})
        dkg.add_node("Service", "svc4", {"port": "redis", "service_name": "cache"})
        result = detect_complexity_hints(dkg)
        # 4 services, even with non-int ports -> coordinated
        assert result == "coordinated"

    def test_missing_port_field(self):
        """Services without port field should be counted but not crash."""
        dkg = DKG()
        dkg.add_node("Host", "host1", {"ip": "10.0.0.1"})
        dkg.add_node("Service", "svc1", {"service_name": "web"})
        dkg.add_node("Service", "svc2", {"service_name": "ssh"})
        dkg.add_node("Service", "svc3", {"service_name": "db"})
        dkg.add_node("Service", "svc4", {"service_name": "cache"})
        result = detect_complexity_hints(dkg)
        # 4 services -> coordinated
        assert result == "coordinated"


class TestSeedVotes:
    """Tests for DynamicScalingEngine.seed_votes()."""

    def test_seed_votes_prefills_queue(self):
        """seed_votes should pre-fill the vote queue."""
        engine = DynamicScalingEngine(hysteresis=2)
        engine.seed_votes("coordinated")
        assert len(engine._level_votes) == 2
        assert all(v == ScalingLevel.COORDINATED for v in engine._level_votes)

    def test_seed_votes_distributed(self):
        """seed_votes with distributed level."""
        engine = DynamicScalingEngine(hysteresis=2)
        engine.seed_votes("distributed")
        assert all(v == ScalingLevel.DISTRIBUTED for v in engine._level_votes)

    def test_seed_votes_solo(self):
        """seed_votes with solo level (no-op effectively)."""
        engine = DynamicScalingEngine(hysteresis=2)
        engine.seed_votes("solo")
        assert all(v == ScalingLevel.SOLO for v in engine._level_votes)
        # current_level stays SOLO (was already SOLO)
        assert engine.current_level == ScalingLevel.SOLO

    def test_seed_then_decide_matching(self):
        """When seeded votes match decide()'s target, should switch immediately."""
        engine = DynamicScalingEngine(hysteresis=2)
        engine.seed_votes("coordinated")

        # Create a DKG that yields B >= 0.3 (coordinated territory):
        # AD ports (env_complexity=1.0) + services
        dkg = _make_dkg_with_services([445, 389, 80, 443])
        level = engine.decide(dkg)
        # N_norm=4/6=0.667, env_complexity=1.0 → B=0.28*0.667+0.18*1.0=0.367
        # Seeded COORDINATED + target COORDINATED → switch
        assert level == ScalingLevel.COORDINATED
        assert engine.current_level == ScalingLevel.COORDINATED

    def test_seed_then_decide_mismatch(self):
        """When seeded votes don't match decide() target, should NOT switch."""
        engine = DynamicScalingEngine(hysteresis=2)
        engine.seed_votes("coordinated")

        # Create a DKG that yields B < 0.3 (solo territory)
        dkg = _make_dkg_with_services([80])
        level = engine.decide(dkg)
        # Votes disagree (COORDINATED + SOLO), no switch
        assert level == ScalingLevel.SOLO
        assert engine.current_level == ScalingLevel.SOLO

    def test_no_seed_first_decide_stays_solo(self):
        """Without seed_votes, first decide() stays SOLO (hysteresis=2)."""
        engine = DynamicScalingEngine(hysteresis=2)
        dkg = _make_dkg_with_services([80, 443, 8080, 3306])
        level = engine.decide(dkg)
        # First vote only — hysteresis not yet met
        assert level == ScalingLevel.SOLO
        assert engine.current_level == ScalingLevel.SOLO

    def test_seed_votes_idempotent(self):
        """Calling seed_votes twice should just overwrite."""
        engine = DynamicScalingEngine(hysteresis=2)
        engine.seed_votes("coordinated")
        engine.seed_votes("distributed")
        assert all(v == ScalingLevel.DISTRIBUTED for v in engine._level_votes)

    def test_seed_votes_invalid_level_raises(self):
        """Invalid level string should raise ValueError."""
        engine = DynamicScalingEngine(hysteresis=2)
        with pytest.raises(ValueError):
            engine.seed_votes("nonexistent")


class TestComputeTaskBreadthWithComplexity:
    """Verify compute_task_breadth works correctly with various inputs."""

    def test_single_service_low_B(self):
        """Single HTTP service should yield B < 0.3 (solo)."""
        dkg = _make_dkg_with_services([80])
        B = compute_task_breadth(dkg)
        # N_norm = 1/6 ≈ 0.167, no other factors → B ≈ 0.28 * 0.167 = 0.047
        assert B < 0.3

    def test_four_services_B(self):
        """4 services should yield moderate B."""
        dkg = _make_dkg_with_services([80, 443, 8080, 3306])
        B = compute_task_breadth(dkg)
        # N_norm = 4/6 ≈ 0.667 → B ≈ 0.28 * 0.667 = 0.187
        assert 0.10 < B < 0.35

    def test_ad_environment_high_B(self):
        """AD ports should push B high via env_complexity."""
        dkg = _make_dkg_with_services([445, 389, 80])
        B = compute_task_breadth(dkg)
        # N_norm = 3/6=0.5, env_complexity=1.0 → B = 0.28*0.5 + 0.18*1.0 = 0.32
        assert B >= 0.30

    def test_k8s_environment_B(self):
        """K8s ports should push B via env_complexity=0.8."""
        dkg = _make_dkg_with_services([6443, 10250, 80])
        B = compute_task_breadth(dkg)
        # N_norm = 3/6=0.5, env_complexity=0.8 → B = 0.28*0.5 + 0.18*0.8 = 0.284
        assert B > 0.20

    def test_defense_increases_B(self):
        """Defense presence should increase B."""
        dkg = _make_dkg_with_services([80, 443, 8080])
        defense = _make_defense(complexity=0.5)
        B_with = compute_task_breadth(dkg, defense)
        B_without = compute_task_breadth(dkg)
        assert B_with >= B_without
