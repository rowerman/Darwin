"""Dynamic Scaling Engine — B dimension + TDI'' + scaling state machine.

Reference: pentestgpt_v2 TDA-EGATS (difficulty-aware MCTS)
           DARWIN framework spec — B = 0.4*N_norm + 0.3*M_domain + 0.3*L_move
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

from darwin.dkg import DKG
from darwin.dpm import DefenseStateVector


class ScalingLevel(str, Enum):
    """Dynamic scaling levels."""
    SOLO = "solo"                # 0 sub-agents, Orchestrator handles everything
    COORDINATED = "coordinated"   # 1-2 sub-agents
    DISTRIBUTED = "distributed"   # 3+ sub-agents


@dataclass
class TDAState:
    """Task Difficulty Assessment state.

    Reference: pentestgpt_v2 TDI formula, extended with D (Defense) and B (Breadth).
    TDI'' = 0.20*H + 0.20*(1-E) + 0.10*C + 0.10*(1-S) + 0.15*D + 0.25*B
    """
    H: float = 0.5   # Horizon: estimated remaining steps (0-1)
    E: float = 0.3   # Evidence confidence (0-1)
    C: float = 0.0   # Context load (0-1)
    S: float = 0.5   # Historical success rate (0-1)
    D: float = 0.0   # Defense complexity (0-1)
    B: float = 0.0   # Task breadth (0-1) — NEW dimension

    history_H: List[float] = field(default_factory=list)
    history_E: List[float] = field(default_factory=list)
    observation_count: int = 0

    @property
    def tdi(self) -> float:
        """Compute TDI'' value."""
        return (
            0.20 * self.H
            + 0.20 * (1.0 - self.E)
            + 0.10 * self.C
            + 0.10 * (1.0 - self.S)
            + 0.15 * self.D
            + 0.25 * self.B
        )

    def update_horizon(self, estimated_remaining_steps: int, max_steps: int = 50):
        """Update horizon estimate with EMA smoothing."""
        raw_H = min(estimated_remaining_steps / max_steps, 1.0)
        if self.history_H:
            self.H = 0.7 * raw_H + 0.3 * self.history_H[-1]
        else:
            self.H = raw_H
        self.history_H.append(self.H)

    def update_evidence(self, new_confidence: float):
        """Update evidence confidence with EMA."""
        if self.history_E:
            self.E = 0.7 * new_confidence + 0.3 * self.history_E[-1]
        else:
            self.E = new_confidence
        self.history_E.append(self.E)

    def update_context_load(self, token_count: int, max_tokens: int = 180000):
        """Update context load ratio."""
        self.C = min(token_count / max_tokens, 1.0)

    def update_success_rate(self, successes: int, attempts: int):
        """Update historical success rate with Laplace smoothing."""
        alpha = 1.0
        self.S = (successes + alpha) / (attempts + 2 * alpha)

    def update_defense_complexity(self, defense_state: DefenseStateVector):
        """Update defense complexity from DPM."""
        self.D = defense_state.defense_complexity

    def update_breadth(self, dkg: DKG):
        """Update task breadth from DKG topology."""
        self.B = compute_task_breadth(dkg)

    def update_all(
        self,
        estimated_remaining_steps: int = 25,
        evidence_confidence: float = 0.5,
        token_count: int = 0,
        successes: int = 0,
        attempts: int = 1,
        defense_state: DefenseStateVector | None = None,
        dkg: DKG | None = None,
    ):
        """Update all TDA dimensions at once."""
        self.update_horizon(estimated_remaining_steps)
        self.update_evidence(evidence_confidence)
        self.update_context_load(token_count)
        self.update_success_rate(successes, attempts)
        if defense_state:
            self.update_defense_complexity(defense_state)
        if dkg:
            self.update_breadth(dkg)
        self.observation_count += 1

    def summary(self) -> str:
        return (
            f"TDI''={self.tdi:.3f} "
            f"(H={self.H:.2f} E={self.E:.2f} C={self.C:.2f} "
            f"S={self.S:.2f} D={self.D:.2f} B={self.B:.2f})"
        )


def compute_task_breadth(dkg: DKG) -> float:
    """Compute B (Task Breadth) from current DKG state.

    B = 0.4 * N_norm + 0.3 * M_domain + 0.3 * L_move

    Reference: DARWIN framework spec — DKG topology drives scaling decisions.
    """
    hosts = dkg.query_nodes("Host")
    domains = dkg.query_nodes("Domain")
    credentials = dkg.query_nodes("Credential")

    n_targets = len(hosts)
    is_multi_domain = len(domains) > 1

    # Detect lateral movement need: internal hosts + available credentials
    internal_hosts = [h for h in hosts if h.get("is_internal", False)]
    needs_lateral = len(internal_hosts) > 0 and len(credentials) > 0

    N_norm = min(n_targets / 5.0, 1.0)
    M_domain = 1.0 if is_multi_domain else 0.0
    L_move = 1.0 if needs_lateral else 0.0

    return 0.4 * N_norm + 0.3 * M_domain + 0.3 * L_move


class DynamicScalingEngine:
    """Dynamic scaling decision engine.

    Determines whether to run in Solo, Coordinated, or Distributed mode
    based on Task Breadth (B) and overall task difficulty (TDI'').

    Transition rules:
      B < 0.3           → SOLO (0 sub-agents)
      0.3 ≤ B < 0.6     → COORDINATED (1-2 sub-agents)
      B ≥ 0.6           → DISTRIBUTED (3+ sub-agents)

    Smoothing: requires 2 consecutive assessments to agree before switching,
    preventing oscillation at boundary B values.
    """

    def __init__(self, hysteresis: int = 2):
        self.current_level = ScalingLevel.SOLO
        self.tda = TDAState()
        self._level_votes: List[ScalingLevel] = []
        self.hysteresis = hysteresis

    def decide(self, dkg: DKG, defense_state: DefenseStateVector | None = None) -> ScalingLevel:
        """Decide scaling level based on current state."""
        # Compute B from DKG
        B = compute_task_breadth(dkg)
        self.tda.B = B

        # Update defense complexity
        if defense_state:
            self.tda.D = defense_state.defense_complexity

        # Determine target level
        if B < 0.3:
            target = ScalingLevel.SOLO
        elif B < 0.6:
            target = ScalingLevel.COORDINATED
        else:
            target = ScalingLevel.DISTRIBUTED

        # Apply hysteresis
        self._level_votes.append(target)
        if len(self._level_votes) > self.hysteresis:
            self._level_votes.pop(0)

        # Only switch if all recent votes agree
        if len(self._level_votes) >= self.hysteresis and all(
            v == target for v in self._level_votes
        ):
            self.current_level = target

        return self.current_level

    def get_recommended_agent_count(self, level: ScalingLevel | None = None) -> tuple[int, List[str]]:
        """Get recommended number and types of sub-agents.

        Returns:
            (count, agent_types) — e.g., (2, ["recon", "exploit"])
        """
        lvl = level or self.current_level

        if lvl == ScalingLevel.SOLO:
            return 0, []

        elif lvl == ScalingLevel.COORDINATED:
            # 1-2 agents: recon + exploit most valuable first
            hosts = self._get_host_count()
            if hosts > 1:
                return 2, ["recon", "exploit"]
            return 1, ["exploit"]

        else:  # DISTRIBUTED
            # 3+ agents: recon + exploit + pivot/ad/persist as needed
            agent_types = ["recon", "exploit"]
            if self.tda.B > 0.7:
                agent_types.append("pivot")
            if self.tda.D > 0.5:
                agent_types.append("exploit")  # dedicated bypass agent
            return len(agent_types), agent_types

    def _get_host_count(self) -> int:
        """Get current host count (placeholder — actual count from DKG)."""
        return 1  # Will be overridden with actual DKG query

    def reset(self):
        """Reset scaling engine state for a new task."""
        self.current_level = ScalingLevel.SOLO
        self.tda = TDAState()
        self._level_votes = []


# ── Collaboration Detection ─────────────────────────────────────────

@dataclass
class CollaborationOpportunity:
    """A detected opportunity for cross-agent collaboration."""
    opportunity_type: str  # "credential_reuse", "new_internal_host", "vuln_cross_reference"
    source_agent: str
    target_agent: str
    description: str
    confidence: float
    dkg_evidence: Dict[str, Any] = field(default_factory=dict)


def scan_collaboration_opportunities(dkg: DKG) -> List[CollaborationOpportunity]:
    """Scan DKG for cross-agent collaboration opportunities.

    Called periodically by the Orchestrator (every ~5 cycles) to detect
    patterns that require agent coordination:
    1. New credentials → can they be reused on other hosts?
    2. New sessions → do they reveal previously unreachable hosts?
    3. Cross-vulnerability patterns → does Agent-A's finding help Agent-B?
    """
    opportunities = []

    credentials = dkg.query_nodes("Credential")
    sessions = dkg.query_nodes("Session")
    hosts = dkg.query_nodes("Host")
    vulnerabilities = dkg.query_nodes("Vulnerability")

    # 1. Credential reuse opportunity
    if credentials and len(hosts) > 1:
        unreached_hosts = [h for h in hosts if not h.get("is_reachable", True)]
        if unreached_hosts:
            opportunities.append(CollaborationOpportunity(
                opportunity_type="credential_reuse",
                source_agent="exploit",
                target_agent="pivot",
                description=f"Credentials available for {len(unreached_hosts)} unreached hosts",
                confidence=0.7,
                dkg_evidence={"credentials": len(credentials), "unreached": len(unreached_hosts)},
            ))

    # 2. New internal host discovery via session
    if sessions:
        for session in sessions:
            session_host = session.get("host", "")
            # Check if this session reveals new network access
            if session.get("access_level") in ("root", "admin", "system"):
                opportunities.append(CollaborationOpportunity(
                    opportunity_type="new_internal_host",
                    source_agent="exploit",
                    target_agent="recon",
                    description=f"High-privilege session on {session_host} — scan for internal hosts",
                    confidence=0.8,
                    dkg_evidence={"session_host": session_host},
                ))

    # 3. Cross-vulnerability patterns
    if len(vulnerabilities) >= 2:
        vuln_types = [v.get("type") for v in vulnerabilities]
        # Check for complementary vulnerability chains
        if "SQLi" in vuln_types and "FileUpload" in vuln_types:
            opportunities.append(CollaborationOpportunity(
                opportunity_type="vuln_cross_reference",
                source_agent="exploit_sqli",
                target_agent="exploit_upload",
                description="SQLi credentials could enable authenticated file upload exploitation",
                confidence=0.5,
                dkg_evidence={"vuln_types": vuln_types},
            ))

    return opportunities


# ── Scaling Level Display ───────────────────────────────────────────

def format_scaling_decision(
    level: ScalingLevel, B: float, tdi: float, agent_count: int, agent_types: List[str]
) -> str:
    """Format scaling decision for logging/display."""
    return (
        f"[SCALING] Level={level.value.upper()} | B={B:.2f} | TDI''={tdi:.3f} | "
        f"Agents={agent_count}({','.join(agent_types) if agent_types else 'none'})"
    )
