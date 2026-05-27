"""Dynamic Scaling Engine — B dimension + TDI'' + scaling state machine.

Reference: pentestgpt_v2 TDA-EGATS (difficulty-aware MCTS)
           DARWIN framework spec — B = 0.28*N_norm + 0.12*M_domain + 0.18*L_move
           + 0.18*V_diversity + 0.14*D_present + 0.10*env_complexity
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

    def update_breadth(self, dkg: DKG, defense_state: DefenseStateVector | None = None):
        """Update task breadth from DKG topology and defense state."""
        self.B = compute_task_breadth(dkg, defense_state)

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
            self.update_breadth(dkg, defense_state)
        self.observation_count += 1

    def summary(self) -> str:
        return (
            f"TDI''={self.tdi:.3f} "
            f"(H={self.H:.2f} E={self.E:.2f} C={self.C:.2f} "
            f"S={self.S:.2f} D={self.D:.2f} B={self.B:.2f})"
        )


def compute_task_breadth(dkg: DKG, defense_state: DefenseStateVector | None = None) -> float:
    """Compute B (Task Breadth) from current DKG state.

    B = 0.28*N_norm + 0.12*M_domain + 0.18*L_move
      + 0.18*V_diversity + 0.14*D_present + 0.18*env_complexity

    N_norm uses service (port) count rather than host count so multi-port
    single-host targets (e.g. HTTP+SSH+MySQL+LDAP) score higher.
    env_complexity = 1.0 for AD (SMB+LDAP), 0.8 for cloud (K8s API),
    weighted at 0.18 to reliably push single-host AD/cloud into Coordinated.
    """
    hosts = dkg.query_nodes("Host")
    domains = dkg.query_nodes("Domain")
    credentials = dkg.query_nodes("Credential")
    vulnerabilities = dkg.query_nodes("Vulnerability")
    services = dkg.query_nodes("Service")

    n_services = len(services)
    n_targets = len(hosts)
    is_multi_domain = len(domains) > 1

    # Detect lateral movement need:
    # - internal hosts discovered by PivotAgent + available credentials, OR
    # - multiple hosts with credentials (potential lateral move before internal scan)
    internal_hosts = [h for h in hosts if h.get("is_internal", False)]
    needs_lateral = (
        (len(internal_hosts) > 0 and len(credentials) > 0)
        or (len(hosts) > 1 and len(credentials) > 0)
    )

    # N_norm uses service count to reward multi-port/multi-service targets
    N_norm = min(n_services / 6.0, 1.0) if n_services > 0 else min(n_targets / 5.0, 1.0)
    M_domain = 1.0 if is_multi_domain else 0.0
    L_move = 1.0 if needs_lateral else 0.0

    # Vulnerability diversity: count unique vuln types in DKG
    vuln_types: set[str] = set()
    for v in vulnerabilities:
        vt = v.get("vuln_type") or v.get("type") or ""
        if vt:
            vuln_types.add(vt.lower())
    V_diversity = min(len(vuln_types) / 5.0, 1.0)

    # Defense presence: 1.0 if WAF/Honey/Trap detected
    D_present = 0.0
    if defense_state is not None:
        D_present = 1.0 if defense_state.defense_complexity > 0.1 else 0.0

    # Environment complexity boost: AD/cloud environments trigger higher B
    is_ad = bool(domains) or any(
        s.get("port") in (445, 389, 636, 3268, 3269) for s in dkg.query_nodes("Service")
    )
    is_cloud = any(
        s.get("port") in (6443, 10250, 10255) for s in dkg.query_nodes("Service")
    )
    env_complexity = 0.0
    if is_ad: env_complexity = 1.0   # AD requires multi-agent
    elif is_cloud: env_complexity = 0.8  # K8s benefits from coordination

    # B with environment-aware boost
    b_raw = (
        0.28 * N_norm
        + 0.12 * M_domain
        + 0.18 * L_move
        + 0.18 * V_diversity
        + 0.14 * D_present
        + 0.18 * env_complexity
    )

    return min(b_raw, 1.0)


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
        # Compute B from DKG (now includes vuln diversity + defense presence)
        B = compute_task_breadth(dkg, defense_state)
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

    Called periodically by the Orchestrator (every cycle) to detect
    patterns that require agent coordination:

    1. Credential reuse — can new creds unlock unreached hosts?
    2. Session-based discovery — high-privilege sessions revealing internal hosts
    3. Vulnerability chains — complementary vuln types forming attack chains
    4. Agent conflict — multiple agents targeting the same endpoint
    5. Credential + auth bypass — stolen creds enabling auth-required exploits
    """
    opportunities: List[CollaborationOpportunity] = []

    credentials = dkg.query_nodes("Credential")
    sessions = dkg.query_nodes("Session")
    hosts = dkg.query_nodes("Host")
    vulnerabilities = dkg.query_nodes("Vulnerability")
    endpoints = dkg.query_nodes("Endpoint")
    flags = dkg.query_nodes("Flag")

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

    # 2. New internal host discovery via high-privilege session
    if sessions:
        for session in sessions:
            session_host = session.get("host", "")
            if session.get("access_level") in ("root", "admin", "system"):
                opportunities.append(CollaborationOpportunity(
                    opportunity_type="new_internal_host",
                    source_agent="exploit",
                    target_agent="recon",
                    description=f"High-privilege session on {session_host} — scan for internal hosts",
                    confidence=0.8,
                    dkg_evidence={"session_host": session_host},
                ))

    # 3. Cross-vulnerability chains
    if len(vulnerabilities) >= 2:
        vuln_types_lower = [
            (v.get("vuln_type") or v.get("type") or "").lower()
            for v in vulnerabilities
        ]

        # Chain patterns: (pair, chain_name, confidence)
        chains = [
            (("sqli", "fileupload"), "sqli_fileupload_chain",
             "SQLi credentials → authenticated file upload → shell", 0.6),
            (("sqli", "lfi"), "sqli_lfi_chain",
             "SQLi data extraction + LFI log poisoning → RCE", 0.55),
            (("xss", "sqli"), "xss_sqli_chain",
             "XSS session theft → authenticated SQLi", 0.5),
            (("fileupload", "lfi"), "fileupload_lfi_chain",
             "File upload + LFI include → RCE", 0.65),
            (("ssrf", "cmdi"), "ssrf_cmdi_chain",
             "SSRF internal probe + CMDi on internal service", 0.55),
            (("idor", "sqli"), "idor_sqli_chain",
             "IDOR data leak → targeted SQLi on exposed parameters", 0.5),
            (("idor", "xss"), "idor_xss_chain",
             "IDOR user data → XSS against admin viewers", 0.45),
        ]

        for (a, b), chain_name, desc, conf in chains:
            if a in vuln_types_lower and b in vuln_types_lower:
                opportunities.append(CollaborationOpportunity(
                    opportunity_type="vuln_cross_reference",
                    source_agent=f"exploit_{a}",
                    target_agent=f"exploit_{b}",
                    description=desc,
                    confidence=conf,
                    dkg_evidence={"vuln_types": vuln_types_lower, "chain": chain_name},
                ))

    # 4. Agent conflict detection — multiple agents targeting same endpoint
    if len(vulnerabilities) >= 2:
        endpoint_counts: dict[str, int] = {}
        for v in vulnerabilities:
            ep = v.get("endpoint", "")
            if ep:
                endpoint_counts[ep] = endpoint_counts.get(ep, 0) + 1
        for ep, count in endpoint_counts.items():
            if count >= 2:
                opportunities.append(CollaborationOpportunity(
                    opportunity_type="agent_conflict",
                    source_agent="orchestrator",
                    target_agent="orchestrator",
                    description=f"{count} agents targeting same endpoint: {ep} — coordinate or deduplicate",
                    confidence=0.8,
                    dkg_evidence={"endpoint": ep, "agent_count": count},
                ))

    # 5. Credential + auth-required endpoint → coordinated auth bypass
    if credentials:
        auth_endpoints = [
            e for e in endpoints
            if e.get("auth_required") or "login" in (e.get("url", "") or "")
        ]
        if auth_endpoints and len(vulnerabilities) > 0:
            opportunities.append(CollaborationOpportunity(
                opportunity_type="credential_chain",
                source_agent="recon",
                target_agent="exploit",
                description=f"Credentials + {len(auth_endpoints)} auth endpoints + {len(vulnerabilities)} vulns → authenticated exploit",
                confidence=0.6,
                dkg_evidence={
                    "credentials": len(credentials),
                    "auth_endpoints": len(auth_endpoints),
                    "vulns": len(vulnerabilities),
                },
            ))

    # 6. Flag found → signal all agents to stop (high priority)
    if flags:
        verified = [f for f in flags if f.get("verified") or f.get("value", "").startswith("flag{")]
        if verified:
            opportunities.append(CollaborationOpportunity(
                opportunity_type="flag_captured",
                source_agent="orchestrator",
                target_agent="all",
                description=f"Flag captured: {verified[0].get('value', '')[:60]} — terminate all agents",
                confidence=1.0,
                dkg_evidence={"flag": verified[0].get("value", "")[:60]},
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
