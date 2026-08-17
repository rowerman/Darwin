"""Unified data model for DARWIN pipeline.

All data exchanged between phases goes through these dataclasses.
No raw dicts cross phase boundaries — every read normalises, every write validates.

Usage:
    from darwin.data_model import Endpoint, Service, Vulnerability, normalize_dkg_state

    state = normalize_dkg_state(dkg)  # reads all DKG nodes, returns typed objects
    prompt = state.to_prompt_context()  # consistent LLM prompt format
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


# ── Core Orchestrator Types ─────────────────────────────────────────────

class OrchestratorPhase(str, Enum):
    INIT = "init"
    BOOTSTRAP = "bootstrap"
    EXPLOIT = "exploit"
    DONE = "done"
    FAILED = "failed"
    RECON = "recon"
    ANALYZE = "analyze"
    BYPASS = "defense_bypass"
    VERIFY = "verify"


@dataclass
class TaskResult:
    """Result of an orchestrated penetration test task."""
    success: bool
    flag: str = ""
    steps: int = 0
    tokens_used: int = 0
    time_elapsed: float = 0.0
    phase_at_end: OrchestratorPhase = OrchestratorPhase.DONE
    defense_detected: bool = False
    waf_bypassed: bool = False
    waf_type: str = ""
    defense_complexity: float = 0.0
    dkg_summary: str = ""
    error: str = ""


@dataclass
class VulnerabilityHypothesis:
    """A hypothesized vulnerability for testing."""
    vuln_type: str
    endpoint: str
    param: str
    confidence: float
    evidence: str
    suggested_tool: str = ""
    tool_args: dict = field(default_factory=dict)
    suggested_payloads: list[str] = field(default_factory=list)
    research_techniques: list = field(default_factory=list)
    research_cves: list = field(default_factory=list)
    # O2.1: belief status — "" (untested) | tested | confirmed | rejected |
    # blocked | inconclusive. Written by the orchestrator's confidence
    # feedback loop and mirrored onto the DKG Vulnerability node.
    status: str = ""


@dataclass
class ExploitationPlan:
    """Structured penetration test plan with dynamic task tracking."""
    plan_id: str
    phase: str
    goal: str
    tasks: list = field(default_factory=list)
    status: str = "pending"
    created_at: str = ""
    updated_at: str = ""


# ── Core Data Types ──────────────────────────────────────────────────────

@dataclass
class EndpointInfo:
    """Normalised endpoint, regardless of how it was discovered."""
    url: str
    method: str = "GET"
    params: List[str] = field(default_factory=list)   # input parameter names
    body_format: str = ""                               # "json", "form", or ""
    auth_required: bool = False
    sample_status: int = 0
    sample_response: str = ""
    sample_content_type: str = ""
    proto: str = "http"                                 # "http", "mysql", "redis", "kubernetes", etc.

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url, "method": self.method,
            "params": ", ".join(self.params),
            "body_format": self.body_format,
            "auth_required": self.auth_required,
            "sample_status": self.sample_status,
            "sample_response": self.sample_response[:500],
            "sample_content_type": self.sample_content_type,
            "proto": self.proto,
        }

    def to_prompt_line(self) -> str:
        """Single-line summary for LLM prompt context."""
        prefix = f"[{self.proto}] " if self.proto != "http" else ""
        parts = [f"{prefix}{self.method} {self.url}"]
        if self.params and self.proto == "http":
            parts.append(f"INPUT params: {', '.join(self.params)}")
        if self.body_format:
            parts.append(f"body: {self.body_format}")
        if self.sample_response:
            resp = self.sample_response[:200]
            parts.append(f"→ HTTP {self.sample_status}: {resp}")
        return " | ".join(parts)

    @classmethod
    def from_dkg(cls, raw: Dict[str, Any]) -> "EndpointInfo":
        """Normalise from a DKG Endpoint node dict."""
        url = (raw.get("url") or "").strip()
        params_str = raw.get("params", "") or raw.get("param", "") or ""
        params = [p.strip() for p in params_str.split(",") if p.strip()]
        return cls(
            url=url,
            method=(raw.get("method") or "GET").upper(),
            params=params,
            body_format=raw.get("body_format", "") or "",
            auth_required=bool(raw.get("auth_required", False)),
            sample_status=int(raw.get("sample_status", 0)),
            sample_response=str(raw.get("sample_response", "") or ""),
            sample_content_type=str(raw.get("sample_content_type", "") or ""),
            proto=str(raw.get("proto", "http") or "http"),
        )


@dataclass
class ServiceInfo:
    """Normalised service discovered by nmap/recon."""
    port: int
    protocol: str = "tcp"
    version: str = ""
    banner: str = ""
    skip_exploit: bool = False
    http_reachable: Optional[bool] = None

    @classmethod
    def from_dkg(cls, raw: Dict[str, Any]) -> "ServiceInfo":
        return cls(
            port=int(raw.get("port", 0)),
            protocol=str(raw.get("protocol", "tcp")),
            version=str(raw.get("version", "") or ""),
            banner=str(raw.get("banner", "") or ""),
            skip_exploit=bool(raw.get("skip_exploit", False)),
            http_reachable=raw.get("http_reachable"),
        )


@dataclass
class VulnerabilityInfo:
    """Normalised vulnerability hypothesis."""
    vuln_type: str
    endpoint: str
    param: str = ""
    confidence: float = 0.5
    evidence: str = ""
    suggested_tool: str = ""
    tool_args: Dict[str, Any] = field(default_factory=dict)

    def to_prompt_line(self) -> str:
        return (
            f"[{self.vuln_type}] {self.endpoint}"
            + (f"?{self.param}" if self.param else "")
            + f" (conf={self.confidence:.1f}) — {self.evidence[:100]}"
        )

    @classmethod
    def from_dkg(cls, raw: Dict[str, Any]) -> "VulnerabilityInfo":
        return cls(
            vuln_type=str(raw.get("vuln_type", "") or ""),
            endpoint=str(raw.get("endpoint", "") or ""),
            param=str(raw.get("parameter", "") or raw.get("param", "") or ""),
            confidence=float(raw.get("confidence", 0.5)),
            evidence=str(raw.get("evidence", "") or ""),
            suggested_tool=str(raw.get("suggested_tool", "") or ""),
            tool_args=raw.get("tool_args", {}) if isinstance(raw.get("tool_args"), dict) else {},
        )


@dataclass
class CredentialInfo:
    """Normalised credential."""
    username: str = ""
    password: str = ""
    hash_value: str = ""
    source_host: str = ""

    @classmethod
    def from_dkg(cls, raw: Dict[str, Any]) -> "CredentialInfo":
        return cls(
            username=str(raw.get("user", "") or raw.get("username", "") or ""),
            password=str(raw.get("password", "") or ""),
            hash_value=str(raw.get("hash", "") or ""),
            source_host=str(raw.get("source_host", "") or ""),
        )


# ── Unified State ────────────────────────────────────────────────────────

@dataclass
class PipelineState:
    """All data the pipeline has collected, in typed form.

    Created by `normalize_dkg_state(dkg)`. Used by all phases to build
    LLM prompts without raw dict access.
    """
    endpoints: List[EndpointInfo] = field(default_factory=list)
    services: List[ServiceInfo] = field(default_factory=list)
    vulnerabilities: List[VulnerabilityInfo] = field(default_factory=list)
    credentials: List[CredentialInfo] = field(default_factory=list)
    flags: List[str] = field(default_factory=list)
    analysis_notes: List[str] = field(default_factory=list)
    hosts: List[dict] = field(default_factory=list)
    sessions: List[dict] = field(default_factory=list)
    domains: List[dict] = field(default_factory=list)

    def get_endpoint(self, url: str) -> Optional[EndpointInfo]:
        """Find an endpoint by URL (loose match)."""
        url_norm = url.rstrip("/")
        for ep in self.endpoints:
            if ep.url.rstrip("/") == url_norm:
                return ep
        return None

    def get_params_for_url(self, url: str) -> List[str]:
        """Get known parameter names for a URL."""
        ep = self.get_endpoint(url)
        return ep.params if ep else []

    def to_prompt_context(self) -> str:
        """Render full state as LLM prompt text. Single canonical format."""
        parts = []

        if self.analysis_notes:
            parts.append("## Application Understanding")
            for note in self.analysis_notes[-2:]:
                parts.append(f"- {note}")
            parts.append("")

        parts.append("## Endpoints (with probed responses)")
        seen_urls = set()
        for ep in self.endpoints:
            if ep.url not in seen_urls:
                seen_urls.add(ep.url)
                parts.append(ep.to_prompt_line())
        parts.append("")

        # Parameter-name guide
        param_entries = []
        for ep in self.endpoints:
            if ep.params:
                param_entries.append(f"  {ep.url}: {', '.join(ep.params)}")
        if param_entries:
            parts.append("## Known Parameter Names (use EXACTLY these)")
            parts.extend(param_entries)
            parts.append("")

        if self.vulnerabilities:
            parts.append("## Vulnerability Hypotheses")
            for v in self.vulnerabilities:
                parts.append(f"- {v.to_prompt_line()}")
            parts.append("")
        else:
            parts.append("## Vulnerability Hypotheses")
            parts.append("(none identified yet — exploit phase will generate hypotheses)")
            parts.append("")

        if self.services:
            parts.append("## Services")
            for s in self.services:
                if s.port and s.version:
                    parts.append(f"- port {s.port}/{s.protocol}: {s.version}"
                                 + (" [skip]" if s.skip_exploit else ""))
            parts.append("")

        if self.credentials:
            parts.append("## Credentials")
            for c in self.credentials:
                parts.append(f"- {c.username}@{c.source_host}"
                             + (f" (hash: {c.hash_value[:20]}...)" if c.hash_value else ""))
            parts.append("")
        else:
            parts.append("## Credentials")
            parts.append("(none discovered yet)")
            parts.append("")

        if self.hosts:
            parts.append("## Hosts")
            # Standard fields rendered inline; all other fields rendered
            # as key=value pairs so discovery modules (K8S, AD, cloud)
            # can surface metadata without modifying this function.
            _HOST_STANDARD = {"ip", "os", "is_internal", "is_reachable",
                              "type", "id", "discovered_by"}
            for h in self.hosts:
                line = f"- {h.get('ip','')}"
                if h.get("is_internal"):
                    line += " (internal)"
                # Render any non-standard fields
                extras = []
                for k, v in h.items():
                    if k in _HOST_STANDARD or v is None:
                        continue
                    if isinstance(v, dict):
                        # Flatten small dicts inline
                        if v and len(str(v)) < 200:
                            extras.append(f"{k}={v}")
                    elif isinstance(v, list):
                        if v and len(str(v)) < 200:
                            extras.append(f"{k}={v}")
                    elif isinstance(v, bool):
                        if v:
                            extras.append(k)
                    elif isinstance(v, str) and v:
                        extras.append(f"{k}={v[:120]}")
                if extras:
                    line += "  [" + ", ".join(extras) + "]"
                elif h.get("os"):
                    line += f" [{h['os']}]"
                parts.append(line)
            parts.append("")

        if self.sessions:
            parts.append("## Active Sessions")
            for s in self.sessions:
                parts.append(f"- {s.get('user','')}@{s.get('host','')}"
                             + f" [{s.get('access_level','user')}]")
            parts.append("")

        if self.domains:
            parts.append("## Domains")
            for d in self.domains:
                parts.append(f"- {d.get('name','')} (DC: {d.get('dc_ip','')})"
                             + (f" FL: {d.get('functional_level','')}"
                                if d.get('functional_level') else ""))
            parts.append("")

        return "\n".join(parts)


# ── Cycle Transition Summary ──────────────────────────────────────────────

@dataclass
class CycleTransitionSummary:
    """Structured summary of what happened in a cycle iteration.

    Injected into LLM context between main loop cycles to maintain awareness
    of what has been tried, what succeeded, and what failed.
    """
    cycle_number: int = 0
    flags_found: List[str] = field(default_factory=list)
    tasks_completed: int = 0
    tasks_failed: int = 0
    tasks_exhausted: int = 0
    new_endpoints: int = 0
    new_credentials: int = 0
    new_vulnerabilities: int = 0
    defense_changed: bool = False
    waf_type: str = ""
    failed_approaches: List[str] = field(default_factory=list)
    successful_approaches: List[str] = field(default_factory=list)
    active_sessions: List[str] = field(default_factory=list)
    highest_confidence_vuln: str = ""

    def to_prompt_block(self) -> str:
        """Render as a structured block for LLM context injection."""
        lines = [
            f"[CYCLE {self.cycle_number} COMPLETE]",
            f"Flags: {len(self.flags_found)} found"
            + (f" ({', '.join(self.flags_found[:3])})" if self.flags_found else ""),
            f"Tasks: {self.tasks_completed} done, {self.tasks_failed} failed, "
            f"{self.tasks_exhausted} exhausted",
            f"Discoveries: {self.new_endpoints} endpoints, "
            f"{self.new_credentials} credentials, "
            f"{self.new_vulnerabilities} vulnerabilities",
        ]
        if self.defense_changed and self.waf_type:
            lines.append(f"Defense: {self.waf_type} active")
        if self.failed_approaches:
            lines.append("Approaches that FAILED (do NOT retry):")
            for i, fa in enumerate(self.failed_approaches[:5], 1):
                lines.append(f"  {i}. {fa[:150]}")
        if self.successful_approaches:
            lines.append("Successful approaches (build on these):")
            for i, sa in enumerate(self.successful_approaches[:3], 1):
                lines.append(f"  {i}. {sa[:150]}")
        if self.highest_confidence_vuln:
            lines.append(f"Highest-confidence vuln: {self.highest_confidence_vuln}")
        lines.append("Continue exploitation. Build on successes, avoid failed approaches.\n")
        return "\n".join(lines)


# ── Normalisation ────────────────────────────────────────────────────────

def normalize_dkg_state(dkg: Any) -> PipelineState:
    """Read all DKG nodes and return a fully typed PipelineState.

    This is THE single entry point for consuming DKG data. All phases
    call this instead of dkg.query_nodes() + raw dict access.

    Args:
        dkg: DKG instance (must have query_nodes method)

    Returns:
        PipelineState with all data validated and normalised.
    """
    state = PipelineState()

    # Endpoints
    for raw in dkg.query_nodes("Endpoint"):
        try:
            state.endpoints.append(EndpointInfo.from_dkg(raw))
        except Exception:
            pass  # Skip malformed entries

    # Services
    for raw in dkg.query_nodes("Service"):
        try:
            state.services.append(ServiceInfo.from_dkg(raw))
        except Exception:
            pass

    # Vulnerabilities
    for raw in dkg.query_nodes("Vulnerability"):
        try:
            state.vulnerabilities.append(VulnerabilityInfo.from_dkg(raw))
        except Exception:
            pass

    # Credentials
    for raw in dkg.query_nodes("Credential"):
        try:
            state.credentials.append(CredentialInfo.from_dkg(raw))
        except Exception:
            pass

    # Flags
    for raw in dkg.query_nodes("Flag"):
        val = raw.get("value", "")
        if val and raw.get("verified"):
            state.flags.append(str(val))

    # Analysis notes — phase field distinguishes sub-types since add_node()
    # forces data["type"] to the node type ("Analysis"), overwriting any
    # caller-provided "type" key (e.g. "application_understanding").
    for raw in dkg.query_nodes("Analysis"):
        content = raw.get("content", "")
        if content and raw.get("phase") in ("analyze", "service_research"):
            state.analysis_notes.append(str(content))

    # Hosts — pass through all fields so discovery modules (K8S, AD, cloud)
    # can attach metadata without changing this function.
    for raw in dkg.query_nodes("Host"):
        try:
            host_dict: dict = {}
            for k, v in raw.items():
                if k in ("type", "id"):
                    continue
                host_dict[k] = v
            state.hosts.append(host_dict)
        except Exception:
            pass

    # Sessions
    for raw in dkg.query_nodes("Session"):
        try:
            state.sessions.append({"host": raw.get("host", ""),
                                   "user": raw.get("user", ""),
                                   "access_level": raw.get("access_level", "user")})
        except Exception:
            pass

    # Domains
    for raw in dkg.query_nodes("Domain"):
        try:
            state.domains.append({"name": raw.get("name", ""),
                                  "dc_ip": raw.get("dc_ip", ""),
                                  "functional_level": raw.get("functional_level", "")})
        except Exception:
            pass

    return state
