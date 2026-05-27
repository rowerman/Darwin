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
from typing import Any, Dict, List, Optional


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

        return "\n".join(parts)


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

    # Analysis notes
    for raw in dkg.query_nodes("Analysis"):
        content = raw.get("content", "")
        if content and raw.get("type") == "application_understanding":
            state.analysis_notes.append(str(content))

    return state
