"""Cross-Task Experience Graph — pattern abstraction and retrieval across tasks.

Reference:
  - AWE MemoryStorage (SQLite tables: payload_attempts, detected_filters,
    successful_bypasses, strategy_effectiveness)
  - VulnBot rag/ (Milvus vector DB + Embedding + Reranker)
  - DARWIN framework spec — abstract patterns across task boundaries
"""

from __future__ import annotations

import json
import math
import os
import re
import threading
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

import networkx as nx


# ── Pattern Types ───────────────────────────────────────────────────

@dataclass
class BypassPattern:
    """Abstract bypass technique pattern."""
    pattern_id: str
    mechanism: str           # e.g., "double_URL_encode", "case_alternation"
    abstract_description: str  # e.g., "Double URL encoding bypasses ModSecurity CRS"
    applicable_defense_types: List[str] = field(default_factory=list)
    applicable_vuln_types: List[str] = field(default_factory=list)
    preconditions: List[str] = field(default_factory=list)
    total_attempts: int = 0
    total_successes: int = 0
    avg_attempts_to_success: float = 0.0
    last_successful_use: str = ""
    half_life_days: int = 30
    reinforcement_count: int = 0
    created_from_task: str = ""

    @property
    def success_rate(self) -> float:
        if self.total_attempts == 0:
            return 0.0
        return self.total_successes / self.total_attempts

    @property
    def is_active(self) -> bool:
        """Pattern is still active (has been used recently)."""
        return self.reinforcement_count > 0 or self.total_attempts > 0


@dataclass
class ExploitPattern:
    """Abstract exploitation technique pattern with concrete steps."""
    pattern_id: str
    mechanism: str
    abstract_description: str
    vulnerability_type: str
    required_context: str = ""
    total_attempts: int = 0
    total_successes: int = 0
    last_successful_use: str = ""
    half_life_days: int = 30
    created_from_task: str = ""
    concrete_techniques: List[str] = field(default_factory=list)  # actual steps that worked
    technology_stack: List[str] = field(default_factory=list)  # what tech this applies to

    @property
    def success_rate(self) -> float:
        if self.total_attempts == 0:
            return 0.0
        return self.total_successes / self.total_attempts


@dataclass
class CredentialPattern:
    """Credential discovered during a penetration test that should persist across runs.

    Unlike ExploitPattern/BypassPattern (which describe techniques), credential
    patterns store concrete username:password pairs for specific hosts/ports.
    """
    pattern_id: str
    host: str               # target hostname or IP
    port: int               # target port
    service_type: str       # "mssql", "mysql", "ssh", "http", etc.
    username: str
    password: str
    source: str = ""        # "user_provided", "discovered", "brute_force", "default"
    total_successes: int = 1
    last_successful_use: str = ""
    half_life_days: int = 14
    created_from_task: str = ""

    @property
    def is_active(self) -> bool:
        return self.total_successes > 0

    @property
    def key(self) -> str:
        """Unique key for deduplication: host:port:username"""
        return f"{self.host}:{self.port}:{self.username}"


@dataclass
class TaskRecord:
    """Record of a completed penetration test task for pattern extraction."""
    task_id: str
    benchmark: str
    vulnerability_types: List[str]
    outcome: str  # "success" | "partial" | "failure"
    defense_encountered: Dict[str, Any] = field(default_factory=dict)
    successful_bypasses: List[Dict[str, Any]] = field(default_factory=list)
    failed_bypasses: List[Dict[str, Any]] = field(default_factory=list)
    exploit_chain: List[Dict[str, Any]] = field(default_factory=list)
    technology_stack: List[str] = field(default_factory=list)  # e.g. ["FastAPI","JWT","Jinja2","MySQL"]
    key_findings: List[str] = field(default_factory=list)  # e.g. ["default creds demo:demo","OpenAPI at /openapi.json"]
    timestamp: str = ""

    def summary(self) -> str:
        return (
            f"Task {self.task_id} ({self.benchmark}): {self.outcome}\n"
            f"  Vulns: {self.vulnerability_types}\n"
            f"  Tech: {self.technology_stack}\n"
            f"  Defense: {self.defense_encountered}\n"
            f"  Bypasses: {len(self.successful_bypasses)} success / {len(self.failed_bypasses)} fail\n"
            f"  Chain: {len(self.exploit_chain)} steps"
        )


# ── CTEG Core ───────────────────────────────────────────────────────


# P13: tool -> abstract vulnerability type for single-execution bridge.
# Mirrors the orchestrator's exploit-chain vuln map so per-execution
# records land in the same pattern space as task-level commits.
_TOOL_VULN_TYPES = {
    "sqlmap_test": "sqli",
    "xss_reflection_test": "xss",
    "command_injection_test": "cmdi",
    "ffuf_fuzz": "fuzz",
    "send_payload": "injection",
    "hydra_http_brute": "auth",
    "hydra_ssh_brute": "auth",
    "test_credential": "auth",
    "ssh_exec": "rce",
    "ssh_key_exec": "rce",
    "http_post": "http",
    "curl_get": "http",
}


# ── Scenario-aware retrieval (P4) ─────────────────────────────────

# Coarse target-domain derivation. Patterns do NOT persist a domain field;
# both the pattern side and the profile side derive it deterministically
# from vulnerability types (plus service/protocol heuristics on the state
# side), so no persistence/schema migration is needed.
_DOMAIN_BY_VULN = {
    "sqli": "web", "xss": "web", "cmdi": "web", "lfi": "web", "rfi": "web",
    "file_upload": "web", "ssrf": "web", "idor": "web", "auth": "web",
    "rce": "web", "deserialization": "web", "ssti": "web", "injection": "web",
    "fuzz": "web", "http": "web", "default_creds": "web",
    "sql": "db", "redis": "db", "nosql": "db", "database": "db",
    "cloud": "cloud", "iam": "cloud", "s3": "cloud",
    "k8s": "k8s", "container": "container",
    "ad": "ad", "kerberos": "ad", "ldap": "ad",
    "network": "network", "smb": "network", "ssh": "network",
}

_DOMAIN_BY_PROTO = {
    "http": "web", "https": "web", "mysql": "db", "postgresql": "db",
    "mssql": "db", "mongodb": "db", "redis": "db", "elasticsearch": "db",
    "kubernetes": "k8s", "docker": "container", "ssh": "network",
    "smb": "network", "ftp": "network", "ldap": "ad", "kerberos": "ad",
}

# Multi-dimension matching weights. An exact primary-dimension match
# (vuln or defense) scores 1.0 and therefore passes the default gate;
# tech-stack and domain overlaps only boost or jointly qualify.
_W_VULN = 1.0
_W_DEF = 1.0
_W_TECH = 0.3
_W_DOMAIN = 0.2

# App-level technology keywords surfaced in analysis notes.
_APP_TECH_KEYWORDS = (
    "wordpress", "drupal", "joomla", "tomcat", "jenkins", "django",
    "laravel", "rails", "php", "asp.net", "confluence", "gitlab",
    "magento", "prestashop", "fastapi", "flask", "node.js", "express",
    "spring", "mysql", "postgresql", "mongodb", "redis", "elasticsearch",
    "kubernetes", "docker", "nginx", "apache", "iis",
)

_TECH_STOPWORDS = {
    "tcp", "udp", "http", "https", "date", "server", "up", "via",
    "the", "and", "for", "with", "open", "port",
}


@dataclass
class ScenarioProfile:
    """Current-task scenario fingerprint used to gate CTEG retrieval."""

    vuln_types: set = field(default_factory=set)
    defense_types: set = field(default_factory=set)
    tech_stack: set = field(default_factory=set)
    domains: set = field(default_factory=set)


def _domain_for_vulns(vulns: list[str]) -> set:
    return {_DOMAIN_BY_VULN.get(str(v).strip().lower(), "") for v in vulns} - {""}


def _tech_terms_from_text(text: str) -> set:
    out = set()
    for token in re.findall(r"[a-z0-9][a-z0-9.\-+]*", text.lower()):
        if len(token) >= 3 and token not in _TECH_STOPWORDS:
            out.add(token)
    return out


def build_scenario_profile(
    state: Any, vulnerabilities: list | None = None, defense: Any = None
) -> ScenarioProfile:
    """Build the current-task fingerprint from typed world state.

    Pure function (no IO, no LLM, never raises): merges vulnerability
    hypotheses (typed state + passed list), detected defense types, tech
    stack terms from services/analysis notes, and derived domains.
    """
    vuln_types: set = set()
    try:
        for v in list(getattr(state, "vulnerabilities", None) or []):
            vt = str(getattr(v, "vuln_type", "") or "").strip().lower()
            if vt:
                vuln_types.add(vt)
    except Exception:
        pass
    for v in vulnerabilities or []:
        try:
            vt = str(getattr(v, "vuln_type", "") or "").strip().lower()
        except Exception:
            vt = ""
        if vt:
            vuln_types.add(vt)

    defense_types: set = set()
    try:
        waf = str(getattr(defense, "waf_type", "") or "").strip().lower()
        if waf:
            defense_types.add(waf)
    except Exception:
        pass

    tech_stack: set = set()
    try:
        for s in list(getattr(state, "services", None) or []):
            ver = str(getattr(s, "version", "") or "")
            banner = str(getattr(s, "banner", "") or "")
            proto = str(getattr(s, "protocol", "") or "")
            tech_stack |= _tech_terms_from_text(f"{ver} {banner}")
            if proto:
                tech_stack |= _tech_terms_from_text(proto)
    except Exception:
        pass
    try:
        for note in list(getattr(state, "analysis_notes", None) or []):
            note_l = str(note).lower()
            for kw in _APP_TECH_KEYWORDS:
                if kw in note_l:
                    tech_stack.add(kw)
    except Exception:
        pass

    domains = _domain_for_vulns(sorted(vuln_types))
    try:
        for s in list(getattr(state, "services", None) or []):
            proto = str(getattr(s, "protocol", "") or getattr(s, "proto", "") or "")
            d = _DOMAIN_BY_PROTO.get(proto.strip().lower())
            if d:
                domains.add(d)
    except Exception:
        pass

    return ScenarioProfile(
        vuln_types=vuln_types,
        defense_types=defense_types,
        tech_stack=tech_stack,
        domains=domains,
    )


def match_score(pattern: Any, profile: ScenarioProfile) -> float:
    """Weighted scenario-overlap score for one CTEG pattern.

    Per-dimension scores: exact intersection = 1.0, "any"/unknown wildcard =
    0.5, no overlap = 0. Returns the weighted sum
    (w_vuln*vuln + w_def*def + w_tech*tech + w_domain*domain), so a single
    exact primary-dimension match (1.0) clears the default gate of 0.5 while
    tech/domain overlaps alone do not.
    """
    vuln_score = 0.0
    def_score = 0.0
    tech_score = 0.0
    domain_score = 0.0

    applicable_vulns = list(
        getattr(pattern, "applicable_vuln_types", None) or []
    )
    vuln_type = getattr(pattern, "vulnerability_type", "") or ""
    if applicable_vulns:
        norm = {str(v).strip().lower() for v in applicable_vulns}
        if "any" in norm:
            vuln_score = 0.5 if profile.vuln_types else 0.0
        elif norm & {str(v).strip().lower() for v in profile.vuln_types}:
            vuln_score = 1.0
        pattern_vulns = list(norm)
    elif vuln_type:
        vt = vuln_type.strip().lower()
        if vt in {str(v).strip().lower() for v in profile.vuln_types}:
            vuln_score = 1.0
        elif vt in ("any", "unknown", ""):
            vuln_score = 0.5 if profile.vuln_types else 0.0
        pattern_vulns = [vt]
    else:
        pattern_vulns = []

    applicable_defs = list(
        getattr(pattern, "applicable_defense_types", None) or []
    )
    if applicable_defs:
        norm_defs = {str(d).strip().lower() for d in applicable_defs}
        if "any" in norm_defs:
            def_score = 0.5 if profile.defense_types else 0.0
        elif norm_defs & {str(d).strip().lower() for d in profile.defense_types}:
            def_score = 1.0

    tech_stack = list(getattr(pattern, "technology_stack", None) or [])
    if tech_stack:
        pattern_tech = {
            str(t).strip().lower() for t in tech_stack
        } | _tech_terms_from_text(" ".join(str(t) for t in tech_stack))
        if pattern_tech & profile.tech_stack:
            tech_score = 1.0

    pattern_domains = _domain_for_vulns(pattern_vulns)
    if pattern_domains & profile.domains:
        domain_score = 1.0

    return (
        _W_VULN * vuln_score
        + _W_DEF * def_score
        + _W_TECH * tech_score
        + _W_DOMAIN * domain_score
    )


class CTEG:
    """Cross-Task Experience Graph.

    Stores abstract exploit and bypass patterns that survive task boundaries.
    Unlike AWE MemoryStorage (per-task persistence), CTEG generalizes patterns
    across tasks, stripping challenge-specific details.

    Implementation:
      Phase 1: JSON file + NetworkX (lightweight, no external DB)
      Phase 2: Milvus/Qdrant vector DB + Neo4j (production scale)
    """

    def __init__(self, storage_path: str = "cteg_state.json"):
        self.graph = nx.MultiDiGraph()
        self.storage_path = storage_path
        self._lock = threading.RLock()
        self._created_at = datetime.now().isoformat()
        self._task_count = 0

        # Load existing state if available
        if os.path.exists(storage_path):
            self._load(storage_path)

    # ── Pattern Storage ──────────────────────────────────────────

    def add_bypass_pattern(self, pattern: BypassPattern) -> str:
        """Store a bypass pattern in the graph."""
        with self._lock:
            self.graph.add_node(pattern.pattern_id, **{
                "type": "BypassPattern",
                "mechanism": pattern.mechanism,
                "abstract_description": pattern.abstract_description,
                "applicable_defense_types": pattern.applicable_defense_types,
                "applicable_vuln_types": pattern.applicable_vuln_types,
                "preconditions": pattern.preconditions,
                "total_attempts": pattern.total_attempts,
                "total_successes": pattern.total_successes,
                "success_rate": pattern.success_rate,
                "last_successful_use": pattern.last_successful_use,
                "half_life_days": pattern.half_life_days,
                "reinforcement_count": pattern.reinforcement_count,
                "created_at": datetime.now().isoformat(),
            })
            self._persist()
        return pattern.pattern_id

    def add_exploit_pattern(self, pattern: ExploitPattern) -> str:
        """Store an exploit pattern in the graph."""
        with self._lock:
            self.graph.add_node(pattern.pattern_id, **{
                "type": "ExploitPattern",
                "mechanism": pattern.mechanism,
                "abstract_description": pattern.abstract_description,
                "vulnerability_type": pattern.vulnerability_type,
                "required_context": pattern.required_context,
                "total_attempts": pattern.total_attempts,
                "total_successes": pattern.total_successes,
                "success_rate": pattern.success_rate,
                "last_successful_use": pattern.last_successful_use,
                "half_life_days": pattern.half_life_days,
                "created_at": datetime.now().isoformat(),
            })
            self._persist()
        return pattern.pattern_id

    def update_pattern_attempt(
        self, pattern_id: str, success: bool, attempts: int = 1
    ) -> None:
        """Update attempt/success counts for a pattern."""
        with self._lock:
            if pattern_id in self.graph:
                node = self.graph.nodes[pattern_id]
                node["total_attempts"] = node.get("total_attempts", 0) + attempts
                node["total_successes"] = node.get("total_successes", 0) + (1 if success else 0)
                node["success_rate"] = (
                    node["total_successes"] / node["total_attempts"]
                    if node["total_attempts"] > 0 else 0.0
                )
                if success:
                    node["last_successful_use"] = datetime.now().isoformat()
                    node["reinforcement_count"] = node.get("reinforcement_count", 0) + 1
                self._persist()

    # ── Credential Persistence ────────────────────────────────────

    def add_credential(
        self, host: str, port: int, service_type: str,
        username: str, password: str, source: str = "discovered",
    ) -> str:
        """Store a discovered credential for cross-task reuse.

        Deduplicates by host:port:username — if the same credential exists,
        updates the password and increments the success counter.
        """
        cred_key = f"{host}:{port}:{username}"
        with self._lock:
            # Check for existing credential
            for nid, data in self.graph.nodes(data=True):
                if data.get("type") == "CredentialPattern":
                    existing_key = f"{data.get('host','')}:{data.get('port','')}:{data.get('username','')}"
                    if existing_key == cred_key:
                        data["password"] = password
                        data["total_successes"] = data.get("total_successes", 0) + 1
                        data["last_successful_use"] = datetime.now().isoformat()
                        self._persist()
                        return nid

            # New credential
            pattern_id = f"cred-{service_type}-{host}-{port}-{username}"
            self.graph.add_node(pattern_id, **{
                "type": "CredentialPattern",
                "host": host,
                "port": port,
                "service_type": service_type,
                "username": username,
                "password": password,
                "source": source,
                "total_successes": 1,
                "last_successful_use": datetime.now().isoformat(),
                "half_life_days": 14,
                "created_at": datetime.now().isoformat(),
            })
            self._persist()
        return pattern_id

    def get_credentials(
        self, host: str = "", port: int = 0, service_type: str = "",
    ) -> list[dict]:
        """Retrieve known credentials, optionally filtered by host/port/service.

        Returns list of dicts with host, port, service_type, username, password.
        Sorted by total_successes descending (most reliable first).
        """
        creds = []
        with self._lock:
            for nid, data in self.graph.nodes(data=True):
                if data.get("type") != "CredentialPattern":
                    continue
                if host and data.get("host", "") != host:
                    continue
                if port and data.get("port", 0) != port:
                    continue
                if service_type and data.get("service_type", "") != service_type:
                    continue
                # Check half-life: credentials older than 14 days are stale
                last_use = data.get("last_successful_use", "")
                if last_use:
                    try:
                        last_dt = datetime.fromisoformat(last_use)
                        age_days = (datetime.now() - last_dt).days
                        if age_days > data.get("half_life_days", 14):
                            continue
                    except Exception:
                        pass
                creds.append({
                    "host": data.get("host", ""),
                    "port": data.get("port", 0),
                    "service_type": data.get("service_type", ""),
                    "username": data.get("username", ""),
                    "password": data.get("password", ""),
                    "total_successes": data.get("total_successes", 0),
                    "last_successful_use": last_use,
                })
        creds.sort(key=lambda c: c["total_successes"], reverse=True)
        return creds

    # ── Pattern Abstraction ──────────────────────────────────────

    def extract_patterns(self, task_record: TaskRecord) -> List[Tuple[BypassPattern | ExploitPattern, str]]:
        """Extract abstract patterns from a completed task record.

        Strips all challenge-specific details (IPs, hostnames, specific payloads)
        and retains only the abstract mechanism.

        Returns:
            List of (pattern, edge_type) tuples for insertion into the graph.
        """
        patterns = []

        # Extract bypass patterns
        for bp in task_record.successful_bypasses:
            mechanism = bp.get("strategy", "unknown")
            defense_type = task_record.defense_encountered.get("type", "unknown")

            pattern = BypassPattern(
                pattern_id=f"bp-{mechanism}-{defense_type}",
                mechanism=mechanism,
                abstract_description=bp.get("abstract", bp.get("notes", f"{mechanism} bypass for {defense_type}")),
                applicable_defense_types=[defense_type],
                applicable_vuln_types=task_record.vulnerability_types,
                total_attempts=1,
                total_successes=1,
                last_successful_use=task_record.timestamp or datetime.now().isoformat(),
                created_from_task=task_record.task_id,
            )
            patterns.append((pattern, "bypass_applies_to_defense"))

        # Extract failed bypass patterns (negative examples)
        for fb in task_record.failed_bypasses:
            mechanism = fb.get("strategy", "unknown")
            defense_type = task_record.defense_encountered.get("type", "unknown")

            pattern = BypassPattern(
                pattern_id=f"bp-fail-{mechanism}-{defense_type}",
                mechanism=mechanism,
                abstract_description=f"{mechanism} FAILED against {defense_type}",
                applicable_defense_types=[defense_type],
                applicable_vuln_types=task_record.vulnerability_types,
                total_attempts=1,
                total_successes=0,
                created_from_task=task_record.task_id,
            )
            patterns.append((pattern, "bypass_failed_against"))

        # Extract exploit patterns with concrete techniques
        for step in task_record.exploit_chain:
            vuln_type = step.get("vuln_type", task_record.vulnerability_types[0] if task_record.vulnerability_types else "unknown")
            mechanism = step.get("mechanism", "") or step.get("tool", "") or step.get("action", "unknown")
            tool = step.get("tool", "")
            url = step.get("url", "")
            method = step.get("method", "GET")

            # Build a rich description from concrete step details
            desc_parts = [f"{vuln_type} exploitation"]
            if tool:
                desc_parts.append(f"via {tool}")
            if url:
                desc_parts.append(f"on {url}")
            if method:
                desc_parts.append(f"({method})")

            # Collect concrete techniques from all steps
            concrete = []
            for s in task_record.exploit_chain:
                parts = [s.get('tool', ''), s.get('method', 'GET'),
                         s.get('url', s.get('params', '')), "→",
                         (s.get('result', '') or '')[:80]]
                concrete.append(" ".join(p for p in parts if p))

            pattern = ExploitPattern(
                pattern_id=f"ep-{vuln_type}-{task_record.task_id[:8]}",
                mechanism=mechanism,
                abstract_description="; ".join(desc_parts),
                vulnerability_type=vuln_type,
                required_context=step.get("context", ""),
                total_attempts=1,
                total_successes=1 if task_record.outcome == "success" else 0,
                last_successful_use=task_record.timestamp if task_record.outcome == "success" else "",
                created_from_task=task_record.task_id,
                concrete_techniques=concrete,
                technology_stack=task_record.technology_stack,
            )
            patterns.append((pattern, "exploit_applies_to_vuln"))

        return patterns

    def commit_task(self, task_record: TaskRecord) -> int:
        """Extract and store all patterns from a completed task.

        Returns:
            Number of new patterns added.
        """
        patterns = self.extract_patterns(task_record)
        new_count = 0

        with self._lock:
            for pattern, edge_type in patterns:
                pid = pattern.pattern_id
                if pid not in self.graph:
                    if isinstance(pattern, BypassPattern):
                        self.add_bypass_pattern(pattern)
                    else:
                        self.add_exploit_pattern(pattern)
                    new_count += 1
                else:
                    # Merge: update existing pattern
                    if isinstance(pattern, BypassPattern):
                        self.update_pattern_attempt(
                            pid, pattern.total_successes > 0, pattern.total_attempts,
                        )
                    else:
                        self.update_pattern_attempt(
                            pid, pattern.total_successes > 0, pattern.total_attempts,
                        )

            self._task_count += 1
            self._persist()

        return new_count

    def record_execution(self, record: Any, source: str = "execution_memory") -> int:
        """Bridge one normalized ExecutionRecord into the experience store (P13).

        Narrow adapter: builds a single-step TaskRecord and reuses
        ``commit_task`` / ``extract_patterns``, so the graph structure,
        dedup and decay logic stay untouched. The caller (MemoryManager)
        decides which executions are worth sharing.

        Returns:
            Number of new patterns added (0 when merged into existing ones).
        """
        tool = str(getattr(record, "tool", "") or "")
        if not tool:
            return 0
        success = bool(getattr(record, "success", False))
        vuln_type = _TOOL_VULN_TYPES.get(tool, tool)
        result_text = str(getattr(record, "stdout", "") or "")[:200]
        if not result_text:
            result_text = str(getattr(record, "stderr", "") or "")[:200]
        task_id = str(
            getattr(record, "task_id", "") or f"mem-{int(datetime.now().timestamp())}"
        )
        task_record = TaskRecord(
            task_id=task_id,
            benchmark="execution_memory",
            vulnerability_types=[vuln_type],
            outcome="success" if success else "failure",
            exploit_chain=[
                {
                    "tool": tool,
                    "vuln_type": vuln_type,
                    "mechanism": tool,
                    "url": "",
                    "method": "GET",
                    "params": "",
                    "result": result_text,
                    "source": source,
                }
            ],
            timestamp=(
                str(getattr(record, "timestamp", "") or "")
                or datetime.now().isoformat()
            ),
        )
        return self.commit_task(task_record)

    # ── Pattern Retrieval ────────────────────────────────────────

    def query_bypass_patterns(
        self, defense_type: str, vuln_type: str = "", top_k: int = 5
    ) -> List[BypassPattern]:
        """Query bypass patterns effective against a specific defense type."""
        candidates = []

        with self._lock:
            for nid, data in self.graph.nodes(data=True):
                if data.get("type") != "BypassPattern":
                    continue
                defense_types = data.get("applicable_defense_types", [])
                if defense_type not in defense_types and "any" not in defense_types:
                    continue
                if vuln_type:
                    vuln_types = data.get("applicable_vuln_types", [])
                    if vuln_type not in vuln_types and "any" not in vuln_types:
                        continue

                success_rate = data.get("success_rate", 0.0)
                decay = self._compute_decay(data)
                score = success_rate * decay
                candidates.append((score, data))

        candidates.sort(key=lambda x: x[0], reverse=True)

        results = []
        for score, data in candidates[:top_k]:
            results.append(BypassPattern(
                pattern_id=data.get("pattern_id", ""),
                mechanism=data.get("mechanism", ""),
                abstract_description=data.get("abstract_description", ""),
                applicable_defense_types=data.get("applicable_defense_types", []),
                applicable_vuln_types=data.get("applicable_vuln_types", []),
                total_attempts=data.get("total_attempts", 0),
                total_successes=data.get("total_successes", 0),
                last_successful_use=data.get("last_successful_use", ""),
                half_life_days=data.get("half_life_days", 30),
                reinforcement_count=data.get("reinforcement_count", 0),
            ))
        return results

    def query_exploit_patterns(
        self, vuln_type: str, top_k: int = 5
    ) -> List[ExploitPattern]:
        """Query exploit patterns for a specific vulnerability type."""
        candidates = []

        with self._lock:
            for nid, data in self.graph.nodes(data=True):
                if data.get("type") != "ExploitPattern":
                    continue
                if data.get("vulnerability_type") != vuln_type:
                    continue

                success_rate = data.get("success_rate", 0.0)
                decay = self._compute_decay(data)
                score = success_rate * decay
                candidates.append((score, data))

        candidates.sort(key=lambda x: x[0], reverse=True)

        results = []
        for score, data in candidates[:top_k]:
            results.append(ExploitPattern(
                pattern_id=data.get("pattern_id", ""),
                mechanism=data.get("mechanism", ""),
                abstract_description=data.get("abstract_description", ""),
                vulnerability_type=data.get("vulnerability_type", ""),
                required_context=data.get("required_context", ""),
                total_attempts=data.get("total_attempts", 0),
                total_successes=data.get("total_successes", 0),
                last_successful_use=data.get("last_successful_use", ""),
                half_life_days=data.get("half_life_days", 30),
            ))
        return results

    def get_suggestions(
        self,
        defense_type: str = "",
        vuln_type: str = "",
        tech_stack: tuple = (),
        top_k: int = 3,
        min_overlap: float = 0.5,
        profile: ScenarioProfile | None = None,
    ) -> Dict[str, Any]:
        """Get scenario-matched CTEG pattern suggestions (P4).

        Hard-gated retrieval: only patterns whose weighted scenario overlap
        with the current task reaches ``min_overlap`` are returned, sorted by
        (overlap score, success_rate * decay) and capped at ``top_k``. When
        nothing matches, both strategy lists are empty — callers must inject
        nothing rather than placeholder text.

        Backward compatible: without ``profile`` the legacy scalar arguments
        (defense_type / vuln_type / tech_stack) are folded into a profile.
        """
        if profile is None:
            profile = ScenarioProfile(
                vuln_types={vuln_type} if vuln_type else set(),
                defense_types={defense_type} if defense_type else set(),
                tech_stack=set(tech_stack),
                domains=_domain_for_vulns([vuln_type]) if vuln_type else set(),
            )

        bypass: list[tuple[float, BypassPattern, float]] = []
        exploit: list[tuple[float, ExploitPattern, float]] = []
        with self._lock:
            for nid, data in self.graph.nodes(data=True):
                ntype = data.get("type", "")
                if ntype == "BypassPattern":
                    pattern = BypassPattern(
                        pattern_id=data.get("pattern_id", ""),
                        mechanism=data.get("mechanism", ""),
                        abstract_description=data.get("abstract_description", ""),
                        applicable_defense_types=data.get("applicable_defense_types", []),
                        applicable_vuln_types=data.get("applicable_vuln_types", []),
                        preconditions=data.get("preconditions", []),
                        total_attempts=data.get("total_attempts", 0),
                        total_successes=data.get("total_successes", 0),
                        last_successful_use=data.get("last_successful_use", ""),
                        half_life_days=data.get("half_life_days", 30),
                        reinforcement_count=data.get("reinforcement_count", 0),
                    )
                    score = match_score(pattern, profile)
                    if score >= min_overlap:
                        bypass.append((score, pattern, self._compute_decay(data)))
                elif ntype == "ExploitPattern":
                    pattern = ExploitPattern(
                        pattern_id=data.get("pattern_id", ""),
                        mechanism=data.get("mechanism", ""),
                        abstract_description=data.get("abstract_description", ""),
                        vulnerability_type=data.get("vulnerability_type", ""),
                        required_context=data.get("required_context", ""),
                        total_attempts=data.get("total_attempts", 0),
                        total_successes=data.get("total_successes", 0),
                        last_successful_use=data.get("last_successful_use", ""),
                        half_life_days=data.get("half_life_days", 30),
                        created_from_task=data.get("created_from_task", ""),
                        concrete_techniques=data.get("concrete_techniques", []),
                        technology_stack=data.get("technology_stack", []),
                    )
                    score = match_score(pattern, profile)
                    if score >= min_overlap:
                        exploit.append((score, pattern, self._compute_decay(data)))

        def _key(item: tuple[float, Any, float]) -> tuple[float, float]:
            score, pattern, decay = item
            return (score, decay * pattern.success_rate)

        bypass.sort(key=_key, reverse=True)
        exploit.sort(key=_key, reverse=True)

        return {
            "bypass_strategies": [
                {
                    "mechanism": b.mechanism,
                    "description": b.abstract_description,
                    "success_rate": b.success_rate,
                    "preconditions": b.preconditions,
                    "overlap": round(s, 3),
                }
                for s, b, _ in bypass[:top_k]
            ],
            "exploit_strategies": [
                {
                    "mechanism": e.mechanism,
                    "description": e.abstract_description,
                    "success_rate": e.success_rate,
                    "context": e.required_context,
                    "techniques": e.concrete_techniques,
                    "source": "learned",
                    "overlap": round(s, 3),
                }
                for s, e, _ in exploit[:top_k]
            ],
        }

    # ── Decay & Maintenance ──────────────────────────────────────

    def _compute_decay(self, node_data: Dict[str, Any]) -> float:
        """Compute time-based decay factor. Half-life = 30 days by default."""
        last_use = node_data.get("last_successful_use", "")
        half_life = node_data.get("half_life_days", 30)

        if not last_use:
            return 0.5  # never used successfully

        try:
            last_dt = datetime.fromisoformat(last_use)
            days_since = (datetime.now() - last_dt).days
        except (ValueError, TypeError):
            return 0.5

        if days_since < 0:
            return 1.0

        return math.pow(0.5, days_since / half_life)

    def prune_stale_patterns(self, stale_threshold_days: int = 90) -> int:
        """Remove patterns that haven't been used in a long time."""
        removed = 0
        with self._lock:
            nodes_to_remove = []
            for nid, data in self.graph.nodes(data=True):
                last_use = data.get("last_successful_use", "")
                if not last_use:
                    continue
                try:
                    last_dt = datetime.fromisoformat(last_use)
                    days_since = (datetime.now() - last_dt).days
                except (ValueError, TypeError):
                    continue
                if days_since > stale_threshold_days and data.get("reinforcement_count", 0) < 3:
                    nodes_to_remove.append(nid)

            for nid in nodes_to_remove:
                self.graph.remove_node(nid)
                removed += 1

            if removed > 0:
                self._persist()
        return removed

    # ── Persistence ──────────────────────────────────────────────

    def _persist(self):
        if self.storage_path:
            with open(self.storage_path, "w", encoding="utf-8") as f:
                json.dump(self.to_dict(), f, indent=2, default=str)

    def _load(self, path: str):
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            for node in data.get("nodes", []):
                nid = node.pop("id", node.pop("pattern_id", ""))
                if nid:
                    self.graph.add_node(nid, **node)
            for edge in data.get("edges", []):
                u = edge.pop("from", edge.pop("source", ""))
                v = edge.pop("to", edge.pop("target", ""))
                if u and v:
                    self.graph.add_edge(u, v, **edge)
            self._task_count = data.get("task_count", 0)
        except (FileNotFoundError, json.JSONDecodeError):
            pass

    def commit_attempt(
        self, vuln_type: str, tool: str, success: bool,
    ) -> None:
        """Record a single exploitation attempt for CTEG pattern learning.

        Called by ExploitAgent after each tool execution to feed back
        into CTEG's learned patterns incrementally.
        """
        pattern_id = f"ep-{vuln_type}-{tool}"
        with self._lock:
            if pattern_id in self.graph:
                self.update_pattern_attempt(pattern_id, success, attempts=1)
            else:
                pattern = ExploitPattern(
                    pattern_id=pattern_id,
                    mechanism=tool,
                    abstract_description=f"{tool} {'succeeded' if success else 'failed'} against {vuln_type}",
                    vulnerability_type=vuln_type,
                    total_attempts=1,
                    total_successes=1 if success else 0,
                )
                self.add_exploit_pattern(pattern)

    def to_dict(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "nodes": [
                    {"id": nid, **data}
                    for nid, data in self.graph.nodes(data=True)
                ],
                "edges": [
                    {"from": u, "to": v, **data}
                    for u, v, data in self.graph.edges(data=True)
                ],
                "task_count": self._task_count,
                "created_at": self._created_at,
            }

    def reset(self):
        """Clear all patterns (for CTEG ablation experiments)."""
        with self._lock:
            self.graph.clear()
            self._task_count = 0
            self._created_at = datetime.now().isoformat()
            self._persist()

    @property
    def pattern_count(self) -> int:
        return self.graph.number_of_nodes()
