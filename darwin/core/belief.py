"""Unified cognition snapshot (O1) — one renderer for every LLM call site.

The DARWIN orchestrator historically handed different LLM calls different
views of the world: execution-phase calls relied on raw conversation history
(which decays under compression), while plan-review calls saw a hand-built
prompt that omitted the latest discoveries and vulnerability beliefs.

This module provides the single ``## [COGNITION SNAPSHOT] Current Cognition``
block used by every LLM-facing prompt:

    facts    — services / endpoints / credentials / sessions / flags
    beliefs  — vulnerability hypotheses with confidence, evidence, status
    plan     — done/failed/pending summary plus active tasks
    defense  — WAF / defense complexity when detected
    rationale— preserved plan entries (why each active task exists)

It also provides the per-task delta helper (``node_ids_by_type`` +
``render_new_discoveries``) so the plan-review LLM sees exactly what the
just-completed task changed in the world model.

The block header carries ``SNAPSHOT_MARKER``; ``LLMSession.compress()`` uses
that marker to route snapshot messages verbatim into the preserved payload
instead of letting the summarizer LLM compress them away (O3.2).

Design rules:
- Pure rendering: no IO, no LLM calls, no DKG writes.
- Duck-typed inputs so callers can pass typed models or stand-ins.
- Never raises on malformed input; a section that fails to render is skipped.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable


SNAPSHOT_MARKER = "[COGNITION SNAPSHOT]"


@dataclass(frozen=True)
class SnapshotCaps:
    """Per-section item limits. compact=True tightens these further."""

    services: int = 6
    endpoints: int = 8
    credentials: int = 6
    sessions: int = 4
    vulns: int = 8
    plan_tasks: int = 10
    failed_approaches: int = 6
    rationale: int = 5
    line_len: int = 140


def _clip(text: Any, limit: int) -> str:
    """One-line clip: collapse newlines, truncate with ellipsis."""
    text = str(text or "").strip().replace("\n", " ")
    if not text:
        return ""
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _format_confidence(value: Any) -> str:
    """Render a confidence value tolerantly: numeric -> percent, else raw."""
    if value is None:
        return ""
    try:
        number = float(value)
    except (TypeError, ValueError):
        return str(value)
    return f"{number:.0%}"


def _compact(caps: SnapshotCaps, compact: bool) -> SnapshotCaps:
    """Return tighter caps for compact rendering (compression/truncation)."""
    if not compact:
        return caps
    return SnapshotCaps(
        services=min(caps.services, 3),
        endpoints=min(caps.endpoints, 5),
        credentials=min(caps.credentials, 4),
        sessions=min(caps.sessions, 3),
        vulns=min(caps.vulns, 6),
        plan_tasks=min(caps.plan_tasks, 6),
        failed_approaches=min(caps.failed_approaches, 4),
        rationale=min(caps.rationale, 3),
        line_len=min(caps.line_len, 100),
    )


# ── Section renderers ──────────────────────────────────────────────


def _render_facts(state: Any, caps: SnapshotCaps) -> str:
    """Facts section: flags / sessions / credentials / services / endpoints."""
    lines: list[str] = []
    try:
        flags = list(getattr(state, "flags", None) or [])
        if flags:
            lines.append(f"Flags: {', '.join(str(f) for f in flags[:3])}")
    except Exception:
        pass
    try:
        sessions = list(getattr(state, "sessions", None) or [])
        if sessions:
            _s = []
            for s in sessions[: caps.sessions]:
                if isinstance(s, dict):
                    _s.append(f"{s.get('user','?')}@{s.get('host','?')}"
                              f"[{s.get('access_level','user')}]")
                else:
                    _s.append(str(s))
            lines.append(f"Sessions: {', '.join(_s)}")
    except Exception:
        pass
    try:
        creds = list(getattr(state, "credentials", None) or [])
        if creds:
            _c = []
            for c in creds[: caps.credentials]:
                user = getattr(c, "username", "") or ""
                host = getattr(c, "source_host", "") or ""
                _c.append(f"{user}@{host}" if host else user)
            lines.append(f"Credentials ({len(creds)}): {', '.join(_c)}")
    except Exception:
        pass
    try:
        services = list(getattr(state, "services", None) or [])
        _svc = []
        for s in services[: caps.services]:
            port = getattr(s, "port", 0) or 0
            proto = getattr(s, "protocol", "tcp") or "tcp"
            ver = getattr(s, "version", "") or getattr(s, "banner", "") or ""
            _svc.append(f":{port}/{proto} {_clip(ver, 60)}".strip())
        if _svc:
            lines.append("Services: " + " | ".join(_svc))
    except Exception:
        pass
    try:
        endpoints = list(getattr(state, "endpoints", None) or [])
        _ep = []
        for ep in endpoints[: caps.endpoints]:
            method = getattr(ep, "method", "GET") or "GET"
            url = getattr(ep, "url", "") or ""
            params = list(getattr(ep, "params", None) or [])
            _ep.append(f"{method} {url}" + (f" params={','.join(params)}" if params else ""))
        if _ep:
            lines.append("Endpoints:\n" + "\n".join(f"  - {_clip(e, caps.line_len)}" for e in _ep))
    except Exception:
        pass
    return "\n".join(lines)


def _render_topology(state: Any, caps: SnapshotCaps) -> str:
    """Render a bounded local graph and computed attack-path summaries."""
    topology = getattr(state, "topology", None)
    if topology is None:
        return ""
    nodes = list(getattr(topology, "nodes", None) or [])
    edges = list(getattr(topology, "edges", None) or [])
    paths = list(getattr(topology, "attack_paths", None) or [])
    if not nodes and not edges and not paths:
        return ""

    def node_id(node: Any) -> str:
        return str(getattr(node, "id", "?") or "?")

    lines = [
        f"Topology (revision={getattr(topology, 'revision', 0)}, "
        f"anchors={','.join(str(x) for x in (getattr(topology, 'anchors', []) or [])[:6]) or 'none'}):"
    ]
    for node in sorted(nodes, key=node_id)[: caps.services + caps.endpoints + caps.sessions]:
        props = dict(getattr(node, "properties", None) or {})
        label = node_id(node)
        node_type = str(getattr(node, "node_type", "") or "")
        identity = props.get("url") or props.get("name") or props.get("ip") or props.get("port")
        if identity:
            label += f" ({identity})"
        if props.get("virtual"):
            label += " [virtual]"
        conf = getattr(node, "confidence", None)
        conf_text = f" conf={_format_confidence(conf)}" if conf is not None else ""
        lines.append(f"  - {node_type}:{label}{conf_text}")
        if node_type == "Credential":
            for key in ("username", "password", "hash", "source_host", "port"):
                if props.get(key) not in (None, ""):
                    lines.append(f"      {key}={props[key]}")

    # Keep credentials available even when the graph relation is not yet
    # connected to an anchor (common immediately after discovery).
    credentials = list(getattr(state, "credentials", None) or [])
    if credentials:
        lines.append("Credential values (benchmark context):")
        for cred in credentials[: caps.credentials]:
            user = getattr(cred, "username", "") or ""
            host = getattr(cred, "source_host", "") or ""
            password = getattr(cred, "password", "") or ""
            hash_value = getattr(cred, "hash_value", "") or ""
            secret = f"password={password}" if password else (f"hash={hash_value}" if hash_value else "")
            lines.append(f"  - {user}@{host} {secret}".rstrip())

    if credentials and edges:
        lines.append("")
    for edge in sorted(
        edges,
        key=lambda e: (
            str(getattr(e, "from_id", "")),
            str(getattr(e, "to_id", "")),
            str(getattr(e, "edge_type", "")),
        ),
    )[: caps.plan_tasks * 4]:
        src = str(getattr(edge, "from_id", "?"))
        dst = str(getattr(edge, "to_id", "?"))
        edge_type = str(getattr(edge, "edge_type", "") or "relationship")
        conf = getattr(edge, "confidence", None)
        suffix = f" conf={_format_confidence(conf)}" if conf is not None else ""
        lines.append(f"  - {src} -[{edge_type}]-> {dst}{suffix}")

    if paths:
        lines.append("Attack paths:")
        for path in sorted(paths, key=lambda p: str(getattr(p, "path_id", "")))[:caps.vulns]:
            desc = _clip(getattr(path, "description", ""), caps.line_len)
            conf = float(getattr(path, "confidence", 0.0) or 0.0)
            lines.append(f"  - [{getattr(path, 'category', '')}] {desc} conf={conf:.0%}")
            prereqs = list(getattr(path, "prerequisites", None) or [])
            if prereqs:
                lines.append(f"    prerequisites: {', '.join(str(x) for x in prereqs[:4])}")
            tools = list(getattr(path, "recommended_tools", None) or [])
            if tools:
                lines.append(f"    tools: {', '.join(str(x) for x in tools[:5])}")
            for step in list(getattr(path, "steps", None) or [])[:4]:
                if isinstance(step, dict):
                    lines.append(
                        f"    step: {step.get('action', '')} "
                        f"tool={step.get('tool', '')} target={step.get('target', '')}"
                    )
    return "\n".join(lines)


def _render_beliefs(vulnerabilities: Iterable[Any], caps: SnapshotCaps) -> str:
    """Beliefs section: hypotheses with confidence / evidence / status."""
    vulns = list(vulnerabilities or [])
    if not vulns:
        return ""
    lines = ["Beliefs (vulnerability hypotheses):"]
    for v in vulns[: caps.vulns]:
        try:
            vt = getattr(v, "vuln_type", "") or ""
            ep = getattr(v, "endpoint", "") or ""
            param = getattr(v, "param", "") or ""
            conf = float(getattr(v, "confidence", 0.5) or 0.5)
            status = getattr(v, "status", "") or ""
            evidence = _clip(getattr(v, "evidence", "") or "", caps.line_len)
            line = f"- [{vt}] {ep}"
            if param:
                line += f" param={param}"
            line += f" conf={conf:.0%}"
            if status:
                line += f" ({status})"
            if evidence:
                line += f" — {evidence}"
            lines.append(line)
            cves = list(getattr(v, "research_cves", None) or [])
            if cves:
                lines.append("    CVEs: " + ", ".join(str(c) for c in cves[:3]))
        except Exception:
            continue
    return "\n".join(lines)


def _render_plan(plan: Any, caps: SnapshotCaps) -> str:
    """Plan section: progress summary + active (pending) tasks."""
    if plan is None:
        return ""
    try:
        tasks = list(getattr(plan, "tasks", None) or [])
    except Exception:
        return ""

    def _status(t: Any) -> str:
        status = getattr(t, "status", None)
        if status is None and isinstance(t, dict):
            status = t.get("status")
        if status is None:
            return ""
        return status.value if hasattr(status, "value") else str(status)

    def _field(t: Any, name: str, default: Any = "") -> Any:
        if isinstance(t, dict):
            return t.get(name, default)
        return getattr(t, name, default)

    done = sum(1 for t in tasks if _status(t) in ("success", "done"))
    failed = sum(
        1 for t in tasks
        if _status(t) in ("failed", "skipped", "exhausted", "abandoned")
    )
    pending = [
        t for t in tasks
        if _status(t) in ("pending", "ready", "created", "")
    ]
    lines = [
        f"Plan: {done}/{len(tasks)} done, {failed} failed, {len(pending)} pending"
    ]
    for t in pending[: caps.plan_tasks]:
        tid = str(_field(t, "id", "?"))
        instr = _clip(_field(t, "instruction", "") or _field(t, "goal", "") or "", 100)
        deps = _field(t, "dependent_task_ids") or _field(t, "dependencies") or []
        dep_str = f" (waits: {', '.join(str(d) for d in deps[:3])})" if deps else ""
        lines.append(f"  - {tid}: {instr}{dep_str}")
    if len(pending) > caps.plan_tasks:
        lines.append(f"  ... and {len(pending) - caps.plan_tasks} more pending")
    return "\n".join(lines)


def _render_defense(defense: Any) -> str:
    """Defense section: only when a defense was actually detected."""
    if defense is None:
        return ""
    try:
        waf = getattr(defense, "waf_type", "") or ""
        complexity = float(getattr(defense, "defense_complexity", 0) or 0)
    except Exception:
        return ""
    if not waf and complexity <= 0:
        return ""
    return f"Defense: WAF={waf or 'none'}, complexity={complexity:.2f}"


def _render_rationale(entries: Iterable[Any], caps: SnapshotCaps) -> str:
    """Preserved plan rationale — why the active tasks exist."""
    entries = list(entries or [])
    if not entries:
        return ""
    lines = ["Preserved rationale (why these tasks exist):"]
    for e in entries[: caps.rationale]:
        try:
            tid = getattr(e, "task_id", "") or ""
            goal = _clip(getattr(e, "goal", "") or "", 100)
            lines.append(f"- [{tid}] {goal}")
            hypo = getattr(e, "hypothesis", "") or ""
            if hypo:
                lines.append(f"    hypothesis: {_clip(hypo, caps.line_len)}")
            for ev in list(getattr(e, "evidence", None) or [])[:2]:
                lines.append(f"    evidence: {_clip(ev, caps.line_len)}")
        except Exception:
            continue
    return "\n".join(lines)


# ── Public API ─────────────────────────────────────────────────────


def render_belief_snapshot(
    state: Any,
    vulnerabilities: Iterable[Any] | None = None,
    plan: Any = None,
    defense: Any = None,
    rationale_entries: Iterable[Any] | None = None,
    *,
    compact: bool = False,
    caps: SnapshotCaps | None = None,
) -> str:
    """Render the unified cognition block for one LLM call.

    Returns an empty string when there is nothing to report (empty world),
    so callers can omit the block entirely.
    """
    caps = _compact(caps or SnapshotCaps(), compact)
    sections: list[str] = []
    for renderer in (
        lambda: _render_facts(state, caps),
        lambda: _render_topology(state, caps),
        lambda: _render_beliefs(vulnerabilities or [], caps),
        lambda: _render_plan(plan, caps),
        lambda: _render_defense(defense),
        lambda: _render_rationale(rationale_entries or [], caps),
    ):
        try:
            block = renderer()
        except Exception:
            block = ""
        if block:
            sections.append(block)
    if not sections:
        return ""
    return f"## {SNAPSHOT_MARKER} Current Cognition\n" + "\n\n".join(sections)


def render_critical_facts(state: Any, caps: SnapshotCaps | None = None) -> str:
    """Compression-only structured extraction with FULL secret values.

    Used by ``MemoryManager.compression_digest()`` at compression time so the
    summarizer (or the preserved payload) never loses credential passwords,
    session tokens, flag values or confirmed vulnerability parameters. Unlike
    the everyday belief snapshot, this renderer includes the actual secret
    values — it must therefore only be used inside the compression path.

    Returns "" when there is nothing to report. Never raises on malformed
    input; a section that fails to render is skipped.
    """
    caps = caps or SnapshotCaps()
    lines: list[str] = []
    try:
        flags = list(getattr(state, "flags", None) or [])
        if flags:
            lines.append(f"Flags: {', '.join(str(f) for f in flags[:5])}")
    except Exception:
        pass
    try:
        creds = list(getattr(state, "credentials", None) or [])
        if creds:
            _c = []
            for c in creds[: caps.credentials]:
                user = getattr(c, "username", "") or ""
                host = getattr(c, "source_host", "") or ""
                secret = getattr(c, "password", "") or ""
                hash_val = getattr(c, "hash_value", "") or ""
                if secret:
                    _c.append(f"{user}@{host} password={secret}")
                elif hash_val:
                    _c.append(f"{user}@{host} hash={hash_val[:40]}")
                else:
                    _c.append(f"{user}@{host}")
            lines.append("Credentials (full values):\n" + "\n".join(f"  - {x}" for x in _c))
    except Exception:
        pass
    try:
        sessions = list(getattr(state, "sessions", None) or [])
        if sessions:
            _s = []
            for s in sessions[: caps.sessions]:
                if isinstance(s, dict):
                    host = s.get("host", "?")
                    user = s.get("user", "?")
                    access = s.get("access_level", "user")
                    token = s.get("token") or s.get("cookie") or s.get("shell_type") or ""
                    entry = f"{user}@{host}[{access}]"
                    if token:
                        entry += f" token={str(token)[:80]}"
                    _s.append(entry)
                else:
                    _s.append(str(s))
            lines.append("Sessions (with tokens when known): " + " | ".join(_s))
    except Exception:
        pass
    try:
        vulns = list(getattr(state, "vulnerabilities", None) or [])
        if vulns:
            _v = []
            for v in vulns[: caps.vulns]:
                vt = getattr(v, "vuln_type", "") or ""
                ep = getattr(v, "endpoint", "") or ""
                param = getattr(v, "param", "") or ""
                conf = float(getattr(v, "confidence", 0.5) or 0.5)
                _v.append(f"[{vt}] {ep}" + (f" param={param}" if param else "") + f" conf={conf:.0%}")
            lines.append("Vulnerabilities:\n" + "\n".join(f"  - {x}" for x in _v))
    except Exception:
        pass
    try:
        services = list(getattr(state, "services", None) or [])
        _svc = []
        for s in services[: caps.services]:
            port = getattr(s, "port", 0) or 0
            proto = getattr(s, "protocol", "tcp") or "tcp"
            ver = getattr(s, "version", "") or getattr(s, "banner", "") or ""
            _svc.append(f":{port}/{proto} {_clip(ver, 80)}".strip())
        if _svc:
            lines.append("Services: " + " | ".join(_svc))
    except Exception:
        pass
    try:
        endpoints = list(getattr(state, "endpoints", None) or [])
        _ep = []
        for ep in endpoints[: caps.endpoints]:
            method = getattr(ep, "method", "GET") or "GET"
            url = getattr(ep, "url", "") or ""
            params = list(getattr(ep, "params", None) or [])
            _ep.append(f"{method} {url}" + (f" params={','.join(params)}" if params else ""))
        if _ep:
            lines.append("Endpoints:\n" + "\n".join(f"  - {_clip(e, caps.line_len)}" for e in _ep))
    except Exception:
        pass
    try:
        notes = list(getattr(state, "analysis_notes", None) or [])
        if notes:
            lines.append("Application understanding: " + _clip(notes[-1], 200))
    except Exception:
        pass
    if not lines:
        return ""
    return "\n".join(lines)


# ── Per-task discovery diff (O1.2) ─────────────────────────────────

TRACKED_NODE_TYPES = (
    "Endpoint",
    "Vulnerability",
    "Credential",
    "Session",
    "Flag",
    "Service",
)


def node_ids_by_type(dkg: Any) -> dict[str, set[str]]:
    """Snapshot of node ids grouped by type (for before/after diffing)."""
    out: dict[str, set[str]] = {}
    for ntype in TRACKED_NODE_TYPES:
        try:
            out[ntype] = {
                str(n.get("id", ""))
                for n in dkg.query_nodes(ntype)
            }
        except Exception:
            out[ntype] = set()
    return out


def _node_label(ntype: str, node: dict, fallback: str) -> str:
    try:
        if ntype == "Endpoint":
            return str(node.get("url") or node.get("uri") or fallback)
        if ntype == "Vulnerability":
            label = f"[{node.get('vuln_type', '?')}] {node.get('endpoint', '')}"
            if node.get("parameter"):
                label += f" param={node.get('parameter')}"
            return label
        if ntype == "Credential":
            return (
                f"{node.get('cred_type', '?')} "
                f"{node.get('username', '?')}@{node.get('source_host', '?')}"
            )
        if ntype == "Session":
            return f"{node.get('session_type', '?')} on {node.get('host', '?')}"
        if ntype == "Flag":
            return str(node.get("value", fallback))
        if ntype == "Service":
            return (
                f":{node.get('port', '?')} "
                f"{node.get('service_name', '')} "
                f"{node.get('version', '')}".strip()
            )
    except Exception:
        pass
    return fallback


def render_new_discoveries(
    before: dict[str, set[str]] | None,
    dkg: Any,
    *,
    max_items_per_type: int = 6,
) -> str:
    """Render what changed in the world model since ``before`` was captured.

    Only brand-new node ids are reported (per-type). Returns "" when there
    is no baseline or nothing new was discovered.
    """
    if not before:
        return ""
    try:
        after = node_ids_by_type(dkg)
    except Exception:
        return ""
    blocks: list[str] = []
    for ntype in TRACKED_NODE_TYPES:
        new_ids = (after.get(ntype) or set()) - (before.get(ntype) or set())
        if not new_ids:
            continue
        lines: list[str] = []
        for nid in sorted(new_ids)[:max_items_per_type]:
            try:
                node = dkg.get_node(nid) or {}
            except Exception:
                node = {}
            lines.append(f"  - {_clip(_node_label(ntype, node, nid), 120)}")
        if len(new_ids) > max_items_per_type:
            lines.append(f"  ... and {len(new_ids) - max_items_per_type} more")
        blocks.append(
            f"  {ntype} ({len(new_ids)}):\n" + "\n".join(lines)
        )
    if not blocks:
        return ""
    return "## New This Task (world-state changes)\n" + "\n".join(blocks)
