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
    done = sum(1 for t in tasks if isinstance(t, dict) and t.get("status") == "done")
    failed = sum(
        1 for t in tasks
        if isinstance(t, dict) and t.get("status") in ("failed", "skipped", "exhausted")
    )
    pending = [
        t for t in tasks
        if isinstance(t, dict) and t.get("status") in ("pending", None, "")
    ]
    lines = [
        f"Plan: {done}/{len(tasks)} done, {failed} failed, {len(pending)} pending"
    ]
    for t in pending[: caps.plan_tasks]:
        tid = t.get("id", "?")
        instr = _clip(t.get("instruction", "") or t.get("goal", "") or "", 100)
        deps = t.get("dependent_task_ids") or t.get("dependencies") or []
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
