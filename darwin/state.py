"""State management utilities extracted from Orchestrator.

Provides standalone functions for DKG state normalization, checkpointing,
chain detection, and logging.  Each function takes ``orch`` as the first
parameter (the Orchestrator instance) instead of ``self``.
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
from typing import Any

from darwin.data_model import (
    CycleTransitionSummary,
    PipelineState,
    normalize_dkg_state,
)

logger = logging.getLogger(__name__)


# ── State Access ──────────────────────────────────────────────────────────


def get_state(orch) -> PipelineState:
    """Return a typed snapshot of the current DKG state.

    All phases call this instead of raw dkg.query_nodes() + dict access.
    """
    return normalize_dkg_state(orch.dkg)


# ── Chain Detection ───────────────────────────────────────────────────────


def detect_chain_topology(
    orch, chain_mode_config: str = "auto"
) -> bool:
    """Detect if the target has multi-step attack chain topology.

    Activates chain_mode when: >= 2 distinct services each have
    associated vulnerability hypotheses, or >= 3 services total,
    indicating a multi-step chain target.

    Args:
        chain_mode_config: "auto" (detect), "off" (never activate)
    """
    if chain_mode_config == "off":
        return False

    if chain_mode_config != "auto":
        # Unknown value — don't activate
        return False

    services = orch.dkg.query_nodes("Service")
    vulns = orch.dkg.query_nodes("Vulnerability")

    # Count services that have vulnerability hypotheses
    services_with_vulns: set[str] = set()
    for v in vulns:
        svc = v.get("service") or v.get("port")
        if svc:
            services_with_vulns.add(str(svc))

    # Need >= 2 distinct services with vulns to qualify as chain
    if len(services_with_vulns) >= 2:
        orch._chain_mode = True
        orch._chain_services_total = len(services_with_vulns)
        return True

    # Also activate if >= 3 services total (potential chain, even w/o vulns yet)
    if len(services) >= 3:
        orch._chain_mode = True
        orch._chain_services_total = len(services)
        return True

    return False


def count_unexploited_services(orch) -> int:
    """Count services that still have unexploited vulnerability hypotheses.

    A service is considered exploited if its associated vulnerability
    nodes are marked as exploited.
    """
    vulns = orch.dkg.query_nodes("Vulnerability")
    exploited: set[str] = set()
    for v in vulns:
        if v.get("exploited") or v.get("status") == "exploited":
            svc = v.get("service") or v.get("port")
            if svc:
                exploited.add(str(svc))

    services_with_vulns: set[str] = set()
    for v in vulns:
        svc = v.get("service") or v.get("port")
        if svc:
            services_with_vulns.add(str(svc))

    return len(services_with_vulns - exploited)


# ── Artifact Extraction ───────────────────────────────────────────────────


def extract_recent_artifacts(orch) -> str | None:
    """Extract recently discovered intermediate artifacts from DKG state.

    Called after systematic pass and plan-driven task completions to inject
    a summary of recently discovered credentials, endpoints, files, and
    sessions into the LLM context for subsequent task decisions.

    Returns a context message string, or None if nothing new to report.
    """
    parts: list[str] = []
    try:
        creds = orch.dkg.query_nodes("Credential")
        if creds:
            recent_creds = [c for c in creds if c.get("confirmed")]
            if recent_creds:
                parts.append("New confirmed credentials:")
                for c in recent_creds[-4:]:
                    parts.append(
                        f"  {c.get('cred_type','?')} {c.get('username','?')}"
                        f" @ {c.get('source_host','?')}"
                    )
            # Also surface unconfirmed AWS/cloud credentials — they are
            # actionable even without explicit confirmation (e.g. IMDS
            # metadata extraction yields access keys that DAVE cannot
            # independently verify through a login test).
            _aws_creds = [
                c for c in creds
                if not c.get("confirmed")
                and any(kw in str(c.get("cred_type", "")).lower()
                       for kw in ("aws", "iam", "sts", "s3", "cloud"))
            ]
            for c in _aws_creds[-2:]:
                ct = c.get("cred_type", "cloud")
                cuser = c.get("username", "") or c.get("access_key_id", "") or ""
                chost = c.get("source_host", "") or c.get("host", "") or ""
                parts.append(
                    f"  [UNCONFIRMED BUT ACTIONABLE] {ct} credential"
                    + (f" {cuser}" if cuser else "")
                    + (f" @ {chost}" if chost else "")
                    + " — use with aws_cli / aws_sts_query / aws_iam_federation"
                )
        # ── Cryptographic artifacts ──
        # Scan Analysis nodes and Endpoint responses for private keys,
        # PEM certificates, and JWT tokens that may enable federation
        # attacks (SAML / OIDC).  These are often missed because the
        # simple "credentials → test_credential" pipeline doesn't know
        # what to do with raw key material.
        for an in orch.dkg.query_nodes("Analysis"):
            ev = str(an.get("evidence", "") or an.get("summary", "") or an.get("findings", "") or "")
            if "-----BEGIN" in ev:
                parts.append(
                    "PEM / private key material found in analysis output"
                    + " — consider saml_forge → aws_cli assume-role-with-saml"
                )
                break

        sessions = orch.dkg.query_nodes("Session")
        if sessions:
            parts.append(f"Active sessions ({len(sessions)}):")
            for s in sessions[-4:]:
                parts.append(
                    f"  {s.get('session_type','?')} on {s.get('host','?')}"
                )

        # Extract file paths / URLs from recent Endpoint discoveries
        eps = orch.dkg.query_nodes("Endpoint")
        recent_eps = [
            e for e in eps
            if e.get("discovered_by") and "deep_recon" in str(e.get("discovered_by", ""))
        ]
        if recent_eps:
            parts.append(f"Recently discovered paths ({len(recent_eps)}):")
            for ep in recent_eps[-6:]:
                parts.append(f"  {ep.get('url','') or ep.get('uri','')}")
    except Exception:
        return None

    if not parts:
        return None

    return (
        "[INTERMEDIATE ARTIFACTS — recent task results]\n"
        + "\n".join(parts)
        + "\nUse these in subsequent exploitation tasks."
    )


# ── Cycle Summary ─────────────────────────────────────────────────────────


def build_cycle_summary(orch) -> CycleTransitionSummary:
    """Build a structured summary of the current cycle's progress.

    Tracks deltas (new discoveries since last cycle) and surfaces
    failed/successful approaches so the LLM knows what to avoid/repeat.
    """
    plan = getattr(orch, 'exploitation_plan', None)
    tasks_done = sum(1 for t in (plan.tasks or []) if t.get("status") == "done") if plan else 0
    tasks_failed = sum(1 for t in (plan.tasks or []) if t.get("status") == "failed") if plan else 0
    tasks_exhausted = sum(1 for t in (plan.tasks or [])
                          if t.get("status") == "exhausted"
                          or t.get("id") in orch._exhausted_task_ids) if plan else 0

    failed_approaches = []
    successful_approaches = []
    if plan:
        for t in plan.tasks:
            instr = t.get("instruction", "")
            status = t.get("status", "")
            if status == "failed":
                failed_approaches.append(instr)
            elif status == "done":
                successful_approaches.append(instr)

    state = get_state(orch)
    flags_found = [str(f) for f in state.flags[:3]]

    prev_ep = getattr(orch, '_prev_endpoint_count', 0)
    prev_cred = getattr(orch, '_prev_credential_count', 0)
    prev_vuln = getattr(orch, '_prev_vulnerability_count', 0)
    new_ep = max(0, len(state.endpoints) - prev_ep)
    new_cred = max(0, len(state.credentials) - prev_cred)
    new_vuln = max(0, len(state.vulnerabilities) - prev_vuln)
    orch._prev_endpoint_count = len(state.endpoints)
    orch._prev_credential_count = len(state.credentials)
    orch._prev_vulnerability_count = len(state.vulnerabilities)

    # No-progress detection: terminate if consecutive loops produce nothing
    if new_ep == 0 and new_cred == 0 and new_vuln == 0 and not flags_found:
        orch._no_progress_loops += 1
    else:
        orch._no_progress_loops = 0

    highest_vuln = ""
    if orch.vulnerabilities:
        best = max(orch.vulnerabilities, key=lambda v: v.confidence, default=None)
        if best:
            highest_vuln = f"{best.vuln_type} @ {best.endpoint} ({best.confidence:.0%})"

    return CycleTransitionSummary(
        cycle_number=orch._loop_count,
        flags_found=flags_found,
        tasks_completed=tasks_done,
        tasks_failed=tasks_failed,
        tasks_exhausted=tasks_exhausted,
        new_endpoints=new_ep,
        new_credentials=new_cred,
        new_vulnerabilities=new_vuln,
        defense_changed=bool(orch.defense_state.waf_type),
        waf_type=orch.defense_state.waf_type or "",
        failed_approaches=failed_approaches[-10:],
        successful_approaches=successful_approaches[-5:],
        active_sessions=[s.get("host", "") for s in orch.dkg.query_nodes("Session")],
        highest_confidence_vuln=highest_vuln,
    )


# ── Plan Status ───────────────────────────────────────────────────────────


def format_plan_status(orch) -> str:
    """Format plan progress for LLM prompts."""
    plan = getattr(orch, 'exploitation_plan', None)
    if not plan or not plan.tasks:
        return "(no plan)"
    done = sum(1 for t in plan.tasks if t.get("status") == "done")
    failed = sum(1 for t in plan.tasks if t.get("status") in ("failed", "skipped", "exhausted"))
    pending = sum(1 for t in plan.tasks if t.get("status") == "pending")
    exhausted = sum(1 for t in plan.tasks if t.get("status") == "exhausted"
                    or t.get("id") in orch._exhausted_task_ids)
    lines = [f"## Exploitation Plan ({done}/{len(plan.tasks)} done, {failed} failed, {exhausted} exhausted, {pending} pending)"]
    for t in orch._topological_sort(plan.tasks):
        status = t.get("status", "pending").upper()
        deps = t.get("dependent_task_ids", []) or t.get("dependencies", [])
        dep_str = f" (waits for: {', '.join(deps)})" if deps else ""
        lines.append(f"  {t.get('id','?')}: [{status}] {t.get('instruction','')[:100]}{dep_str}")
    return "\n".join(lines)


# ── Defense Evasion Context ───────────────────────────────────────────────


def build_defense_evasion_context(orch) -> str:
    """Build defense-aware evasion guidance for the plan generation prompt.

    When DPM detects active defenses (WAF, Process Hiding, LOTL), inject
    specific guidance so the LLM adapts its exploitation strategy.
    """
    if not orch.defense_state or orch.defense_state.defense_complexity < 0.1:
        return ""

    parts: list[str] = []
    ds = orch.defense_state

    if ds.waf_type and ds.waf_type != "none":
        parts.append(
            f"**WAF Detected ({ds.waf_type})**: All payloads MUST be encoded BEFORE sending. "
            f"Proactive bypass strategy (apply in order):\n"
            f"  1. Double URL encoding: %25%33%63 → %3c\n"
            f"  2. Case alternation: SeLeCt, UnIoN, FrOm\n"
            f"  3. Inline comments: SEL/**/ECT, UN/**/ION\n"
            f"  4. HTML entity encoding: &#x3c; for <\n"
            f"  5. Parameter pollution: add duplicate params with junk values\n"
            f"  6. Content-Type switch: try multipart/form-data instead of JSON\n"
            f"For SQL injection with WAF, use sqlmap_test with tamper scripts. "
            f"For other payload types, use send_payload with encoding='url_double' or encoding='html_entity'."
        )

    if getattr(ds, 'defense_category_scores', None):
        scores = ds.defense_category_scores
        if isinstance(scores, dict):
            if scores.get("honey", 0) > 0.3:
                parts.append(
                    "**Honeypot Detected**: Be suspicious of unusually easy credentials, "
                    "obvious flag locations (/flag.txt), and unrestricted access to sensitive "
                    "endpoints. Always verify flags through DAVE."
                )
            if scores.get("trap", 0) > 0.3:
                parts.append(
                    "**Trap Detected**: Avoid infinite-loop endpoints, extremely large "
                    "responses, and requests that trigger repeated redirects."
                )
            if scores.get("cloak", 0) > 0.3:
                parts.append(
                    "**Cloak Detected**: Some services/ports may be hidden or respond "
                    "slowly. Probe non-standard ports and use timing analysis."
                )

    if not parts:
        return ""

    return "## Active Defenses (adapt your attack strategy)\n" + "\n".join(parts) + "\n"


# ── Truncation Context ────────────────────────────────────────────────────


def build_truncation_context(orch) -> str:
    """Build structured DKG state summary for injection when conversation is truncated.

    Called by _maybe_compress() when the conversation history is truncated
    (max_compressions reached).  Gives the LLM critical state facts directly
    instead of a generic "DKG has the facts" message.
    """
    lines = ["[DKG STATE AT TRUNCATION — structured facts preserved]"]
    try:
        # Flags captured so far
        flags = orch.dkg.query_nodes("Flag")
        if flags:
            lines.append("Flags: " + ", ".join(
                f.get("value", "?") for f in flags
            ))

        # Credentials discovered
        creds = orch.dkg.query_nodes("Credential")
        if creds:
            lines.append(f"Credentials ({len(creds)}):")
            for c in creds[:8]:
                lines.append(
                    f"  {c.get('cred_type','?')} {c.get('username','?')}"
                    f"@{c.get('source_host','?')}"
                    + (f" (confirmed)" if c.get("confirmed") else "")
                )

        # Active sessions
        sessions = orch.dkg.query_nodes("Session")
        if sessions:
            lines.append(f"Sessions ({len(sessions)}):")
            for s in sessions[:5]:
                lines.append(
                    f"  {s.get('session_type','?')} on {s.get('host','?')}"
                )

        # Services discovered (non-HTTP only to save space)
        services = orch.dkg.query_nodes("Service")
        db_svcs = [s for s in services if s.get("port") and s.get("port") not in (80, 443, 8080, 8443)]
        if db_svcs:
            lines.append(f"Non-HTTP services ({len(db_svcs)}):")
            for s in db_svcs[:10]:
                lines.append(
                    f"  {s.get('service_name','?')} on :{s.get('port')}"
                    f" ({s.get('version','')})".rstrip()
                )

        # Vulnerability summary
        vulns = orch.dkg.query_nodes("Vulnerability")
        if vulns:
            lines.append(f"Known vulnerabilities ({len(vulns)}):")
            for v in vulns[:10]:
                lines.append(
                    f"  {v.get('vuln_type','?')} @ {v.get('endpoint','?')}"
                )
    except Exception:
        lines.append("  (error reading DKG state)")
    return "\n".join(lines)


# ── Checkpoint ────────────────────────────────────────────────────────────


def checkpoint_path(orch, phase: str) -> str:
    """Generate a checkpoint path for a given phase."""
    sanitized = re.sub(r"[^a-zA-Z0-9_.-]", "_", orch.target_url)
    return os.path.join("checkpoints", f"checkpoint_{sanitized}_{phase}.json")


def save_checkpoint(orch, phase_suffix: str = "") -> str:
    """Save full orchestrator state + DKG for potential resume."""
    ts = time.strftime("%Y%m%d_%H%M%S", time.localtime(orch.start_time or time.time()))
    suffix = f"_{phase_suffix}" if phase_suffix else ""
    path = os.path.join("checkpoints", f"resume_{ts}{suffix}.json")
    dkg_path = os.path.join("checkpoints", f"dkg_{ts}{suffix}.json")

    checkpoint = {
        "_format_version": 1,
        "target_url": getattr(orch, 'target_url', ''),
        "phase": orch.phase.value,
        "loop_count": getattr(orch, '_loop_count', 0),
        "step_count": orch.step_count,
        "start_time": orch.start_time,
        "task_description": getattr(orch, '_task_description', ''),
        "solo_iterations": orch._solo_iterations,
        "multi_agent_iterations": orch._multi_agent_iterations,
        "analyze_done": orch._analyze_done,
        "svc_research_done": orch._svc_research_done,
        "research_done": orch._research_done,
        "known_flags": list(orch._known_flags) if hasattr(orch, '_known_flags') else [],
        "solo_exhausted": getattr(orch, '_solo_exhausted', False),
        "multi_exhausted": getattr(orch, '_multi_exhausted', False),
        "vulnerabilities": [
            {"vuln_type": v.vuln_type, "endpoint": v.endpoint,
             "param": v.param, "confidence": v.confidence,
             "evidence": v.evidence, "suggested_tool": v.suggested_tool,
             "tool_args": v.tool_args}
            for v in orch.vulnerabilities
        ],
        "exploitation_plan": (
            {"plan_id": orch.exploitation_plan.plan_id,
             "phase": orch.exploitation_plan.phase,
             "goal": orch.exploitation_plan.goal,
             "tasks": orch.exploitation_plan.tasks,
             "status": orch.exploitation_plan.status}
            if orch.exploitation_plan else None
        ),
        "exhausted_task_ids": list(orch._exhausted_task_ids),
        # Chain / multi-flag mode state
        "chain_mode": getattr(orch, '_chain_mode', False),
        "captured_flags": list(getattr(orch, '_captured_flags', [])),
        "chain_services_total": getattr(orch, '_chain_services_total', 0),
        "chain_exhausted": getattr(orch, '_chain_exhausted', False),
        "no_progress_loops": getattr(orch, '_no_progress_loops', 0),
        "solo_exhausted_stall": getattr(orch, '_solo_exhausted_stall', 0),
        "solo_empty_runs": getattr(orch, '_solo_empty_runs', 0),
        "prev_solo_done_count": getattr(orch, '_prev_solo_done_count', 0),
        "dkg_path": dkg_path,
    }

    os.makedirs("checkpoints", exist_ok=True)
    with open(path, "w") as f:
        json.dump(checkpoint, f, indent=2, default=str)
    orch.dkg.save(dkg_path)
    logger.info("Orchestrator checkpoint saved: %s", path)
    return path


def find_latest_checkpoint(target_url: str = "") -> str | None:
    """Find the most recent orchestrator checkpoint, optionally matching target."""
    import glob
    pattern = os.path.join("checkpoints", "resume_*.json")
    files = sorted(glob.glob(pattern), key=os.path.getmtime, reverse=True)
    if not target_url:
        return files[0] if files else None
    for f in files:
        try:
            with open(f) as fh:
                data = json.load(fh)
            if data.get("target_url") == target_url:
                return f
        except Exception:
            continue
    return None


async def load_checkpoint(orch, path: str) -> bool:
    """Load orchestrator + DKG from checkpoint. Returns True on success."""
    # Import here to avoid circular dependency (OrchestratorPhase,
    # VulnerabilityHypothesis, ExploitationPlan are defined in orchestrator.py).
    from darwin.orchestrator import OrchestratorPhase, VulnerabilityHypothesis, ExploitationPlan

    try:
        with open(path) as f:
            checkpoint = json.load(f)

        if checkpoint.get("_format_version") != 1:
            logger.warning("Checkpoint format version mismatch: %s", path)
            return False

        orch.target_url = checkpoint.get("target_url", orch.target_url)
        orch.phase = OrchestratorPhase(checkpoint.get("phase", "init"))
        orch._loop_count = checkpoint.get("loop_count", 0)
        orch.step_count = checkpoint.get("step_count", 0)
        orch.start_time = checkpoint.get("start_time", time.time())
        orch._task_description = checkpoint.get("task_description", "")
        orch._solo_iterations = checkpoint.get("solo_iterations", 0)
        orch._multi_agent_iterations = checkpoint.get("multi_agent_iterations", 0)
        orch._analyze_done = checkpoint.get("analyze_done", False)
        orch._svc_research_done = checkpoint.get("svc_research_done", False)
        orch._research_done = checkpoint.get("research_done", False)
        orch._known_flags = set(checkpoint.get("known_flags", []))
        orch._solo_exhausted = checkpoint.get("solo_exhausted", False)
        orch._multi_exhausted = checkpoint.get("multi_exhausted", False)
        orch._exhausted_task_ids = set(checkpoint.get("exhausted_task_ids", []))

        # Restore chain / multi-flag mode state
        orch._chain_mode = checkpoint.get("chain_mode", False)
        orch._captured_flags = checkpoint.get("captured_flags", [])
        orch._chain_services_total = checkpoint.get("chain_services_total", 0)
        orch._chain_exhausted = checkpoint.get("chain_exhausted", False)
        orch._no_progress_loops = checkpoint.get("no_progress_loops", 0)
        orch._solo_exhausted_stall = checkpoint.get("solo_exhausted_stall", 0)
        orch._solo_empty_runs = checkpoint.get("solo_empty_runs", 0)
        orch._prev_solo_done_count = checkpoint.get("prev_solo_done_count", 0)

        # Restore vulnerabilities
        orch.vulnerabilities = []
        for vd in checkpoint.get("vulnerabilities", []):
            orch.vulnerabilities.append(VulnerabilityHypothesis(
                vuln_type=vd.get("vuln_type", ""),
                endpoint=vd.get("endpoint", ""),
                param=vd.get("param", ""),
                confidence=vd.get("confidence", 0.0),
                evidence=vd.get("evidence", ""),
                suggested_tool=vd.get("suggested_tool", ""),
                tool_args=vd.get("tool_args", {}),
            ))

        # Restore exploitation plan
        ep_data = checkpoint.get("exploitation_plan")
        if ep_data:
            orch.exploitation_plan = ExploitationPlan(
                plan_id=ep_data.get("plan_id", f"plan-resume-{int(time.time())}"),
                phase=ep_data.get("phase", ""),
                goal=ep_data.get("goal", ""),
                tasks=ep_data.get("tasks", []),
                status=ep_data.get("status", "pending"),
            )

        # Restore DKG
        dkg_path = checkpoint.get("dkg_path", "")
        if dkg_path and os.path.exists(dkg_path):
            from darwin.dkg import DKG
            orch.dkg = DKG.load(dkg_path)
            logger.info("DKG restored from %s (%d nodes)",
                        dkg_path, len(orch.dkg.graph.nodes))

        logger.info("Checkpoint loaded: %s (phase=%s, loop=%d, step=%d)",
                    path, orch.phase.value, orch._loop_count, orch.step_count)
        return True
    except Exception as e:
        logger.error("Failed to load checkpoint %s: %s", path, e)
        return False


# ── Task Logging ──────────────────────────────────────────────────────────


def task_log_event(orch, level: str, event: str, **data: Any) -> None:
    """Record a structured event in the task log."""
    orch._task_log.append({
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime()),
        "elapsed_s": round(time.time() - orch.start_time, 3),
        "phase": orch.phase.value,
        "level": level,
        "event": event,
        **data,
    })


def task_log_write(orch) -> None:
    """Persist the task log to JSON file."""
    if orch._task_log_path and orch._task_log:
        os.makedirs(os.path.dirname(orch._task_log_path) or ".", exist_ok=True)
        with open(orch._task_log_path, "w", encoding="utf-8") as f:
            json.dump({
                "target": orch.target_url,
                "model": orch.llm.model,
                "provider": orch.llm.provider,
                "time_budget": orch.time_budget,
                "events": orch._task_log,
                "dkg_summary": orch.dkg.summary(),
                "cteg_patterns_committed": getattr(orch, '_cteg_committed', 0),
            }, f, indent=2, default=str)
        logger.info("Task log written to %s (%d events)", orch._task_log_path, len(orch._task_log))


# ── JSON Extraction ───────────────────────────────────────────────────────


def extract_json_array(text: str) -> list | None:
    """Extract the first complete JSON array using bracket counting.

    Handles nested brackets and trailing text — more robust than regex.
    Returns the parsed list, or None if no valid array found.
    """
    start = text.find('[')
    if start == -1:
        return None
    depth = 0
    for i, c in enumerate(text[start:], start):
        if c == '[':
            depth += 1
        elif c == ']':
            depth -= 1
            if depth == 0:
                try:
                    return json.loads(text[start:i + 1])
                except json.JSONDecodeError:
                    return None
    return None


def extract_json(text: str) -> Any:
    """Extract JSON from LLM response text."""
    # Try direct parse
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    # Try to find JSON array/object in markdown code blocks
    match = re.search(r"```(?:json)?\s*([\s\S]*?)```", text)
    if match:
        try:
            return json.loads(match.group(1))
        except json.JSONDecodeError:
            pass
    # Try bracket-counting for JSON arrays (handles nesting + trailing text)
    result = extract_json_array(text)
    if result is not None:
        return result
    # Non-greedy match for JSON objects (no nesting issues with {})
    match = re.search(r"\{.*?\}", text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(0))
        except json.JSONDecodeError:
            pass
    return {}


# ── Parse Summary ─────────────────────────────────────────────────────────


def format_parse_summary(parsed: dict) -> str:
    """Convert parse_response output to a compact (<800 char) string."""
    lines = []
    ct = parsed.get("type", "?")
    size = parsed.get("size_bytes", 0)
    if size > 1048576:
        size_str = f"{size / 1048576:.1f}MB"
    elif size > 1024:
        size_str = f"{size / 1024:.1f}KB"
    else:
        size_str = f"{size}B"
    lines.append(f"Type={ct}, Size={size_str}")

    flags = parsed.get("flags", [])
    if flags:
        lines.append(f"FLAGS={flags}")

    if ct == "html":
        if parsed.get("title"):
            lines.append(f"Title: {parsed['title'][:80]}")
        lines.append(f"Forms={parsed.get('forms',0)} Inputs={parsed.get('inputs',0)} Links={parsed.get('links_count',0)}")
        apis = parsed.get("api_paths", [])
        if apis:
            lines.append(f"API: {' '.join(apis[:8])[:180]}")
        eps = parsed.get("endpoints", [])
        if eps:
            lines.append(f"EP: {' '.join(eps[:10])[:200]}")
        sc = parsed.get("scripts", [])
        if sc:
            lines.append(f"JS: {' '.join(sc[:5])[:150]}")
    elif ct == "json":
        tlk = parsed.get("top_level_keys")
        if tlk:
            lines.append(f"Keys: {tlk}")
        iv = parsed.get("interesting_values", [])
        for item in iv[:5]:
            lines.append(f"  [{item['path']}]: {item['value'][:80]}")
    elif ct == "text":
        urls = parsed.get("urls", [])
        if urls:
            lines.append(f"URLs: {' '.join(urls[:6])}")
        jwts = parsed.get("jwt_tokens", [])
        if jwts:
            lines.append(f"JWT: {jwts[:3]}")

    result = "\n".join(lines)
    return result[:800]


# ── Console Printing ──────────────────────────────────────────────────────


def print_phase(orch, name: str) -> None:
    """Print a phase transition banner."""
    line = "=" * 56
    print(f"\n{line}\n  PHASE: {name}\n{line}")


def print_discovery(orch, category: str, items: list[str], max_show: int = 8) -> None:
    """Print discovered items with count. Skips if empty."""
    if not items:
        return
    print(f"\n[{category}] {len(items)} discovered:")
    for item in items[:max_show]:
        print(f"  - {item}")
    if len(items) > max_show:
        print(f"  ... and {len(items) - max_show} more")


def print_plan_status(orch) -> None:
    """Print current exploitation plan status to console."""
    status = format_plan_status(orch)
    if status and status != "(no plan)":
        print(f"\n{status}")


def print_task_execution(orch, task: dict, tool_names: list[str], iteration: int) -> None:
    """Print task execution header."""
    tid = task.get("id", "?")
    instr = task.get("instruction", "")[:100]
    print(f"\n[{orch.phase.value.upper()}:{iteration}] Task {tid}: {instr}")
    if tool_names:
        print(f"  Tools: {', '.join(tool_names[:3])}")


def print_task_result(orch, task: dict, success: bool, result_summary: str) -> None:
    """Print task result summary."""
    status_icon = "  [OK]" if success else "  [FAIL]"
    print(f"{status_icon} {result_summary[:250]}")


def print_progress(orch, scaling_level: Any, B: float) -> None:
    """Print loop progress indicator."""
    elapsed = time.time() - orch.start_time
    flag_count = len(getattr(orch, '_known_flags', set()))
    print(
        f"\n{'─' * 48}\n"
        f"Loop {orch._loop_count}/{getattr(orch, 'MAX_LOOPS', 10)} | "
        f"Phase: {orch.phase.value.upper()} | "
        f"Mode: {scaling_level.value if hasattr(scaling_level, 'value') else scaling_level}"
        f" (B={B:.2f}) | "
        f"Flags: {flag_count} | "
        f"Tokens: {orch.llm.token_count} | "
        f"Elapsed: {elapsed:.0f}s/{orch.time_budget}s\n"
        f"{'─' * 48}"
    )
