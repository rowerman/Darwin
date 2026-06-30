"""Attack Chain Runner — executes multi-step benchmark chains via DARWIN.

Reads chain.yaml definitions and runs each step sequentially, reusing the DKG
across steps so credentials, sessions, and discovered hosts persist.

Supports checkpoint/resume: saves chain progress after each step to
checkpoints/chains/, and can resume from the last saved checkpoint.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import time
from pathlib import Path
from typing import Any, Dict, List

import yaml

from darwin.dkg import DKG
from darwin.orchestrator import Orchestrator, TaskResult
from darwin.utils.llm import LLMSession

log = logging.getLogger(__name__)

CHAIN_CHECKPOINT_DIR = os.path.join("checkpoints", "chains")


# ── Chain context builder ────────────────────────────────────────────

def _build_chain_context(
    dkg: DKG,
    per_step_results: list,
    step_num: int,
    total_steps: int,
    chain_id: str,
) -> str:
    """Build rich chain context from DKG state for injection into next step.

    Extracts credentials, sessions, hosts, flags, and non-HTTP services
    from the DKG so the next step's LLM has full awareness of intermediate
    artifacts discovered in prior steps.
    """
    lines = [
        f"[CHAIN CONTEXT] This is step {step_num}/{total_steps} of attack "
        f"chain '{chain_id}'.\n",
        "PREVIOUS STEPS:",
    ]
    for r in per_step_results:
        status = "SUCCESS" if r.get("success") else "FAILED"
        flag = r.get("flag", "")
        lines.append(
            f"  Step {r['step']} ({r['scenario']}): {status}"
            + (f" flag={flag}" if flag else "")
            + (f" error={r.get('error','')}" if r.get("error") and not r.get("success") else "")
        )

    # Extract intermediate artifacts from DKG
    try:
        creds = dkg.query_nodes("Credential")
        if creds:
            lines.append(f"\nCredentials discovered ({len(creds)}):")
            for c in creds:
                lines.append(
                    f"  {c.get('cred_type','?')} {c.get('username','?')}"
                    f"@{c.get('source_host','?')}"
                    + (" (confirmed)" if c.get("confirmed") else "")
                )

        sessions = dkg.query_nodes("Session")
        if sessions:
            lines.append(f"\nActive sessions ({len(sessions)}):")
            for s in sessions:
                lines.append(
                    f"  {s.get('session_type','?')} on {s.get('host','?')}"
                )

        hosts = dkg.query_nodes("Host")
        internal = [h for h in hosts if h.get("role") == "internal"]
        if internal:
            lines.append(f"\nInternal hosts discovered ({len(internal)}):")
            for h in internal:
                lines.append(f"  {h.get('hostname','?')} ({h.get('ip','?')})")

        flags = dkg.query_nodes("Flag")
        if flags:
            lines.append(f"\nFlags captured ({len(flags)}):")
            for f in flags:
                lines.append(f"  {f.get('value','?')}")

        services = dkg.query_nodes("Service")
        non_http = [s for s in services
                    if s.get("port") and s.get("port") not in (80, 443, 8080, 8443)]
        if non_http:
            lines.append(f"\nNon-HTTP services ({len(non_http)}):")
            for s in non_http[:10]:
                lines.append(
                    f"  {s.get('service_name','?')} on :{s.get('port')} "
                    f"({s.get('version','')})".rstrip()
                )
    except Exception:
        pass

    lines.append(
        "\nUse DKG credentials, sessions, and discovered hosts for lateral "
        "movement and credential reuse in this step."
    )
    return "\n".join(lines)


# ── Chain checkpoint functions ────────────────────────────────────────

def save_chain_checkpoint(
    chain_id: str,
    current_step: int,
    total_steps: int,
    per_step_results: list,
    dkg: DKG,
) -> str:
    """Save chain progress checkpoint for potential resume.

    Args:
        chain_id: Chain identifier.
        current_step: Number of steps COMPLETED (0-indexed after completion).
        total_steps: Total number of steps in the chain.
        per_step_results: List of per-step result dicts for completed steps.
        dkg: Current DKG state.

    Returns:
        Path to the saved checkpoint file.
    """
    ts = time.strftime("%Y%m%d_%H%M%S", time.localtime())
    os.makedirs(CHAIN_CHECKPOINT_DIR, exist_ok=True)

    cp_path = os.path.join(
        CHAIN_CHECKPOINT_DIR, f"{chain_id}_step{current_step}_{ts}.json"
    )
    dkg_path = os.path.join(
        CHAIN_CHECKPOINT_DIR, f"{chain_id}_dkg_step{current_step}_{ts}.json"
    )

    checkpoint = {
        "_format_version": 1,
        "chain_id": chain_id,
        "current_step": current_step,
        "total_steps": total_steps,
        "per_step_results": per_step_results,
        "dkg_path": dkg_path,
        "saved_at": ts,
    }
    with open(cp_path, "w") as f:
        json.dump(checkpoint, f, indent=2, default=str)
    dkg.save(dkg_path)
    log.info("Chain checkpoint saved: step %d/%d → %s", current_step, total_steps, cp_path)
    return cp_path


def load_chain_checkpoint(chain_id: str) -> dict | None:
    """Find the most recent chain checkpoint. Returns None if not found."""
    if not os.path.isdir(CHAIN_CHECKPOINT_DIR):
        return None

    pattern = re.compile(rf"{re.escape(chain_id)}_step(\d+)_(\d{{8}}_\d{{6}})\.json$")
    candidates: list[tuple[str, int, str]] = []
    for fname in os.listdir(CHAIN_CHECKPOINT_DIR):
        m = pattern.match(fname)
        if m:
            candidates.append((fname, int(m.group(1)), m.group(2)))

    if not candidates:
        return None

    candidates.sort(key=lambda x: x[2], reverse=True)  # latest first
    latest = candidates[0]
    cp_path = os.path.join(CHAIN_CHECKPOINT_DIR, latest[0])

    with open(cp_path) as f:
        checkpoint = json.load(f)

    log.info(
        "Found chain checkpoint: step %d/%d (%s)",
        checkpoint["current_step"],
        checkpoint["total_steps"],
        cp_path,
    )
    return checkpoint


# ── Main chain runner ─────────────────────────────────────────────────

async def run_chain(
    chain_yaml: str,
    steps_config: List[Dict[str, Any]],
    llm_profile: str = "default",
    time_budget_per_step: int = 600,
    resume: bool = False,
) -> Dict[str, Any]:
    """Run an attack chain across multiple scenarios.

    Args:
        chain_yaml: Path to chain.yaml file.
        steps_config: List of per-step configs, each with:
            - target_url (str): URL/host for this step
            - description (str): task description
            - username (str | None): SSH/creds for this step
            - password (str | None): SSH/creds for this step
        llm_profile: LLM config profile name.
        time_budget_per_step: Max seconds per step.
        resume: If True, load the most recent checkpoint and skip
                completed steps.

    Returns:
        Dict with chain_id, completed_steps, total_steps, success, per_step_results.
    """
    with open(chain_yaml) as f:
        chain = yaml.safe_load(f)

    nodes = chain.get("nodes", [])
    chain_id = chain.get("chain_id", Path(chain_yaml).stem)
    total_steps = len(nodes)

    if len(steps_config) != total_steps:
        raise ValueError(
            f"Chain has {total_steps} steps but {len(steps_config)} step configs provided"
        )

    dkg = DKG()
    per_step_results: List[Dict[str, Any]] = []
    start_step = 0

    # ── Resume logic ──
    if resume:
        checkpoint = load_chain_checkpoint(chain_id)
        if checkpoint:
            per_step_results = checkpoint.get("per_step_results", [])
            start_step = checkpoint.get("current_step", 0)
            dkg_path = checkpoint.get("dkg_path", "")
            if dkg_path and os.path.exists(dkg_path):
                dkg.load(dkg_path)
                log.info(
                    "Resumed DKG from %s (%d nodes)",
                    dkg_path,
                    len(dkg.graph.nodes),
                )
            log.info(
                "Resuming chain '%s' from step %d/%d",
                chain_id,
                start_step + 1,
                total_steps,
            )

    completed_steps = sum(1 for r in per_step_results if r.get("success"))

    for i in range(start_step, total_steps):
        node = nodes[i]
        step_num = node.get("step", i + 1)
        scenario = node.get("scenario", "unknown")
        description = node.get("description", f"Chain step {step_num}")
        expected_flag = node.get("flag", "")
        cfg = steps_config[i]

        target_url = cfg.get("target_url", "")
        task_desc = cfg.get("description", description)
        username = cfg.get("username")
        password = cfg.get("password")

        hint = node.get("next_hint", "")
        if hint:
            task_desc += f"\nHint: {hint}"

        print(f"\n--- Chain {chain_id} Step {step_num}/{total_steps}: {scenario} ---")
        print(f"  Target: {target_url}")
        print(f"  Expected flag: {expected_flag}")

        llm = LLMSession.from_config(profile=llm_profile)

        # ── Inject rich chain context ──
        chain_context = _build_chain_context(
            dkg, per_step_results, step_num, total_steps, chain_id
        )
        llm.add_context_message(chain_context, role="user")

        orch = Orchestrator(
            llm_session=llm,
            time_budget=time_budget_per_step,
            dkg=dkg,
        )

        try:
            result: TaskResult = await orch.run(
                task_description=task_desc,
                target_url=target_url,
                username=username,
                password=password,
            )
        except Exception as e:
            result = TaskResult(
                success=False,
                flag="",
                steps=0,
                tokens_used=0,
                time_elapsed=0,
                error=str(e),
            )

        step_result = {
            "step": step_num,
            "scenario": scenario,
            "target_url": target_url,
            "success": result.success,
            "flag": result.flag,
            "expected_flag": expected_flag,
            "flag_match": result.flag == expected_flag if expected_flag else None,
            "steps_taken": result.steps,
            "tokens_used": result.tokens_used,
            "time_elapsed": result.time_elapsed,
            "defense_detected": result.defense_detected,
            "waf_bypassed": result.waf_bypassed,
            "error": result.error,
        }
        per_step_results.append(step_result)

        if result.success:
            completed_steps += 1
            print(
                f"  ✓ Flag: {result.flag} ({result.steps} steps, "
                f"{result.tokens_used} tokens)"
            )
        else:
            print(f"  ✗ Failed: {result.error or 'no flag found'}")
            # Continue chain even on failure — subsequent steps may still work

        # ── Persist chain checkpoint after each step ──
        save_chain_checkpoint(
            chain_id, i + 1, total_steps, per_step_results, dkg
        )

    all_flags_match = all(
        r.get("flag_match") for r in per_step_results if r.get("expected_flag")
    )
    total_tokens = sum(r.get("tokens_used", 0) for r in per_step_results)
    total_time = sum(r.get("time_elapsed", 0) for r in per_step_results)
    total_steps_taken = sum(r.get("steps_taken", 0) for r in per_step_results)
    defenses_encountered = sum(
        1 for r in per_step_results if r.get("defense_detected")
    )
    wafs_bypassed = sum(1 for r in per_step_results if r.get("waf_bypassed"))

    return {
        "chain_id": chain_id,
        "total_steps": total_steps,
        "completed_steps": completed_steps,
        "chain_completion_rate": (
            completed_steps / total_steps if total_steps > 0 else 0.0
        ),
        "partial_credit_score": (
            sum(1.0 / total_steps for r in per_step_results if r.get("success"))
            if total_steps > 0
            else 0.0
        ),
        "success": all_flags_match and completed_steps == total_steps,
        "hop_count": total_steps,
        "total_tokens": total_tokens,
        "total_time_seconds": total_time,
        "total_steps_taken": total_steps_taken,
        "defenses_encountered": defenses_encountered,
        "wafs_bypassed": wafs_bypassed,
        "per_step_results": per_step_results,
    }
