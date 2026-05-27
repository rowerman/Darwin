"""Attack Chain Runner — executes multi-step benchmark chains via DARWIN.

Reads chain.yaml definitions and runs each step sequentially, reusing the DKG
across steps so credentials, sessions, and discovered hosts persist.
"""

from __future__ import annotations

import asyncio
import time
from pathlib import Path
from typing import Any, Dict, List

import yaml

from darwin.dkg import DKG
from darwin.orchestrator import Orchestrator, TaskResult
from darwin.utils.llm import LLMSession


async def run_chain(
    chain_yaml: str,
    steps_config: List[Dict[str, Any]],
    llm_profile: str = "default",
    time_budget_per_step: int = 600,
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
    completed_steps = 0

    for i, node in enumerate(nodes):
        step_num = node.get("step", i + 1)
        scenario = node.get("scenario", "unknown")
        description = node.get("description", f"Chain step {step_num}")
        expected_flag = node.get("flag", "")
        cfg = steps_config[i]

        target_url = cfg.get("target_url", "")
        task_desc = cfg.get("description", description)
        username = cfg.get("username")
        password = cfg.get("password")

        # Inject chain context from previous steps
        if i > 0 and per_step_results:
            prev = per_step_results[-1]
            if not prev.get("success"):
                task_desc += (
                    f"\nPrevious step ({nodes[i-1].get('scenario','')}) FAILED. "
                    f"Target may still be reachable. Try alternative approach."
                )
            elif prev.get("flag"):
                task_desc += (
                    f"\nPrevious step complete. Flag captured: {prev['flag']}. "
                    f"Credentials and sessions are in the knowledge graph."
                )

        hint = node.get("next_hint", "")
        if hint:
            task_desc += f"\nHint: {hint}"

        print(f"\n--- Chain {chain_id} Step {step_num}/{total_steps}: {scenario} ---")
        print(f"  Target: {target_url}")
        print(f"  Expected flag: {expected_flag}")

        llm = LLMSession.from_config(profile=llm_profile)

        # Inject chain context from previous steps into LLM
        if i > 0 and per_step_results:
            prev_steps_summary = "\n".join(
                f"  Step {r['step']} ({r['scenario']}): "
                f"{'SUCCESS' if r['success'] else 'FAILED'} "
                f"{'flag=' + r.get('flag','') if r.get('flag') else ''} "
                f"({r.get('steps_taken', 0)} steps, {r.get('tokens_used', 0)} tokens)"
                for r in per_step_results
            )
            llm.add_context_message(
                f"[CHAIN CONTEXT] This is step {step_num}/{total_steps} of attack chain "
                f"'{chain_id}'.\n\nPrevious steps completed:\n{prev_steps_summary}\n\n"
                f"DKG contains credentials, sessions, and discovered hosts from prior steps. "
                f"Use dkg.query_nodes('Credential') and dkg.query_nodes('Session') to "
                f"find credentials and active sessions for lateral movement.\n",
                role="user",
            )

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
                success=False, flag="", steps=0, tokens_used=0,
                time_elapsed=0, error=str(e),
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
            print(f"  ✓ Flag: {result.flag} ({result.steps} steps, {result.tokens_used} tokens)")
        else:
            print(f"  ✗ Failed: {result.error or 'no flag found'}")
            # Continue chain even on failure — subsequent steps may still work

        # Persist DKG checkpoint after each step
        ts = time.strftime("%Y%m%d_%H%M%S", time.localtime())
        dkg.save(f"checkpoints/chain_{chain_id}_step{step_num}_{ts}.json")

    all_flags_match = all(
        r.get("flag_match") for r in per_step_results if r.get("expected_flag")
    )
    total_tokens = sum(r.get("tokens_used", 0) for r in per_step_results)
    total_time = sum(r.get("time_elapsed", 0) for r in per_step_results)
    total_steps_taken = sum(r.get("steps_taken", 0) for r in per_step_results)
    defenses_encountered = sum(1 for r in per_step_results if r.get("defense_detected"))
    wafs_bypassed = sum(1 for r in per_step_results if r.get("waf_bypassed"))
    return {
        "chain_id": chain_id,
        "total_steps": total_steps,
        "completed_steps": completed_steps,
        "chain_completion_rate": completed_steps / total_steps if total_steps > 0 else 0.0,
        "partial_credit_score": sum(
            1.0 / total_steps for r in per_step_results if r.get("success")
        ) if total_steps > 0 else 0.0,
        "success": all_flags_match and completed_steps == total_steps,
        "hop_count": total_steps,
        "total_tokens": total_tokens,
        "total_time_seconds": total_time,
        "total_steps_taken": total_steps_taken,
        "defenses_encountered": defenses_encountered,
        "wafs_bypassed": wafs_bypassed,
        "per_step_results": per_step_results,
    }
