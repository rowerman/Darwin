#!/usr/bin/env python3
"""Transform runner.py into a slim solo-only orchestrator."""

import re
import sys

PATH = "/home/kianabin/Darwin/darwin/runner.py"

with open(PATH) as f:
    text = f.read()

lines = text.split("\n")
print(f"Read {len(lines)} lines")

# ============================================================
# 1. Fix imports (lines 24-36)
# ============================================================
old_imports = """from darwin.cteg import CTEG, TaskRecord
from darwin.data_model import normalize_dkg_state, PipelineState, EndpointInfo
from darwin.dkg import DKG
from darwin.dpm import DefensePerceptionModule, DefenseStateVector
from darwin.dave import DAVE, ExploitAttempt, parse_tool_stdout
from darwin.tools.mcp_client import MCPClientPool, load_mcp_config
from darwin.tools.mcp_gateway import MCPGateway, ToolResult
from darwin.tools.recon_server import create_recon_gateway, parse_response
from darwin.tools.attack_server import create_attack_gateway
from darwin.utils.http_client import HTTPClient, ProbeClient, HTTPResponse
from darwin.utils.llm import LLMSession
from darwin.utils.phase_logger import PhaseLogger
"""

new_imports = """from darwin.cteg import CTEG, TaskRecord
from darwin.data_model import normalize_dkg_state, PipelineState, EndpointInfo
from darwin.dkg import DKG
from darwin.dpm import DefensePerceptionModule, DefenseStateVector
from darwin.dave import DAVE, ExploitAttempt, parse_tool_stdout
from darwin.tools.mcp_client import MCPClientPool, load_mcp_config
from darwin.tools.mcp_gateway import MCPGateway, ToolResult
from darwin.tools.recon_server import create_recon_gateway, parse_response
from darwin.tools.attack_server import create_attack_gateway
from darwin.utils.http_client import HTTPClient, ProbeClient, HTTPResponse
from darwin.utils.llm import LLMSession
from darwin.utils.phase_logger import PhaseLogger

# Module imports - thin wrappers delegate to these
from darwin.bootstrap import bootstrap_scan as _bootstrap_scan_fn
from darwin.bootstrap import deep_recon as _deep_recon_fn
from darwin.bootstrap import detect_defenses as _detect_defenses_fn
from darwin.bootstrap import cloud_discovery_hint as _cloud_discovery_hint_fn
from darwin.bootstrap import try_auto_login as _try_auto_login_fn
from darwin.bootstrap import try_db_default_credentials as _try_db_default_credentials_fn
from darwin.analyzer import service_research as _service_research_fn
from darwin.analyzer import active_service_research as _active_service_research_fn
from darwin.analyzer import analyze_phase as _analyze_phase_fn
from darwin.analyzer import augment_from_dkg as _augment_from_dkg_fn
from darwin.analyzer import research_phase as _research_phase_fn
from darwin.planner import generate_exploitation_plan as _generate_exploitation_plan_fn
from darwin.planner import validate_plan as _validate_plan_fn
from darwin.planner import sanitize_plan_tools as _sanitize_plan_tools_fn
from darwin.planner import select_next_plan_task as _select_next_plan_task_fn
from darwin.planner import review_and_update_plan as _review_and_update_plan_fn
from darwin.planner import classify_and_replan as _classify_and_replan_fn
from darwin.planner import replan_after_failure as _replan_after_failure_fn
from darwin.planner import sync_plan_to_dkg as _sync_plan_to_dkg_fn
from darwin.planner import generate_phase_summary as _generate_phase_summary_fn
from darwin.planner import is_duplicate_task as _is_duplicate_task_fn
from darwin.planner import cap_pending_tasks as _cap_pending_tasks_fn
from darwin.planner import update_plan_after_task as _update_plan_after_task_fn
from darwin.state import get_state as _get_state_fn
from darwin.state import build_cycle_summary as _build_cycle_summary_fn
from darwin.state import extract_recent_artifacts as _extract_recent_artifacts_fn
from darwin.state import detect_chain_topology as _detect_chain_topology_fn
from darwin.state import save_checkpoint as _save_checkpoint_fn
from darwin.state import find_latest_checkpoint as _find_latest_checkpoint_fn
from darwin.state import load_checkpoint as _load_checkpoint_fn
from darwin.state import print_phase as _print_phase_fn
from darwin.state import print_discovery as _print_discovery_fn
"""

# Find the import block - line 24 (0-indexed: 23)
old_imports_start = text.find(old_imports)
if old_imports_start >= 0:
    text = text.replace(old_imports, new_imports, 1)
    print("1. Imports replaced")
else:
    print("1. WARNING: Could not find old imports block")

# ============================================================
# 2. Simplify __init__ - remove scaling engine and multi-agent fields
# ============================================================
# Remove: self.scaling_engine = DynamicScalingEngine(hysteresis=2)
text = text.replace(
    "        self.scaling_engine = DynamicScalingEngine(hysteresis=2)\n",
    "",
    1
)
print("2a. Removed scaling_engine")

# Remove multi-agent related fields from __init__
lines_to_remove = [
    "        self._multi_pool = None  # SubAgentPool, created on first multi-agent cycle",
    "        self._dkg_snapshot: dict[str, int] = {}",
    "        self._solo_iterations = 0",
    "        self._multi_agent_iterations = 0",
    "        self._solo_exhausted = False",
    "        self._multi_exhausted = False",
    "        self._solo_exhausted_stall = 0",
    "        self._solo_empty_runs = 0",
    "        self._prev_solo_done_count = 0",
]
for lr in lines_to_remove:
    text = text.replace(lr + "\n", "", 1)

# Also remove comment referencing multi-agent
text = text.replace(
    "        # DKG state snapshot for cross-agent coordination detection\n        # (ReconAgent discoveries → ExploitAgent replan trigger)\n",
    "",
    1
)
print("2b. Removed multi-agent __init__ fields")

# ============================================================
# 3. Add thin wrapper methods after __init__ (before run())
# ============================================================
thin_wrappers = """
    # ── Thin wrappers delegating to module functions ──────────────

    async def _bootstrap_scan(self, target_url, port_range=None):
        return await _bootstrap_scan_fn(self, target_url, port_range)

    async def _deep_recon(self):
        return await _deep_recon_fn(self)

    async def _detect_defenses(self):
        return await _detect_defenses_fn(self)

    async def _cloud_discovery_hint(self):
        return await _cloud_discovery_hint_fn(self)

    async def _try_auto_login(self, target_url, endpoint_url, username, password):
        return await _try_auto_login_fn(self, target_url, endpoint_url, username, password)

    async def _try_db_default_credentials(self, host, discovered_ports):
        return await _try_db_default_credentials_fn(self, host, discovered_ports)

    async def _service_research(self):
        return await _service_research_fn(self)

    async def _active_service_research(self):
        return await _active_service_research_fn(self)

    async def _analyze_phase(self):
        return await _analyze_phase_fn(self)

    async def _augment_from_dkg(self):
        return await _augment_from_dkg_fn(self)

    async def _research_phase(self):
        return await _research_phase_fn(self)

    async def _generate_exploitation_plan(self, target_url, cteg_hints=None):
        plan = await _generate_exploitation_plan_fn(self, target_url, cteg_hints)
        # NEW: validate plan after generation
        errors = _validate_plan_fn(self, plan.tasks if plan else [])
        if errors:
            log.warning("Plan validation: %d issue(s)", len(errors))
            for e in errors[:5]:
                log.warning("  %s", e)
        return plan

    def _select_next_plan_task(self, plan=None):
        return _select_next_plan_task_fn(self, plan)

    async def _review_and_update_plan(self, task, success, task_result=""):
        plan = self.exploitation_plan
        await _review_and_update_plan_fn(self, task, success, task_result)
        # NEW: validate plan after review
        if self.exploitation_plan and self.exploitation_plan != plan:
            errors = _validate_plan_fn(self, self.exploitation_plan.tasks)
            if errors:
                log.warning("Plan validation after review: %d issue(s)", len(errors))
                for e in errors[:5]:
                    log.warning("  %s", e)

    async def _replan_after_failure(self, failed_task, result=None):
        # NEW: use classify_and_replan instead of simple replan
        return await _classify_and_replan_fn(self, failed_task, result)

    def _sanitize_plan_tools(self, tasks):
        return _sanitize_plan_tools_fn(self, tasks)

    def _sync_plan_to_dkg(self):
        return _sync_plan_to_dkg_fn(self)

    def _generate_phase_summary(self, phase="exploit"):
        return _generate_phase_summary_fn(self, phase)

    def _is_duplicate_task(self, new_task, existing_tasks):
        return _is_duplicate_task_fn(new_task, existing_tasks)

    def _cap_pending_tasks(self, tasks, max_total=20, max_pending=7):
        return _cap_pending_tasks_fn(self, tasks, max_total, max_pending)

    async def _update_plan_after_task(self, task, success, result=None):
        return await _update_plan_after_task_fn(self, task, success, result)

    def _get_state(self):
        return _get_state_fn(self)

    def _build_cycle_summary(self):
        return _build_cycle_summary_fn(self)

    def _extract_recent_artifacts(self):
        return _extract_recent_artifacts_fn(self)

    def _detect_chain_topology(self, chain_mode_config="auto"):
        return _detect_chain_topology_fn(self, chain_mode_config)

    def _save_orchestrator_checkpoint(self, phase_suffix=""):
        return _save_checkpoint_fn(self, phase_suffix)

    @staticmethod
    def _find_latest_checkpoint(target_url=""):
        return _find_latest_checkpoint_fn(target_url)

    async def _load_orchestrator_checkpoint(self, path):
        return await _load_checkpoint_fn(self, path)

    def _print_phase(self, name):
        return _print_phase_fn(self, name)

    def _print_discovery(self, category, items, max_show=8):
        return _print_discovery_fn(self, category, items, max_show)

    def _print_plan_status(self):
        return _print_plan_status_fn(self)

    def _print_task_execution(self, task, tool_names, iteration):
        return _print_task_execution_fn(self, task, tool_names, iteration)

    def _print_task_result(self, task, success, result_summary):
        return _print_task_result_fn(self, task, success, result_summary)

    def _print_progress(self, *args, **kwargs):
        # Simplified - no B value or scaling level
        print(f"\\n[loop {self._loop_count}] flags={len(self._known_flags)}, "
              f"tokens={self.llm.token_count}, "
              f"elapsed={time.time() - self.start_time:.0f}s")
"""

# Insert thin wrappers after __init__ (after the last __init__ line and before run())
# Find the async def run( line
insert_marker = "        self._chain_exhausted = False"
insert_point = text.find(insert_marker)
if insert_point >= 0:
    insert_point = text.index("\n", insert_point) + 1  # after the newline
    text = text[:insert_point] + "\n" + thin_wrappers + text[insert_point:]
    print("3. Thin wrappers added after __init__")
else:
    print("3. WARNING: Could not find insertion point for thin wrappers")

# ============================================================
# 4. Simplify run() while loop
# ============================================================
# Find the while loop: "while not self._should_terminate(result, MAX_LOOPS):"
# Remove from that line through the matching dedent level
# We need to replace the entire loop body

old_loop_start = "            while not self._should_terminate(result, MAX_LOOPS):"
loop_start_idx = text.find(old_loop_start)
if loop_start_idx < 0:
    print("4. WARNING: Could not find while loop start")
else:
    # Find where the while loop ends - the next line at the same indentation level
    # The while loop starts with "            while"
    # We need to find the line after the while body that has the same indentation
    # Actually, let's find: "# ── Last resort: generic flag search"
    last_resort_marker = "            # ── Last resort: generic flag search ─────────────────"
    last_resort_idx = text.find(last_resort_marker, loop_start_idx)

    new_loop_body = """            while not self._should_terminate(result, MAX_LOOPS):
                self._loop_count += 1

                # Check DKG for flags found by sub-agents in previous iterations
                dkg_flags = [
                    f.get("value", "") for f in self.dkg.query_nodes("Flag")
                    if f.get("verified") or f.get("value", "").startswith("flag{")
                ]
                for fv in dkg_flags:
                    if fv and fv not in self._known_flags:
                        self._known_flags.add(fv)
                        if not self._chain_mode:
                            # ORIGINAL BEHAVIOR: stop on first flag
                            self.phase = OrchestratorPhase.DONE
                            result = TaskResult(
                                success=True, flag=fv, steps=self.step_count,
                                tokens_used=self.llm.token_count,
                                time_elapsed=time.time() - self.start_time,
                            )
                        else:
                            # CHAIN MODE: record intermediate flag, continue
                            self._captured_flags.append(fv)
                            log.info("Chain mode: captured intermediate flag %s (%d/%d services)",
                                     fv[:40], len(self._captured_flags),
                                     max(self._chain_services_total, 1))
                            # Check if all exploitable services are exhausted
                            if self._count_unexploited_services() == 0:
                                self._chain_exhausted = True
                                log.info("Chain mode: all services exhausted, chain complete")
                if result and result.success:
                    # In chain mode, only break if chain exhausted
                    if self._chain_mode:
                        if self._chain_exhausted:
                            # Build final result with last captured flag
                            final_flag = self._captured_flags[-1] if self._captured_flags else ""
                            result = TaskResult(
                                success=True, flag=final_flag, steps=self.step_count,
                                tokens_used=self.llm.token_count,
                                time_elapsed=time.time() - self.start_time,
                            )
                            result.all_flags = list(self._captured_flags)
                            break
                        # Otherwise continue the loop
                    else:
                        break

                # Service research (once)
                if not self._svc_research_done:
                    await self._service_research()
                    self._svc_research_done = True

                    # ── Phase log: service research ──
                    if self.phase_logger:
                        _cves = []
                        for a in self.dkg.query_nodes("Analysis"):
                            if a.get("type") == "cve_findings" and a.get("content"):
                                _cves.append(a.get("content", "")[:500])
                        _cve_text = "\\n".join(_cves[:10]) if _cves else "(no CVEs found)"
                        self.phase_logger.log_phase("service_research", _cve_text,
                            metadata={"cve_count": len(_cves)})

                # Analyze phase (once)
                if not self._analyze_done:
                    await self._analyze_phase()
                    self._analyze_done = True
                    # Snapshot current discovery count so we can detect
                    # significant new services/endpoints for re-analysis
                    self._analyze_service_snapshot = (
                        len(self.dkg.query_nodes("Service"))
                        + len(self.dkg.query_nodes("Endpoint"))
                    )

                    # ── Phase log: analyze ──
                    if self.phase_logger:
                        _vuln_lines = []
                        for v in self.vulnerabilities[:20]:
                            _vuln_lines.append(
                                f"[{v.vuln_type}] {v.endpoint} param={v.param} "
                                f"conf={v.confidence:.0%}"
                            )
                        _vuln_text = "\\n".join(_vuln_lines) if _vuln_lines else "(no vulnerabilities)"
                        if len(self.vulnerabilities) > 20:
                            _vuln_text += f"\\n... and {len(self.vulnerabilities) - 20} more"
                        self.phase_logger.log_phase("analyze", _vuln_text,
                            metadata={"vuln_count": len(self.vulnerabilities)})

                # Research phase
                if self.vulnerabilities and not self._research_done:
                    log.info("[PHASE] _research_phase START")
                    await self._research_phase()
                    self._research_done = True
                    log.info("[PHASE] _research_phase DONE")

                    # ── Phase log: research ──
                    if self.phase_logger:
                        _researched = sum(
                            1 for v in self.vulnerabilities
                            if v.research_techniques or v.research_cves
                        )
                        self.phase_logger.log_phase("research_phase",
                            f"Researched {_researched}/{len(self.vulnerabilities)} vulnerabilities",
                            metadata={"vulns_total": len(self.vulnerabilities),
                                      "vulns_researched": _researched})

                # Unified LLM loop
                result = await self._unified_llm_loop(target_url, cteg_hints)

                # Re-analyze if new services discovered
                if self._analyze_done and self._reanalyze_count < self._max_reanalyze:
                    _current_svc = len(self.dkg.query_nodes("Service"))
                    _current_eps = len(self.dkg.query_nodes("Endpoint"))
                    _new_total = _current_svc + _current_eps
                    if _new_total > self._analyze_service_snapshot + 2:
                        log.info("New services/endpoints detected (%d→%d), re-running analysis",
                                 self._analyze_service_snapshot, _new_total)
                        self._analyze_done = False
                        self._svc_research_done = False
                        self._reanalyze_count += 1

                # Checkpoint DKG after each loop iteration
                self.dkg.save(self._checkpoint_path(f"loop_{self._loop_count}"))

                # Update no-progress detection
                _cur_eps = len(self.dkg.query_nodes("Endpoint"))
                _cur_creds = len(self.dkg.query_nodes("Credential"))
                _cur_vulns = len(self.dkg.query_nodes("Vulnerability"))
                if (_cur_eps <= self._prev_endpoint_count and
                    _cur_creds <= self._prev_credential_count and
                    _cur_vulns <= self._prev_vulnerability_count):
                    self._no_progress_loops = getattr(self, '_no_progress_loops', 0) + 1
                else:
                    self._no_progress_loops = 0
                    self._prev_endpoint_count = _cur_eps
                    self._prev_credential_count = _cur_creds
                    self._prev_vulnerability_count = _cur_vulns
"""

    text = text[:loop_start_idx] + new_loop_body + text[last_resort_idx:]
    print("4. While loop replaced")

# ============================================================
# 5. Simplify _should_terminate()
# ============================================================
old_terminate = """    def _should_terminate(self, result: TaskResult | None, max_loops: int) -> bool:
        \"\"\"Check if the main loop should stop.\"\"\"
        if result and result.success:
            # Chain mode: only stop if chain exhausted or safety cap reached
            if getattr(self, '_chain_mode', False):
                if getattr(self, '_chain_exhausted', False):
                    log.info("Chain mode: chain exhausted, terminating")
                    return True
                _max_flags = getattr(self, '_chain_max_flags', 10)
                if len(getattr(self, '_captured_flags', [])) >= _max_flags:
                    log.info("Chain mode: safety cap reached (%d flags), terminating", _max_flags)
                    return True
                # Otherwise continue — don't terminate on intermediate flag
            else:
                return True
        if self._time_exceeded() or self._tokens_exceeded():
            return True
        if self.phase in (OrchestratorPhase.DONE, OrchestratorPhase.FAILED):
            return True
        if self._loop_count >= max_loops:
            log.info("Max loops (%d) reached", max_loops)
            return True
        if getattr(self, '_solo_exhausted', False):
            # Multi-agent mode also exhausted → terminate
            if getattr(self, '_multi_exhausted', False):
                log.info("All modes exhausted — terminating main loop")
                return True
            # Solo exhausted, multi never entered — track no-progress loops.
            # In chain mode with multi-agent active, don't count solo stalls
            # (multi-agent is the primary work mode for chain scenarios).
            if not getattr(self, '_chain_mode', False):
                _stalled = getattr(self, '_solo_exhausted_stall', 0) + 1
                self._solo_exhausted_stall = _stalled
                if _stalled >= 3:
                    log.info("Solo mode exhausted, no multi-agent entry after %d loops — terminating", _stalled)
                    return True
        else:
            self._solo_exhausted_stall = 0
        # No-progress: consecutive outer loops with zero new discoveries
        if getattr(self, '_no_progress_loops', 0) >= 2:
            log.info("No progress for %d consecutive loops — terminating", self._no_progress_loops)
            return True
        return False
"""

new_terminate = """    def _should_terminate(self, result: TaskResult | None, max_loops: int) -> bool:
        \"\"\"Check if the main loop should stop - simplified solo-only version.\"\"\"
        if result and result.success:
            if self._chain_mode:
                if self._chain_exhausted:
                    return True
                return False  # continue for more flags
            return True
        if self._time_exceeded() or self._tokens_exceeded():
            return True
        if self.phase in (OrchestratorPhase.DONE, OrchestratorPhase.FAILED):
            return True
        if self._loop_count >= max_loops:
            return True
        if getattr(self, '_no_progress_loops', 0) >= 2:
            return True
        return False
"""

if old_terminate in text:
    text = text.replace(old_terminate, new_terminate, 1)
    print("5. _should_terminate simplified")
else:
    print("5. WARNING: Could not find old _should_terminate")

# ============================================================
# 6. Delete multi-agent methods
# ============================================================
methods_to_delete = [
    ("_scan_collaboration_opportunities", "    def _scan_collaboration_opportunities"),
    ("_run_multi_agent_cycle", "    async def _run_multi_agent_cycle"),
    ("_analyze_from_recon_findings", "    async def _analyze_from_recon_findings"),
    ("_spawn_agents_from_dkg", "    async def _spawn_agents_from_dkg"),
    ("_spawn_followup_agents", "    async def _spawn_followup_agents"),
    ("_take_dkg_snapshot", "    def _take_dkg_snapshot"),
    ("_detect_dkg_changes", "    def _detect_dkg_changes"),
    ("_summarize_dkg_changes", "    def _summarize_dkg_changes"),
    ("_execute_privesc", "    async def _execute_privesc"),
    ("_exploit_phase", "    async def _exploit_phase"),
    ("_llm_driven_exploit", "    async def _llm_driven_exploit"),
]

for name, signature in methods_to_delete:
    idx = text.find(signature)
    if idx >= 0:
        # Find the end - next method at same indentation level ("    def " or "    async def ")
        # or end of file
        rest = text[idx + 1:]  # skip past the def line
        # Find next method at indentation level 4
        next_method = re.search(r"\n    (?:async )?def ", text[idx + 4:])
        if next_method:
            end_idx = idx + 4 + next_method.start()
        else:
            end_idx = len(text)
        # Strip trailing empty lines
        block = text[idx:end_idx]
        text = text[:idx] + text[end_idx:]
        print(f"6. Deleted method {name} ({len(block)} chars)")
    else:
        print(f"6. WARNING: Could not find method {name} to delete")

# ============================================================
# 7. Delete original implementations replaced by thin wrappers
# ============================================================
# These methods have FULL implementations that should now be deleted since
# thin wrappers delegate to module functions.
original_methods_to_delete = [
    ("_bootstrap_scan", "    async def _bootstrap_scan"),
    ("_deep_recon", "    async def _deep_recon"),
    ("_detect_defenses", "    async def _detect_defenses"),
    ("_try_auto_login", "    async def _try_auto_login"),
    ("_try_db_default_credentials", "    async def _try_db_default_credentials"),
    ("_cloud_discovery_hint", "    async def _cloud_discovery_hint"),
    ("_service_research", "    async def _service_research"),
    ("_active_service_research", "    async def _active_service_research"),
    ("_research_phase", "    async def _research_phase"),
    ("_analyze_phase", "    async def _analyze_phase"),
    ("_augment_from_dkg", "    def _augment_from_dkg"),
    ("_generate_exploitation_plan", "    async def _generate_exploitation_plan"),
    ("_sanitize_plan_tools", "    def _sanitize_plan_tools"),
    ("_select_next_plan_task", "    def _select_next_plan_task"),
    ("_review_and_update_plan", "    async def _review_and_update_plan"),
    ("_replan_after_failure", "    async def _replan_after_failure"),
    ("_sync_plan_to_dkg", "    def _sync_plan_to_dkg"),
    ("_generate_phase_summary", "    def _generate_phase_summary"),
    ("_is_duplicate_task", "    def _is_duplicate_task"),
    ("_cap_pending_tasks", "    def _cap_pending_tasks"),
    ("_update_plan_after_task", "    async def _update_plan_after_task"),
    ("_get_state", "    def _get_state"),
    ("_build_cycle_summary", "    def _build_cycle_summary"),
    ("_extract_recent_artifacts", "    def _extract_recent_artifacts"),
    ("_detect_chain_topology", "    def _detect_chain_topology"),
    ("_save_orchestrator_checkpoint", "    def _save_orchestrator_checkpoint"),
    ("_find_latest_checkpoint", "    def _find_latest_checkpoint"),
    ("_load_orchestrator_checkpoint", "    async def _load_orchestrator_checkpoint"),
    ("_print_phase", "    def _print_phase\("),
    ("_print_discovery", "    def _print_discovery\("),
    ("_print_plan_status", "    def _print_plan_status"),
    ("_print_task_execution", "    def _print_task_execution"),
    ("_print_task_result", "    def _print_task_result"),
    ("_print_progress", "    def _print_progress"),
]

for name, signature_re in original_methods_to_delete:
    # Use re.escape for the signature
    pattern = r"\n    " + signature_re  # match at start of line
    if "\\(" in signature_re:
        pattern = r"\n    " + signature_re
    else:
        pattern = r"\n    " + re.escape(signature_re)

    match = re.search(pattern, text)
    if match:
        method_start = match.start() + 1  # include the newline
        rest = text[method_start + 1:]

        # Find the body - skip the def line and docstring/body
        # Find next method at indentation level 4, or end of file
        next_method = re.search(r"\n    (?:async )?def ", text[method_start + 4:])
        if next_method:
            end_idx = method_start + 4 + next_method.start()
        else:
            end_idx = len(text)

        # Check if the method ends with a blank line before the next one
        block = text[method_start:end_idx]
        # Remove the block
        text = text[:method_start] + text[end_idx:]
        print(f"7. Deleted original method {name} ({len(block)} chars)")
    else:
        print(f"7. WARNING: Could not find original method {name} to delete")

# ============================================================
# 8. Write result
# ============================================================
with open(PATH, "w") as f:
    f.write(text)

new_lines = text.split("\n")
print(f"\nDone! {len(lines)} lines -> {len(new_lines)} lines")
print(f"Removed {len(lines) - len(new_lines)} lines")
