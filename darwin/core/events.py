"""Unified runtime event vocabulary (P2).

Aligns with the trace events already emitted by the orchestrator task log
(M0): plan_generated, task_scheduled, tool_result. Later milestones wire
every component to emit these events so a run is fully reconstructible.
"""

from __future__ import annotations

from enum import Enum


class RuntimeEvent(str, Enum):
    """Canonical event names for the v2 control plane."""

    RUN_STARTED = "run_started"
    STATE_OBSERVED = "state_observed"
    PLAN_GENERATED = "plan_generated"
    TASK_CREATED = "task_created"
    TASK_SCHEDULED = "task_scheduled"
    TASK_STARTED = "task_started"
    CAPABILITY_SELECTED = "capability_selected"
    TOOL_CALLED = "tool_called"
    TOOL_SUCCEEDED = "tool_succeeded"
    TOOL_FAILED = "tool_failed"
    TASK_EVALUATED = "task_evaluated"
    TASK_STATE_CHANGED = "task_state_changed"
    REPLAN_REQUESTED = "replan_requested"
    PLAN_REVISED = "plan_revised"
    RUN_FINISHED = "run_finished"


# M0 status: the orchestrator task log already emits these strings:
#   plan_generated, task_scheduled, tool_result
# tool_result carries a success flag and maps to TOOL_SUCCEEDED /
# TOOL_FAILED. The migration adapter (P10/P15) binds orchestrator log
# calls to this vocabulary.
