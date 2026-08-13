"""ToolExecutor — executes a Task against the tool gateways (P5 + P8).

P5a deliverable: a concrete Executor that consumes a Task and returns a
normalized ExecutionResult, plus the plan-adherence signal (planned tool
vs executed tool).

P8 deliverable: optional capability dispatch. When Task.action carries a
"capability" name, the executor resolves the capability, validates
preconditions, and tries the capability's supported tools in order
(falling back only on TOOL_ERROR / INVALID_ARGUMENT). Tasks without a
capability keep the legacy direct tool dispatch unchanged.

P5c (after P6) will migrate the orchestrator's LLM-driven execution branch
onto this strict Task-consumption path. Until then the orchestrator routes
only the fix-retry seam through ToolExecutor; the main loop still emits
adherence data via its tool_result trace event.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any

from darwin.core.capabilities import (
    CapabilityRegistry,
    ContextResolver,
    PreconditionValidator,
    default_registry,
    normalize_result,
)
from darwin.core.evaluator import FailureAnalyzer, FailureType
from darwin.core.task import Task


@dataclass
class ToolOutcome:
    """Minimal normalized tool result (gateway-agnostic)."""

    success: bool
    stdout: str
    stderr: str
    exit_code: int
    elapsed_ms: float
    parsed_output: dict


@dataclass
class ExecutionResult:
    """Normalized outcome of executing one Task (P5 concrete shape)."""

    task_id: str
    tool: str
    planned_tool: str
    adherence: bool
    success: bool
    stdout: str = ""
    stderr: str = ""
    exit_code: int = 0
    elapsed_ms: float = 0.0
    normalized: dict = field(default_factory=dict)
    parsed_output: dict = field(default_factory=dict)
    # P8: capability-mode metadata (empty for legacy direct dispatch).
    capability: str = ""
    tool_attempts: list[str] = field(default_factory=list)


class ToolExecutor:
    """Executes Tasks through the registered tool gateways (P5)."""

    def __init__(
        self,
        attack_gateway=None,
        recon_gateway=None,
        mcp_pool=None,
        capability_registry: CapabilityRegistry | None = None,
    ) -> None:
        self.attack_gateway = attack_gateway
        self.recon_gateway = recon_gateway
        self.mcp_pool = mcp_pool
        # P8: capability layer (additive; legacy dispatch unchanged).
        self.capability_registry = capability_registry or default_registry()
        self.validator = PreconditionValidator()
        self.resolver = ContextResolver()
        self._analyzer = FailureAnalyzer()

    @staticmethod
    def _from_any(obj: Any) -> ToolOutcome:
        """Normalize any gateway result (ToolResult-like) into ToolOutcome."""
        if obj is None:
            return ToolOutcome(False, "", "no result", -1, 0.0, {})
        return ToolOutcome(
            success=bool(getattr(obj, "success", False)),
            stdout=str(getattr(obj, "stdout", "") or ""),
            stderr=str(getattr(obj, "stderr", "") or ""),
            exit_code=-1
            if getattr(obj, "exit_code", -1) is None
            else int(getattr(obj, "exit_code", -1)),
            elapsed_ms=float(getattr(obj, "elapsed_ms", 0.0) or 0.0),
            parsed_output=dict(getattr(obj, "parsed_output", {}) or {}),
        )

    async def _invoke(self, tool: str, params: dict) -> ToolOutcome:
        try:
            if self.attack_gateway is not None and tool in self.attack_gateway.get_tool_names():
                return self._from_any(await self.attack_gateway.call(tool, params))
            if self.recon_gateway is not None and tool in self.recon_gateway.get_tool_names():
                return self._from_any(await self.recon_gateway.call(tool, params))
            if self.mcp_pool is not None and tool in self.mcp_pool.get_tool_names():
                raw = await self.mcp_pool.call_tool(tool, params)
                if not isinstance(raw, dict):
                    raw = {}
                is_error = bool(raw.get("isError", False))
                text = ""
                content = raw.get("content", [])
                if content and isinstance(content[0], dict):
                    text = str(content[0].get("text", ""))
                return ToolOutcome(
                    success=not is_error,
                    stdout=text,
                    stderr=text if is_error else "",
                    exit_code=1 if is_error else 0,
                    elapsed_ms=0.0,
                    parsed_output={},
                )
            return ToolOutcome(False, "", f"Unknown tool: {tool}", 1, 0.0, {})
        except Exception as e:  # defensive, mirrors gateway behavior
            return ToolOutcome(False, "", str(e), -1, 0.0, {})

    async def execute(self, task: Task) -> ExecutionResult:
        """Execute the Task's action and return a normalized result."""
        action = task.action or {}
        capability_name = str(action.get("capability", "") or "")
        if capability_name:
            return await self._execute_capability(task, capability_name)
        return await self._execute_tool(task)

    async def _execute_tool(self, task: Task) -> ExecutionResult:
        """Legacy direct-dispatch path (no capability on the task)."""
        action = task.action or {}
        tool = str(action.get("tool", "") or "")
        params = action.get("params", {}) or {}
        if isinstance(params, str):
            try:
                params = json.loads(params)
            except (json.JSONDecodeError, TypeError):
                params = {"url": params}
        if not isinstance(params, dict):
            params = {"value": params}

        start = time.monotonic()
        outcome = await self._invoke(tool, params)
        elapsed_ms = outcome.elapsed_ms or ((time.monotonic() - start) * 1000.0)
        return ExecutionResult(
            task_id=task.id,
            tool=tool,
            planned_tool=tool,
            adherence=True,  # the executor always uses the planned tool
            success=outcome.success,
            stdout=outcome.stdout,
            stderr=outcome.stderr,
            exit_code=outcome.exit_code,
            elapsed_ms=elapsed_ms,
            normalized=outcome.parsed_output,
            parsed_output=outcome.parsed_output,
        )

    # ── P8: capability dispatch ─────────────────────────────────────

    @staticmethod
    def _result_from_outcome(
        task_id: str,
        capability,
        tool: str,
        outcome: ToolOutcome,
    ) -> ExecutionResult:
        """Build an ExecutionResult for one capability tool attempt."""
        return ExecutionResult(
            task_id=task_id,
            tool=tool,
            planned_tool=capability.default_tool,
            adherence=True,  # capability is the plan unit; fallback is not a deviation
            success=outcome.success,
            stdout=outcome.stdout,
            stderr=outcome.stderr,
            exit_code=outcome.exit_code,
            elapsed_ms=outcome.elapsed_ms,
            normalized=outcome.parsed_output,
            parsed_output=outcome.parsed_output,
        )

    async def _execute_capability(
        self, task: Task, capability_name: str
    ) -> ExecutionResult:
        """Execute a task through its capability contract.

        Rules (approved P8 design):
        - unknown capability -> explicit failure (never silently falls
          back to the task's tool field);
        - missing precondition -> PRECONDITION_MISSING-style failure;
        - supported tools are tried in order; only TOOL_ERROR /
          INVALID_ARGUMENT failures trigger the next tool;
        - a meaningful failure (auth / hypothesis / defense / ...) stops
          the chain so the real signal reaches the Evaluator.
        """
        capability = self.capability_registry.get(capability_name)
        if capability is None:
            return ExecutionResult(
                task_id=task.id,
                tool="",
                planned_tool="",
                adherence=False,
                success=False,
                stderr=f"unknown capability: {capability_name}",
                exit_code=1,
                capability=capability_name,
            )

        missing = self.validator.validate(capability, task)
        if missing:
            return ExecutionResult(
                task_id=task.id,
                tool="",
                planned_tool=capability.default_tool,
                adherence=True,
                success=False,
                stderr=f"precondition missing: {', '.join(missing)}",
                exit_code=1,
                capability=capability_name,
            )

        if not capability.supported_tools:
            return ExecutionResult(
                task_id=task.id,
                tool="",
                planned_tool=capability.default_tool,
                adherence=True,
                success=False,
                stderr=f"capability has no supported tools: {capability_name}",
                exit_code=1,
                capability=capability_name,
            )

        params_by_tool = self.resolver.resolve(capability, task)
        attempts: list[str] = []
        last_outcome: ToolOutcome | None = None
        for tool in capability.supported_tools:
            attempts.append(tool)
            last_outcome = await self._invoke(tool, params_by_tool.get(tool, {}))
            if last_outcome.success:
                return normalize_result(
                    self._result_from_outcome(task.id, capability, tool, last_outcome),
                    capability_name,
                    attempts,
                )
            cls = self._analyzer.classify(last_outcome, tool=tool)
            if cls.failure_type not in (
                FailureType.TOOL_ERROR,
                FailureType.INVALID_ARGUMENT,
            ):
                # Meaningful failure: switching tools would mask the real
                # signal. Stop and let the Evaluator classify it.
                return normalize_result(
                    self._result_from_outcome(task.id, capability, tool, last_outcome),
                    capability_name,
                    attempts,
                )

        # Every supported tool failed with a retryable tool error.
        return normalize_result(
            self._result_from_outcome(
                task.id,
                capability,
                capability.supported_tools[-1],
                last_outcome,
            ),
            capability_name,
            attempts,
        )
