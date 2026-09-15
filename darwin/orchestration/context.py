"""Shared context for orchestrator coordinators.

Every coordinator receives the owning :class:`darwin.orchestrator.Orchestrator`
instance and forwards unknown attribute reads, writes and method calls to it.
State therefore stays on the Orchestrator (single source of truth) while each
coordinator owns a domain slice of behavior. Tool calls go through the
injected tool port (``orch._tool_port``) so coordinators never touch gateways
directly.
"""
from __future__ import annotations

from darwin.tools.mcp_gateway import ToolResult
import asyncio
import contextlib


class CoordinatorContext:
    """Mixin-free shared-context base for phase coordinators.

    - ``self.<attr>`` reads/writes fall through to the owning Orchestrator.
    - ``self.<method>`` calls resolve locally first, then fall through to the
      Orchestrator (which routes cross-coordinator calls through thin
      delegates).
    - ``_call_tool()`` is the only sanctioned way to invoke external tools.
    """

    def __init__(self, orch):
        object.__setattr__(self, "_orch", orch)

    async def _llm_generate_async(
        self,
        prompt: str,
        system_prompt: str | None = None,
        tools=None,
        temperature: float | None = None,
        timeout: float = 180.0,
        stage: str | None = None,
    ):
        """Run an LLM call without letting a stuck request outlive its budget.

        Prefers the real ``LLMSession.generate_async`` (threaded + bounded by
        ``asyncio.wait_for``).  Test double sessions only implement the sync
        ``generate``; those run in an executor under the same outer timeout so
        structured phases never block the event loop indefinitely.
        """
        llm = getattr(self._orch, "llm", None)
        timeout = max(1.0, float(timeout))
        generate_async = getattr(llm, "generate_async", None)
        if generate_async is not None:
            return await generate_async(
                prompt=prompt,
                system_prompt=system_prompt,
                tools=tools,
                temperature=temperature,
                timeout=timeout,
                stage=stage,
            )
        loop = asyncio.get_running_loop()

        def _run():
            return llm.generate(
                prompt, system_prompt, tools, temperature, timeout, stage
            )

        fut = loop.run_in_executor(None, _run)
        deadline = loop.time() + timeout + 10.0
        # Poll instead of asyncio.wait_for: a completed run_in_executor future
        # occasionally never wakes wait_for's waiter in this event loop setup,
        # stalling structured stages until their outer budget kills the run.
        while not fut.done():
            remaining = deadline - loop.time()
            if remaining <= 0:
                raise asyncio.TimeoutError()
            await asyncio.sleep(min(0.25, remaining))
        return fut.result()

    def _llm_isolated(self):
        """Scope for self-contained prompts (no shared conversation history).

        Stages such as fix_analysis/flag_search embed all the state they need,
        so replaying the whole session history only slows the call down and
        lets one stage's raw output leak into the next.  Session doubles
        without ``isolated_scope`` run unchanged.
        """
        llm = getattr(self._orch, "llm", None)
        scope = getattr(llm, "isolated_scope", None)
        return scope() if callable(scope) else contextlib.nullcontext()

    def _tokens_used(self) -> int:
        """Tokens consumed by this run (cumulative, not current context size)."""
        llm = getattr(self._orch, "llm", None)
        total = getattr(llm, "total_tokens", 0)
        if total:
            return int(total)
        return int(getattr(llm, "token_count", 0) or 0)

    def __getattr__(self, name):
        return getattr(object.__getattribute__(self, "_orch"), name)

    def __setattr__(self, name, value):
        if name == "_orch":
            object.__setattr__(self, name, value)
        else:
            setattr(object.__getattribute__(self, "_orch"), name, value)

    def _unusable_tools(self) -> dict:
        """Run-level memo of tools this run cannot use, and why.

        Planning-side findings (a binary that is not installed) and
        execution-side ones (a tool refusing "not allow-listed") share one
        record, so a plan review cannot resurrect a task that can only fail
        the same way again.
        """
        memo = getattr(self, "_unusable_tools_memo", None)
        if not isinstance(memo, dict):
            memo = {}
            self._unusable_tools_memo = memo
        return memo

    def _remember_unusable(self, tool: str, reason: str) -> None:
        if tool:
            self._unusable_tools().setdefault(str(tool), str(reason or "unusable"))

    def _unusable_tools_note(self) -> str:
        memo = self._unusable_tools()
        if not memo:
            return ""
        listed = ", ".join(
            f"{tool} ({reason})" for tool, reason in sorted(memo.items())
        )
        return (
            f"## Tools unusable in this run\n{listed}\n"
            "Do NOT create tasks with these tools — they cannot run here. "
            "Use another tool or a different approach.\n\n"
        )

    async def _call_tool(self, name: str, params: dict) -> ToolResult:
        # A tool call must never outlive the active run/phase deadline.
        remaining = self._orch._remaining_budget()
        if remaining <= 0:
            return ToolResult(tool_name=name, success=False, stdout="",
                              stderr="time budget exceeded", exit_code=-1,
                              elapsed_ms=0)
        try:
            return await asyncio.wait_for(
                self._orch._tool_port.call(name, params), timeout=remaining
            )
        except asyncio.TimeoutError:
            return ToolResult(tool_name=name, success=False, stdout="",
                              stderr=f"tool timeout after {remaining:.1f}s",
                              exit_code=-1, elapsed_ms=remaining * 1000)
