"""ThoughtLogger — captures and persists LLM chain-of-thought events per run.

Design v2 (P0): standalone module. LLMSession holds an optional observer of
this type; Orchestrator only wires it once (``llm.thought_logger = logger``).
The logger itself owns stage tracking, event sequencing, and persistence.

Output files under ``log/thought/``:
    <run_id>_thoughts.jsonl — one JSON object per line (machine-parseable)
    <run_id>_thoughts.log   — human-readable rendering of the same events

Never raises on IO failures — it logs a warning and continues, so the agent
main loop is never blocked by logging.
"""

from __future__ import annotations

import json
import logging
import os
import time
from contextlib import contextmanager
from typing import Any, Dict, Optional

log = logging.getLogger(__name__)

THOUGHT_SUBDIR = "thought"
DEFAULT_STAGE = "main_loop"


class ThoughtLogger:
    """Observer for LLMSession that records every LLM interaction.

    Events:
        llm_call:     one generate() invocation — prompt, system prompt,
                      reasoning (chain of thought), output, tool calls.
        tool_result:  one add_tool_result() invocation — tool feedback the
                      LLM faces before its next decision.
    """

    def __init__(
        self,
        run_id: str,
        log_dir: str = "log",
        enabled: bool = True,
    ):
        self.run_id = run_id
        self.log_dir = log_dir
        self.enabled = enabled
        self._seq = 0
        self._stage: str = DEFAULT_STAGE
        self._last_call_stage: Optional[str] = None
        self._dir_created = False
        self._jsonl_path: str = ""
        self._log_path: str = ""

    # ------------------------------------------------------------------
    # Stage tracking
    # ------------------------------------------------------------------

    def set_stage(self, stage: str) -> None:
        """Set the current stage label; None/empty falls back to main_loop."""
        self._stage = stage or DEFAULT_STAGE

    @contextmanager
    def stage(self, stage: str):
        """Temporarily switch stage for a block, restoring the previous one."""
        prev = self._stage
        self._stage = stage or prev
        try:
            yield
        finally:
            self._stage = prev

    @property
    def current_stage(self) -> str:
        return self._stage

    # ------------------------------------------------------------------
    # Capture API (called by LLMSession)
    # ------------------------------------------------------------------

    def record_call(
        self,
        stage: Optional[str],
        model: str,
        prompt: str,
        system_prompt: Optional[str],
        reasoning: Optional[str],
        content: str,
        tool_calls: Optional[list],
    ) -> None:
        """Record one LLM generate() invocation."""
        if not self.enabled or not self._ensure_paths():
            return
        event: Dict[str, Any] = {
            "type": "llm_call",
            "seq": self._next_seq(),
            "ts": self._now(),
            "stage": stage or self._stage,
            "model": model,
            "prompt": prompt,
            "system_prompt": system_prompt,
            "reasoning": reasoning,
            "content": content,
            "tool_calls": tool_calls,
        }
        self._last_call_stage = stage or self._stage
        self._append(event)

    def record_tool_result(self, tool_call_id: str, result: str) -> None:
        """Record one tool result fed back to the LLM."""
        if not self.enabled or not self._ensure_paths():
            return
        event: Dict[str, Any] = {
            "type": "tool_result",
            "seq": self._next_seq(),
            "ts": self._now(),
            "stage": self._last_call_stage or self._stage,
            "tool_call_id": tool_call_id,
            "result": result,
        }
        self._append(event)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _ensure_paths(self) -> bool:
        """Create log/thought/ once. Returns False when disabled or on error."""
        if not self.enabled:
            return False
        if self._dir_created:
            return True
        try:
            dir_path = os.path.join(self.log_dir, THOUGHT_SUBDIR)
            os.makedirs(dir_path, exist_ok=True)
            self._jsonl_path = os.path.join(
                dir_path, f"{self.run_id}_thoughts.jsonl"
            )
            self._log_path = os.path.join(
                dir_path, f"{self.run_id}_thoughts.log"
            )
            self._dir_created = True
            return True
        except OSError as exc:
            log.warning(
                "ThoughtLogger: cannot create thought log dir under %s: %s",
                self.log_dir, exc,
            )
            return False

    def _next_seq(self) -> int:
        self._seq += 1
        return self._seq

    @staticmethod
    def _now() -> str:
        return time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime())

    def _append(self, event: Dict[str, Any]) -> None:
        """Append event to both JSONL and readable log. Never raises."""
        try:
            with open(self._jsonl_path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(event, ensure_ascii=False, default=str) + "\n")
            with open(self._log_path, "a", encoding="utf-8") as fh:
                fh.write(self._render(event) + "\n\n")
        except (OSError, TypeError, ValueError) as exc:
            log.warning("ThoughtLogger: failed to write thought event: %s", exc)

    @staticmethod
    def _render(event: Dict[str, Any]) -> str:
        """Render one event into a human-readable block."""
        kind = event.get("type", "event")
        lines = [
            f"===== [#{event.get('seq')}] {kind}  "
            f"stage={event.get('stage')}  ts={event.get('ts')} ====="
        ]
        if kind == "llm_call":
            lines.append(f"model: {event.get('model')}")
            lines.append("\n--- prompt (information faced) ---")
            lines.append(str(event.get("prompt") or ""))
            lines.append("\n--- reasoning (chain of thought) ---")
            lines.append(str(event.get("reasoning") or ""))
            lines.append("\n--- output ---")
            lines.append(str(event.get("content") or ""))
            tool_calls = event.get("tool_calls")
            if tool_calls:
                lines.append("\n--- tool calls ---")
                for tc in tool_calls:
                    if isinstance(tc, dict):
                        name = tc.get("name", "?")
                        args = json.dumps(
                            tc.get("arguments", {}),
                            ensure_ascii=False, default=str,
                        )
                        lines.append(f"  {name}({args})")
        else:
            lines.append(f"tool_call_id: {event.get('tool_call_id')}")
            lines.append("\n--- result ---")
            lines.append(str(event.get("result") or ""))
        return "\n".join(lines)
