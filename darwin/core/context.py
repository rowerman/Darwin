"""Context management (P3) — token-budget-aware compression orchestration.

Owns the threshold check, structured digest assembly, LLM compression
invocation, truncation fallback and the resulting event logging, so the
orchestrator stays a thin loop controller. The orchestrator wires a
``ContextManager`` with its LLMSession + MemoryManager and delegates:

    _maybe_compress()          -> context.maybe_compress()
    _tokens_exceeded(budget)   -> context.tokens_exceeded(budget)
    _build_truncation_context() -> context.truncation_context()
"""

from __future__ import annotations

import logging
from typing import Any, Callable

log = logging.getLogger(__name__)


class ContextManager:
    """Coordinates compression between the LLM session and the memory layers."""

    def __init__(
        self,
        llm: Any,
        memory: Any,
        dkg: Any = None,
        max_context_tokens: int = 384000,
        compression_threshold: float = 0.4,
        event_logger: Callable[..., Any] | None = None,
    ) -> None:
        self.llm = llm
        self.memory = memory
        self.dkg = dkg
        self.max_context_tokens = max_context_tokens
        self.compression_threshold = compression_threshold
        # Single source of truth: keep the session's own window in sync so
        # `llm.context_load` (property) and `compress()`'s internal threshold
        # check cannot drift when a caller configures a different limit.
        if hasattr(self.llm, "max_context_tokens"):
            self.llm.max_context_tokens = max_context_tokens
        # Optional callable(event_type, event_name, **kwargs), e.g. the
        # orchestrator's structured task-log event hook.
        self.event_logger = event_logger

    def maybe_compress(self) -> bool:
        """Compress conversation history if context load exceeds the threshold.

        Returns True if a compression pass saved tokens. Never raises — the
        orchestrator must stay resilient when compression is unavailable.
        """
        try:
            if self.llm.context_load < self.compression_threshold:
                return False
        except Exception:
            return False

        try:
            trunc_ctx = self.truncation_context()
            preserved_text, compressible_text, discarded_count = (
                self.memory.compression_payload()
            )
            structured = self.memory.compression_digest()
            if preserved_text or compressible_text or discarded_count or structured:
                log.debug(
                    "compression: preserved=%d chars, compressible=%d chars, "
                    "discarded=%d records, structured=%d chars",
                    len(preserved_text), len(compressible_text),
                    discarded_count, len(structured),
                )
            saved = self.llm.compress(
                max_context_tokens=self.max_context_tokens,
                compression_threshold=self.compression_threshold,
                truncation_context=trunc_ctx,
                preserved_context=preserved_text,
                structured_input=structured,
            )
        except Exception as exc:  # compression must never break the loop
            log.warning("Context compression failed: %s", exc)
            return False

        if saved > 0:
            self._log_event(
                "context_compressed",
                tokens_saved=saved,
                new_token_count=self.llm.token_count,
                compression_count=getattr(self.llm, "_compressed_count", 0),
            )
            log.info(
                "Context compressed: saved ~%d tokens (total: %d, load: %.1f%%)",
                saved, self.llm.token_count, self.llm.context_load * 100,
            )
        elif saved < 0:
            log.warning("Context compression failed, continuing with high context load")
        return saved > 0

    def tokens_exceeded(self, token_budget: int) -> bool:
        """Check if the token budget is exceeded, attempting compression first."""
        try:
            if self.llm.token_count <= token_budget:
                return False
            if self.maybe_compress():
                return self.llm.token_count > token_budget
        except Exception:
            return True
        return True

    def truncation_context(self) -> str:
        """Structured DKG state for injection when history is truncated.

        Uses the memory layer's live belief snapshot when wired; falls back to
        a manual DKG summary (flags / credentials / sessions / services /
        vulnerabilities) when unavailable.
        """
        provider = getattr(self.memory, "belief_provider", None)
        if callable(provider):
            try:
                ctx = provider()
                if ctx:
                    return ctx
            except Exception:
                pass
        lines = ["[DKG STATE AT TRUNCATION — structured facts preserved]"]
        if self.dkg is None:
            return "\n".join(lines)
        try:
            flags = self.dkg.query_nodes("Flag")
            if flags:
                lines.append("Flags: " + ", ".join(
                    str(f.get("value", "?")) for f in flags
                ))
            creds = self.dkg.query_nodes("Credential")
            if creds:
                lines.append(f"Credentials ({len(creds)}):")
                for c in creds[:8]:
                    lines.append(
                        f"  {c.get('cred_type','?')} {c.get('username','?')}"
                        f"@{c.get('source_host','?')}"
                        + (f" (confirmed)" if c.get("confirmed") else "")
                    )
            sessions = self.dkg.query_nodes("Session")
            if sessions:
                lines.append(f"Sessions ({len(sessions)}):")
                for s in sessions[:5]:
                    lines.append(
                        f"  {s.get('session_type','?')} on {s.get('host','?')}"
                    )
            services = self.dkg.query_nodes("Service")
            db_svcs = [
                s for s in services
                if s.get("port") and s.get("port") not in (80, 443, 8080, 8443)
            ]
            if db_svcs:
                lines.append(f"Non-HTTP services ({len(db_svcs)}):")
                for s in db_svcs[:10]:
                    lines.append(
                        f"  {s.get('service_name','?')} on :{s.get('port')}"
                        f" ({s.get('version','')})".rstrip()
                    )
            vulns = self.dkg.query_nodes("Vulnerability")
            if vulns:
                lines.append(f"Known vulnerabilities ({len(vulns)}):")
                for v in vulns[:10]:
                    lines.append(
                        f"  {v.get('vuln_type','?')} @ {v.get('endpoint','?')}"
                    )
        except Exception:
            lines.append("  (error reading DKG state)")
        return "\n".join(lines)

    def _log_event(self, name: str, **kwargs: Any) -> None:
        if self.event_logger is None:
            return
        try:
            self.event_logger("info", name, **kwargs)
        except Exception:
            pass
