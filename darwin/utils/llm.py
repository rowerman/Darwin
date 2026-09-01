"""LLM unified interface using LiteLLM, with automatic function-to-tool conversion.

Reference: Cochise src/cochise/common.py:89 — LLMFunctionMapping pattern
"""

from __future__ import annotations

import html
import json
import time
import inspect
import re
from typing import Any, Callable, Dict, List, Optional

import litellm

# Suppress LiteLLM's verbose INFO logs — they produce 2-4 lines per
# LLM call that add zero debugging value for DARWIN experiments.
import logging
logging.getLogger("LiteLLM").setLevel(logging.WARNING)
logging.getLogger("litellm").setLevel(logging.WARNING)

log = logging.getLogger(__name__)


# P16: memory role prompt lives with the other role prompts; imported by
# identity so compression behavior is unchanged.
from darwin.prompts.memory import SYSTEM_PROMPT_MEMORY as SYSTEM_PROMPT_COMPRESS
# O3.2: the cognition-snapshot marker used to keep decision-critical
# messages out of the summarizer and verbatim in the preserved payload.
from darwin.core.belief import SNAPSHOT_MARKER


class LLMSession:
    """Unified LLM session using LiteLLM (provider-agnostic).

    Reference: Cochise common.py — litellm wrapper with tool calling support.
    """

    def __init__(
        self,
        model: str = "gpt-4o",
        provider: str = "openai",
        api_key: str | None = None,
        base_url: str | None = None,
        temperature: float = 0.7,
        max_tokens: int = 4096,
        max_context_tokens: int = 384000,
        thought_logger: Any = None,
    ):
        self.model = f"{provider}/{model}" if provider != "openai" else model
        self.provider = provider
        self.api_key = api_key
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.max_context_tokens = max_context_tokens
        self.conversation_history: List[Dict[str, Any]] = []
        # P0/P1: optional chain-of-thought observer (duck-typed — needs only
        # record_call() / record_tool_result()). Owns its own persistence.
        self.thought_logger = thought_logger
        self._compressed_count = 0  # number of times compression has been applied
        self._pending_compressed_context = ""  # consumed once in next _build_messages
        self._max_compressions = 3  # prevent cascading telephone-game degradation

        if api_key:
            import os
            _provider_key_map = {
                "openai": "OPENAI_API_KEY",
                "anthropic": "ANTHROPIC_API_KEY",
                "deepseek": "DEEPSEEK_API_KEY",
                "gemini": "GEMINI_API_KEY",
                "ollama": "",
            }
            env_var = _provider_key_map.get(self.provider, "OPENAI_API_KEY")
            if env_var:
                os.environ[env_var] = api_key
        if base_url:
            self.model = f"openai/{model}"
            litellm.api_base = base_url

    @classmethod
    def from_config(cls, profile: str = "default", config_path: str = "config/llm.yaml") -> "LLMSession":
        """Create LLMSession from config/llm.yaml profile.

        Args:
            profile: Profile name (default, reasoning, classifier)
            config_path: Path to llm.yaml config file
        """
        import os

        try:
            import yaml
        except ImportError:
            import logging
            logging.getLogger(__name__).warning("PyYAML not installed, cannot load %s", config_path)
            return cls()

        if not os.path.exists(config_path):
            import logging
            logging.getLogger(__name__).warning("LLM config not found at %s", config_path)
            return cls()

        with open(config_path, encoding="utf-8") as f:
            cfg = yaml.safe_load(f)

        profile_cfg = cfg.get(profile, cfg.get("default", {}))
        return cls(
            provider=profile_cfg.get("provider", "openai"),
            model=profile_cfg.get("model", "gpt-4o"),
            api_key=profile_cfg.get("api_key"),
            base_url=profile_cfg.get("base_url") or None,
            temperature=float(profile_cfg.get("temperature", 0.7)),
            max_tokens=int(str(profile_cfg.get("max_tokens", 4096)).replace(",", "")),
        )

    def generate(
        self,
        prompt: str,
        system_prompt: str | None = None,
        tools: List[Dict[str, Any]] | None = None,
        temperature: float | None = None,
        timeout: float = 180.0,
        stage: str | None = None,
    ) -> tuple[str, List[Dict[str, Any]] | None]:
        """Generate LLM response with optional tool calling.

        Args:
            prompt: User prompt.
            system_prompt: Optional system prompt.
            tools: Optional list of OpenAI tool definitions.
            temperature: Override the default temperature for this call.
            timeout: LiteLLM request timeout in seconds (default 180s).
            stage: Optional stage label for chain-of-thought logging.
                Falls back to the thought logger's current stage when unset.

        Returns:
            (content, tool_calls) — tool_calls is None if no tools were called.
            tool_calls is a list of dicts with 'name' and 'arguments' keys.
        """
        deadline = getattr(self, "_deadline", 0.0)
        if deadline:
            timeout = min(timeout, max(1.0, deadline - time.monotonic()))
        messages = self._build_messages(prompt, system_prompt)
        self.conversation_history = messages.copy()

        temp = temperature if temperature is not None else self.temperature
        # gpt-5 only supports temperature=1
        if "gpt-5" in self.model:
            temp = 1

        kwargs = dict(
            model=self.model,
            messages=messages,
            temperature=temp,
            max_tokens=self.max_tokens,
            timeout=timeout,
        )
        # Pass the configured credential directly.  This is required when a
        # provider uses an OpenAI-compatible base URL: the model name is then
        # normalized to ``openai/<model>``, while the configured provider can
        # still be DeepSeek (or another compatible backend).
        if self.api_key:
            kwargs["api_key"] = self.api_key

        if tools:
            kwargs["tools"] = tools
            kwargs["tool_choice"] = "auto"

        response = litellm.completion(**kwargs)
        choice = response.choices[0]

        content = choice.message.content or ""
        tool_calls_raw = getattr(choice.message, "tool_calls", None)
        reasoning = getattr(choice.message, "reasoning_content", None)
        if reasoning is None:
            reasoning = getattr(choice.message, "reasoning", None)

        # Add response to conversation history
        assistant_msg: Dict[str, Any] = {"role": "assistant", "content": content}
        if reasoning:
            assistant_msg["reasoning_content"] = reasoning
        parsed_calls: List[Dict[str, Any]] | None = None
        if tool_calls_raw:
            assistant_msg["tool_calls"] = [
                {"id": tc.id, "type": "function",
                 "function": {"name": tc.function.name, "arguments": tc.function.arguments}}
                for tc in tool_calls_raw
            ]
            self.conversation_history.append(assistant_msg)
            parsed_calls = [
                {"id": tc.id, "name": tc.function.name,
                 "arguments": json.loads(tc.function.arguments)}
                for tc in tool_calls_raw
            ]
        else:
            # Some OpenAI-compatible DeepSeek endpoints serialize tool calls
            # as DSML markup in message.content instead of message.tool_calls.
            # Normalize that representation so registry loops can still append
            # tool results and request a final structured response.
            parsed_calls = self._parse_dsml_tool_calls(content)
            if parsed_calls:
                assistant_msg["tool_calls"] = [
                    {"id": call["id"], "type": "function",
                     "function": {
                         "name": call["name"],
                         "arguments": json.dumps(call["arguments"], ensure_ascii=False),
                     }}
                    for call in parsed_calls
                ]
                log.info(
                    "LLMSession: parsed %d DSML tool call(s) (stage=%s, tools=%s)",
                    len(parsed_calls), stage or "?",
                    ", ".join(c["name"] for c in parsed_calls[:5]),
                )
            self.conversation_history.append(assistant_msg)

        # P0/P1: chain-of-thought capture — the observer owns persistence and
        # swallows its own errors, so this never affects the main flow.
        if self.thought_logger is not None:
            self.thought_logger.record_call(
                stage=stage,
                model=self.model,
                prompt=prompt,
                system_prompt=system_prompt,
                reasoning=reasoning,
                content=content,
                tool_calls=parsed_calls,
            )

        return content, parsed_calls

    @staticmethod
    def _parse_dsml_tool_calls(content: str) -> List[Dict[str, Any]] | None:
        """Parse DeepSeek DSML ``invoke`` markup into normalized calls.

        DSML is only accepted when the complete invoke/parameter structure is
        present. Malformed or ordinary text returns ``None`` and follows the
        existing plain-content path.

        Supported syntax::

            <invoke name="tool_name">
                <parameter name="arg">value</parameter>
            </invoke>

        ``tool_name`` is accepted as an alias attribute for ``name``. Parameter
        values are entity-unescaped (``&lt;``/``&gt;``/``&amp;``/``&quot;``) and
        parsed as JSON when possible, mirroring OpenAI ``function.arguments``.
        """
        if not content or "<invoke" not in content:
            return None
        invoke_pattern = re.compile(
            r'<invoke\s+(?:name|tool_name)="([^"]+)"\s*>(.*?)'
            r'</invoke>', re.DOTALL,
        )
        parameter_pattern = re.compile(
            r'<parameter\s+name="([^"]+)"[^>]*>(.*?)'
            r'</parameter>', re.DOTALL,
        )
        calls: List[Dict[str, Any]] = []
        for index, match in enumerate(invoke_pattern.finditer(content), 1):
            name = match.group(1).strip()
            if not name:
                continue
            arguments: Dict[str, Any] = {}
            for param in parameter_pattern.finditer(match.group(2)):
                arg_name = param.group(1).strip()
                raw_value = param.group(2).strip()
                value: Any = html.unescape(raw_value)
                try:
                    value = json.loads(raw_value)
                except (json.JSONDecodeError, TypeError):
                    try:
                        value = json.loads(value)
                    except (json.JSONDecodeError, TypeError):
                        pass
                arguments[arg_name] = value
            calls.append({"id": f"dsml-{index}", "name": name, "arguments": arguments})
        return calls or None

    def _build_messages(
        self, prompt: str, system_prompt: str | None
    ) -> List[Dict[str, str]]:
        """Build message list, continuing conversation history if available."""
        # Consume pending compressed context exactly once
        if self._pending_compressed_context:
            prompt = f"{self._pending_compressed_context}\n\n---\n\n{prompt}"
            self._pending_compressed_context = ""

        if self.conversation_history:
            messages = self.conversation_history.copy()
            # Update system message if caller provides a different one —
            # but never overwrite a compressed context message
            if system_prompt:
                for i, msg in enumerate(messages):
                    if msg.get("role") == "system" and "[COMPRESSED CONTEXT" not in str(msg.get("content", "")):
                        if msg.get("content") != system_prompt:
                            messages[i] = {"role": "system", "content": system_prompt}
                        break
                else:
                    # No non-compressed system message found — insert at 0
                    messages.insert(0, {"role": "system", "content": system_prompt})
            # Strip reasoning_content from all messages — DeepSeek's
            # thinking mode continuity requirement breaks agent workflows
            # where multiple independent LLM calls share conversation history.
            for msg in messages:
                msg.pop("reasoning_content", None)

            # Strip ALL unresolved tool_calls (not just the last assistant message)
            for i in range(len(messages) - 1, -1, -1):
                if messages[i].get("role") == "assistant" and messages[i].get("tool_calls"):
                    tool_ids = {tc["id"] for tc in messages[i]["tool_calls"]}
                    answered = any(
                        m.get("role") == "tool" and m.get("tool_call_id") in tool_ids
                        for m in messages[i+1:]
                    )
                    if not answered:
                        messages[i] = {k: v for k, v in messages[i].items()
                                       if k != "tool_calls"}
            last_role = messages[-1].get("role", "") if messages else ""
            if last_role != "tool":
                messages.append({"role": "user", "content": prompt})
            return messages

        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})
        return messages

    def add_tool_result(self, tool_call_id: str, result: str) -> None:
        """Add tool execution result to conversation history."""
        self.conversation_history.append({
            "role": "tool",
            "tool_call_id": tool_call_id,
            "content": result,
        })
        # P0/P1: record the tool feedback the LLM faces next.
        if self.thought_logger is not None:
            self.thought_logger.record_tool_result(tool_call_id, result)

    def add_context_message(self, content: str, role: str = "user") -> None:
        """Inject a message into conversation history without requiring a tool call.
        Use for system diagnostics, filter debug reports, etc.
        """
        self.conversation_history.append({
            "role": role,
            "content": content,
        })

    def replace_system_prompt(self, new_system_prompt: str) -> None:
        """Replace the first non-compressed system message.
        Preserves compressed context summaries and all other messages.
        """
        for i, msg in enumerate(self.conversation_history):
            if msg.get("role") == "system" and "[COMPRESSED CONTEXT" not in str(msg.get("content", "")):
                self.conversation_history[i] = {"role": "system", "content": new_system_prompt}
                return
        self.conversation_history.insert(0, {"role": "system", "content": new_system_prompt})

    def reset(self) -> None:
        """Clear conversation history."""
        self.conversation_history = []
        self._pending_compressed_context = ""

    @property
    def token_count(self) -> int:
        """Estimate current token usage via litellm token counter."""
        try:
            return litellm.token_counter(
                model=getattr(self, "model", "gpt-4o"),
                messages=self.conversation_history,
            )
        except Exception:
            return sum(len(str(msg)) for msg in self.conversation_history) // 4

    @property
    def context_load(self) -> float:
        """Context load ratio (0.0-1.0)."""
        return min(self.token_count / max(self.max_context_tokens, 1), 1.0)

    def compress(
        self,
        keep_recent: int = 6,
        max_context_tokens: int | None = None,
        compression_threshold: float = 0.4,
        truncation_context: str = "",
        preserved_context: str = "",
        structured_input: str = "",
    ) -> int:
        """Compress conversation history by summarizing older messages.

        Stores the compressed summary in _pending_compressed_context, which is
        consumed exactly once by the next _build_messages call — avoiding the
        system-message-slot conflict with _build_messages/replace_system_prompt.

        Only compresses if context_load exceeds compression_threshold.
        Limits cascading re-compression to _max_compressions passes.

        Args:
            structured_input: Structured memory digest (DKG critical facts +
                plan rationale + graded execution records) built by the memory
                layer. When non-empty the summarizer consumes it PREFERENTIALLY
                over the raw serialized conversation; when empty the legacy
                serialization path is used unchanged.
            truncation_context: Optional structured summary injected when
                max compressions reached and oldest messages are truncated.
                Should contain DKG-derived facts (flags, creds, sessions,
                services) so the LLM has critical state even after truncation.
            preserved_context: Decision-critical memory (P15 G1) injected
                VERBATIM into the compressed context — it must never be
                summarized away.
        """
        effective_max_context = max_context_tokens or self.max_context_tokens
        load = self.token_count / max(effective_max_context, 1)
        if load < compression_threshold:
            return 0

        if len(self.conversation_history) <= keep_recent + 2:
            return 0

        if self._compressed_count >= self._max_compressions:
            # Already compressed too many times — truncate oldest messages instead.
            # Inject a structured summary so the LLM knows context was dropped.
            overflow = len(self.conversation_history) - keep_recent - 2
            if overflow > 0:
                drop_candidates = self.conversation_history[:overflow]
                # O3.2: never drop cognition-snapshot messages on truncation —
                # keep them verbatim and only truncate compressible history.
                marked_keep = [
                    m for m in drop_candidates
                    if SNAPSHOT_MARKER in str(m.get("content", "") or "")
                ]
                truncated_count = overflow - len(marked_keep)
                self.conversation_history = (
                    marked_keep + self.conversation_history[overflow:]
                )
                # Inject a brief truncation notice, with optional DKG state snapshot
                notice = (
                    f"[CONTEXT TRUNCATED] {truncated_count} oldest messages were dropped "
                    f"to stay within context limits. Earlier actions and discoveries "
                    f"may no longer be visible."
                )
                if truncation_context:
                    notice += f"\n\n{truncation_context}"
                else:
                    notice += " Current DKG state has the structured facts."
                _kept_text = "\n".join(
                    str(m.get("content", "") or "") for m in marked_keep
                )
                _preserved_parts = [
                    p for p in (preserved_context, _kept_text) if p
                ]
                if _preserved_parts:
                    notice += (
                        "\n\n## PRESERVED MEMORY (verbatim — do not drop)\n"
                        + "\n\n".join(_preserved_parts)
                    )
                self.conversation_history.insert(0, {"role": "user", "content": notice})
            return 0

        # Protect tool_calls ↔ tool result pairs from being split across
        # the compression boundary.  DeepSeek rejects orphaned tool messages.
        _split = len(self.conversation_history) - keep_recent
        # Walk the boundary leftwards until no orphaned tool messages remain
        # in the "recent" (kept) suffix.  An orphan is a tool-role message
        # whose matching assistant+tool_calls would be left in the compressed
        # (dropped) prefix, breaking the required adjacency.
        _MAX_WALK = 30
        for _ in range(_MAX_WALK):
            _orphan_ids: set[str] = set()
            for _m in self.conversation_history[_split:]:
                if _m.get("role") == "tool" and _m.get("tool_call_id"):
                    _orphan_ids.add(_m["tool_call_id"])
            if not _orphan_ids:
                break  # no orphaned tool messages in recent — safe
            # Check whether the OLD (to-be-compressed) prefix is the ONLY
            # place where any orphaned tool_call_id's matching assistant
            # message lives.  If so, move the boundary left to keep the
            # assistant+tool_calls with its tool result.
            _old_ids: set[str] = set()
            _recent_ids: set[str] = set()
            for _m in self.conversation_history[:_split]:
                for _tc in (_m.get("tool_calls") or []):
                    _old_ids.add(_tc.get("id", ""))
            for _m in self.conversation_history[_split:]:
                for _tc in (_m.get("tool_calls") or []):
                    _recent_ids.add(_tc.get("id", ""))
            _need_move = False
            for _oid in _orphan_ids:
                if _oid in _old_ids and _oid not in _recent_ids:
                    _need_move = True
                    break
            if not _need_move:
                break  # every orphan has its tool_calls also in recent — safe
            _split = max(0, _split - 2)  # move left to capture more context
        _split = max(0, _split)

        old_messages = self.conversation_history[:_split]
        recent = self.conversation_history[_split:]

        # O3.2: partition old history. Cognition-snapshot messages carry the
        # SNAPSHOT_MARKER and are preserved VERBATIM; only unmarked messages
        # (tool outputs, ordinary dialogue) are eligible for summarization.
        marked_messages = [
            m for m in old_messages
            if SNAPSHOT_MARKER in str(m.get("content", "") or "")
        ]
        summarizable = [
            m for m in old_messages
            if SNAPSHOT_MARKER not in str(m.get("content", "") or "")
        ]
        if marked_messages:
            marked_text = "\n\n".join(
                str(m.get("content", "") or "") for m in marked_messages
            )
            preserved_context = (
                f"{preserved_context}\n\n{marked_text}"
                if preserved_context
                else marked_text
            )

        tokens_before = self.token_count

        compression_prompt = (
            f"The following is an older portion of a penetration testing conversation "
            f"that needs to be compressed. Extract and preserve all critical information.\n\n"
        )

        if summarizable:
            serialized = self._serialize_messages(summarizable)
            # O3.2: the summarizer must not see decision-critical (marked)
            # messages at all — neither via the serialized prompt nor via the
            # conversation history it would otherwise receive.
            _history_backup = list(self.conversation_history)
            if structured_input and structured_input.strip():
                # P2: when a structured digest is provided it REPLACES the raw
                # conversation for the summarizer call — the digest is the
                # priority input and stale raw history must not dilute it.
                self.conversation_history = []
            else:
                self.conversation_history = [
                    m for m in _history_backup
                    if SNAPSHOT_MARKER not in str(m.get("content", "") or "")
                ]
            try:
                if structured_input and structured_input.strip():
                    digest_text = (
                        "[STRUCTURED DIGEST — priority summary input from the "
                        "memory layers; prefer these facts over raw conversation]\n\n"
                        + structured_input.strip()
                    )
                else:
                    digest_text = serialized
                summary, _ = self.generate(
                    prompt=compression_prompt + digest_text,
                    system_prompt=SYSTEM_PROMPT_COMPRESS,
                    stage="compress",
                )
            except Exception:
                self.conversation_history = _history_backup
                summary = self._fallback_truncate(summarizable)
                if not summary:
                    return -1
        else:
            # Everything old was decision-critical — nothing to summarize.
            summary = "(all old history was decision-critical context; preserved verbatim below)"

        # Store compressed context for one-time consumption, keep recent messages.
        # If previous compressed context was not consumed (no generate() between
        # compress calls), merge it by prepending.
        prev = getattr(self, '_pending_compressed_context', "")
        context_text = f"[COMPRESSED CONTEXT — {len(old_messages)} messages summarized]\n\n{summary}"
        if preserved_context:
            context_text += (
                f"\n\n## PRESERVED MEMORY (verbatim — do not drop)\n"
                f"{preserved_context}"
            )
        self._pending_compressed_context = (
            f"{prev}\n\n{context_text}" if prev else context_text
        )
        self.conversation_history = recent
        self._compressed_count += 1

        tokens_saved = tokens_before - self.token_count
        return max(tokens_saved, 0)

    def _serialize_messages(self, messages: List[Dict[str, Any]]) -> str:
        """Serialize messages into a compact text representation for compression."""
        lines = []
        for msg in messages:
            role = msg.get("role", "unknown")
            content = msg.get("content", "")
            tool_calls = msg.get("tool_calls")
            tool_call_id = msg.get("tool_call_id")

            if tool_calls:
                calls_str = "; ".join(
                    f"{tc['function']['name']}({tc['function']['arguments']})"
                    for tc in tool_calls
                )
                lines.append(f"[{role} — tool_calls: {calls_str}] {content}")
            elif tool_call_id:
                lines.append(f"[{role} — tool_result id={tool_call_id}] {content[:500]}")
            else:
                lines.append(f"[{role}] {content[:1000]}")
        return "\n\n".join(lines)

    def _fallback_truncate(self, old_messages: List[Dict[str, Any]]) -> str:
        """Fallback: extract key facts without an LLM call when compression fails."""
        facts = []
        for msg in old_messages:
            content = msg.get("content", "")
            if not content:
                continue
            # Extract lines that look like facts
            for line in content.split("\n"):
                line = line.strip()
                if any(kw in line.lower() for kw in
                       ("flag", "port", "service", "endpoint", "vuln", "waf",
                        "host", "ip", "192.", "10.", "sql", "xss", "cmdi",
                        "error", "blocked", "403", "401", "200")):
                    facts.append(line[:200])
            if len(facts) >= 30:
                break
        return "\n".join(facts[:40]) if facts else ""


class LLMFunctionMapping:
    """Auto-convert Python functions to OpenAI tool definitions.

    Reference: Cochise common.py:89 — LLMFunctionMapping with litellm.utils.function_to_dict
    """

    def __init__(self):
        self._registry: Dict[str, tuple[Callable, Dict[str, Any]]] = {}

    def register(self, func: Callable) -> Dict[str, Any]:
        """Register a function and return its OpenAI tool definition."""
        sig = inspect.signature(func)
        doc = inspect.getdoc(func) or ""

        properties = {}
        required = []
        for name, param in sig.parameters.items():
            if name in ("self", "cls"):
                continue
            param_type = "string"
            if param.annotation is int:
                param_type = "integer"
            elif param.annotation is float:
                param_type = "number"
            elif param.annotation is bool:
                param_type = "boolean"

            properties[name] = {"type": param_type, "description": f"Parameter: {name}"}
            if param.default is inspect.Parameter.empty:
                required.append(name)

        tool_def = {
            "type": "function",
            "function": {
                "name": func.__name__,
                "description": doc.split("\n")[0] if doc else "",
                "parameters": {
                    "type": "object",
                    "properties": properties,
                    "required": required,
                },
            },
        }
        self._registry[func.__name__] = (func, tool_def)
        return tool_def

    def call(self, tool_name: str, arguments: Dict[str, Any]) -> Any:
        """Execute a registered function by name."""
        if tool_name not in self._registry:
            raise ValueError(f"Tool '{tool_name}' not registered")
        func, _ = self._registry[tool_name]
        return func(**arguments)

    def get_all_definitions(self) -> List[Dict[str, Any]]:
        """Get all registered tool definitions for LLM tool_choice."""
        return [tool_def for _, tool_def in self._registry.values()]


def estimate_tokens(text: str) -> int:
    """Rough token count (4 chars ≈ 1 token)."""
    return len(text) // 4
