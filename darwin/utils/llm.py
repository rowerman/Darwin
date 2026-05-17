"""LLM unified interface using LiteLLM, with automatic function-to-tool conversion.

Reference: Cochise src/cochise/common.py:89 — LLMFunctionMapping pattern
"""

from __future__ import annotations

import json
import inspect
from typing import Any, Callable, Dict, List, Optional

import litellm


SYSTEM_PROMPT_COMPRESS = """You are a context compressor. Summarize the conversation below into a structured, compact record. Preserve ALL of the following:

1. **Key Facts Discovered**: hosts, IPs, ports, services, endpoints, parameters, technologies, credentials
2. **Actions Taken**: tools used, commands run, payloads sent — and their results (success or failure)
3. **Current State**: active sessions, captured flags, detected defenses, known vulnerabilities
4. **Failed Attempts**: what was tried and why it failed (to avoid repetition)
5. **Defense Intelligence**: any WAF/IDS/honeypot behavior observed

Output ONLY the compressed summary. Do NOT include greetings, explanations, or meta-commentary.
Do NOT use JSON — use concise bullet points grouped under the 5 headings above."""


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
    ):
        self.model = f"{provider}/{model}" if provider != "openai" else model
        self.provider = provider
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.conversation_history: List[Dict[str, Any]] = []
        self._compressed_count = 0  # number of times compression has been applied

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

        with open(config_path) as f:
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
    ) -> tuple[str, List[Dict[str, Any]] | None]:
        """Generate LLM response with optional tool calling.

        Returns:
            (content, tool_calls) — tool_calls is None if no tools were called.
            tool_calls is a list of dicts with 'name' and 'arguments' keys.
        """
        messages = self._build_messages(prompt, system_prompt)
        self.conversation_history = messages.copy()

        kwargs = dict(
            model=self.model,
            messages=messages,
            temperature=self.temperature,
            max_tokens=self.max_tokens,
        )

        if tools:
            kwargs["tools"] = tools
            kwargs["tool_choice"] = "auto"

        response = litellm.completion(**kwargs)
        choice = response.choices[0]

        content = choice.message.content or ""
        tool_calls_raw = getattr(choice.message, "tool_calls", None)

        # Add response to conversation history
        if tool_calls_raw:
            self.conversation_history.append({
                "role": "assistant",
                "content": content,
                "tool_calls": [
                    {"id": tc.id, "type": "function",
                     "function": {"name": tc.function.name, "arguments": tc.function.arguments}}
                    for tc in tool_calls_raw
                ],
            })
            parsed_calls = [
                {"name": tc.function.name, "arguments": json.loads(tc.function.arguments)}
                for tc in tool_calls_raw
            ]
            return content, parsed_calls
        else:
            self.conversation_history.append({"role": "assistant", "content": content})
            return content, None

    def _build_messages(
        self, prompt: str, system_prompt: str | None
    ) -> List[Dict[str, str]]:
        """Build message list, continuing conversation history if available."""
        if self.conversation_history:
            messages = self.conversation_history.copy()
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

    def reset(self) -> None:
        """Clear conversation history."""
        self.conversation_history = []

    @property
    def token_count(self) -> int:
        """Estimate current token usage."""
        total = 0
        for msg in self.conversation_history:
            total += len(str(msg)) // 4  # rough estimate: ~4 chars per token
        return total

    @property
    def context_load(self) -> float:
        """Context load ratio (0.0-1.0)."""
        return min(self.token_count / 180000, 1.0)

    def compress(
        self,
        keep_recent: int = 6,
        max_context_tokens: int = 180000,
        compression_threshold: float = 0.4,
    ) -> int:
        """Compress conversation history by summarizing older messages.

        Reference: Cochise planner.py — persistent dialogue + history compression.
        Keeps the most recent *keep_recent* messages intact. Compresses all older
        messages into a single compact summary injected as a system message.

        Only compresses if context_load exceeds compression_threshold.

        Args:
            keep_recent: Number of most recent messages to preserve intact.
            max_context_tokens: Token count considered 100% context load.
            compression_threshold: Fraction of max_context_tokens that triggers
                                   compression (e.g. 0.4 = 40%).

        Returns:
            Number of tokens saved (positive = compression succeeded,
            0 = below threshold, nothing done, -1 = compression failed).
        """
        if self.context_load < compression_threshold:
            return 0

        if len(self.conversation_history) <= keep_recent + 2:
            return 0  # not enough messages to warrant compression

        # Split: preserve system prompt + recent messages, compress the rest
        old_messages = self.conversation_history[:-keep_recent]
        recent = self.conversation_history[-keep_recent:]

        # Serialize old messages for the compression prompt
        serialized = self._serialize_messages(old_messages)
        tokens_before = self.token_count

        compression_prompt = (
            f"The following is an older portion of a penetration testing conversation "
            f"that needs to be compressed. Extract and preserve all critical information.\n\n"
            f"{serialized}"
        )

        try:
            summary, _ = self.generate(
                prompt=compression_prompt,
                system_prompt=SYSTEM_PROMPT_COMPRESS,
            )
        except Exception:
            # If compression LLM call fails, fall back to truncation
            summary = self._fallback_truncate(old_messages)
            if not summary:
                return -1

        # Replace old messages with compressed summary
        self.conversation_history = [
            {"role": "system", "content": f"[COMPRESSED CONTEXT — {len(old_messages)} messages summarized]\n\n{summary}"}
        ] + recent
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
