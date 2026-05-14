"""LLM unified interface using LiteLLM, with automatic function-to-tool conversion.

Reference: Cochise src/cochise/common.py:89 — LLMFunctionMapping pattern
"""

from __future__ import annotations

import json
import inspect
from typing import Any, Callable, Dict, List, Optional

import litellm


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

        if api_key:
            import os
            os.environ["OPENAI_API_KEY"] = api_key
        if base_url:
            self.model = f"openai/{model}"
            litellm.api_base = base_url

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
