"""Deterministic tool-parameter reliability (P9).

P9 separates INVALID_ARGUMENT (an authoring/schema error that can be
detected BEFORE the tool runs) from genuine execution failure. The
capability path in ``ToolExecutor`` validates every planned tool call
against the gateway's declared parameter schema and applies deterministic
corrections:

    - missing required field  -> pre-execution INVALID_ARGUMENT
      (no tool call is made; the capability falls back to its next tool)
    - unknown parameter       -> dropped (schema-driven correction)
    - missing optional field  -> filled from the schema's declared default

Legacy direct dispatch (``action["tool"]``) is untouched: the
orchestrator's existing LLM parameter-fix loop remains the fallback for
tasks without a capability.

The schema source is the gateway's ``get_tool_definitions()`` (OpenAI
function-calling format). Gateways without schema access contribute
nothing, and the executor then behaves exactly as before for those tools.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class ToolSchema:
    """Declared parameter contract for one gateway tool."""

    name: str
    properties: dict[str, dict]  # param name -> schema dict (may hold "default")
    required: list[str]


@dataclass
class ParamIssue:
    """One pre-execution validation finding."""

    kind: str  # "missing" | "unknown"
    field: str


class ToolSchemaProvider:
    """Collects ToolSchema from gateways exposing get_tool_definitions().

    Tolerant by design: a gateway without schema access, an empty
    definition list, or a malformed definition simply contributes nothing.
    """

    def __init__(self, *gateways: Any) -> None:
        self._schemas: dict[str, ToolSchema] = {}
        for gateway in gateways:
            self._collect(gateway)

    def _collect(self, gateway: Any) -> None:
        getter = getattr(gateway, "get_tool_definitions", None)
        if not callable(getter):
            return
        try:
            definitions = getter()
        except Exception:
            return
        for definition in definitions or []:
            function = (
                definition.get("function")
                if isinstance(definition, dict)
                else None
            )
            if not isinstance(function, dict):
                continue
            name = function.get("name")
            parameters = function.get("parameters") or {}
            properties = parameters.get("properties") or {}
            if not name or not isinstance(properties, dict):
                continue
            self._schemas[str(name)] = ToolSchema(
                name=str(name),
                properties={
                    str(key): dict(meta)
                    for key, meta in properties.items()
                    if isinstance(meta, dict)
                },
                required=[str(r) for r in (parameters.get("required") or [])],
            )

    def get(self, tool: str) -> ToolSchema | None:
        return self._schemas.get(tool)


class ParameterValidator:
    """Pre-execution check against a tool's declared schema."""

    def validate(self, schema: ToolSchema, params: dict) -> list[ParamIssue]:
        """Return missing-required and unknown-key findings (order stable)."""
        issues: list[ParamIssue] = []
        for required in schema.required:
            value = params.get(required)
            if isinstance(value, str):
                present = value.strip() != ""
            elif isinstance(value, (list, tuple, dict, set)):
                present = len(value) > 0
            else:
                present = value is not None
            if not present:
                issues.append(ParamIssue("missing", required))
        for key in params:
            if key not in schema.properties and key not in schema.required:
                issues.append(ParamIssue("unknown", str(key)))
        return issues


class ParameterCorrector:
    """Schema-driven corrections: drop unknown params, fill declared defaults.

    Missing REQUIRED params are left untouched — the validator decides
    whether the task can still proceed after correction.
    """

    def correct(self, schema: ToolSchema, params: dict) -> tuple[dict, bool]:
        """Return (corrected_params, changed)."""
        corrected = dict(params)
        changed = False
        for key in list(corrected):
            if key not in schema.properties and key not in schema.required:
                del corrected[key]
                changed = True
        for name, meta in schema.properties.items():
            if name not in corrected and isinstance(meta, dict) and "default" in meta:
                corrected[name] = meta["default"]
                changed = True
        return corrected, changed
