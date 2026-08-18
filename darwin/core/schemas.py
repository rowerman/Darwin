"""Versioned pydantic schemas for inter-phase LLM outputs (v2 Stage A).

Every phase boundary that consumes LLM-produced JSON (analyze, research,
plan generation, plan review) goes through these models plus the parse
helpers below. Fields are fixed and canonical; unknown keys are dropped
so downstream code only ever consumes the declared fields.

Parse contract:
- Extraction is tolerant (direct JSON, fenced code block, bracket/brace
  counting) and mirrors the orchestrator's legacy ``_extract_json``
  behavior so valid-but-messy LLM output still parses.
- Validation is strict on the declared fields (required keys, types).
- On any failure the helpers return ``(None, error)`` and the caller
  records a ``schema_violation`` event and falls back to its legacy
  lenient path (zero-regression guarantee).
"""

from __future__ import annotations

import json
import re
from typing import Any

from pydantic import BaseModel, Field, field_validator, model_validator


# ── Analyze output ──────────────────────────────────────────────────


class AnalyzeVulnV1(BaseModel):
    """One vulnerability hypothesis from the analyze phase."""

    vuln_type: str
    endpoint: str = ""
    param: str = ""
    confidence: float = 0.5
    evidence: str = ""
    suggested_tool: str = ""
    tool_args: dict[str, Any] = Field(default_factory=dict)

    @field_validator("tool_args", mode="before")
    @classmethod
    def _normalize_tool_args(cls, value: Any) -> Any:
        """Accept a CLI-style string arg and wrap it like the legacy path."""
        if isinstance(value, str):
            try:
                parsed = json.loads(value)
                if isinstance(parsed, dict):
                    return parsed
            except (json.JSONDecodeError, TypeError):
                pass
            return {"url": value}
        if isinstance(value, dict):
            return value
        return {}


class AttackPathV1(BaseModel):
    """One chained attack path from the analyze phase."""

    id: str = ""
    description: str = ""
    steps: list[dict[str, Any]] = Field(default_factory=list)

    @model_validator(mode="before")
    @classmethod
    def _normalize_id(cls, data: Any) -> Any:
        """The analyze prompt asks for ``path_id``; the legacy consumer
        reads ``id``. Accept both, canonicalize to ``id``."""
        if isinstance(data, dict) and not data.get("id") and data.get("path_id"):
            data = {**data, "id": data["path_id"]}
        return data


class AnalyzeOutputV1(BaseModel):
    """Full analyze-phase LLM output (new dict format)."""

    application_understanding: str = ""
    vulnerabilities: list[AnalyzeVulnV1] = Field(default_factory=list)
    attack_paths: list[AttackPathV1] = Field(default_factory=list)


# ── Research output ─────────────────────────────────────────────────


class ResearchFindingV1(BaseModel):
    """One vulnerability research finding (vuln-focused format)."""

    vuln_type: str
    cve_ids: list[str] = Field(default_factory=list)
    exploit_modules: list[str] = Field(default_factory=list)
    key_techniques: list[str] = Field(default_factory=list)
    credentials_to_try: list[str] = Field(default_factory=list)
    confidence_adjustment: float = 0.0

    @field_validator(
        "cve_ids", "exploit_modules", "key_techniques", "credentials_to_try",
        mode="before",
    )
    @classmethod
    def _list_of_str(cls, value: Any) -> Any:
        if value is None:
            return []
        if isinstance(value, list):
            return [str(v) for v in value]
        return [str(value)]


class ServiceResearchFindingV1(BaseModel):
    """One service research finding (service-focused format)."""

    service: str
    exploits_found: list[str] = Field(default_factory=list)
    cves: list[str] = Field(default_factory=list)
    notes: str = ""

    @field_validator("exploits_found", "cves", mode="before")
    @classmethod
    def _list_of_str_svc(cls, value: Any) -> Any:
        if value is None:
            return []
        if isinstance(value, list):
            return [str(v) for v in value]
        return [str(value)]


# ── Plan output ─────────────────────────────────────────────────────


class PlanTaskV1(BaseModel):
    """One plan task from the planner / plan-review LLM.

    ``status`` is intentionally NOT part of the LLM contract — the
    runtime owns task lifecycle via ``TaskStatus``.
    """

    id: str
    instruction: str
    tool: str = ""
    params: dict[str, Any] = Field(default_factory=dict)
    reason: str = ""
    dependent_task_ids: list[str] = Field(default_factory=list)
    priority: float = 0.5
    # Canonical optional fields the legacy runtime consumed beyond the
    # prompt contract (tool guessing / scheduler priority).
    vuln_type: str = ""
    source: str = ""

    @model_validator(mode="before")
    @classmethod
    def _normalize_deps_and_params(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data
        out = dict(data)
        if not out.get("dependent_task_ids") and out.get("dependencies"):
            deps = out["dependencies"]
            out["dependent_task_ids"] = deps if isinstance(deps, list) else [deps]
        return out

    @field_validator("params", mode="before")
    @classmethod
    def _normalize_params(cls, value: Any) -> Any:
        """Accept a JSON-string params like the legacy dict path."""
        if isinstance(value, str):
            try:
                parsed = json.loads(value)
                if isinstance(parsed, dict):
                    return parsed
            except (json.JSONDecodeError, TypeError):
                pass
            return {"url": value}
        if isinstance(value, dict):
            return value
        return {"value": value}


# ── Tolerant JSON extraction (mirrors orchestrator._extract_json) ───

_FENCED_RE = re.compile(r"```(?:json)?\s*([\s\S]*?)```", re.IGNORECASE)


def extract_json_value(text: str) -> Any | None:
    """Extract the first complete JSON value from LLM response text.

    Returns None when nothing parseable is found (caller falls back).
    """
    if not isinstance(text, str) or not text.strip():
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    match = _FENCED_RE.search(text)
    if match:
        try:
            return json.loads(match.group(1))
        except json.JSONDecodeError:
            pass
    # Bracket counting for arrays (handles nesting + trailing text).
    start = text.find("[")
    if start != -1:
        depth = 0
        for i, c in enumerate(text[start:], start):
            if c == "[":
                depth += 1
            elif c == "]":
                depth -= 1
                if depth == 0:
                    try:
                        return json.loads(text[start : i + 1])
                    except json.JSONDecodeError:
                        break
    # Non-greedy object match (no nesting concerns for flat objects).
    match = re.search(r"\{.*?\}", text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(0))
        except json.JSONDecodeError:
            pass
    return None


def _parse(
    text: str, model_cls: type[BaseModel], *, array: bool = True
) -> tuple[Any, str]:
    """Validate extracted JSON against one pydantic model.

    Returns (value, "") on success where value is the model or a list of
    models, or (None, error_message) on any failure.
    """
    try:
        raw = extract_json_value(text)
        if raw is None:
            return None, "no JSON found in LLM output"
        if array:
            if not isinstance(raw, list):
                return None, "expected a JSON array"
            parsed = []
            for item in raw:
                if not isinstance(item, dict):
                    return None, f"array item is not an object: {str(item)[:80]}"
                parsed.append(model_cls.model_validate(item))
            return parsed, ""
        if not isinstance(raw, dict):
            return None, "expected a JSON object"
        return model_cls.model_validate(raw), ""
    except Exception as e:  # pydantic ValidationError and friends
        return None, f"{type(e).__name__}: {e}"


def parse_analyze_output(text: str) -> tuple[AnalyzeOutputV1 | None, str]:
    """Parse the analyze-phase output (dict format, legacy flat-array
    fallback). Returns (None, error) on any validation failure."""
    try:
        raw = extract_json_value(text)
        if raw is None:
            return None, "no JSON found in LLM output"
        if isinstance(raw, list):
            # Legacy backward-compat flat array of vulnerability dicts.
            vulns = []
            for item in raw:
                if not isinstance(item, dict):
                    return None, f"array item is not an object: {str(item)[:80]}"
                vulns.append(AnalyzeVulnV1.model_validate(item))
            return AnalyzeOutputV1(vulnerabilities=vulns), ""
        if not isinstance(raw, dict):
            return None, "expected a JSON object or array"
        return AnalyzeOutputV1.model_validate(raw), ""
    except Exception as e:
        return None, f"{type(e).__name__}: {e}"


def parse_research_findings(
    text: str,
) -> tuple[list[ResearchFindingV1] | None, str]:
    return _parse(text, ResearchFindingV1, array=True)


def parse_service_research_findings(
    text: str,
) -> tuple[list[ServiceResearchFindingV1] | None, str]:
    return _parse(text, ServiceResearchFindingV1, array=True)


def parse_plan_tasks(text: str) -> tuple[list[PlanTaskV1] | None, str]:
    return _parse(text, PlanTaskV1, array=True)
