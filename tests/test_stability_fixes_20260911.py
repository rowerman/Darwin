"""Regression tests for the cloud-25 / cloud-26 stability fixes.

Covers: unlimited token budget, plan-first execution, success_condition
verification (including write intent), the analyze-phase speculative split,
and the HTTP write-tool parameter normalization.
"""

from __future__ import annotations

import types

import pytest

from darwin.core.context import ContextManager
from darwin.core.schemas import AnalyzeOutputV1, parse_analyze_output
from darwin.orchestration.execution import (
    ExecutionCoordinator,
    _call_method,
    _planned_write_intent,
)
from darwin.tools.mcp_gateway import MCPGateway, ToolResult
from darwin.tools.spec import ToolSpec


class _LLM:
    total_tokens = 10_000_000
    token_count = 1


class _SpecGateway:
    """Minimal gateway exposing ToolSpec-backed plan validation."""

    def __init__(self, specs):
        self._specs = {spec.name: spec for spec in specs}

    def get_tool_names(self):
        return set(self._specs)

    def get_tool_specs(self):
        return dict(self._specs)

    def normalize_params(self, name, params):
        return dict(params)


def _coordinator(attack_gw, recon_gw):
    orch = types.SimpleNamespace(attack_gateway=attack_gw, recon_gateway=recon_gw)
    coord = ExecutionCoordinator.__new__(ExecutionCoordinator)
    object.__setattr__(coord, "_orch", orch)
    return coord


def _probe_spec(default_url: bool = False):
    url_schema = {"type": "string"}
    if default_url:
        url_schema["default"] = ""
    return ToolSpec(name="http_method_probe", parameters={"url": url_schema},
                    domains=["web"])


def test_tokens_exceeded_is_disabled_for_unlimited_budget():
    ctx = ContextManager(
        llm=_LLM(), memory=None, dkg=None,
        max_context_tokens=1000, compression_threshold=0.4,
    )
    assert ctx.tokens_exceeded(0) is False


def test_plan_with_complete_params_executes_directly():
    coord = _coordinator(_SpecGateway([_probe_spec()]), _SpecGateway([]))
    ok, missing = coord._plan_params_complete(
        "http_method_probe",
        {"url": "http://x/packages/a/1", "method": "PUT", "data": "echo hi"},
        {"http_method_probe"},
    )
    assert ok is True and missing == []


def test_plan_missing_required_param_falls_back_to_llm():
    coord = _coordinator(_SpecGateway([_probe_spec()]), _SpecGateway([]))
    ok, missing = coord._plan_params_complete(
        "http_method_probe", {"method": "PUT"}, {"http_method_probe"}
    )
    assert ok is False and missing == ["url"]


def test_write_intent_detection():
    assert _planned_write_intent("http_method_probe", {"method": "PUT"}) is True
    assert _planned_write_intent("curl_get", {"url": "http://x"}) is False
    assert _planned_write_intent("file_upload", {"url": "http://x"}) is True
    assert _call_method("http_post", {}) == "POST"
    assert _call_method("curl_get", {}) == "GET"


@pytest.mark.asyncio
async def test_tool_success_condition_rejects_substituted_tool():
    coord = _coordinator(_SpecGateway([]), _SpecGateway([]))
    met, detail = await coord._verify_success_condition(
        {"type": "tool_success", "tool": "http_method_probe", "method": "PUT"},
        [{"name": "curl_get", "args": {"url": "http://x"}, "success": True,
          "stdout": "HTTP/1.1 200 OK", "stderr": "", "method": "GET"}],
        True,
        False,
    )
    assert met is False
    assert "http_method_probe" in detail


@pytest.mark.asyncio
async def test_tool_success_condition_accepts_matching_write():
    coord = _coordinator(_SpecGateway([]), _SpecGateway([]))
    met, _ = await coord._verify_success_condition(
        {"type": "tool_success", "tool": "http_method_probe", "method": "PUT"},
        [{"name": "http_method_probe", "args": {"method": "PUT"}, "success": True,
          "stdout": "HTTP 201 CREATED", "stderr": "", "method": "PUT"}],
        True,
        False,
    )
    assert met is True


@pytest.mark.asyncio
async def test_probe_condition_reads_back_the_effect():
    coord = _coordinator(_SpecGateway([]), _SpecGateway([]))

    async def _fake_call(name, params):
        return ToolResult(tool_name="curl_get", success=True,
                          stdout='HTTP/1.1 200 OK\n\n{"packages":[{"name":"x"}]}',
                          stderr="", exit_code=0, elapsed_ms=0.0)

    coord.__dict__["_call_tool"] = _fake_call
    met, detail = await coord._verify_success_condition(
        {"type": "probe", "url": "http://x/", "contains": "x"},
        [], True, False,
    )
    assert met is True and "confirmed" in detail


@pytest.mark.asyncio
async def test_body_contains_condition_reports_the_gap():
    coord = _coordinator(_SpecGateway([]), _SpecGateway([]))
    met, detail = await coord._verify_success_condition(
        {"type": "body_contains", "value": "AccessDenied"},
        [{"name": "curl_get", "args": {}, "success": True,
          "stdout": "HTTP/1.1 200 OK", "stderr": "", "method": "GET"}],
        True, False,
    )
    assert met is False and "AccessDenied" in detail


def test_analyze_output_separates_speculative_from_evidence():
    payload = (
        '{"application_understanding": "x",'
        ' "vulnerabilities": [{"vuln_type": "IDOR", "endpoint": "http://x/r/1",'
        '   "param": "id", "confidence": 0.7, "evidence": "/r/1 answered 403"}],'
        ' "speculative": [{"vuln_type": "SQLi", "endpoint": "http://x/search",'
        '   "param": "q", "confidence": 0.2, "evidence": "has a q param"}]}'
    )
    model, err = parse_analyze_output(payload)
    assert err == "" and isinstance(model, AnalyzeOutputV1)
    assert [v.vuln_type for v in model.vulnerabilities] == ["IDOR"]
    assert [v.vuln_type for v in model.speculative] == ["SQLi"]


def test_analyze_output_defaults_speculative_to_empty():
    model, err = parse_analyze_output(
        '{"vulnerabilities": [{"vuln_type": "XSS", "endpoint": "http://x"}]}'
    )
    assert err == "" and model.speculative == []


def test_gateway_normalize_params_applies_alias_rules():
    gw = MCPGateway()

    async def _noop(target_url: str):
        return ToolResult(tool_name="t", success=True, stdout="", stderr="",
                          exit_code=0, elapsed_ms=0.0)

    gw.register(
        name="t", func=_noop, description="d",
        parameters={"target_url": {"type": "string"}},
    )
    assert gw.normalize_params("t", {"url": "http://x"}) == {"target_url": "http://x"}
    assert gw.normalize_params("missing", {"url": "http://x"}) == {}
