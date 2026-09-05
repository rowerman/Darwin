"""Structured-output regression tests for the cloud-21/22 failure modes.

Covers:
- report-style analyze JSON (name/affected_endpoint/why/remediation) recovery;
- schema-valid-but-empty output with unverified_hypotheses recovery;
- nested per-endpoint hypothesis blocks (cloud-19/20 style);
- analyze/plan stages never expose registry tools and mark self-describing
  APIs so the planner skips directory brute force.
"""

import json

import pytest

from darwin.core.schemas import parse_analyze_output
from darwin.orchestration.structured import normalize_analyze_output_lenient


def _fake_llm(content):
    class FakeLLM:
        def __init__(self):
            self.calls = []
            self.token_count = 0

        def generate(self, prompt, system_prompt=None, tools=None,
                     temperature=None, timeout=180.0, stage=None):
            self.calls.append((stage, prompt, tools is not None))
            return content, None

        def replace_system_prompt(self, prompt):
            self.calls.append(("replace_system_prompt", prompt))

        def add_context_message(self, content, role="user"):
            self.calls.append(("add_context_message", content))

        def add_tool_result(self, tool_call_id, result):
            self.calls.append(("add_tool_result", tool_call_id))

        def compress(self, **kwargs):
            return 0

    return FakeLLM()


class _NoToolGateway:
    def __init__(self):
        self.calls = []

    def get_tool_names(self):
        return []

    def get_tool_definitions(self):
        return []

    async def call(self, name, params):
        self.calls.append((name, params))
        raise AssertionError("structured stages must not call tools")


def test_lenient_normalization_cloud21_report_style():
    content = json.dumps({
        "service": "Directory API",
        "vulnerabilities": [
            {
                "id": 1,
                "name": "Broken Object Level Authorization on tenant user listing",
                "affected_endpoint": "GET /api/users?tenant=<tenant>",
                "why": "Root discovery does not require an Authorization header.",
                "remediation": "Require authenticated requests.",
            },
            {
                "id": 2,
                "name": "Potential JWT signature bypass",
                "affected_endpoint": "POST /token {tenant}",
                "why": "The endpoint issues a signed JWT.",
                "remediation": "Rotate the secret.",
            },
        ],
    })
    model, err = normalize_analyze_output_lenient(
        content, base_url="http://localhost:10632"
    )
    assert err == ""
    assert model is not None
    assert len(model.vulnerabilities) == 2
    first = model.vulnerabilities[0]
    assert first.endpoint == "http://localhost:10632/api/users"
    assert first.vuln_type == "IDOR"
    assert "Authorization" in first.evidence
    second = model.vulnerabilities[1]
    assert second.endpoint == "http://localhost:10632/token"
    assert second.vuln_type == "AUTH"


def test_lenient_normalization_cloud22_unverified_hypotheses():
    content = json.dumps({
        "host": "localhost",
        "open_ports": [{"port": 10633}],
        "endpoints": [
            {"method": "GET", "path": "/", "status_code": 404,
             "exploitable": False},
        ],
        "vulnerabilities": [],
        "unverified_hypotheses": [
            {
                "vulnerability": "CVE-2021-38647 (OMIGOD) OMI/WSMan unauth RCE",
                "endpoint": "/wsman (POST)",
                "status": "unverified",
                "reason": "banner conflict — probe anyway",
            }
        ],
        "proof_flags": [],
        "outcome": "Insufficient information",
    })
    model, err = normalize_analyze_output_lenient(
        content, base_url="http://localhost:10633"
    )
    assert err == ""
    assert model is not None
    assert len(model.vulnerabilities) == 1
    vuln = model.vulnerabilities[0]
    assert vuln.endpoint == "http://localhost:10633/wsman"
    assert vuln.confidence == 0.3
    assert vuln.vuln_type == "CMDi"  # inferred from "RCE"
    assert "probe anyway" in vuln.evidence


def test_lenient_normalization_nested_endpoint_hypotheses():
    content = json.dumps({
        "application_understanding": "volume attach API",
        "endpoints_reviewed": [
            {
                "method": "POST",
                "path": "/volumes/<id>/attach",
                "vulnerability_hypotheses": [
                    {
                        "vulnerability": "IDOR via predictable sequential volume IDs",
                        "endpoint": "POST /volumes/<id>/attach",
                        "parameter": "id",
                        "why": "No ownership check on attach",
                    }
                ],
            }
        ],
    })
    model, err = normalize_analyze_output_lenient(
        content, base_url="http://localhost:10631"
    )
    assert err == ""
    assert model is not None
    assert len(model.vulnerabilities) == 1
    vuln = model.vulnerabilities[0]
    assert vuln.endpoint == "http://localhost:10631/volumes/<id>/attach"
    assert vuln.param == "id"
    assert vuln.vuln_type == "IDOR"


def test_lenient_normalization_drops_entries_without_endpoint():
    content = json.dumps({
        "vulnerabilities": [
            {"name": "no endpoint here", "why": "x"},
            {"vuln_type": "IDOR", "endpoint": "http://t/a",
             "confidence": 0.4, "evidence": "y"},
        ]
    })
    model, _ = normalize_analyze_output_lenient(content, base_url="")
    assert model is not None
    assert len(model.vulnerabilities) == 1
    assert model.vulnerabilities[0].endpoint == "http://t/a"


def _make_orch(monkeypatch, llm):
    from darwin.orchestrator import Orchestrator
    from darwin.tools.mcp_client import MCPClientPool

    class _FakeMCP:
        def get_tool_names(self):
            return set()

        def get_tool_definitions(self):
            return []

    class _FakeCTEG:
        def __init__(self, storage_path="cteg_state.json"):
            self.storage_path = storage_path

        def add_credential(self, **kwargs):
            pass

        def commit_task(self, *args, **kwargs):
            pass

        def get_credentials(self, *args, **kwargs):
            return []

        def get_suggestions(self, *args, **kwargs):
            return {}

    monkeypatch.setattr("darwin.orchestrator.create_recon_gateway",
                        lambda: _NoToolGateway())
    monkeypatch.setattr("darwin.orchestrator.create_attack_gateway",
                        lambda: _NoToolGateway())
    monkeypatch.setattr("darwin.orchestrator.MCPClientPool", _FakeMCP)
    monkeypatch.setattr("darwin.orchestrator.CTEG", _FakeCTEG)
    return Orchestrator(llm_session=llm, time_budget=1200)


@pytest.mark.asyncio
async def test_analyze_phase_recovers_report_style_output(monkeypatch):
    drifted = json.dumps({
        "service": "Directory API",
        "vulnerabilities": [
            {
                "name": "Broken Object Level Authorization",
                "affected_endpoint": "GET /api/users?tenant=<tenant>",
                "why": "No Authorization check on root discovery.",
            }
        ],
    })
    llm = _fake_llm(drifted)
    orch = _make_orch(monkeypatch, llm)
    orch._task_description = "test"
    orch.dkg.add_node("Endpoint", "ep-root", {
        "url": "http://localhost:10632/", "method": "GET", "params": "",
        "sample_status": 200,
        "sample_response": '{"service": "Directory API", "endpoints": [...]}',
        "discovered_by": "bootstrap",
    })
    async def _probe():
        return ""

    monkeypatch.setattr(orch, "_probe_endpoints", _probe)
    await orch._analyze_phase()
    assert len(orch.vulnerabilities) == 1
    v = orch.vulnerabilities[0]
    assert v.endpoint == "http://localhost:10632/api/users"
    assert v.vuln_type == "IDOR"
    # structured stages never exposed tools
    generate_calls = [
        c for c in llm.calls
        if len(c) == 3 and c[0] in ("analyze", "plan", "plan_review")
    ]
    assert generate_calls
    assert all(c[2] is False for c in generate_calls)


@pytest.mark.asyncio
async def test_plan_prompt_marks_self_describing_api_and_embeds_contract_card(
    monkeypatch,
):
    llm = _fake_llm("[]")
    orch = _make_orch(monkeypatch, llm)
    orch.dkg.add_node("Service", "svc-1", {
        "port": 10632, "protocol": "tcp",
        "service_name": "Directory API",
        "banner": "Directory API",
    })
    orch.dkg.add_node("Endpoint", "ep-root", {
        "url": "http://localhost:10632/", "method": "GET", "params": "",
        "sample_status": 200,
        "sample_response": '{"service": "Directory API", "endpoints": ["POST /token"]}',
        "discovered_by": "bootstrap",
    })
    monkeypatch.setattr("darwin.rag.get_rag", lambda: None)
    await orch._generate_exploitation_plan("http://localhost:10632")
    plan_prompts = [
        p for (stage, p, _) in llm.calls
        if stage == "plan" and p
    ]
    assert plan_prompts
    prompt = plan_prompts[0]
    assert "API self-describing: YES" in prompt
    assert "Tool Contract Card" in prompt
    assert "tool_registry_get" not in prompt
    assert "add directory enumeration" in prompt
    assert "API self-describing: YES" in prompt
