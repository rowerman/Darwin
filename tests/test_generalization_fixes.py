"""Regression tests for the cross-scenario defects found in cloud-23/24.

Covers: planner tool-catalog completeness, host-availability gating of
planned tools, HTTP tool substitution, send_payload contract/headers, ffuf
FUZZ normalization, shell pipeline exit codes, probe baseline semantics,
DAVE flag-first verification, and isolated LLM stages.
"""

import asyncio
import json

import pytest

from darwin.dave import DAVE, ExploitAttempt
from darwin.orchestration.planning import _HTTP_TARGET_PARAMS, _pick_http_tool
from darwin.orchestration.structured import render_tool_contract_card
from darwin.tools.attack_server import (
    create_attack_gateway,
    normalize_fuzz_url,
    _normalize_header_arg,
)
from darwin.tools.availability import clear_cache, is_available
from darwin.tools.mcp_gateway import _pipeline_returncode
from darwin.tools.paths import resolve_wordlist
from darwin.tools.recon_server import create_recon_gateway
from darwin.utils.http_client import (
    BaselineResult,
    HTTPResponse,
    ProbeClient,
)


def _all_specs():
    specs = {}
    for gateway in (create_attack_gateway(), create_recon_gateway()):
        specs.update(gateway.get_tool_specs())
    return specs


def _all_tool_defs():
    defs = []
    for gateway in (create_attack_gateway(), create_recon_gateway()):
        defs.extend(gateway.get_tool_definitions())
    return defs


class TestToolCatalogCompleteness:
    def test_card_lists_every_registered_tool(self):
        """The planner must see the whole catalog.

        The card used to stop at 90 entries; the HTTP/recon tools are
        registered last, so they — and the registry meta-tools — were
        invisible to every plan/analyze call.
        """
        names = {d["function"]["name"] for d in _all_tool_defs()}
        card = render_tool_contract_card(_all_tool_defs())
        rendered = {
            line.split("(", 1)[0][2:]
            for line in card.split("\n")
            if line.startswith("- ")
        }
        assert names <= rendered
        assert "http_method_probe" in rendered
        assert "curl_get" in rendered
        assert "tool_registry_get" in rendered


class TestToolAvailability:
    def test_missing_binary_is_unavailable(self):
        clear_cache()
        spec = type("S", (), {"name": "x", "dependencies": [],
                             "command_template": "definitely-not-a-real-binary-xyz --go",
                             "shell_args": []})()
        assert is_available(spec) is False

    def test_unresolvable_placeholder_dependency_is_ignored(self):
        clear_cache()
        spec = type("S", (), {"name": "x", "dependencies": ["{command}"],
                             "command_template": "{command} 2>&1",
                             "shell_args": []})()
        assert is_available(spec) is True

    def test_pick_http_tool_prefers_available_specialist(self):
        picked = _pick_http_tool(_all_specs())
        assert picked in {"http_method_probe", "http_post", "send_payload", "curl_get"}

    def test_cloud_tool_with_endpoint_url_is_not_http_shaped(self):
        """endpoint_url-based cloud tools are not "HTTP tools by url param"."""
        specs = _all_specs()
        assert "endpoint_url" in _HTTP_TARGET_PARAMS
        aws = specs["aws_sts_query"]
        assert "url" not in aws.parameters
        # The sanitizer must not treat them as non-HTTP and silently drop them.
        assert "endpoint_url" in aws.parameters


class TestToolContractFixes:
    def test_send_payload_param_and_payload_are_optional(self):
        specs = _all_specs()
        required = specs["send_payload"].required
        assert required == ["url"]
        assert "headers" in specs["send_payload"].parameters

    def test_send_payload_accepts_empty_param_json_body(self):
        from darwin.core.parameters import ParameterValidator, ToolSchemaProvider

        class _G:
            def get_tool_definitions(self):
                return _all_tool_defs()

        provider = ToolSchemaProvider(_G())
        schema = provider.get("send_payload")
        issues = ParameterValidator().validate(schema, {
            "url": "http://t/portfolios",
            "param": "",
            "payload": '{"name": "p"}',
            "method": "POST",
            "body_format": "json",
        })
        assert issues == []

    def test_header_normalization_accepts_pipe_and_newline(self):
        normalized = _normalize_header_arg("X-Api-Key: k|Authorization: Bearer t")
        assert normalized == "X-Api-Key: k\nAuthorization: Bearer t"
        assert _normalize_header_arg("") == ""

    def test_fuzz_url_gets_placeholder(self):
        assert normalize_fuzz_url("http://h:10635/") == "http://h:10635/FUZZ"
        assert normalize_fuzz_url("http://h:10635/FUZZ") == "http://h:10635/FUZZ"

    def test_gobuster_uses_v3_subcommand_and_bundled_wordlist(self):
        specs = _all_specs()
        template = specs["gobuster_dir"].command_template
        assert template.startswith("gobuster dir ")
        assert "{wordlist}" in template
        # Declared default stays machine independent; the real path resolves
        # at call time from the bundled wordlist directory.
        assert "/" not in specs["gobuster_dir"].parameters["wordlist"]["default"]
        assert resolve_wordlist(
            specs["gobuster_dir"].parameters["wordlist"]["default"]
        ).endswith(".txt")

    def test_no_hardcoded_absolute_paths_in_templates(self):
        for name, spec in _all_specs().items():
            template = spec.command_template or ""
            assert "/home/kianabin" not in template, name


class TestShellPipelineExitCode:
    def test_sigpipe_with_output_is_treated_as_success(self):
        assert _pipeline_returncode(141, "results") == 0
        assert _pipeline_returncode(141, "") == 141
        assert _pipeline_returncode(0, "") == 0
        assert _pipeline_returncode(2, "err") == 2


class TestProbeBaselineSemantics:
    @staticmethod
    def _client_with_baseline(url, status, body, elapsed=10.0):
        client = ProbeClient()
        client._baselines[url] = BaselineResult(
            url=url,
            response=HTTPResponse(
                url=url, status_code=status, headers={}, body=body,
                elapsed_ms=elapsed,
            ),
            timestamp=0.0,
        )
        return client

    @pytest.mark.asyncio
    async def test_always_forbidden_endpoint_is_not_a_waf(self):
        client = self._client_with_baseline(
            "http://t/api/unsupported", 403,
            '{"error":"AccessDenied","message":"User: arn:aws:iam::1:user/x"}',
        )
        blocked, _, _ = client._analyze_response(
            "' OR '1'='1",
            HTTPResponse(url="http://t/api/unsupported", status_code=403,
                         headers={}, body='{"error":"AccessDenied"}',
                         elapsed_ms=11.0),
            "http://t/api/unsupported",
        )
        assert blocked is False

    @pytest.mark.asyncio
    async def test_status_change_to_403_is_blocked(self):
        client = self._client_with_baseline("http://t/x", 200, "hello world")
        blocked, _, _ = client._analyze_response(
            "' OR '1'='1",
            HTTPResponse(url="http://t/x", status_code=403, headers={},
                         body="blocked", elapsed_ms=12.0),
            "http://t/x",
        )
        assert blocked is True


class TestDaveFlagFirst:
    @pytest.mark.asyncio
    async def test_flag_in_forbidden_body_still_passes(self):
        resp = HTTPResponse(
            url="http://t/logs", status_code=403, headers={},
            body='{"error":"AccessDenied","flag":"flag{unit-test}"}',
            elapsed_ms=5.0,
        )
        result = await DAVE().verify(ExploitAttempt(
            target_url="http://t/logs", http_response=resp,
        ))
        assert result.passed is True
        assert result.flag_value == "flag{unit-test}"


class TestIsolatedLlmScope:
    @staticmethod
    def _session():
        from darwin.utils.llm import LLMSession
        return LLMSession(model="fake", provider="openai", api_key="x")

    def test_isolated_call_does_not_touch_history(self, monkeypatch):
        import darwin.utils.llm as llm_mod

        captured = {}

        def _completion(**kwargs):
            captured["messages"] = kwargs["messages"]
            msg = type("M", (), {"content": "{}", "reasoning_content": None,
                                 "tool_calls": None})()
            return type("R", (), {"choices": [type("C", (), {"message": msg})()]})()

        monkeypatch.setattr(llm_mod.litellm, "completion", _completion)
        session = self._session()
        session.conversation_history = [{"role": "user", "content": "outer"}]
        session._carried_digest = "## [COMPRESSED CONTEXT]\nremember this"

        session.generate(prompt="stage prompt", stage="plan")
        # A plain call continues the session history (outer + prompt + reply).
        assert len(session.conversation_history) > 1

        before = list(session.conversation_history)
        with session.isolated_scope():
            session.generate(prompt="structured prompt", stage="plan")
        assert session.conversation_history == before
        assert "remember this" in captured["messages"][-1]["content"]

    def test_total_tokens_accumulates(self, monkeypatch):
        import darwin.utils.llm as llm_mod

        def _completion(**kwargs):
            msg = type("M", (), {"content": "x" * 400, "reasoning_content": None,
                                 "tool_calls": None})()
            return type("R", (), {"choices": [type("C", (), {"message": msg})()]})()

        monkeypatch.setattr(llm_mod.litellm, "completion", _completion)
        session = self._session()
        assert session.total_tokens == 0
        session.generate(prompt="a" * 400, stage="analyze")
        first = session.total_tokens
        assert first > 0
        session.generate(prompt="b" * 400, stage="analyze")
        assert session.total_tokens > first


class TestTokenBudgetUsesCumulativeUsage:
    def test_tokens_exceeded_uses_total_tokens(self):
        from darwin.core.context import ContextManager
        from darwin.core.memory import MemoryManager

        class _Session:
            def __init__(self):
                self.token_count = 10      # small current context
                self.total_tokens = 5000   # but a lot consumed
                self.context_load = 0.01
                self._compressed_count = 0
                self.max_context_tokens = 1000

            def compress(self, **kwargs):
                return 0

        ctx = ContextManager(llm=_Session(), memory=MemoryManager())
        assert ctx.tokens_exceeded(1000) is True


class TestGobusterParser:
    @staticmethod
    def _paths(stdout):
        from darwin.tools.recon_server import _parse_gobuster_output

        return [p["path"] for p in _parse_gobuster_output(stdout)["discovered_paths"]]

    def test_quiet_output_without_leading_slash(self):
        """gobuster 3.x -q prints 'logs (Status: 200) [Size: 22]'."""
        assert self._paths("health (Status: 200) [Size: 28]\n") == ["/health"]

    def test_standard_output_with_leading_slash(self):
        assert self._paths("/admin (Status: 301) [Size: 0] [--> /admin/]") == ["/admin"]

    def test_banner_lines_are_ignored(self):
        banner = (
            "===============================================================\n"
            "Starting gobuster in directory enumeration mode\n"
            "===============================================================\n"
            "/api (Status: 403) [Size: 10]\n"
        )
        assert self._paths(banner) == ["/api"]


class TestAliasParametersAreOptional:
    def test_alias_declarations_are_not_required(self):
        """A call supplying only the canonical name must pass validation."""
        from darwin.core.parameters import ParameterValidator, ToolSchemaProvider

        class _G:
            def get_tool_definitions(self):
                return _all_tool_defs()

        specs = _all_specs()
        # gobuster/dirb/nikto declare both target_url and url; only the
        # canonical name may be required.
        assert specs["gobuster_dir"].required == ["target_url"]
        assert "url" not in specs["gobuster_dir"].required
        provider = ToolSchemaProvider(_G())
        issues = ParameterValidator().validate(
            provider.get("gobuster_dir"), {"target_url": "http://host:1"}
        )
        assert issues == []


class TestJsonFilterProbing:
    def test_candidates_are_derived_from_record_fields(self):
        from darwin.orchestration.execution import _derive_filter_candidates

        payload = {
            "count": 3,
            "entries": [{"path": "/a", "caller": "?", "action": "read"}],
        }
        pairs = _derive_filter_candidates(payload, ["/api/unsupported", "/logs"])
        assert ("path", "/api/unsupported") in pairs
        # A path already present in the response is tried after unseen ones.
        assert pairs.index(("path", "/logs")) < pairs.index(("path", "/a"))
        assert ("action", "read") in pairs

    def test_non_record_responses_yield_no_candidates(self):
        from darwin.orchestration.execution import _derive_filter_candidates

        assert _derive_filter_candidates({"status": "ok"}) == []
        assert _derive_filter_candidates(["a", "b"]) == []
        assert _derive_filter_candidates(None) == []

    @pytest.mark.asyncio
    async def test_probe_returns_flag_from_filtered_view(self, make_orchestrator, fake_llm):
        from darwin.tools.mcp_gateway import ToolResult

        listing = (
            'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n'
            '{"count":1,"logs":[{"path":"/audited","caller":"?","action":"read"}]}'
        )
        filtered = (
            'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n'
            '{"count":0,"logs":[],"flag":"flag{filtered-view}"}'
        )

        class _Gateway:
            def __init__(self):
                self.calls = []
                self.responses = {name: {} for name in ("curl_get", "http_method_probe")}

            def get_tool_names(self):
                return {"curl_get", "http_method_probe"}

            def get_tool_definitions(self):
                return [
                    {"type": "function", "function": {
                        "name": "curl_get",
                        "description": "",
                        "parameters": {"type": "object",
                                       "properties": {"url": {"type": "string"}},
                                       "required": ["url"]},
                    }}
                ]

            async def call(self, name, params):
                self.calls.append((name, params))
                url = str(params.get("url", ""))
                body = filtered if "?" in url else listing
                return ToolResult(
                    tool_name=name, success=True, stdout=body,
                    stderr="", exit_code=0, elapsed_ms=1.0,
                )

        gw = _Gateway()
        orch = make_orchestrator(fake_llm(content="[]"), gw, gw)
        orch.dkg.add_node("Endpoint", "ep-1", {"url": "http://t/logs"})
        orch.dkg.add_node("Endpoint", "ep-2", {"url": "http://t/audited"})

        result = await orch.execution._probe_json_filter_parameters()

        assert result is not None and result.success
        assert result.flag == "flag{filtered-view}"
        assert any("?" in str(p.get("url", "")) for _, p in gw.calls)
