"""Unit tests for the P9 schema-driven parameter reliability layer."""

import pytest

from darwin.core.capabilities import Capability, CapabilityRegistry
from darwin.core.evaluator import FailureAnalyzer, FailureType
from darwin.core.executor import ToolExecutor
from darwin.core.parameters import (
    ParamIssue,
    ParameterCorrector,
    ParameterValidator,
    ToolSchema,
    ToolSchemaProvider,
)
from darwin.core.task import Task


class FakeResult:
    def __init__(self, success=True, stdout="out", stderr="", exit_code=0):
        self.success = success
        self.stdout = stdout
        self.stderr = stderr
        self.exit_code = exit_code
        self.elapsed_ms = 5.0
        self.parsed_output = {}


class SchemaGateway:
    """Fake gateway that also exposes schemas like the real MCPGateway."""

    def __init__(self, schemas, results=None):
        self.schemas = schemas
        self.results = results or {}
        self.calls = []

    def get_tool_names(self):
        return set(self.schemas)

    def get_tool_definitions(self):
        definitions = []
        for name, properties in self.schemas.items():
            definitions.append(
                {
                    "type": "function",
                    "function": {
                        "name": name,
                        "description": "",
                        "parameters": {
                            "type": "object",
                            "properties": properties,
                            "required": [
                                k
                                for k, v in properties.items()
                                if "default" not in v
                            ],
                        },
                    },
                }
            )
        return definitions

    async def call(self, name, params):
        self.calls.append((name, params))
        return self.results.get(name, FakeResult())


def task_with(capability, target="", params=None, tool=""):
    action = {"target": target, "params": params or {}}
    if capability:
        action["capability"] = capability
    if tool:
        action["tool"] = tool
    return Task(
        id="t1",
        type="exploit",
        goal="g",
        action=action,
        required_context={},
    )


def registry_with(capability):
    reg = CapabilityRegistry()
    reg.register(capability)
    return reg


# ── ToolSchemaProvider ──────────────────────────────────────────────


def test_provider_parses_gateway_definitions():
    gw = SchemaGateway({"curl_get": {"url": {"type": "string"}}})
    provider = ToolSchemaProvider(gw)
    schema = provider.get("curl_get")
    assert schema is not None
    assert schema.name == "curl_get"
    assert schema.required == ["url"]
    assert schema.properties["url"]["type"] == "string"


def test_provider_parses_defaults_and_required():
    gw = SchemaGateway(
        {"my_tool": {"url": {"type": "string"}, "timeout": {"type": "integer", "default": 30}}}
    )
    schema = ToolSchemaProvider(gw).get("my_tool")
    assert schema.required == ["url"]
    assert schema.properties["timeout"]["default"] == 30


def test_provider_tolerates_gateway_without_schema_api():
    class NoSchema:
        def get_tool_names(self):
            return {"curl_get"}

    provider = ToolSchemaProvider(NoSchema(), None)
    assert provider.get("curl_get") is None


def test_provider_ignores_malformed_definitions():
    class Weird:
        def get_tool_definitions(self):
            return [{"type": "function"}, {"function": {"name": "ok", "parameters": {"properties": "nope"}}}]

    provider = ToolSchemaProvider(Weird())
    assert provider.get("ok") is None
    assert provider.get("anything") is None


# ── ParameterValidator ──────────────────────────────────────────────


def test_validator_reports_missing_required_and_unknown():
    schema = ToolSchema(
        name="t",
        properties={"url": {"type": "string"}, "timeout": {"type": "integer"}},
        required=["url", "timeout"],
    )
    issues = ParameterValidator().validate(schema, {"url": "http://x", "bogus": 1})
    kinds = {(i.kind, i.field) for i in issues}
    assert kinds == {("missing", "timeout"), ("unknown", "bogus")}


def test_validator_treats_blank_and_none_as_missing():
    schema = ToolSchema(name="t", properties={"a": {}, "b": {}}, required=["a", "b", "c"])
    issues = ParameterValidator().validate(schema, {"a": "", "b": None, "c": 0})
    fields = [i.field for i in issues if i.kind == "missing"]
    assert fields == ["a", "b"]  # 0 counts as present


def test_validator_clean_params_no_issues():
    schema = ToolSchema(name="t", properties={"url": {"type": "string"}}, required=["url"])
    assert ParameterValidator().validate(schema, {"url": "http://x"}) == []


# ── ParameterCorrector ──────────────────────────────────────────────


def test_corrector_drops_unknown_and_fills_default():
    schema = ToolSchema(
        name="t",
        properties={"url": {"type": "string"}, "timeout": {"type": "integer", "default": 30}},
        required=["url"],
    )
    corrected, changed = ParameterCorrector().correct(
        schema, {"url": "http://x", "bogus": 1}
    )
    assert changed is True
    assert corrected == {"url": "http://x", "timeout": 30}


def test_corrector_no_change_when_valid():
    schema = ToolSchema(name="t", properties={"url": {"type": "string"}}, required=["url"])
    corrected, changed = ParameterCorrector().correct(schema, {"url": "http://x"})
    assert changed is False
    assert corrected == {"url": "http://x"}


# ── Executor integration (capability path only) ─────────────────────


def custom_capability(name, tools, required_context):
    return Capability(
        name=name,
        description="",
        required_context=required_context,
        supported_tools=tools,
        default_tool=tools[0],
    )


@pytest.mark.asyncio
async def test_pre_execution_invalid_argument_falls_back_to_next_tool():
    gw = SchemaGateway(
        {
            "curl_get": {"url": {"type": "string"}, "cookie": {"type": "string"}},
            "http_post": {"url": {"type": "string"}},
        }
    )
    cap = custom_capability("fetch", ["curl_get", "http_post"], ["endpoint"])
    ex = ToolExecutor(recon_gateway=gw, capability_registry=registry_with(cap))
    res = await ex.execute(task_with("fetch", target="http://x"))
    # curl_get was schema-rejected BEFORE the call; http_post ran instead.
    assert gw.calls == [("http_post", {"url": "http://x"})]
    assert res.success is True
    assert res.tool == "http_post"
    assert res.tool_attempts == ["curl_get", "http_post"]


@pytest.mark.asyncio
async def test_schema_correction_fills_default_and_drops_unknown():
    gw = SchemaGateway(
        {"my_tool": {"url": {"type": "string"}, "timeout": {"type": "integer", "default": 30}}}
    )
    cap = custom_capability("custom", ["my_tool"], [])
    ex = ToolExecutor(recon_gateway=gw, capability_registry=registry_with(cap))
    res = await ex.execute(
        task_with("custom", params={"url": "http://x", "bogus": "drop-me"})
    )
    assert gw.calls == [("my_tool", {"url": "http://x", "timeout": 30})]
    assert res.success is True
    assert res.tool == "my_tool"


@pytest.mark.asyncio
async def test_all_tools_pre_fail_with_invalid_argument():
    gw = SchemaGateway(
        {
            "t1": {"cookie": {"type": "string"}},
            "t2": {"cookie": {"type": "string"}},
        }
    )
    cap = custom_capability("fetch", ["t1", "t2"], [])
    ex = ToolExecutor(recon_gateway=gw, capability_registry=registry_with(cap))
    res = await ex.execute(task_with("fetch"))
    assert gw.calls == []  # no tool was invoked
    assert res.success is False
    assert res.exit_code == 1
    assert "invalid argument" in res.stderr
    assert res.tool_attempts == ["t1", "t2"]
    cls = FailureAnalyzer().classify(
        FakeResult(success=False, stderr=res.stderr, exit_code=1), tool=""
    )
    assert cls.failure_type == FailureType.INVALID_ARGUMENT


@pytest.mark.asyncio
async def test_legacy_dispatch_validates_schema():
    # Phase 1: the legacy direct path is schema-validated too. Missing
    # optional params are filled from defaults; valid calls reach the tool.
    gw = SchemaGateway(
        {
            "curl_get": {
                "url": {"type": "string"},
                "cookie": {"type": "string", "default": ""},
            }
        }
    )
    ex = ToolExecutor(recon_gateway=gw)
    res = await ex.execute(
        task_with("", target="http://x", tool="curl_get", params={"url": "http://x"})
    )
    # Optional params without defaults are only filled when validation finds
    # issues (matching the capability path's P9 semantics); a valid call is
    # passed through untouched.
    assert gw.calls == [("curl_get", {"url": "http://x"})]
    assert res.success is True
    assert res.capability == ""


@pytest.mark.asyncio
async def test_legacy_dispatch_uncorrectable_missing_required():
    # A call missing a required parameter becomes a pre-execution
    # INVALID_ARGUMENT and the tool is NOT invoked.
    gw = SchemaGateway({"curl_get": {"url": {"type": "string"}}})
    ex = ToolExecutor(recon_gateway=gw)
    res = await ex.execute(
        task_with("", target="http://x", tool="curl_get", params={"cookie": "x"})
    )
    assert gw.calls == []
    assert res.success is False
    assert "missing required parameter 'url'" in res.stderr
    assert res.exit_code == 1


@pytest.mark.asyncio
async def test_real_schema_does_not_break_builtin_capability():
    # Built-in fetch_url against a gateway with realistic curl_get schema.
    gw = SchemaGateway(
        {"curl_get": {"url": {"type": "string"}, "headers": {"type": "string", "default": ""}}}
    )
    ex = ToolExecutor(recon_gateway=gw)
    res = await ex.execute(task_with("fetch_url", target="http://x"))
    assert gw.calls == [("curl_get", {"url": "http://x"})]
    assert res.success is True
