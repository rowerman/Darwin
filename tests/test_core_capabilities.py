"""Unit tests for the P8 Capability layer (darwin.core.capabilities)."""

import pytest

from darwin.core.capabilities import (
    Capability,
    CapabilityRegistry,
    ContextResolver,
    PreconditionValidator,
    default_registry,
)
from darwin.core.evaluator import FailureAnalyzer, FailureType
from darwin.core.executor import ExecutionResult, ToolExecutor
from darwin.core.task import Task


class FakeResult:
    def __init__(
        self,
        success=True,
        stdout="out",
        stderr="",
        exit_code=0,
        elapsed_ms=5.0,
        parsed_output=None,
    ):
        self.success = success
        self.stdout = stdout
        self.stderr = stderr
        self.exit_code = exit_code
        self.elapsed_ms = elapsed_ms
        self.parsed_output = parsed_output or {}


class FakeGateway:
    def __init__(self, tools, results=None):
        self._tools = set(tools)
        self.results = results or {}
        self.calls = []

    def get_tool_names(self):
        return set(self._tools)

    async def call(self, name, params):
        self.calls.append((name, params))
        return self.results.get(name, FakeResult())


def task_with(capability, target="", params=None, required_context=None, tool=""):
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
        required_context=required_context or {},
    )


# ── Registry ────────────────────────────────────────────────────────


def test_default_registry_has_four_capabilities():
    reg = default_registry()
    names = {c.name for c in reg.list()}
    assert names == {
        "fetch_url",
        "verify_sql_injection",
        "test_credentials",
        "acquire_shell",
    }
    for cap in reg.list():
        assert cap.supported_tools
        assert cap.default_tool == cap.supported_tools[0]


def test_custom_registry_register_get():
    reg = CapabilityRegistry()
    cap = Capability(
        name="probe",
        description="",
        supported_tools=["curl_get"],
        default_tool="curl_get",
    )
    reg.register(cap)
    assert reg.get("probe") is cap
    assert reg.get("missing") is None


def test_register_empty_name_rejected():
    reg = CapabilityRegistry()
    with pytest.raises(ValueError):
        reg.register(Capability(name="", description=""))


# ── Precondition validation ─────────────────────────────────────────


def test_precondition_missing_endpoint():
    validator = PreconditionValidator()
    cap = default_registry().get("fetch_url")
    assert validator.validate(cap, task_with("fetch_url")) == ["endpoint"]


def test_precondition_met_via_required_context():
    validator = PreconditionValidator()
    cap = default_registry().get("verify_sql_injection")
    task = task_with(
        "verify_sql_injection",
        required_context={"endpoint": "http://x", "parameter": "user"},
    )
    assert validator.validate(cap, task) == []


def test_acquire_shell_accepts_credential_or_access():
    validator = PreconditionValidator()
    cap = default_registry().get("acquire_shell")
    assert (
        validator.validate(
            cap, task_with("acquire_shell", required_context={"access": "session-1"})
        )
        == []
    )
    assert (
        validator.validate(
            cap,
            task_with(
                "acquire_shell",
                required_context={"credential": {"host": "h", "username": "u"}},
            ),
        )
        == []
    )
    assert validator.validate(cap, task_with("acquire_shell")) != []


# ── Context resolver ────────────────────────────────────────────────


def test_resolver_fetch_url_curl_params():
    cap = default_registry().get("fetch_url")
    resolved = ContextResolver().resolve(cap, task_with("fetch_url", target="http://x"))
    assert resolved["curl_get"] == {"url": "http://x"}


def test_resolver_sqlmap_params():
    cap = default_registry().get("verify_sql_injection")
    resolved = ContextResolver().resolve(
        cap,
        task_with(
            "verify_sql_injection",
            target="http://x/login",
            params={"param": "user", "technique": "BT"},
        ),
    )
    assert resolved["sqlmap_test"] == {
        "url": "http://x/login",
        "param": "user",
        "technique": "BT",
    }


def test_resolver_credential_to_test_credential_params():
    cap = default_registry().get("test_credentials")
    cred = {"host": "10.0.0.5", "port": 10222, "username": "root", "password": "pw"}
    resolved = ContextResolver().resolve(
        cap, task_with("test_credentials", required_context={"credential": cred})
    )
    assert resolved["test_credential"] == {
        "user": "root",
        "password": "pw",
        "host": "10.0.0.5",
        "port": 10222,
        "command": "id",
    }


# ── Executor capability dispatch ────────────────────────────────────


@pytest.mark.asyncio
async def test_capability_happy_path_fetch_url():
    gw = FakeGateway(["curl_get", "http_post"])
    ex = ToolExecutor(recon_gateway=gw)
    res = await ex.execute(task_with("fetch_url", target="http://x"))
    assert gw.calls == [("curl_get", {"url": "http://x"})]
    assert isinstance(res, ExecutionResult)
    assert res.success is True
    assert res.capability == "fetch_url"
    assert res.tool == "curl_get"
    assert res.planned_tool == "curl_get"
    assert res.adherence is True
    assert res.tool_attempts == ["curl_get"]


@pytest.mark.asyncio
async def test_capability_fallback_on_tool_error():
    gw = FakeGateway(
        ["sqlmap_test", "http_post"],
        results={
            "sqlmap_test": FakeResult(
                success=False, stderr="internal error: traceback", exit_code=1
            ),
            "http_post": FakeResult(success=True, stdout="200 OK"),
        },
    )
    ex = ToolExecutor(attack_gateway=gw, recon_gateway=gw)
    res = await ex.execute(
        task_with("verify_sql_injection", target="http://x/login", params={"param": "user"})
    )
    assert [c[0] for c in gw.calls] == ["sqlmap_test", "http_post"]
    assert res.success is True
    assert res.tool == "http_post"
    assert res.capability == "verify_sql_injection"
    assert res.tool_attempts == ["sqlmap_test", "http_post"]


@pytest.mark.asyncio
async def test_capability_stops_on_meaningful_failure():
    gw = FakeGateway(
        ["sqlmap_test", "http_post"],
        results={
            "sqlmap_test": FakeResult(success=False, stdout="not vulnerable", exit_code=1)
        },
    )
    ex = ToolExecutor(attack_gateway=gw, recon_gateway=gw)
    res = await ex.execute(
        task_with("verify_sql_injection", target="http://x", params={"param": "user"})
    )
    assert [c[0] for c in gw.calls] == ["sqlmap_test"]
    assert res.success is False
    assert res.tool == "sqlmap_test"
    assert res.tool_attempts == ["sqlmap_test"]


@pytest.mark.asyncio
async def test_unknown_capability_fails_explicitly():
    ex = ToolExecutor()
    res = await ex.execute(task_with("verify_xss", target="http://x"))
    assert res.success is False
    assert "unknown capability" in res.stderr
    assert res.adherence is False
    assert res.tool_attempts == []
    cls = FailureAnalyzer().classify(
        FakeResult(success=False, stderr=res.stderr, exit_code=1), tool=""
    )
    assert cls.failure_type == FailureType.INVALID_ARGUMENT


@pytest.mark.asyncio
async def test_precondition_missing_result_classifies():
    ex = ToolExecutor()
    res = await ex.execute(task_with("fetch_url"))
    assert res.success is False
    assert "precondition missing" in res.stderr
    cls = FailureAnalyzer().classify(
        FakeResult(success=False, stderr=res.stderr, exit_code=1), tool=""
    )
    assert cls.failure_type == FailureType.PRECONDITION_MISSING


@pytest.mark.asyncio
async def test_capability_wins_over_tool_field():
    gw = FakeGateway(["curl_get", "nmap_full_scan"])
    ex = ToolExecutor(recon_gateway=gw)
    res = await ex.execute(
        task_with("fetch_url", target="http://x", tool="nmap_full_scan")
    )
    assert gw.calls == [("curl_get", {"url": "http://x"})]
    assert res.success is True


@pytest.mark.asyncio
async def test_legacy_path_without_capability_unchanged():
    gw = FakeGateway(["curl_get"])
    ex = ToolExecutor(recon_gateway=gw)
    res = await ex.execute(
        task_with("", target="http://x", tool="curl_get", params={"url": "http://x"})
    )
    assert gw.calls == [("curl_get", {"url": "http://x"})]
    assert res.capability == ""
    assert res.tool_attempts == []


@pytest.mark.asyncio
async def test_acquire_shell_ssh_exec_first():
    gw = FakeGateway(["ssh_exec", "ssh_key_exec", "shell_exec"])
    ex = ToolExecutor(attack_gateway=gw)
    cred = {"host": "10.0.0.5", "port": 22, "username": "root", "password": "pw"}
    res = await ex.execute(
        task_with("acquire_shell", required_context={"credential": cred})
    )
    assert [c[0] for c in gw.calls] == ["ssh_exec"]
    assert gw.calls[0][1] == {
        "host": "10.0.0.5",
        "port": 22,
        "username": "root",
        "password": "pw",
        "command": "id",
    }
    assert res.tool == "ssh_exec"


@pytest.mark.asyncio
async def test_test_credentials_fallback_hydra():
    gw = FakeGateway(
        ["test_credential", "hydra_http_brute"],
        results={
            "test_credential": FakeResult(success=False, stderr="internal error", exit_code=1)
        },
    )
    ex = ToolExecutor(attack_gateway=gw)
    cred = {"host": "10.0.0.5", "port": 22, "username": "root", "password": "pw"}
    res = await ex.execute(
        task_with(
            "test_credentials",
            required_context={"credential": cred},
            target="http://x/login",
        )
    )
    assert [c[0] for c in gw.calls] == ["test_credential", "hydra_http_brute"]
    assert gw.calls[1][1] == {"url": "http://x/login"}
    assert res.success is True
    assert res.tool == "hydra_http_brute"
