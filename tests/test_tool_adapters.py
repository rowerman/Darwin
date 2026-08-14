"""P15 G5: Tool Adapter layer tests."""

from darwin.core.capabilities import (
    Capability,
    ContextResolver,
    default_registry,
)
from darwin.core.task import Task
from darwin.tools.adapters import (
    AcquireShellAdapter,
    FetchUrlAdapter,
    TestCredentialsAdapter,
    VerifySqlInjectionAdapter,
    default_adapters,
)


def task_with(capability, target="", params=None, required_context=None):
    action = {"target": target, "params": params or {}}
    if capability:
        action["capability"] = capability
    return Task(
        id="t1",
        type="exploit",
        goal="g",
        action=action,
        required_context=required_context or {},
    )


def test_default_adapters_four_in_order():
    names = [a.capability_name for a in default_adapters()]
    assert names == [
        "fetch_url",
        "verify_sql_injection",
        "test_credentials",
        "acquire_shell",
    ]


def test_fetch_url_adapter_params():
    resolved = FetchUrlAdapter().resolve(
        {"endpoint": "http://x"}, {"cookie": "s=1"}
    )
    assert resolved == {
        "curl_get": {"url": "http://x", "cookie": "s=1"},
        "http_post": {"url": "http://x", "cookie": "s=1"},
    }


def test_verify_sql_injection_adapter_params():
    resolved = VerifySqlInjectionAdapter().resolve(
        {"endpoint": "http://x/login", "parameter": "user"},
        {"technique": "BT"},
    )
    assert resolved["sqlmap_test"] == {
        "url": "http://x/login",
        "param": "user",
        "technique": "BT",
    }


def test_test_credentials_adapter_params():
    env = {
        "endpoint": "http://x/login",
        "username": "root",
        "port": 10222,
        "command": "id",
        "credential": {"host": "10.0.0.5", "password": "pw"},
    }
    resolved = TestCredentialsAdapter().resolve(env, {})
    assert resolved["test_credential"] == {
        "user": "root",
        "password": "pw",
        "host": "10.0.0.5",
        "port": 10222,
        "command": "id",
    }
    assert resolved["hydra_http_brute"] == {"url": "http://x/login"}


def test_acquire_shell_adapter_params():
    env = {
        "username": "root",
        "port": 22,
        "command": "id",
        "credential": {"host": "10.0.0.5", "password": "pw"},
    }
    resolved = AcquireShellAdapter().resolve(env, {})
    assert resolved["ssh_exec"] == {
        "host": "10.0.0.5",
        "port": 22,
        "username": "root",
        "password": "pw",
        "command": "id",
    }
    assert resolved["ssh_key_exec"]["user"] == "root"
    assert resolved["shell_exec"] == {"command": "id"}


def test_resolver_dispatches_builtin_to_adapter():
    resolver = ContextResolver()
    assert set(resolver._adapters) == {
        "fetch_url",
        "verify_sql_injection",
        "test_credentials",
        "acquire_shell",
    }
    cap = default_registry().get("fetch_url")
    resolved = resolver.resolve(cap, task_with("fetch_url", target="http://x"))
    assert resolved == {
        "curl_get": {"url": "http://x"},
        "http_post": {"url": "http://x"},
    }


def test_resolver_falls_back_to_legacy_for_custom_capability():
    resolver = ContextResolver()
    cap = Capability(
        name="custom",
        description="",
        supported_tools=["my_tool"],
        default_tool="my_tool",
    )
    resolved = resolver.resolve(
        cap, task_with("custom", params={"url": "http://x"})
    )
    assert resolved == {"my_tool": {"url": "http://x"}}  # passthrough
