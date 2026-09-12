"""Write-capable HTTP surface: verbs and parameter shapes.

The planner LLM declares parameters as strings but sends dict/list shapes
(``headers={"X-Api-Key": "k"}``, ``data={"name": "pkg"}``), and write tasks
need verbs beyond POST. These tests pin the general rule "every HTTP write
tool accepts the same shapes and can express the same verbs" — they are not
scoped to any single tool or scenario.
"""

from __future__ import annotations

import urllib.request

import pytest

from darwin.tools.attack_server import create_attack_gateway
from darwin.tools.params import coerce_body, headers_to_lines, normalize_headers
from darwin.tools.recon_server import create_recon_gateway


class _Captured(dict):
    """Dict that also answers attribute access for captured Request args."""


@pytest.fixture()
def captured_request(monkeypatch):
    captured = _Captured()

    class _FakeRequest:
        def __init__(self, url, data=None, headers=None, method=None, **kwargs):
            captured.update(url=url, data=data, headers=headers, method=method)
            raise RuntimeError("stopped-before-transport")

    monkeypatch.setattr(urllib.request, "Request", _FakeRequest)
    return captured


def test_normalize_headers_accepts_dict_list_and_string():
    assert normalize_headers({"X-Api-Key": "k"}) == {"X-Api-Key": "k"}
    assert normalize_headers(["A: 1", "B:2"]) == {"A": "1", "B": "2"}
    assert normalize_headers("A: 1|B: 2") == {"A": "1", "B": "2"}
    assert normalize_headers("") == {}
    assert headers_to_lines({"A": "1"}) == "A: 1"


def test_coerce_body_serializes_structured_bodies():
    body, content_type = coerce_body({"name": "pkg"})
    assert body == b'{"name": "pkg"}' and content_type == "application/json"
    body, content_type = coerce_body("raw text")
    assert body == b"raw text" and content_type == ""
    assert coerce_body(None) == (None, "")


@pytest.mark.asyncio
async def test_http_post_accepts_dict_headers_and_put(captured_request):
    gateway = create_recon_gateway()
    result = await gateway.call("http_post", {
        "url": "http://127.0.0.1:1/packages/a/1.0.0",
        "method": "put",
        "data": {"name": "a", "version": "1.0.0"},
        "headers": {"Content-Type": "text/plain"},
    })

    assert "has no attribute 'split'" not in result.stderr
    assert captured_request["method"] == "PUT"
    assert captured_request["headers"]["Content-Type"] == "text/plain"
    assert captured_request["data"] == b'{"name": "a", "version": "1.0.0"}'


@pytest.mark.asyncio
async def test_http_post_rejects_non_write_verbs(captured_request):
    gateway = create_recon_gateway()
    result = await gateway.call("http_post", {
        "url": "http://127.0.0.1:1/x", "method": "GET",
    })

    assert result.success is False and result.exit_code == 2
    assert "unsupported method" in result.stderr
    assert captured_request == {}  # no request was attempted


@pytest.mark.asyncio
async def test_http_post_dict_body_defaults_to_json_content_type(captured_request):
    gateway = create_recon_gateway()
    await gateway.call("http_post", {
        "url": "http://127.0.0.1:1/x", "data": '{"a": 1}',
    })

    assert captured_request["headers"]["Content-Type"] == (
        "application/x-www-form-urlencoded"
    )


@pytest.mark.asyncio
async def test_http_method_probe_accepts_dict_headers(captured_request):
    gateway = create_recon_gateway()
    await gateway.call("http_method_probe", {
        "url": "http://127.0.0.1:1/x",
        "method": "PUT",
        "data": "echo hi",
        "headers": {"Content-Type": "text/plain"},
    })

    assert captured_request["method"] == "PUT"
    assert captured_request["headers"]["Content-Type"] == "text/plain"
    assert "{" not in "".join(captured_request["headers"])


@pytest.mark.asyncio
async def test_send_payload_honours_non_post_verbs(monkeypatch):
    gateway = create_attack_gateway()
    seen: dict = {}

    async def _fake_request(method, url, data="", headers="", **kwargs):
        seen.update(method=method, url=url, data=data, headers=headers)
        from darwin.tools.mcp_gateway import ToolResult
        return ToolResult(tool_name="send_payload", success=True, stdout="",
                          stderr="", exit_code=0, elapsed_ms=0.0)

    monkeypatch.setattr(
        "darwin.tools.attack_server._python_request", _fake_request
    )
    result = await gateway.call("send_payload", {
        "url": "http://127.0.0.1:1/x",
        "method": "PUT",
        "payload": '{"action": "resolve"}',
        "body_format": "json",
        "headers": {"X-Api-Key": "k"},
    })

    assert result.success is True
    assert seen["method"] == "PUT"
    assert "X-Api-Key: k" in seen["headers"]


@pytest.mark.asyncio
async def test_send_payload_rejects_unsupported_verb():
    gateway = create_attack_gateway()
    result = await gateway.call("send_payload", {
        "url": "http://127.0.0.1:1/x", "method": "TRACE",
    })

    assert result.success is False and result.exit_code == 2
