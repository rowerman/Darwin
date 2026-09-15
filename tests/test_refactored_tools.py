import asyncio

import pytest

from darwin.tools.attack_server import _http_envelope_result, create_attack_gateway
from darwin.tools.recon_server import create_recon_gateway
from darwin.tools.mcp_gateway import ToolResult


def _definition(gateway, name):
    return next(
        d["function"] for d in gateway.get_tool_definitions()
        if d["function"]["name"] == name
    )


def _envelope(stdout: str) -> ToolResult:
    return ToolResult(tool_name="shell_exec", success=True, stdout=stdout,
                      stderr="", exit_code=0, elapsed_ms=1.0)


def test_http_envelope_marks_4xx_as_failed_with_status_and_allow_header():
    """A 405 is an ordinary HTTP answer: keep its status/Allow, fail the call."""
    stdout = (
        "STATUS:405\n"
        "HEADER:Server:Werkzeug/3.1.8\n"
        "HEADER:Allow:POST, OPTIONS\n"
        "BODY_START\n"
        "{\"error\":\"method not allowed\"}\n"
    )

    result = _http_envelope_result(
        _envelope(stdout), method="get", url="http://t/workflows",
        tool_name="send_payload",
    )

    assert result.success is False and result.exit_code == 405
    assert result.tool_name == "send_payload"
    assert result.parsed_output["status"] == 405
    assert result.parsed_output["headers"]["Allow"] == "POST, OPTIONS"
    assert "method not allowed" in result.parsed_output["body"]
    assert result.parsed_output["method"] == "GET"


def test_http_envelope_keeps_2xx_as_success():
    stdout = "STATUS:200\nHEADER:Content-Type:application/json\nBODY_START\n{\"ok\":1}\n"

    result = _http_envelope_result(
        _envelope(stdout), method="POST", url="http://t/workflows",
    )

    assert result.success is True and result.exit_code == 0
    assert result.parsed_output["body"].strip() == '{"ok":1}'


def test_http_envelope_without_status_is_a_failed_call():
    """No HTTP answer (connection error) must never be reported as success."""
    result = _http_envelope_result(
        _envelope("ERROR:<urlopen error [Errno 111] Connection refused>\n"),
        method="POST", url="http://t/workflows",
    )

    assert result.success is False and result.exit_code == -1
    assert "Connection refused" in result.stderr
    assert result.parsed_output == {}


def test_refactored_tool_contracts_expose_optional_defaults():
    recon = create_recon_gateway()
    curl = _definition(recon, "curl_get")
    assert curl["parameters"]["properties"]["timeout"]["default"] == 30
    assert "headers" not in curl["parameters"].get("required", [])
    nikto = _definition(recon, "nikto_scan")
    assert nikto["parameters"]["required"] == ["target_url"]


@pytest.mark.asyncio
async def test_ssrf_probe_iterates_ports_and_paths(monkeypatch):
    attack = create_attack_gateway()
    calls = []

    class _Proc:
        returncode = 0

        async def communicate(self):
            return b"ok", b""

    async def fake_shell(command, **kwargs):
        calls.append(command)
        return _Proc()

    monkeypatch.setattr(asyncio, "create_subprocess_shell", fake_shell)
    result = await attack.call(
        "ssrf_probe",
        {
            "ssrf_url": "http://target/fetch",
            "url_param": "url",
            "internal_hosts": "h1,h2,h3,h4,h5,h6,h7,h8",
            "ports": "10670,10671",
            "paths": "/,/flag",
        },
    )
    assert result.success is True
    assert result.parsed_output["probes_sent"] == 30
    assert any("%3A10670" in c for c in calls)
    assert any("%3A10671" in c for c in calls)
    assert any("flag" in c for c in calls)


@pytest.mark.asyncio
async def test_object_store_listing_is_not_success(monkeypatch):
    attack = create_attack_gateway()
    outputs = [b'{"objects":["flag.txt"]}\n200\n', b"flag{object-read}\n200\n"]

    class _Proc:
        returncode = 0

        async def communicate(self):
            return outputs.pop(0), b""

    async def fake_shell(command, **kwargs):
        return _Proc()

    monkeypatch.setattr(asyncio, "create_subprocess_shell", fake_shell)
    result = await attack.call(
        "object_store_get",
        {"endpoint_url": "http://target", "object_name": "flag.txt"},
    )

    assert result.success is True
    assert result.parsed_output["flags"] == ["flag{object-read}"]
