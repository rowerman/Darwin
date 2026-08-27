import asyncio

import pytest

from darwin.tools.attack_server import create_attack_gateway
from darwin.tools.recon_server import create_recon_gateway


def _definition(gateway, name):
    return next(
        d["function"] for d in gateway.get_tool_definitions()
        if d["function"]["name"] == name
    )


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
