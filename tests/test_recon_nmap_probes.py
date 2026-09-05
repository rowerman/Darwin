"""Unit tests for Darwin's automatic DARWIN cloud nmap-probe preparation."""

from __future__ import annotations

import os
import time

import pytest

from darwin.tools import recon_server
from darwin.tools.mcp_gateway import MCPGateway


_MARKER = recon_server._CLOUD_PROBES_MARKER
_SYSTEM_TEXT = "Exclude 1\nProbe TCP Sys q|ping|\nrarity 1\n"
_CUSTOM_TEXT = (
    f"# Custom probes for {_MARKER} scenarios\n"
    "Probe TCP IMDS q|GET /latest/meta-data/ HTTP/1.0\r\n\r\n|\n"
    "rarity 5\nports 10670\n"
)


@pytest.fixture(autouse=True)
def _reset_ready_cache(monkeypatch):
    monkeypatch.setattr(recon_server, "_nmap_cloud_probes_ready", False)


def _configure_sources(tmp_path, monkeypatch, system_text=_SYSTEM_TEXT,
                       custom_text=_CUSTOM_TEXT, datadir_name="dd"):
    sys_file = tmp_path / "sys" / "nmap-service-probes"
    sys_file.parent.mkdir(parents=True, exist_ok=True)
    sys_file.write_text(system_text, encoding="utf-8")
    custom_file = tmp_path / "cloud-probes.txt"
    custom_file.write_text(custom_text, encoding="utf-8")
    monkeypatch.setattr(recon_server, "_SYSTEM_PROBES_CANDIDATES", (str(sys_file),))
    monkeypatch.setenv("DARWIN_NMAP_CLOUD_PROBES", str(custom_file))
    monkeypatch.setenv("NMAP_DATADIR", str(tmp_path / datadir_name))
    return tmp_path / datadir_name


def test_noop_when_sources_missing(tmp_path, monkeypatch):
    monkeypatch.setattr(recon_server, "_SYSTEM_PROBES_CANDIDATES", ())
    monkeypatch.setenv("DARWIN_NMAP_CLOUD_PROBES", str(tmp_path / "missing.txt"))
    monkeypatch.setenv("NMAP_DATADIR", str(tmp_path / "dd"))

    recon_server._ensure_nmap_cloud_probes()

    assert not (tmp_path / "dd" / "nmap-service-probes").exists()
    assert recon_server._nmap_cloud_probes_ready is False


def test_creates_merged_probe_file(tmp_path, monkeypatch):
    datadir = _configure_sources(tmp_path, monkeypatch)

    recon_server._ensure_nmap_cloud_probes()

    target = datadir / "nmap-service-probes"
    assert target.is_file()
    content = target.read_text(encoding="utf-8")
    assert content.startswith(_SYSTEM_TEXT)
    assert _MARKER in content
    assert "Probe TCP IMDS" in content
    assert recon_server._nmap_cloud_probes_ready is True


def test_skips_rewrite_when_target_is_fresh(tmp_path, monkeypatch):
    datadir = _configure_sources(tmp_path, monkeypatch)
    recon_server._ensure_nmap_cloud_probes()
    target = datadir / "nmap-service-probes"
    future = time.time() + 60
    os.utime(target, (future, future))
    original = target.read_bytes()
    monkeypatch.setattr(recon_server, "_nmap_cloud_probes_ready", False)

    recon_server._ensure_nmap_cloud_probes()

    assert target.read_bytes() == original
    assert target.stat().st_mtime == future


def test_refreshes_stale_target_with_darwin_marker(tmp_path, monkeypatch):
    datadir = _configure_sources(tmp_path, monkeypatch)
    target = datadir / "nmap-service-probes"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(f"# {_MARKER} (old)\nProbe TCP OLD q|x|\n", encoding="utf-8")
    os.utime(target, (1, 1))

    recon_server._ensure_nmap_cloud_probes()

    content = target.read_text(encoding="utf-8")
    assert "Probe TCP IMDS" in content
    assert content.startswith(_SYSTEM_TEXT)


def test_leaves_unmanaged_user_file_untouched(tmp_path, monkeypatch):
    datadir = _configure_sources(tmp_path, monkeypatch)
    target = datadir / "nmap-service-probes"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("user-managed probes, no darwin marker\n", encoding="utf-8")

    recon_server._ensure_nmap_cloud_probes()

    assert target.read_text(encoding="utf-8") == "user-managed probes, no darwin marker\n"
    assert recon_server._nmap_cloud_probes_ready is False


def test_write_failure_is_silent(tmp_path, monkeypatch):
    _configure_sources(tmp_path, monkeypatch)
    datadir_file = tmp_path / "dd"
    datadir_file.write_text("not a directory\n", encoding="utf-8")

    recon_server._ensure_nmap_cloud_probes()  # must not raise

    assert recon_server._nmap_cloud_probes_ready is False


@pytest.mark.asyncio
async def test_shell_tool_prepare_hook_runs_before_command():
    gateway = MCPGateway()
    calls = []
    gateway.register_shell_tool(
        name="echo_prepared",
        command_template="echo ok",
        description="test prepare hook",
        parameters={},
        prepare=lambda: calls.append("prepared"),
    )

    result = await gateway.call("echo_prepared", {})

    assert calls == ["prepared"]
    assert result.success is True


@pytest.mark.skipif(os.name == "nt", reason="requires POSIX PATH stub")
@pytest.mark.asyncio
async def test_recon_nmap_tools_run_probe_preparation(tmp_path, monkeypatch):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    stub = bin_dir / "nmap"
    stub.write_text("#!/bin/sh\nprintf '22/tcp open ssh OpenSSH stub\\n'\n",
                    encoding="utf-8")
    stub.chmod(stub.stat().st_mode | 0o111)
    monkeypatch.setenv("PATH", str(bin_dir) + os.pathsep + os.environ.get("PATH", ""))
    calls = []
    monkeypatch.setattr(recon_server, "_ensure_nmap_cloud_probes",
                        lambda: calls.append("prepared"))

    gateway = MCPGateway()
    recon_server.register_recon_tools(gateway)
    result = await gateway.call("nmap_scan", {"target": "127.0.0.1"})

    assert calls == ["prepared"]
    assert result.success is True
    assert [p["port"] for p in result.parsed_output["open_ports"]] == [22]
