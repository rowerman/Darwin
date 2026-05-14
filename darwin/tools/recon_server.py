"""Reconnaissance tools — port scanning, directory enumeration, fingerprinting.

Reference: VulnBot roles/collector.py — tool list for recon agent
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List

from darwin.tools.mcp_gateway import MCPGateway, ToolResult


def _parse_nmap_output(stdout: str) -> Dict[str, Any]:
    """Parse nmap output for open ports and services."""
    ports = []
    for line in stdout.split("\n"):
        match = re.match(r"(\d+)/tcp\s+(\w+)\s+(.+)", line)
        if match:
            ports.append({
                "port": int(match.group(1)),
                "state": match.group(2),
                "service": match.group(3).strip(),
            })
    return {"open_ports": ports, "count": len(ports)}


def _parse_dirb_output(stdout: str) -> Dict[str, Any]:
    """Parse dirb output for discovered paths."""
    paths = []
    for line in stdout.split("\n"):
        if line.startswith("+ "):
            parts = line[2:].split()
            if parts:
                path = parts[0]
                code = parts[1] if len(parts) > 1 else "???"
                paths.append({"path": path, "code": code})
    return {"discovered_paths": paths, "count": len(paths)}


def _parse_whatweb_output(stdout: str) -> Dict[str, Any]:
    """Parse whatweb output for technology stack."""
    techs = []
    for line in stdout.split("\n"):
        line = line.strip()
        if line and "http" in line:
            # Extract technologies in brackets
            tech_matches = re.findall(r"\[(.*?)\]", line)
            techs.extend(tech_matches)
    return {"technologies": techs}


def register_recon_tools(gateway: MCPGateway) -> MCPGateway:
    """Register all reconnaissance tools on the gateway.

    Reference: VulnBot roles/collector.py tool list
    """
    # ── nmap: Port scanning ─────────────────────────────────────
    gateway.register_shell_tool(
        name="nmap_scan",
        command_template="nmap -sV -T4 --top-ports 1000 {target}",
        description="Scan target for open ports and service versions using nmap",
        parameters={
            "target": {"type": "string", "description": "Target IP or hostname"},
        },
        parser=_parse_nmap_output,
    )

    gateway.register_shell_tool(
        name="nmap_full_scan",
        command_template="nmap -sV -T4 -p- {target}",
        description="Full port scan (all 65535 ports) of target",
        parameters={
            "target": {"type": "string", "description": "Target IP or hostname"},
        },
        parser=_parse_nmap_output,
    )

    # ── dirb: Directory enumeration ─────────────────────────────
    gateway.register_shell_tool(
        name="dirb_scan",
        command_template="dirb {target_url} /usr/share/wordlists/dirb/common.txt -S -w",
        description="Enumerate directories and files on a web server using dirb",
        parameters={
            "target_url": {"type": "string", "description": "Target URL to scan"},
        },
        parser=_parse_dirb_output,
    )

    # ── curl: HTTP probing ──────────────────────────────────────
    async def curl_get(url: str, headers: str = "", follow_redirects: bool = True) -> ToolResult:
        """Make HTTP GET request with curl."""
        import asyncio
        cmd = f"curl -s -i {'-L' if follow_redirects else ''}"
        if headers:
            for h in headers.split(","):
                cmd += f" -H '{h.strip()}'"
        cmd += f" '{url}'"

        proc = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=30)
        return ToolResult(
            tool_name="curl_get",
            success=proc.returncode == 0,
            stdout=stdout.decode("utf-8", errors="replace"),
            stderr=stderr.decode("utf-8", errors="replace"),
            exit_code=proc.returncode or 0,
            elapsed_ms=0,
        )

    gateway.register(
        name="curl_get",
        func=curl_get,
        description="Make HTTP GET request and return full response with headers",
        parameters={
            "url": {"type": "string", "description": "Target URL"},
            "headers": {"type": "string", "description": "Optional comma-separated headers"},
            "follow_redirects": {"type": "boolean", "description": "Follow HTTP redirects"},
        },
    )

    # ── whatweb: Technology fingerprinting ──────────────────────
    gateway.register_shell_tool(
        name="whatweb_scan",
        command_template="whatweb -q {target_url}",
        description="Identify web technologies used by a target",
        parameters={
            "target_url": {"type": "string", "description": "Target URL"},
        },
        parser=_parse_whatweb_output,
    )

    return gateway


def create_recon_gateway() -> MCPGateway:
    """Factory: create a gateway with all recon tools registered."""
    gateway = MCPGateway()
    return register_recon_tools(gateway)
