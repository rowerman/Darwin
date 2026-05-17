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


def _parse_masscan_output(stdout: str) -> Dict[str, Any]:
    """Parse masscan output for open ports."""
    ports = []
    for line in stdout.split("\n"):
        match = re.search(r"Discovered open port (\d+)/tcp", line)
        if match:
            ports.append({"port": int(match.group(1)), "protocol": "tcp"})
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


def _parse_gobuster_output(stdout: str) -> Dict[str, Any]:
    """Parse gobuster dir output for discovered paths."""
    paths = []
    for line in stdout.split("\n"):
        line = line.strip()
        if not line or line.startswith("[") or line.startswith("=") or "Error" in line:
            continue
        match = re.match(r"(/\S+)", line)
        if match:
            code_match = re.search(r"\(Status:\s*(\d+)", line)
            code = code_match.group(1) if code_match else "200"
            paths.append({"path": match.group(1), "code": code})
    return {"discovered_paths": paths, "count": len(paths)}


def _parse_nikto_output(stdout: str) -> Dict[str, Any]:
    """Parse nikto output for vulnerabilities and findings."""
    findings = []
    for line in stdout.split("\n"):
        line = line.strip()
        if line.startswith("+ "):
            finding = line[2:].strip()
            parts = finding.split(":")
            finding_type = "info"
            if "vulnerab" in finding.lower() or "critical" in finding.lower():
                finding_type = "vulnerability"
            elif "warn" in finding.lower():
                finding_type = "warning"
            findings.append({"type": finding_type, "detail": finding})
    return {"findings": findings, "count": len(findings)}


def _parse_whatweb_output(stdout: str) -> Dict[str, Any]:
    """Parse whatweb output for technology stack."""
    techs = []
    for line in stdout.split("\n"):
        line = line.strip()
        if line and "http" in line:
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

    # ── masscan: Fast port scanning ─────────────────────────────
    gateway.register_shell_tool(
        name="masscan_scan",
        command_template="masscan {target} --top-ports 1000 --rate=10000 2>&1",
        description="Fast port scan of top 1000 ports using masscan (much faster than nmap)",
        parameters={
            "target": {"type": "string", "description": "Target IP or CIDR range (e.g. 192.168.1.0/24)"},
        },
        parser=_parse_masscan_output,
        timeout=120,
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

    # ── gobuster: Fast directory enumeration ─────────────────────
    gateway.register_shell_tool(
        name="gobuster_dir",
        command_template="gobuster dir -u {target_url} -w /usr/share/wordlists/dirb/common.txt -q 2>&1",
        description="Fast directory brute-force using gobuster (Go-based, faster than dirb)",
        parameters={
            "target_url": {"type": "string", "description": "Target URL to scan"},
        },
        parser=_parse_gobuster_output,
        timeout=90,
    )

    # ── nikto: Web server scanner ───────────────────────────────
    gateway.register_shell_tool(
        name="nikto_scan",
        command_template="nikto -h {target_url} -Tuning 12345 -nointeractive 2>&1 | head -200",
        description="Scan web server for known vulnerabilities, misconfigurations, and info leaks using nikto",
        parameters={
            "target_url": {"type": "string", "description": "Target URL with optional port (e.g. http://host:8080)"},
        },
        parser=_parse_nikto_output,
        timeout=180,
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
