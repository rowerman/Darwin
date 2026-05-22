"""Reconnaissance tools — port scanning, directory enumeration, fingerprinting.

Reference: VulnBot roles/collector.py — tool list for recon agent
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List

from darwin.tools.mcp_gateway import MCPGateway, ToolResult


def _parse_nmap_output(stdout: str) -> Dict[str, Any]:
    """Parse nmap -sV output for open ports, service names, and versions.

    Example input line:
      22/tcp    open     ssh          OpenSSH 8.9p1 Ubuntu ...
      32768/tcp open     http         Apache httpd 2.4.67 ((Debian))
    """
    ports = []
    for line in stdout.split("\n"):
        match = re.match(r"(\d+)/tcp\s+(\w+)\s+(.+)", line)
        if match:
            # Split the remainder into service name and version
            remainder = match.group(3).strip()
            parts = remainder.split(None, 1)  # split on whitespace, max 2 parts
            service_name = parts[0] if parts else remainder
            version = parts[1] if len(parts) > 1 else ""
            ports.append({
                "port": int(match.group(1)),
                "state": match.group(2),
                "service": service_name,
                "version": version,
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
    """Parse dirb output for discovered paths.

    Handles both short format: + /path (CODE:200)
    and full-URL format:    + http://host/path (CODE:200|SIZE:1234)
    """
    paths = []
    for line in stdout.split("\n"):
        if line.startswith("+ "):
            parts = line[2:].split()
            if parts:
                path = parts[0]
                # If path is a full URL, extract just the path component
                if path.startswith("http://") or path.startswith("https://"):
                    from urllib.parse import urlparse as _up
                    parsed = _up(path)
                    path = parsed.path or "/"
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

    # ── nmap vulners: CVE detection for services ─────────────────
    gateway.register_shell_tool(
        name="nmap_vulners_scan",
        command_template="nmap -sV --script vulners {target} -p {ports} 2>&1",
        description="Scan target with nmap vulners NSE script. Detects CVEs for each discovered service based on version fingerprint. Provides CVE IDs, CVSS scores, and exploit availability links.",
        parameters={
            "target": {"type": "string", "description": "Target IP or hostname"},
            "ports": {"type": "string", "description": "Ports to scan (e.g. '80,443' or '1-1000')"},
        },
        timeout=300,
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
        command_template="dirb {target_url} /usr/share/dirb/wordlists/common.txt -S -w",
        description="Enumerate directories and files on a web server using dirb",
        parameters={
            "target_url": {"type": "string", "description": "Target URL to scan"},
        },
        parser=_parse_dirb_output,
    )

    # ── gobuster: Fast directory enumeration ─────────────────────
    gateway.register_shell_tool(
        name="gobuster_dir",
        command_template="gobuster dir -u {target_url} -w /usr/share/dirb/wordlists/common.txt -q 2>&1",
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
    async def curl_get(url: str, headers: str = "", cookie: str = "", follow_redirects: bool = True) -> ToolResult:
        """Make HTTP GET request with curl."""
        import asyncio
        cmd = f"curl -s -i {'-L' if follow_redirects else ''}"
        if cookie:
            _ck = cookie.strip().rstrip(";")
            cmd += f" -H 'Cookie: {_ck}'"
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
        description="Make HTTP GET request. Use cookie param to maintain session from try_login.",
        parameters={
            "url": {"type": "string", "description": "Target URL"},
            "headers": {"type": "string", "description": "Optional comma-separated headers"},
            "cookie": {"type": "string", "description": "Session cookie string from try_login"},
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

    # ── HTTP POST tool ──────────────────────────────────────────
    async def _http_post(url: str, data: str = "", headers: str = "",
                        cookie: str = "", content_type: str = "application/x-www-form-urlencoded") -> ToolResult:
        import urllib.request as _ur
        try:
            hdrs = {"Content-Type": content_type}
            if cookie:
                hdrs["Cookie"] = cookie.strip().rstrip(";")
            if headers:
                for h in headers.split("|"):
                    if ":" in h:
                        k, v = h.split(":", 1)
                        hdrs[k.strip()] = v.strip()
            body = data.encode() if isinstance(data, str) else data
            req = _ur.Request(url, data=body, headers=hdrs, method="POST")
            with _ur.urlopen(req, timeout=30) as resp:
                rbody = resp.read().decode(errors="replace")
                rhdrs = dict(resp.headers)
                return ToolResult(tool_name="http_post",
                    success=True,
                    stdout=f"HTTP {resp.status}\n" + "\n".join(
                        f"{k}: {v}" for k, v in rhdrs.items()) + f"\n\n{rbody[:8000]}",
                    stderr="", exit_code=0, elapsed_ms=0,
                    parsed_output={"status": resp.status, "headers": rhdrs, "body": rbody[:8000]},
                )
        except Exception as e:
            return ToolResult(tool_name="http_post", success=False, stdout="", stderr=str(e), exit_code=1, elapsed_ms=0)

    gateway.register(
        name="http_post", func=_http_post,
        description="Send HTTP POST request. Use cookie parameter to maintain session from try_login.",
        parameters={
            "url": {"type": "string", "description": "Target URL"},
            "data": {"type": "string", "description": "POST body data (key=value&key=value format)"},
            "headers": {"type": "string", "description": "Optional headers"},
            "cookie": {"type": "string", "description": "Session cookie string from try_login"},
        },
    )

    # ── Form extraction tool ────────────────────────────────────
    async def _form_extract(url: str) -> ToolResult:
        import urllib.request as _ur, re as _re, json as _json
        try:
            req = _ur.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with _ur.urlopen(req, timeout=15) as resp:
                html = resp.read().decode(errors="replace")
        except Exception as e:
            return ToolResult(tool_name="form_extract", success=False, stdout="", stderr=str(e), exit_code=1, elapsed_ms=0)
        forms = []
        for m in _re.finditer(r'<form[^>]*>(.*?)</form>', html, _re.I | _re.DOTALL):
            tag = _re.search(r'<form[^>]*>', m.group(0), _re.I)
            if not tag:
                continue
            action = _re.search(r"""action=["']([^"']*)["']""", tag.group(0), _re.I)
            method = _re.search(r"""method=["'](\w+)["']""", tag.group(0), _re.I)
            form = {"form_index": len(forms), "action": action.group(1) if action else "",
                    "method": (method.group(1) or "post").upper() if method else "POST", "inputs": []}
            for inp in _re.findall(r'<input[^>]*>', m.group(1), _re.I):
                name = _re.search(r"""name=["'](\w+)["']""", inp, _re.I)
                itype = _re.search(r"""type=["'](\w+)["']""", inp, _re.I)
                value = _re.search(r"""value=["']([^"']*)["']""", inp, _re.I)
                form["inputs"].append({"name": name.group(1) if name else "",
                    "type": (itype.group(1) or "text").lower() if itype else "text",
                    "value": value.group(1) if value else ""})
            forms.append(form)
        pw = 'type="password"' in html.lower()
        links = list(set(_re.findall(r"""href=["']([^"']+)["']""", html, _re.I)))[:30]
        result = {"url": url, "forms": forms, "password_field_present": pw, "links": links}
        return ToolResult(tool_name="form_extract", success=True, stdout=_json.dumps(result, indent=2),
                          stderr="", exit_code=0, elapsed_ms=0, parsed_output=result)

    gateway.register(
        name="form_extract", func=_form_extract,
        description="Extract all HTML forms, inputs, and links from a URL. Returns structured JSON.",
        parameters={"url": {"type": "string", "description": "URL to extract forms from"}},
    )

    # ── try_login tool ─────────────────────────────────────────
    async def _try_login_tool(url: str, username: str = "test", password: str = "test") -> ToolResult:
        from urllib.parse import urlparse as _up2, urljoin as _uj
        import aiohttp, re as _re2
        base = url
        if "://" in url:
            p = _up2(url)
            base = f"{p.scheme}://{p.netloc}"
        jar = aiohttp.CookieJar()
        pre_cookies = 0
        try:
            async with aiohttp.ClientSession(cookie_jar=jar) as sess:
                pre_cookies = len(list(jar))
                for login_url in [base, f"{base}/login", f"{base}/signin"]:
                    try:
                        async with sess.get(login_url, timeout=aiohttp.ClientTimeout(total=10)) as r:
                            html = await r.text()
                    except Exception:
                        continue
                    bl = html.lower()
                    if "password" not in bl and "username" not in bl:
                        continue
                    action_m = _re2.search(r"""action=["']([^"']*)["']""", html, _re2.I)
                    action = action_m.group(1) if action_m else ""
                    submit_url = _uj(login_url, action) if action else login_url
                    inputs = _re2.findall(r"""<input[^>]+name=["'](\w+)["']""", html, _re2.I)
                    hidden = _re2.findall(
                        r"""<input[^>]+type=["']hidden["'][^>]+name=["'](\w+)["'][^>]+value=["']([^"']*)["']""",
                        html, _re2.I)
                    data = {}
                    for name in inputs:
                        nl = name.lower()
                        if nl in ("username", "user", "email", "login"):
                            data[name] = username
                        elif nl in ("password", "pass", "passwd", "pwd"):
                            data[name] = password
                    for h_name, h_value in hidden:
                        if h_name not in data:
                            data[h_name] = h_value
                    try:
                        async with sess.post(submit_url, data=data, timeout=aiohttp.ClientTimeout(total=10)) as r:
                            pw_html = await r.text()
                    except Exception:
                        continue
                    orig_has_pw = 'type="password"' in html.lower()
                    resp_has_pw = 'type="password"' in pw_html.lower()
                    if resp_has_pw and not orig_has_pw:
                        pw_inputs = _re2.findall(r"""<input[^>]+name=["'](\w+)["']""", pw_html, _re2.I)
                        pw_hidden = _re2.findall(
                            r"""<input[^>]+type=["']hidden["'][^>]+name=["'](\w+)["'][^>]+value=["']([^"']*)["']""",
                            pw_html, _re2.I)
                        pw_data = {}
                        for name in pw_inputs:
                            nl = name.lower()
                            if nl in ("username", "user", "email", "login"):
                                pw_data[name] = username
                            elif nl in ("password", "pass", "passwd", "pwd"):
                                pw_data[name] = password
                        for h_name, h_value in pw_hidden:
                            if h_name not in pw_data:
                                pw_data[h_name] = h_value
                        try:
                            async with sess.post(submit_url, data=pw_data, timeout=aiohttp.ClientTimeout(total=10)) as r:
                                await r.text()
                        except Exception:
                            pass
                    break
                post_cookies = len(list(jar))
                new_cookies = post_cookies - pre_cookies
                cookie_str = "; ".join(f"{c.key}={c.value}" for c in jar) if jar else ""
                return ToolResult(tool_name="try_login",
                    success=(new_cookies > 0),
                    stdout=f"Login {'OK' if new_cookies > 0 else 'FAILED'}. New cookies: {new_cookies}. Session: {cookie_str[:200]}",
                    stderr="", exit_code=0, elapsed_ms=0,
                    parsed_output={"login_success": new_cookies > 0, "new_cookies": new_cookies,
                                   "session_cookie": cookie_str[:200], "url": base},
                )
        except Exception as e:
            return ToolResult(tool_name="try_login", success=False, stdout="", stderr=str(e), exit_code=1, elapsed_ms=0)

    # ── IDOR header test tool ───────────────────────────────────
    async def _idor_header_test(url: str, cookie: str = "", user_ids: str = "") -> ToolResult:
        """Test for IDOR via HTTP headers. Tries common IDOR headers
        (X-UserId, X-User-Id) with various user IDs. Returns all responses."""
        import urllib.request as _ur, re as _re2
        headers_to_try = ["X-UserId", "X-User-Id"]
        ids_to_try = ["10052", "10032", "10033", "10053", "0", "1", "2", "3", "10", "100", "1000", "10000", "50000"]
        if user_ids:
            ids_to_try = [x.strip() for x in user_ids.split(",") if x.strip()]
        results = []
        for hdr in headers_to_try:
            for uid in ids_to_try[:15]:
                try:
                    hdrs = {"User-Agent": "Mozilla/5.0", hdr: uid}
                    if cookie:
                        hdrs["Cookie"] = cookie.strip().rstrip(";")
                    req = _ur.Request(url, headers=hdrs)
                    with _ur.urlopen(req, timeout=10) as resp:
                        body = resp.read().decode(errors="replace")
                        flags = _re2.findall(r'flag\{[^}]+\}', body, re.I)
                        results.append({
                            "header": hdr, "user_id": uid, "status": resp.status,
                            "flag_found": bool(flags),
                            "flag": flags[0] if flags else None,
                            "body_snippet": body[:300],
                        })
                        if flags:
                            return ToolResult(tool_name="idor_header_test", success=True,
                                stdout=f"FLAG FOUND: {flags[0]} (header={hdr}, user_id={uid})",
                                stderr="", exit_code=0, elapsed_ms=0,
                                parsed_output={"flag": flags[0], "header": hdr, "user_id": uid})
                except Exception:
                    continue
        return ToolResult(tool_name="idor_header_test", success=False,
            stdout=f"Tested {len(results)} header+ID combinations, no flag found. "
                   f"Results: {str(results[:10])[:500]}",
            stderr="", exit_code=0, elapsed_ms=0, parsed_output={"results": results})

    gateway.register(
        name="idor_header_test", func=_idor_header_test,
        description="Test for IDOR via HTTP headers (X-UserId, X-User-Id) with various user IDs. Use when you have a session cookie and suspect IDOR.",
        parameters={
            "url": {"type": "string", "description": "Target URL (e.g. dashboard endpoint)"},
            "cookie": {"type": "string", "description": "Session cookie from try_login"},
            "user_ids": {"type": "string", "description": "Comma-separated user IDs to try (default: 0,1,2,3,10032,10033)"},
        },
    )

    gateway.register(
        name="try_login", func=_try_login_tool,
        description="Try to log in to a web app. Auto-detects forms, handles multi-step login, CSRF tokens. Returns session cookie on success.",
        parameters={
            "url": {"type": "string", "description": "Base URL of the web application"},
            "username": {"type": "string", "description": "Username to try"},
            "password": {"type": "string", "description": "Password to try"},
        },
    )

    return gateway


def create_recon_gateway() -> MCPGateway:
    """Factory: create a gateway with all recon tools registered."""
    gateway = MCPGateway()
    return register_recon_tools(gateway)
