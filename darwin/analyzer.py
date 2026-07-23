"""Standalone analysis and research functions extracted from Orchestrator.

Each function takes ``orch`` (an Orchestrator instance) as the first parameter
and operates on the orchestrator's DKG, LLM session, vulnerability list, and
tool gateways.

Provides:
  - service_research          : Hardcoded service-port CVE lookup (pre-analyze).
  - active_service_research   : LLM-driven service exploit research (post-recon).
  - analyze_phase             : LLM-driven vulnerability analysis.
  - augment_from_dkg          : Derive vulnerability hypotheses from DKG state.
  - research_phase            : LLM-driven vulnerability research (post-analyze).
  - probe_endpoints           : Probe endpoints for sample responses.
  - format_vulnerability_summary      : Full vuln text block for LLM prompts.
  - format_vulnerability_summary_short : Compact one-line-per-vuln summary.
  - extract_links_from_html   : Extract navigable links from HTML.
  - extract_ids_from_url      : Extract numeric ID patterns from URL paths.
  - extract_ids_from_body     : Scan HTML body for numeric IDs.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from typing import Any, Optional

# ---------------------------------------------------------------------------
# Local imports
# ---------------------------------------------------------------------------
from darwin.data_model import EndpointInfo, VulnerabilityHypothesis, normalize_dkg_state
from darwin.dkg import DKG
from darwin.tools.mcp_gateway import ToolResult
from darwin.tools.recon_server import parse_response
from darwin.prompts.orchestrator import (
    SYSTEM_PROMPT_ANALYZE,
    SYSTEM_PROMPT_ORCHESTRATOR_UNIFIED,
)

log = logging.getLogger(__name__)


# ===================================================================
# Private helpers
# ===================================================================


def _extract_json_array(text: str) -> list | None:
    """Extract the first complete JSON array using bracket counting.

    Handles nested brackets and trailing text -- more robust than regex.
    Returns the parsed list, or None if no valid array found.
    """
    start = text.find("[")
    if start == -1:
        return None
    depth = 0
    for i, c in enumerate(text[start:], start):
        if c == "[":
            depth += 1
        elif c == "]":
            depth -= 1
            if depth == 0:
                try:
                    return json.loads(text[start : i + 1])
                except json.JSONDecodeError:
                    return None
    return None


def _extract_json(text: str) -> Any:
    """Extract JSON from LLM response text."""
    # Try direct parse
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    # Try to find JSON array/object in markdown code blocks
    match = re.search(r"```(?:json)?\s*([\s\S]*?)```", text)
    if match:
        try:
            return json.loads(match.group(1))
        except json.JSONDecodeError:
            pass
    # Try bracket-counting for JSON arrays (handles nesting + trailing text)
    result = _extract_json_array(text)
    if result is not None:
        return result
    # Non-greedy match for JSON objects (no nesting issues with {})
    match = re.search(r"\{.*?\}", text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(0))
        except json.JSONDecodeError:
            pass
    return {}


def _guess_tool(vuln_type: str) -> str:
    """Map vuln type to a default tool when no suggested_tool is available."""
    vt = vuln_type.lower()
    if "sql" in vt:
        return "sqlmap_test"
    if "xss" in vt:
        return "xss_reflection_test"
    if "cmdi" in vt or "command" in vt:
        return "command_injection_test"
    if "ssti" in vt:
        return "send_payload"
    if "lfi" in vt or "path" in vt:
        return "curl_get"
    if "idor" in vt:
        return "curl_get"
    if "ssrf" in vt:
        return "curl_get"
    return "curl_get"


def _format_parse_summary(parsed: dict) -> str:
    """Convert parse_response output to a compact (<800 char) string."""
    lines = []
    ct = parsed.get("type", "?")
    size = parsed.get("size_bytes", 0)
    if size > 1048576:
        size_str = f"{size / 1048576:.1f}MB"
    elif size > 1024:
        size_str = f"{size / 1024:.1f}KB"
    else:
        size_str = f"{size}B"
    lines.append(f"Type={ct}, Size={size_str}")

    flags = parsed.get("flags", [])
    if flags:
        lines.append(f"FLAGS={flags}")

    if ct == "html":
        if parsed.get("title"):
            lines.append(f"Title: {parsed['title'][:80]}")
        lines.append(
            f"Forms={parsed.get('forms',0)} Inputs={parsed.get('inputs',0)} Links={parsed.get('links_count',0)}"
        )
        apis = parsed.get("api_paths", [])
        if apis:
            lines.append(f"API: {' '.join(apis[:8])[:180]}")
        eps = parsed.get("endpoints", [])
        if eps:
            lines.append(f"EP: {' '.join(eps[:10])[:200]}")
        sc = parsed.get("scripts", [])
        if sc:
            lines.append(f"JS: {' '.join(sc[:5])[:150]}")
    elif ct == "json":
        tlk = parsed.get("top_level_keys")
        if tlk:
            lines.append(f"Keys: {tlk}")
        iv = parsed.get("interesting_values", [])
        for item in iv[:5]:
            lines.append(f"  [{item['path']}]: {item['value'][:80]}")
    elif ct == "text":
        urls = parsed.get("urls", [])
        if urls:
            lines.append(f"URLs: {' '.join(urls[:6])}")
        jwts = parsed.get("jwt_tokens", [])
        if jwts:
            lines.append(f"JWT: {jwts[:3]}")

    result = "\n".join(lines)
    return result[:800]


def _format_tool_feedback(
    orch, tc_name: str, tc_args: dict, result, defence_probe: str = ""
) -> str:
    """Format a tool execution result into structured feedback for the LLM.

    Gives the LLM clear status, stdout, stderr, and defense probe findings.
    """
    status = "SUCCESS" if (hasattr(result, "success") and result.success) else "FAILED"
    exit_code = getattr(result, "exit_code", "?")
    stdout = getattr(result, "stdout", "") or ""
    stderr = getattr(result, "stderr", "") or ""
    elapsed = getattr(result, "elapsed_ms", 0)

    # Detect timeout (empty output + failure)
    if status == "FAILED" and not stdout and not stderr:
        status = "TIMEOUT"

    parts = [
        f"[TOOL: {tc_name}]",
        f"STATUS: {status} (exit={exit_code}, {elapsed}ms)",
        f"ARGS: {json.dumps(tc_args, default=str)[:200]}",
    ]
    if stdout:
        _INFO_TOOLS = {
            "wpscan_enum",
            "knowledge_search",
            "nmap_port_range",
            "nmap_full_scan",
            "nikto_scan",
            "dirb_scan",
            "gobuster_dir",
            "nvd_search_cves",
            "searchsploit_search",
            "metasploit_search",
            "go_exploitdb_search",
        }
        _stdout_limit = 5000 if tc_name in _INFO_TOOLS else 1500
        parts.append(f"STDOUT: {stdout[:_stdout_limit]}")
    if stderr:
        parts.append(f"STDERR: {stderr[:500]}")
    if not stdout and not stderr:
        parts.append("(no output)")
    if defence_probe:
        parts.append(defence_probe)

    # Auto-parse: for large or structured responses, append a compact summary.
    _PARSABLE_TOOLS = {"curl_get", "http_post"}
    if (
        stdout
        and tc_name in _PARSABLE_TOOLS
        and len(stdout) > 5000
        and status == "SUCCESS"
    ):
        try:
            content_type = "auto"
            if stdout.startswith("HTTP/"):
                ct_match = re.search(r"Content-Type:\s*(\S+)", stdout, re.I)
                if ct_match:
                    ct_val = ct_match.group(1).lower()
                    if "html" in ct_val:
                        content_type = "html"
                    elif "json" in ct_val:
                        content_type = "json"
            parsed = parse_response(stdout, content_type=content_type)
            summary = _format_parse_summary(parsed)
            if summary:
                parts.append(f"PARSED SUMMARY:\n{summary}")
        except Exception:
            pass  # best-effort, never break feedback

    return "\n".join(parts)


def _fmt_tool_list(gateway) -> str:
    """Format tool definitions into a compact text block for the analyze prompt."""
    lines = []
    for d in sorted(
        gateway.get_tool_definitions(), key=lambda d: d["function"]["name"]
    ):
        name = d["function"]["name"]
        props = d["function"]["parameters"].get("properties", {})
        required = d["function"]["parameters"].get("required", [])
        req_params = [p for p in required if p in props]
        opt_params = [p for p in props if p not in required]
        sig = ", ".join(req_params)
        if opt_params:
            sig += (", " if sig else "") + ", ".join(f"{p}?" for p in opt_params)
        desc = d["function"].get("description", "")
        if len(desc) > 140:
            _cut = desc[:140].rfind(" ")
            desc = desc[:_cut] + "..."
        _hint = f"  → {desc}" if desc else ""
        lines.append(
            f"  {name}({sig}){_hint}" if sig else f"  {name}{_hint}"
        )
    return "\n".join(lines)


# ===================================================================
# Public API
# ===================================================================


async def service_research(orch) -> None:
    """Hardcoded service-port vulnerability lookup. Runs BEFORE analyze.

    For each discovered service with a meaningful version, search local RAG
    and MCP/NVD for known CVEs. Results are injected into the LLM context
    so that ``analyze_phase`` can generate precise, evidence-based hypotheses.
    Skips services marked skip_exploit (SSH, etc.).
    """
    services = orch.dkg.query_nodes("Service")
    if not services:
        return

    log.info("service_research: searching %d services for known CVEs", len(services))
    service_research_text = ""
    try:
        for s in services[:10]:
            port = s.get("port", 0)
            version = s.get("version", "") or s.get("banner", "")
            if s.get("skip_exploit"):
                continue
            if not version or version in ("unknown", "tcpwrapped", "http", "https", ""):
                continue
            # MCP NVD CVE search
            try:
                if "nvd_search_cves" in orch.mcp_pool.get_tool_names():
                    mcp_result = await orch.mcp_pool.call_tool(
                        "nvd_search_cves",
                        {"keyword": version, "limit": 3},
                    )
                    content = mcp_result.get("content", [{}])
                    text = content[0].get("text", "") if content else ""
                    if text and "0 matching CVEs" not in text:
                        service_research_text += f"  [NVD CVEs] {text[:400]}\n"
            except Exception:
                pass

            # RAG knowledge_search for non-HTTP database services
            _NON_HTTP_RAG_PORTS = {
                22, 6379, 3306, 5432, 1433, 1521, 27017, 11211, 9200, 8086, 5984, 9042,
                9092, 4444,
            }
            if port in _NON_HTTP_RAG_PORTS:
                try:
                    svc_name = version or f"port {port}"
                    rag_result = await orch.attack_gateway.call(
                        "knowledge_search",
                        {
                            "query": f"{svc_name} exploitation unauthorized access weak credentials",
                            "category": "",
                        },
                    )
                    if rag_result and getattr(rag_result, "success", False):
                        rag_text = (rag_result.stdout or rag_result.stderr or "")[:800]
                        if rag_text and "no results" not in rag_text.lower():
                            service_research_text += (
                                f"\n  [RAG Knowledge for {svc_name}]: {rag_text}\n"
                            )
                except Exception:
                    pass

        if service_research_text:
            orch.llm.add_context_message(
                f"[SERVICE RESEARCH] Known vulnerabilities for discovered services:\n"
                f"{service_research_text}",
                role="user",
            )
            # Persist to DKG so data survives analyze phase reset
            orch.dkg.add_node("Analysis", f"svc-research-{int(time.time())}", {
                "phase": "service_research",
                "type": "cve_findings",
                "content": service_research_text,
            })
            log.info(
                "service_research: injected %d chars of CVE data",
                len(service_research_text),
            )
    except Exception as e:
        log.warning("service_research failed: %s", e)

    # -- Service research summary --
    services = orch.dkg.query_nodes("Service")
    cve_notes = [
        a for a in orch.dkg.query_nodes("Analysis") if a.get("type") == "cve_findings"
    ]
    if cve_notes:
        cve_preview = cve_notes[0].get("content", "")[:300]
        cve_ids = re.findall(r"CVE-\d{4}-\d{4,}", cve_preview)
        if cve_ids:
            print(f"[RESEARCH] Found CVEs: {', '.join(cve_ids[:8])}")
        else:
            print(f"[RESEARCH] CVE data injected ({len(cve_preview)} chars)")
    else:
        print(f"[RESEARCH] No known CVEs found for {len(services)} services")


async def active_service_research(orch) -> None:
    """LLM actively researches each discovered service using exploit tools.

    Runs AFTER recon populates DKG and BEFORE analyze identifies vulns.
    The LLM can call: metasploit_search, searchsploit_search,
    go_exploitdb_search, cve_lookup to find known exploits for each
    service version discovered during scanning.
    """
    services = orch.dkg.query_nodes("Service")
    if not services:
        return

    # Build service list for the LLM
    service_list = []
    for s in services[:8]:
        port = s.get("port", "?")
        protocol = s.get("protocol", "?")
        version = s.get("version", "") or s.get("banner", "")
        if version:
            service_list.append(f"  port {port}/{protocol}: {version}")

    if not service_list:
        return

    log.info("active_service_research: LLM researching %d services", len(service_list))

    # Give LLM exploit research tools + MCP research tools
    research_tools = []
    for td in orch.attack_gateway.get_tool_definitions():
        name = td.get("function", {}).get("name", "")
        if name in (
            "metasploit_search",
            "searchsploit_search",
            "go_exploitdb_search",
            "cve_lookup",
        ):
            research_tools.append(td)
    try:
        for td in orch.mcp_pool.get_tool_definitions():
            name = td.get("function", {}).get("name", "")
            if any(
                kw in name.lower()
                for kw in ("search", "cve", "vuln", "exploit", "code", "repo")
            ):
                research_tools.append(td)
    except Exception:
        pass

    prompt = (
        "Discovered services -- research each one for known exploits:\n"
        + "\n".join(service_list)
        + "\n\n"
        "For EACH service version above, call metasploit_search and "
        "searchsploit_search to find known exploits. If CVEs were found "
        "by nmap_vulners, look them up with cve_lookup. "
        "Output findings as JSON:\n"
        '[{"service": "OpenSSH 8.9p1", "exploits_found": [...], '
        '"cves": [...], "notes": "..."}]\n'
    )

    orch._maybe_compress()
    content, tool_calls = orch.llm.generate(
        prompt=prompt,
        system_prompt=getattr(orch, "_analyze_prompt_formatted", SYSTEM_PROMPT_ANALYZE),
        tools=research_tools,
    )

    # Execute research tool calls (max 2 rounds)
    for _ in range(2):
        if not tool_calls:
            break
        for tc in tool_calls:
            tc_name = tc.get("name", "")
            tc_args = tc.get("arguments", {})
            tc_id = tc.get("id", "")
            if tc_name in orch.attack_gateway.get_tool_names():
                result = await orch.attack_gateway.call(tc_name, tc_args)
            else:
                continue
            tool_stdout = _format_tool_feedback(orch, tc_name, tc_args, result, "")
            orch.llm.add_tool_result(tc_id, tool_stdout[:2000])

        orch._maybe_compress()
        content, tool_calls = orch.llm.generate(
            prompt="Continue researching. Output JSON summary when done.",
            system_prompt=getattr(orch, "_analyze_prompt_formatted", SYSTEM_PROMPT_ANALYZE),
            tools=research_tools,
        )

    # Store findings in DKG Service nodes
    if content:
        try:
            findings = _extract_json(content)
            if isinstance(findings, list):
                for f in findings:
                    if isinstance(f, dict):
                        svc_name = f.get("service", "")
                        for s in services:
                            ver = s.get("version", "") or s.get("banner", "")
                            if svc_name and svc_name in ver:
                                orch.dkg.add_node("Service", s.get("id", ""), {
                                    "research_exploits": f.get("exploits_found", []),
                                    "research_cves": f.get("cves", []),
                                    "research_notes": f.get("notes", ""),
                                })
        except Exception as e:
            log.warning("Active service research parse failed: %s", e)

    log.info("active_service_research: complete")


async def analyze_phase(orch) -> None:
    """Analyze reconnaissance data to identify potential vulnerabilities."""
    orch.phase = type(orch.phase).ANALYZE if hasattr(orch.phase, "ANALYZE") else "analyze"

    # -- Probe endpoints: capture actual responses before analysis --
    app_context = await probe_endpoints(orch)

    # Build typed pipeline state from DKG (single source of truth)
    state = normalize_dkg_state(orch.dkg)

    analyze_system_prompt = SYSTEM_PROMPT_ANALYZE.format(
        attack_tools=_fmt_tool_list(orch.attack_gateway),
        recon_tools=_fmt_tool_list(orch.recon_gateway),
    )
    orch._analyze_prompt_formatted = analyze_system_prompt

    # Transition to analyze phase (preserve history, swap system prompt)
    orch.llm.replace_system_prompt(analyze_system_prompt)
    transition = (
        f"[PHASE TRANSITION] Moving from reconnaissance to vulnerability analysis.\n"
        f"Services discovered: {len(state.services)}, Endpoints: {len(state.endpoints)}\n"
        f"Your task: analyze the application and identify vulnerabilities.\n"
        f"The conversation above contains all reconnaissance results -- do not repeat them."
    )
    orch.llm.add_context_message(transition, role="user")

    # Build unreachable services warning
    unreachable_warning = ""
    unreachable = [s for s in state.services if s.http_reachable is False]
    if unreachable:
        unreachable_warning = (
            "\n## WARNING -- Ports found by nmap but NOT HTTP-reachable:\n"
            + "\n".join(f"- port {s.port}/{s.protocol}" for s in unreachable[:10])
            + "\nDo NOT generate hypotheses for these services.\n"
        )

    # Use canonical prompt format from PipelineState
    state_context = state.to_prompt_context()

    # CTAGE: cloud topology context for analyze phase
    cloud_topology_context = ""
    if hasattr(orch, "_cloud_topology") and orch._cloud_topology:
        ct = orch._cloud_topology
        if ct.clusters or ct.high_risk_pods:
            lines = ["\n## Cloud/K8s Topology (CTAGE)"]
            if ct.clusters:
                for c in ct.clusters:
                    lines.append(f"- Cluster: {c.get('name', '')} ({c.get('version', '')})")
            if ct.nodes:
                lines.append(
                    f"- Nodes: {len(ct.nodes)} "
                    f"({sum(1 for n in ct.nodes if n.get('is_control_plane'))} control-plane, "
                    f"{sum(1 for n in ct.nodes if not n.get('is_control_plane'))} worker)"
                )
            if ct.namespaces:
                lines.append(f"- Namespaces: {len(ct.namespaces)}")
            if ct.pods:
                lines.append(f"- Pods: {len(ct.pods)}")
            if ct.service_accounts:
                lines.append(f"- ServiceAccounts: {len(ct.service_accounts)}")
            if ct.rbac_bindings:
                lines.append(f"- RBAC Bindings: {len(ct.rbac_bindings)}")
            if ct.high_risk_pods:
                lines.append(f"\n### High-Risk Pods ({len(ct.high_risk_pods)})")
                for profile in ct.high_risk_pods[:10]:
                    lines.append(
                        f"- {profile.namespace}/{profile.pod_name}: "
                        f"risk={profile.risk_score:.2f}, "
                        f"vectors={profile.escape_vectors}, "
                        f"sa={profile.service_account}"
                    )
            if ct.iam_roles:
                lines.append(f"\n### IAM Roles ({len(ct.iam_roles)})")
                for role in ct.iam_roles[:5]:
                    lines.append(f"- {role.get('role_name', '')} ({role.get('provider', '')})")
            if ct.cross_account_trusts:
                lines.append(f"\n### Cross-Account Trusts ({len(ct.cross_account_trusts)})")
                for trust in ct.cross_account_trusts[:5]:
                    lines.append(
                        f"- {trust.get('source_role', '')} → account {trust.get('target_account', '')}"
                    )
            cloud_topology_context = "\n".join(lines) + "\n"

    # CTAGE: compute attack paths from cloud topology
    cloud_attack_paths_context = ""
    try:
        from darwin.cloud_attack_path import compute_attack_paths

        attack_path_report = compute_attack_paths(orch.dkg)
        if attack_path_report.paths:
            cloud_attack_paths_context = attack_path_report.to_prompt_context() + "\n"
            log.info(
                "CTAGE Reasoner: %d attack paths injected into analyze prompt",
                len(attack_path_report.paths),
            )
    except Exception as e:
        log.debug("CTAGE Reasoner: attack path computation skipped (%s)", e)

    prompt = (
        f"## Mission\n{orch._task_description}\n\n"
        f"Target information:\n"
        f"{unreachable_warning}"
        f"{app_context}"
        f"{cloud_topology_context}"
        f"{cloud_attack_paths_context}"
        f"{state_context}\n\n"
        f"## Instructions\n"
        f"1. First, understand what this application DOES based on the endpoint responses above.\n"
        f"2. Identify what business logic each endpoint implements.\n"
        f"3. THEN identify potential vulnerabilities based on your understanding.\n"
        f"4. For each vulnerability, explain WHY you think it exists (not just pattern matching).\n"
        f"5. If an endpoint returns static content regardless of input, note that it's "
        f"likely NOT exploitable and skip it.\n"
        f"6. CRITICAL: Use the EXACT parameter names from 'Known Parameter Names' above. "
        f"Do NOT guess parameter names from response field names."
    )
    cteg_suggestions = orch.cteg.get_suggestions(
        defense_type=orch.defense_state.waf_type or "",
        vuln_type="",
    )
    if cteg_suggestions.get("bypass_strategies") or cteg_suggestions.get(
        "exploit_strategies"
    ):
        prompt += (
            f"\n\nPrior cross-task experience suggests:\n"
            f"{json.dumps(cteg_suggestions, indent=2)}"
        )
    else:
        prompt += "\n\nNo prior cross-task experience available for this target type."

    orch._maybe_compress()
    tokens_before = orch.llm.token_count

    print(f"\n{'=' * 50}")
    print(f"[ANALYZE] Asking LLM to identify vulnerabilities...")
    print(
        f"[ANALYZE] State: {len(state.endpoints)} endpoints, "
        f"{len(state.services)} services, "
        f"{len(state.vulnerabilities)} vulns"
    )

    content, _ = orch.llm.generate(prompt=prompt)
    tokens_used = orch.llm.token_count - tokens_before
    orch._task_log_event(
        "info",
        "llm_analyze_call",
        prompt=prompt,
        response=content[:2000],
        tokens_used=tokens_used,
        cteg_suggestions=cteg_suggestions,
    ) if hasattr(orch, "_task_log_event") else None

    print(f"[ANALYZE] LLM response ({tokens_used} tokens):")
    print(f"{content[:1500]}")
    if len(content) > 1500:
        print(f"  ... ({len(content) - 1500} more chars)")
    print(f"{'=' * 50}\n")

    # Parse LLM's vulnerability hypotheses
    try:
        parsed = _extract_json(content)
        # New format: {"application_understanding": "...", "vulnerabilities": [...]}
        # Old format (backward compat): [...] flat array
        if isinstance(parsed, dict):
            app_understanding = parsed.get("application_understanding", "")
            if app_understanding:
                print(f"\n[UNDERSTAND] {app_understanding}\n")
                # Persist to DKG for plan-generation and sub-agent access
                orch.dkg.add_node("Analysis", f"analysis-{int(time.time())}", {
                    "phase": "analyze",
                    "type": "application_understanding",
                    "content": app_understanding,
                    "endpoint_count": len(orch.dkg.query_nodes("Endpoint")),
                })
            vulns_json = parsed.get("vulnerabilities", [])
            # Parse attack_paths: multi-step chains that structure the exploit order.
            attack_paths = parsed.get("attack_paths", [])
            if attack_paths and isinstance(attack_paths, list):
                for ap in attack_paths[:5]:
                    if isinstance(ap, dict):
                        ap_id = ap.get("id", f"path-{int(time.time() * 1000) % 100000}")
                        ap_steps = ap.get("steps", [])
                        ap_desc = ap.get("description", "")
                        orch.dkg.add_node("Analysis", f"attack-path-{ap_id}", {
                            "phase": "analyze",
                            "type": "attack_path",
                            "content": ap_desc,
                            "path_id": ap_id,
                            "steps": ap_steps,
                            "step_count": len(ap_steps),
                        })
                log.info(
                    "analyze_phase: stored %d attack paths in DKG",
                    len([ap for ap in attack_paths if isinstance(ap, dict)]),
                )
        else:
            vulns_json = parsed if isinstance(parsed, list) else []
        print(
            f"[ANALYZE] Parsed {len(vulns_json)} vulnerability hypotheses from LLM"
        )

        # Collect all known params from typed PipelineState
        all_known_params: set[str] = set()
        for ep in state.endpoints:
            for p in ep.params:
                all_known_params.add(p)

        for v in vulns_json:
            vt = v.get("vuln_type", "")
            # Correct guessed parameter names against known params
            llm_param = v.get("param", "")
            if llm_param and all_known_params and llm_param not in all_known_params:
                ep_url = v.get("endpoint", "")
                ep_params = state.get_params_for_url(ep_url)
                if ep_params:
                    log.warning(
                        "ANALYZE: LLM guessed param '%s' but DKG has %s for %s -- correcting",
                        llm_param,
                        ep_params,
                        ep_url,
                    )
                    v["param"] = ep_params[0]
                else:
                    log.warning(
                        "ANALYZE: LLM guessed param '%s' but no DKG params found for %s",
                        llm_param,
                        ep_url,
                    )

            vt = v.get("vuln_type", "")
            hypothesis = VulnerabilityHypothesis(
                vuln_type=vt,
                endpoint=v.get("endpoint", ""),
                param=v.get("param", ""),
                confidence=float(v.get("confidence", 0.5)),
                evidence=v.get("evidence", ""),
                suggested_tool=v.get("suggested_tool", ""),
                tool_args=(
                    v.get("tool_args", {})
                    if isinstance(v.get("tool_args"), dict)
                    else {}
                ),
            )
            orch.vulnerabilities.append(hypothesis)

            # Record in DKG with LLM-suggested tool if provided
            dkg_props: dict = {
                "vuln_type": vt,
                "endpoint": hypothesis.endpoint,
                "parameter": hypothesis.param,
                "severity": "unknown",
                "source": "llm_analysis",
            }
            suggested_tool = v.get("suggested_tool", "")
            if suggested_tool:
                # Validate tool name against actual registry
                all_valid_tools = (
                    orch.attack_gateway.get_tool_names()
                    + orch.recon_gateway.get_tool_names()
                )
                if suggested_tool not in all_valid_tools:
                    # Fuzzy match: find closest real tool name
                    from difflib import get_close_matches

                    matches = get_close_matches(
                        suggested_tool, all_valid_tools, n=1, cutoff=0.3
                    )
                    if matches:
                        log.info(
                            "Analyze: corrected tool '%s' → '%s'",
                            suggested_tool,
                            matches[0],
                        )
                        suggested_tool = matches[0]
                    else:
                        log.warning(
                            "Analyze: unknown tool '%s' -- dropping suggestion",
                            suggested_tool,
                        )
                        suggested_tool = ""
                dkg_props["suggested_tool"] = suggested_tool
                tool_args = v.get("tool_args", {})
                # Normalize: CLI-style string args -> dict if possible
                if isinstance(tool_args, str):
                    log.info(
                        "Analyze: tool_args was string '%s' -- converting to dict with 'url'",
                        tool_args[:80],
                    )
                    tool_args = {"url": tool_args}
                if isinstance(tool_args, dict):
                    dkg_props["tool_args"] = tool_args
            orch.dkg.add_node(
                "Vulnerability", f"vuln-{len(orch.vulnerabilities)}", dkg_props
            )
    except Exception as e:
        log.warning(
            "analyze_phase: failed to parse LLM vulnerability output: %s", e
        )

    # Fallback: if LLM produced no hypotheses, build from DKG findings
    if not orch.vulnerabilities:
        await augment_from_dkg(orch)
    else:
        # Always augment LLM results with DKG-derived hypotheses
        before = len(orch.vulnerabilities)
        await augment_from_dkg(orch)
        if len(orch.vulnerabilities) > before:
            log.info(
                "analyze_phase: augmented %d LLM hypotheses with %d from DKG",
                before,
                len(orch.vulnerabilities) - before,
            )

    # -- Vulnerability summary --
    if orch.vulnerabilities:
        print(f"\n[ANALYZE] {len(orch.vulnerabilities)} vulnerability hypotheses:")
        _MAX_SHOW = 15
        for i, v in enumerate(orch.vulnerabilities[:_MAX_SHOW], 1):
            vt_padded = f"[{v.vuln_type:<12}]"
            ep_short = v.endpoint[:55] if v.endpoint else "?"
            param_str = f"param={v.param}" if v.param else "param=(none)"
            print(
                f"  {i:2d}. {vt_padded} {ep_short:<56} {param_str:<20} conf={v.confidence:.0%}"
            )
            if v.evidence:
                print(f"      Evidence: {v.evidence[:130]}")
            if v.suggested_tool and v.suggested_tool != "curl_get":
                print(f"      Tool: {v.suggested_tool}")
        if len(orch.vulnerabilities) > _MAX_SHOW:
            print(
                f"  ... and {len(orch.vulnerabilities) - _MAX_SHOW} more"
            )
    else:
        print("[ANALYZE] No vulnerability hypotheses generated.")

    orch.step_count += 1


async def augment_from_dkg(orch) -> None:
    """Add vulnerability hypotheses derived from DKG endpoints and findings.

    Uses LLM to classify nikto findings into actionable vuln types.
    Writes derived hypotheses to BOTH ``orch.vulnerabilities`` AND DKG.
    """
    # Collect nikto findings for LLM classification
    nikto_findings = []
    for v in orch.dkg.query_nodes("Vulnerability"):
        detail = v.get("detail", "")
        endpoint = v.get("endpoint", "")
        if detail and endpoint and v.get("source") == "nikto":
            nikto_findings.append({"detail": detail, "endpoint": endpoint})

    if nikto_findings:
        # Ask LLM to classify all nikto findings in one batch
        findings_text = "\n".join(
            f"{i+1}. [{f['endpoint']}] {f['detail']}"
            for i, f in enumerate(nikto_findings[:15])
        )
        try:
            orch._maybe_compress()
            llm_content, _ = orch.llm.generate(
                prompt=(
                    "Classify each nikto finding into a vulnerability type. "
                    "Allowed types: SQLI, XSS, CMDI, SSTI, LFI, IDOR, CSRF, AUTH. "
                    "For each, also specify a suggested_tool (sqlmap_test, "
                    "xss_reflection_test, command_injection_test, or curl_get) "
                    "and confidence (0.0-1.0).\n\n"
                    f"Nikto findings:\n{findings_text}\n\n"
                    "Output JSON array: [{\"index\": 1, \"vuln_type\": \"...\", "
                    '"suggested_tool": "...", "confidence": 0.X}]'
                ),
                system_prompt="You are a vulnerability classifier. Output only valid JSON.",
            )
            classifications = _extract_json(llm_content)
            if isinstance(classifications, list):
                class_map = {}
                for c in classifications:
                    if isinstance(c, dict):
                        idx = c.get("index", 0)
                        class_map[idx - 1] = c  # 1-based -> 0-based

                for i, nf in enumerate(nikto_findings):
                    cls = class_map.get(i, {})
                    vtype = cls.get("vuln_type", "") or "XSS"
                    suggested_tool = cls.get("suggested_tool", "")
                    confidence = float(cls.get("confidence", 0.3))
                    endpoint = nf["endpoint"]
                    if not any(
                        vv.endpoint == endpoint and vv.vuln_type == vtype
                        for vv in orch.vulnerabilities
                    ):
                        orch.vulnerabilities.append(
                            VulnerabilityHypothesis(
                                vuln_type=vtype,
                                endpoint=endpoint,
                                param="",
                                confidence=confidence,
                                evidence=nf["detail"],
                                suggested_tool=suggested_tool,
                            )
                        )
                        props: dict = {
                            "vuln_type": vtype,
                            "endpoint": endpoint,
                            "parameter": "",
                            "severity": "low",
                            "source": "llm_classified",
                            "detail": nf["detail"],
                        }
                        if suggested_tool:
                            props["suggested_tool"] = suggested_tool
                        orch.dkg.add_node(
                            "Vulnerability",
                            f"vuln-{len(orch.vulnerabilities)}",
                            props,
                        )
                return  # LLM classified successfully, skip fallback
        except Exception as e:
            log.warning(
                "LLM nikto classification failed: %s -- using keyword fallback", e
            )

    # Fallback: keyword-based classification (if LLM unavailable)
    for v in orch.dkg.query_nodes("Vulnerability"):
        detail = v.get("detail", "")
        vtype = "XSS"
        for kw, vt in [
            ("sql", "SQLI"),
            ("injection", "SQLI"),
            ("xss", "XSS"),
            ("cross-site", "XSS"),
            ("command injection", "CMDI"),
            ("rce", "CMDI"),
            ("directory listing", "LFI"),
            ("path traversal", "LFI"),
            ("idor", "IDOR"),
            ("broken auth", "AUTH"),
            ("csrf", "CSRF"),
        ]:
            if kw in detail.lower():
                vtype = vt
                break
        endpoint = v.get("endpoint", "")
        if not any(
            vv.endpoint == endpoint and vv.vuln_type == vtype
            for vv in orch.vulnerabilities
        ):
            orch.vulnerabilities.append(
                VulnerabilityHypothesis(
                    vuln_type=vtype,
                    endpoint=endpoint,
                    param="",
                    confidence=0.3,
                    evidence=detail,
                )
            )
            orch.dkg.add_node(
                "Vulnerability",
                f"vuln-{len(orch.vulnerabilities)}",
                {
                    "vuln_type": vtype,
                    "endpoint": endpoint,
                    "parameter": "",
                    "severity": "low",
                    "source": "nikto_keyword",
                    "detail": detail,
                },
            )
    # Every endpoint -> at least one injection hypothesis
    common_params = [
        "q", "id", "search", "query", "user", "input", "name", "file", "page",
    ]
    for ep in orch.dkg.query_nodes("Endpoint"):
        url, params = ep.get("url", ""), ep.get("params", "")
        method = ep.get("method", "GET")
        if not url:
            continue
        if params:
            if any(
                v.endpoint == url and v.param == params for v in orch.vulnerabilities
            ):
                continue
            for vt in ("SQLI", "XSS", "CMDI"):
                orch.vulnerabilities.append(
                    VulnerabilityHypothesis(
                        vuln_type=vt,
                        endpoint=url,
                        param=params,
                        confidence=0.30,
                        evidence=f"{method} parameter: {params}",
                    )
                )
                orch.dkg.add_node(
                    "Vulnerability",
                    f"vuln-{len(orch.vulnerabilities)}",
                    {
                        "vuln_type": vt,
                        "endpoint": url,
                        "parameter": params,
                        "severity": "medium",
                        "source": "param_heuristic",
                    },
                )
        elif method == "POST":
            # POST endpoint -- collect params from ALL endpoint nodes
            all_ep = orch.dkg.query_nodes("Endpoint")
            post_params = [
                e.get("params", "")
                for e in all_ep
                if e.get("params", "") and e.get("params", "") not in ("", "*")
            ]
            best_param = post_params[0] if post_params else "job_type"
            all_params = list(
                dict.fromkeys(
                    [best_param]
                    + post_params
                    + ["job_type", "type", "name", "id", "query"]
                )
            )
            for p in all_params[:3]:
                if not any(
                    v.endpoint == url and getattr(v, "param", "") == p
                    for v in orch.vulnerabilities
                ):
                    for vt in ("SQLI", "XSS", "CMDI"):
                        tool = (
                            "sqlmap_test"
                            if vt == "SQLI"
                            else (
                                "xss_reflection_test"
                                if vt == "XSS"
                                else "command_injection_test"
                            )
                        )
                        orch.vulnerabilities.append(
                            VulnerabilityHypothesis(
                                vuln_type=vt,
                                endpoint=url,
                                param=p,
                                confidence=0.30,
                                evidence=f"POST endpoint -- injection test (param={p})",
                                suggested_tool=tool,
                                tool_args={
                                    "url": url,
                                    "param": p,
                                    "method": "POST",
                                    "body_format": "json",
                                },
                            )
                        )
                        orch.dkg.add_node(
                            "Vulnerability",
                            f"vuln-{len(orch.vulnerabilities)}",
                            {
                                "vuln_type": vt,
                                "endpoint": url,
                                "parameter": p,
                                "severity": "medium",
                                "source": "post_endpoint_heuristic",
                                "suggested_tool": tool,
                                "tool_args": {
                                    "url": url,
                                    "param": p,
                                    "method": "POST",
                                    "body_format": "json",
                                },
                            },
                        )
    # Endpoints with numeric path segments -> IDOR + SQLI
    for ep in orch.dkg.query_nodes("Endpoint"):
        url = ep.get("url", "")
        if not url or not url.startswith("http") or any(
            v.endpoint == url for v in orch.vulnerabilities
        ):
            continue
        if re.search(r"/\d+", url):
            orch.vulnerabilities.append(
                VulnerabilityHypothesis(
                    vuln_type="IDOR",
                    endpoint=url,
                    param="id",
                    confidence=0.3,
                    evidence="Numeric ID in URL path",
                )
            )
            orch.vulnerabilities.append(
                VulnerabilityHypothesis(
                    vuln_type="SQLI",
                    endpoint=url,
                    param="id",
                    confidence=0.25,
                    evidence="Numeric ID in URL path",
                )
            )
            orch.dkg.add_node(
                "Vulnerability",
                f"vuln-{len(orch.vulnerabilities) - 1}",
                {
                    "vuln_type": "IDOR",
                    "endpoint": url,
                    "parameter": "id",
                    "severity": "medium",
                    "source": "path_heuristic",
                },
            )
            orch.dkg.add_node(
                "Vulnerability",
                f"vuln-{len(orch.vulnerabilities)}",
                {
                    "vuln_type": "SQLI",
                    "endpoint": url,
                    "parameter": "id",
                    "severity": "medium",
                    "source": "path_heuristic",
                },
            )

    # Safety net: if too few vulns from LLM, supplement with heuristic hypotheses
    if len(orch.vulnerabilities) < 5:
        for ep in orch.dkg.query_nodes("Endpoint"):
            url = ep.get("url", "")
            if not url or not url.startswith("http"):
                continue
            if any(v.endpoint == url for v in orch.vulnerabilities):
                continue  # already has a hypothesis
            resp = ep.get("sample_response", "")
            params = ep.get("params", "")
            method = ep.get("method", "GET")
            resp_len = ep.get("response_size", 0)
            # Pick the single most likely vuln type based on response characteristics
            if params:
                vt, param = "SQLI", params.split(",")[0] if params else "id"
            elif method == "POST":
                vt, param = "CMDI", "cmd"
            elif resp_len > 100000:
                vt, param = "XSS", "q"  # large SPA -> XSS
            elif "json" in resp.lower() or resp.strip().startswith("{"):
                vt, param = "IDOR", "id"  # API response -> IDOR
            else:
                vt, param = "XSS", "q"
            orch.vulnerabilities.append(
                VulnerabilityHypothesis(
                    vuln_type=vt,
                    endpoint=url,
                    param=param,
                    confidence=0.30,
                    evidence=(
                        f"Heuristic -- {method} endpoint, {resp_len}b response, "
                        f"params={params or 'none'}"
                    ),
                )
            )
            tool = _guess_tool(vt)
            orch.dkg.add_node(
                "Vulnerability",
                f"vuln-{len(orch.vulnerabilities)}",
                {
                    "vuln_type": vt,
                    "endpoint": url,
                    "parameter": param,
                    "severity": "low",
                    "source": "generic_fallback",
                    "suggested_tool": tool,
                },
            )

    # -- Non-HTTP service vulnerability detection --
    _NON_HTTP_VULN_MAP = {
        6379: (
            "AuthBypass",
            "Redis may be accessible without authentication",
            "redis_cmd",
            "redis",
        ),
        27017: (
            "AuthBypass",
            "MongoDB may be accessible without authentication",
            "shell_exec",
            "mongodb",
        ),
        11211: (
            "AuthBypass",
            "Memcached may be accessible without authentication",
            "shell_exec",
            "memcached",
        ),
        3306: (
            "WeakAuth",
            "MySQL may use weak/default credentials",
            "mysql_query",
            "mysql",
        ),
        5432: (
            "WeakAuth",
            "PostgreSQL may use weak/default credentials",
            "psql_query",
            "postgresql",
        ),
        1433: (
            "WeakAuth",
            "MSSQL may use weak/default credentials",
            "mssql_query",
            "mssql",
        ),
        1521: (
            "WeakAuth",
            "Oracle may use weak/default credentials",
            "oracle_query",
            "oracle",
        ),
        22: (
            "WeakAuth",
            "SSH may be accessible with weak credentials or key-based auth",
            "ssh_exec",
            "ssh",
        ),
    }
    # Service name -> vuln mapping (for non-standard ports)
    _SVC_NAME_MAP = {
        "redis": (6379,),
        "mysql": (3306,),
        "postgresql": (5432,),
        "mssql": (1433,),
        "oracle": (1521,),
        "mongodb": (27017,),
        "memcached": (11211,),
        "ssh": (22,),
        "openssh": (22,),
    }
    for svc in orch.dkg.query_nodes("Service"):
        port = svc.get("port")
        # Match by port first, then by service name for non-standard ports
        target_port = None
        if port in _NON_HTTP_VULN_MAP:
            target_port = port
        else:
            version = (svc.get("version", "") or svc.get("banner", "")).lower()
            for name, ports in _SVC_NAME_MAP.items():
                if name in version:
                    target_port = ports[0]
                    break
        if target_port is None:
            continue
        if svc.get("skip_exploit") and target_port != 22:
            continue
        vt, evidence, tool, proto = _NON_HTTP_VULN_MAP[target_port]
        host = svc.get("ip", getattr(orch, "target_host", "localhost"))
        endpoint = f"{proto}://{host}:{port}"
        if not any(v.endpoint == endpoint for v in orch.vulnerabilities):
            orch.vulnerabilities.append(
                VulnerabilityHypothesis(
                    vuln_type=vt,
                    endpoint=endpoint,
                    param="",
                    confidence=0.70,
                    evidence=evidence,
                    suggested_tool=tool,
                    tool_args={"host": host, "port": port},
                )
            )
            orch.dkg.add_node(
                "Vulnerability",
                f"vuln-svc-{host}-{port}",
                {
                    "vuln_type": vt,
                    "endpoint": endpoint,
                    "parameter": "",
                    "severity": "high" if vt == "AuthBypass" else "medium",
                    "source": "non_http_service_heuristic",
                    "suggested_tool": tool,
                },
            )

    # -- Post-filter: remove web-only vuln types from non-HTTP services --
    _WEB_ONLY_TYPES = {"XSS", "SQLI", "IDOR", "CSRF", "SSTI", "LFI", "RFI", "SSRF", "XXE"}
    _NON_HTTP_PROTOS = {
        "redis", "mysql", "postgresql", "mssql", "oracle",
        "ssh", "mongodb", "memcached", "ldap", "smb",
    }
    _dropped = []
    _kept = []
    for v in orch.vulnerabilities:
        if v.vuln_type in _WEB_ONLY_TYPES and any(
            v.endpoint.startswith(f"{p}://") for p in _NON_HTTP_PROTOS
        ):
            _dropped.append(v)
        else:
            _kept.append(v)
    orch.vulnerabilities = _kept
    # Also remove from DKG (systematic pass reads DKG directly)
    for v in _dropped:
        for n in orch.dkg.query_nodes("Vulnerability"):
            if n.get("endpoint") == v.endpoint and n.get("vuln_type") in _WEB_ONLY_TYPES:
                nid = n.get("id", "")
                if nid:
                    orch.dkg.graph.remove_node(nid)


async def research_phase(orch) -> None:
    """LLM-driven vulnerability research phase. Runs AFTER analyze.

    Gives the LLM research-only tools to investigate each identified
    vulnerability. The LLM can query CVE databases, the knowledge base,
    and exploit databases to gather exploitation intelligence.
    """
    if not orch.vulnerabilities:
        return

    log.info(
        "research_phase: LLM researching %d vulnerabilities",
        len(orch.vulnerabilities),
    )
    orch.phase = type(orch.phase).ANALYZE if hasattr(orch.phase, "ANALYZE") else "analyze"

    # Build research prompt with only research tools
    research_tools = []
    _local_research_tool_names = {
        "knowledge_search",
        "cve_lookup",
        "metasploit_search",
        "searchsploit_search",
        "go_exploitdb_search",
        "curl_get",
        "ddg_web_search",
    }
    for gw in [orch.attack_gateway]:
        for td in gw.get_tool_definitions():
            name = td.get("function", {}).get("name", "")
            if name in _local_research_tool_names:
                research_tools.append(td)
    # Add MCP research tools (NVD CVE, GitHub code search -- NOT web-search)
    try:
        _all_mcp_names: list[str] = []
        for td in orch.mcp_pool.get_tool_definitions():
            name = td.get("function", {}).get("name", "")
            _all_mcp_names.append(name)
            # Only include MCP tools that are NOT web search
            if any(kw in name.lower() for kw in
                   ("cve", "vuln", "nvd", "code", "repo", "issue", "commit", "pull")):
                research_tools.append(td)
        log.info(
            "MCP research tools: %d (from %d total MCP tools)",
            len(research_tools),
            len(_all_mcp_names),
        )
    except Exception:
        pass

    _web_search_line = (
        "- ddg_web_search: search the internet via DuckDuckGo for up-to-date\n"
        "  exploitation techniques, default credentials, and service-specific\n"
        "  attack methods. Use this TOGETHER with knowledge_search -- RAG covers\n"
        "  general techniques, web search provides current service-specific details.\n"
    )

    vuln_text = format_vulnerability_summary(orch)

    # -- Build service-specific search queries --
    _CLOUD_SVC_KEYWORDS: dict[str, str] = {
        "cloudformation": "AWS CloudFormation template injection exploitation",
        "oidc": "OIDC identity federation token exchange attack",
        "saml": "SAML federation Golden SAML assertion forgery",
        "sts": "AWS STS assume role privilege escalation",
        "imds": "AWS IMDS cloud metadata credential theft",
        "s3": "S3 object storage bucket enumeration exploitation",
        "iam": "AWS IAM privilege escalation role enumeration",
        "lambda": "AWS Lambda function exploitation PassRole",
        "organizations": "AWS Organizations SCP bypass enumeration",
        "scp": "AWS SCP service control policy bypass",
        "federation": "cloud identity federation token exchange attack",
        "kubernetes": "Kubernetes RBAC enumeration privilege escalation",
        "k8s": "Kubernetes container escape exploitation",
        "etcd": "etcd Kubernetes secrets enumeration",
        "docker": "Docker socket container escape exploitation",
    }
    _svc_name = "service"
    _is_cloud_svc = False
    # Phase A: Check ALL vulnerabilities for cloud keywords FIRST.
    for v in orch.vulnerabilities:
        ep = (v.endpoint or "").lower()
        tool = (v.suggested_tool or "").lower()
        vt = (v.vuln_type or "").lower()
        ev = (v.evidence or "").lower()
        _combined = f"{vt} {ep} {ev} {tool}"
        for _kw, _label in _CLOUD_SVC_KEYWORDS.items():
            if _kw in _combined:
                _svc_name = _label
                _is_cloud_svc = True
                log.info(
                    "[RAG-SVC] %s (matched keyword '%s' from vuln)", _label, _kw
                )
                break
        if _is_cloud_svc:
            break
    # Phase B: Check DKG service banners for cloud fingerprints
    if not _is_cloud_svc:
        for s in orch.dkg.query_nodes("Service"):
            svc_data = (
                s.get("service_name", "")
                + " "
                + (s.get("version", "") or "")
                + " "
                + (s.get("banner", "") or "")
            ).lower()
            for _kw, _label in _CLOUD_SVC_KEYWORDS.items():
                if _kw in svc_data:
                    _svc_name = _label
                    _is_cloud_svc = True
                    log.info(
                        "[RAG-SVC] %s (matched keyword '%s' from DKG service banner)",
                        _label,
                        _kw,
                    )
                    break
            if _is_cloud_svc:
                break
    # Phase C: Check DKG Analysis notes for cloud hints
    if not _is_cloud_svc:
        for note in orch.dkg.query_nodes("Analysis"):
            note_text = (
                str(note.get("summary", ""))
                + " "
                + str(note.get("findings", ""))
            ).lower()
            for _kw, _label in _CLOUD_SVC_KEYWORDS.items():
                if _kw in note_text:
                    _svc_name = _label
                    _is_cloud_svc = True
                    log.info(
                        "[RAG-SVC] %s (matched keyword '%s' from DKG Analysis)",
                        _label,
                        _kw,
                    )
                    break
            if _is_cloud_svc:
                break
    # Phase D: If still no cloud match, fall back to DB service detection
    if not _is_cloud_svc:
        for v in orch.vulnerabilities:
            ep = (v.endpoint or "").lower()
            tool_str = (v.suggested_tool or "").lower()
            if "mssql" in tool_str or "mssql" in ep:
                _svc_name = "Microsoft SQL Server"
            elif "mysql" in tool_str or "mysql" in ep:
                _svc_name = "MySQL"
            elif "postgres" in tool_str or "psql" in tool_str or "postgres" in ep or "psql" in ep:
                _svc_name = "PostgreSQL"
            elif "redis" in tool_str or "redis" in ep:
                _svc_name = "Redis"
            elif "oracle" in tool_str or "oracle" in ep:
                _svc_name = "Oracle"
            elif "ssh" in tool_str or "ssh" in ep:
                _svc_name = "SSH"
            elif "smb" in tool_str or "smb" in ep:
                _svc_name = "SMB"
            if _svc_name != "service":
                break
        # Also check DKG services for DB matches
        if _svc_name == "service":
            for v in orch.vulnerabilities:
                for s in orch.dkg.query_nodes("Service"):
                    svc_port = str(s.get("port", ""))
                    vuln_port = (
                        str(v.tool_args.get("port", "")) if v.tool_args else ""
                    )
                    svc_data = (
                        s.get("service_name", "")
                        + " "
                        + (s.get("version", "") or "")
                        + " "
                        + (s.get("banner", "") or "")
                    ).lower()
                    if svc_port and vuln_port and svc_port == vuln_port:
                        if "mssql" in svc_data or "sql server" in svc_data:
                            _svc_name = "Microsoft SQL Server"
                        elif "mysql" in svc_data:
                            _svc_name = "MySQL"
                        elif "postgres" in svc_data:
                            _svc_name = "PostgreSQL"
                        elif "redis" in svc_data:
                            _svc_name = "Redis"
                        elif "oracle" in svc_data:
                            _svc_name = "Oracle"
                        break
                if _svc_name != "service":
                    break

    _MCP_TIMEOUT_S = 45  # per-MCP-call cap

    # -- Round 1: Programmatic forced parallel search --
    _rag_query = (
        _svc_name
        if _is_cloud_svc
        else f"{_svc_name} exploitation default credentials weaknesses"
    )
    _web_query = (
        _svc_name
        if _is_cloud_svc
        else f"{_svc_name} default credentials common passwords exploitation techniques"
    )
    _web_alt = (
        _svc_name
        if _is_cloud_svc
        else f"{_svc_name} alternative attack vectors privilege escalation misconfiguration"
    )
    _queries = {
        "rag": _rag_query,
        "exploitdb": _svc_name,
        "searchsploit": _svc_name,
        "web": _web_query,
        "web_alt": _web_alt,
    }
    _tasks: dict[str, asyncio.Task] = {}

    # knowledge_search (RAG)
    try:
        _tasks["rag"] = asyncio.create_task(
            orch.attack_gateway.call(
                "knowledge_search", {"query": _queries["rag"], "category": ""}
            )
        )
    except Exception:
        pass

    # go_exploitdb_search -- local SQLite exploit DB
    try:
        _tasks["exploitdb"] = asyncio.create_task(
            orch.attack_gateway.call(
                "go_exploitdb_search",
                {"query": _queries["exploitdb"], "limit": 10},
            )
        )
    except Exception:
        pass

    # searchsploit_search -- Exploit-DB CLI
    try:
        _tasks["searchsploit"] = asyncio.create_task(
            orch.attack_gateway.call(
                "searchsploit_search", {"query": _queries["searchsploit"]}
            )
        )
    except Exception:
        pass

    # ddg_web_search -- Python DuckDuckGo
    try:
        _tasks["web"] = asyncio.create_task(
            orch.attack_gateway.call(
                "ddg_web_search",
                {"query": _queries["web"], "max_results": 8},
            )
        )
    except Exception:
        pass

    # Wait for all tasks (failures are non-fatal)
    _results: dict[str, str] = {}
    for _key, _task in _tasks.items():
        try:
            _raw = await _task
            if _raw and hasattr(_raw, "stdout") and _raw.stdout:
                _results[_key] = _raw.stdout[:2500]
            elif _raw:
                _results[_key] = str(_raw)[:2500]
        except Exception as _e:
            log.debug("research_phase: %s failed: %s", _key, _e)

    # Build context message with all results
    _context_parts = ["## Research Results (automatic pre-search)\n"]
    _labels = {
        "rag": "knowledge_search (RAG)",
        "exploitdb": "go_exploitdb_search (local Exploit-DB)",
        "searchsploit": "searchsploit_search (Exploit-DB CLI)",
        "web": "ddg_web_search (DuckDuckGo internet)",
    }
    for _key in ("rag", "exploitdb", "searchsploit", "web"):
        _label = _labels.get(_key, _key)
        if _key in _results:
            _context_parts.append(
                f"### {_label}: {_queries.get(_key, '')}\n{_results[_key]}"
            )
        else:
            _context_parts.append(f"### {_label}\n(search unavailable)")
    _context_parts.append("")
    orch.llm.add_context_message("\n".join(_context_parts), role="user")

    # -- Rounds 2-3: LLM-driven free research --
    _first_prompt = (
        "You are in the RESEARCH phase. Do NOT run any exploit tools.\n\n"
        f"## Vulnerabilities to research:\n{vuln_text}\n\n"
        "## Available research tools:\n"
        "- knowledge_search: local knowledge base (general techniques, MITRE ATT&CK, CVEs)\n"
        f"{_web_search_line}"
        "- cve_lookup: look up CVE details\n"
        "- metasploit_search: search for Metasploit modules\n"
        "- searchsploit_search: search ExploitDB for public exploits\n"
        "- go_exploitdb_search: search local exploit database\n"
        "- curl_get: fetch documentation or verify endpoint details\n\n"
        "## Context\n"
        "You already have knowledge_search, exploit DB, AND internet search results above.\n"
        "Review all carefully, then decide if you need MORE specific research.\n\n"
        "## Instructions\n"
        "1. For WeakAuth/credential vulns: extract SPECIFIC username:password pairs\n"
        "   from the search results. List AT LEAST 8-10 combinations to try.\n"
        "2. If nmap_vulners found CVE IDs, look them up with cve_lookup\n"
        "3. Search for known exploits using metasploit_search and searchsploit_search\n"
        "4. If a PlatformDiscovery hypothesis exists (cloud API, K8s, Docker),\n"
        "   research what OTHER services the same endpoint might expose.\n"
        "   Multi-service platforms often run 5-10 services on one port --\n"
        "   don't assume only one is available.\n"
        "5. If you need more details, call additional research tools now.\n"
        "6. When done, output a JSON summary of findings for each vuln:\n"
        '   [{"vuln_type": "...", "cve_ids": [...], "exploit_modules": [...],'
        '     "key_techniques": [...], "credentials_to_try": ["user:pass", ...],'
        '     "confidence_adjustment": 0.0}]\n'
    )

    orch._maybe_compress()
    content, tool_calls = orch.llm.generate(
        prompt=_first_prompt,
        system_prompt=getattr(orch, "_analyze_prompt_formatted", SYSTEM_PROMPT_ANALYZE),
        tools=research_tools,
    )

    # LLM-driven rounds (max 2 more)
    for _ in range(2):
        if not tool_calls:
            break
        for tc in tool_calls:
            tc_name = tc.get("name", "")
            tc_args = tc.get("arguments", {})
            tc_id = tc.get("id", "")
            try:
                if tc_name in orch.attack_gateway.get_tool_names():
                    result = await orch.attack_gateway.call(tc_name, tc_args)
                elif tc_name in orch.recon_gateway.get_tool_names():
                    result = await orch.recon_gateway.call(tc_name, tc_args)
                elif tc_name in orch.mcp_pool.get_tool_names():
                    import json as _json1

                    mcp_raw = await asyncio.wait_for(
                        orch.mcp_pool.call_tool(tc_name, tc_args),
                        timeout=_MCP_TIMEOUT_S,
                    )
                    is_error = mcp_raw.get("isError", False)
                    error_text = ""
                    if is_error:
                        content_list = mcp_raw.get("content", [])
                        if content_list and isinstance(content_list[0], dict):
                            error_text = content_list[0].get("text", "")
                    result = ToolResult(
                        tool_name=tc_name,
                        success=not is_error,
                        stdout=(
                            error_text
                            if is_error
                            else _json1.dumps(mcp_raw, ensure_ascii=False)
                        ),
                        stderr=error_text,
                        exit_code=1 if is_error else 0,
                        elapsed_ms=0,
                    )
                else:
                    continue
            except asyncio.TimeoutError:
                orch.llm.add_tool_result(
                    tc_id,
                    f"MCP tool '{tc_name}' timed out after {_MCP_TIMEOUT_S}s -- skipping",
                )
                continue
            except Exception as _exc:
                orch.llm.add_tool_result(
                    tc_id,
                    f"Tool '{tc_name}' failed: {_exc} -- skipping",
                )
                continue
            tool_stdout = _format_tool_feedback(orch, tc_name, tc_args, result, "")
            orch.llm.add_tool_result(tc_id, tool_stdout[:2000])

        orch._maybe_compress()
        content, tool_calls = orch.llm.generate(
            prompt="Continue researching. Output JSON summary when done.",
            system_prompt=getattr(orch, "_analyze_prompt_formatted", SYSTEM_PROMPT_ANALYZE),
            tools=research_tools,
        )

    # -- Parse findings from final content --
    try:
        findings = _extract_json(content)
        if isinstance(findings, list):
            for f in findings:
                if isinstance(f, dict) and f.get("vuln_type"):
                    vt = f["vuln_type"].lower()
                    for v in orch.vulnerabilities:
                        if v.vuln_type.lower() == vt:
                            if f.get("cve_ids"):
                                v.evidence = (v.evidence or "") + f" CVEs: {f['cve_ids']}"
                                v.research_cves = list(f["cve_ids"])
                            if f.get("key_techniques"):
                                v.evidence = (
                                    (v.evidence or "")
                                    + f" Techniques: {f['key_techniques']}"
                                )
                                v.research_techniques = list(f["key_techniques"])
                            if f.get("credentials_to_try"):
                                cred_list = ", ".join(
                                    str(c) for c in f["credentials_to_try"][:15]
                                )
                                v.evidence = (
                                    (v.evidence or "") + f" Credentials: [{cred_list}]"
                                )
                                v.tool_args = v.tool_args or {}
                                if not v.tool_args.get("credentials"):
                                    v.tool_args["credentials"] = list(
                                        f["credentials_to_try"]
                                    )
                            # Update DKG
                            for vn in orch.dkg.query_nodes("Vulnerability"):
                                if (vn.get("vuln_type") or "").lower() == vt:
                                    orch.dkg.add_node(
                                        "Vulnerability",
                                        vn.get("id", ""),
                                        {
                                            "research_cves": f.get("cve_ids", []),
                                            "research_techniques": f.get(
                                                "key_techniques", []
                                            ),
                                            "research_modules": f.get(
                                                "exploit_modules", []
                                            ),
                                        },
                                    )
    except Exception as e:
        log.warning("Research phase findings parse failed: %s", e)

    log.info(
        "research_phase: complete -- %d vulns researched",
        len(orch.vulnerabilities),
    )


async def probe_endpoints(orch) -> str:
    """Probe each known endpoint with sample requests and capture responses.

    Returns a formatted string for the analyze prompt describing what each
    endpoint actually does. Also writes sample_response to DKG Endpoint nodes.
    Uses typed EndpointInfo for parameter normalisation.
    """
    import urllib.request as _ur
    import json as _js

    endpoints = orch.dkg.query_nodes("Endpoint")
    if not endpoints:
        return ""

    lines = ["\n## Application Behavior (probed responses)\n"]
    probed_urls: set[str] = set()

    for ep in endpoints:
        ep_info = EndpointInfo.from_dkg(ep)
        url = ep_info.url
        if not url or url in probed_urls:
            continue
        probed_urls.add(url)

        method = ep_info.method
        param_names = ep_info.params  # already normalised list
        body_format = ep_info.body_format

        result_parts = [f"**{method} {url}**"]
        if param_names:
            result_parts.append(f"  INPUT params: {', '.join(param_names)}")

        try:
            if method == "POST":
                # Build a sample JSON body from known params
                if not param_names:
                    param_names = ["test"]
                sample_body = _js.dumps(
                    {p: f"sample_{p}" for p in param_names}
                ).encode()
                req = _ur.Request(
                    url,
                    data=sample_body,
                    method="POST",
                    headers={"Content-Type": "application/json"},
                )
            else:
                # GET: if endpoint has params, include a sample value
                if param_names:
                    qs = "&".join(f"{p}=sample_{p}" for p in param_names)
                    sep = "&" if "?" in url else "?"
                    req_url = f"{url}{sep}{qs}"
                else:
                    req_url = url
                req = _ur.Request(req_url)

            with _ur.urlopen(req, timeout=8) as resp:
                body = resp.read().decode("utf-8", errors="replace")
                status = resp.status
                content_type = resp.headers.get("content-type", "")

            resp_summary = body[:500]
            if len(body) > 500:
                resp_summary += f"... (total {len(body)} bytes)"

            # Smart extraction for HTML pages larger than 500B
            if len(body) > 500 and (
                "<html" in body[:200].lower() or "<!doctype" in body[:200].lower()
            ):
                smart_parts = []
                # Extract <title>
                tm = re.search(r"<title[^>]*>([^<]+)</title>", body, re.IGNORECASE)
                if tm:
                    smart_parts.append(f"[TITLE] {tm.group(1).strip()}")
                # Extract form actions and input names
                forms = re.findall(
                    r"<form[^>]*?action\s*=\s*[\"']([^\"']*)[\"'][^>]*>",
                    body,
                    re.IGNORECASE,
                )
                if forms:
                    smart_parts.append(f"[FORMS] actions: {', '.join(forms[:5])}")
                # Extract input names
                inputs = re.findall(
                    r"<input[^>]*?name\s*=\s*[\"']([^\"']*)[\"']",
                    body,
                    re.IGNORECASE,
                )
                if inputs:
                    smart_parts.append(f"[INPUTS] names: {', '.join(inputs[:15])}")
                # Extract textarea names
                textareas = re.findall(
                    r"<textarea[^>]*?name\s*=\s*[\"']([^\"']*)[\"']",
                    body,
                    re.IGNORECASE,
                )
                if textareas:
                    smart_parts.append(
                        f"[TEXTAREAS] names: {', '.join(textareas[:5])}"
                    )
                # Extract links (up to 10)
                links = re.findall(
                    r"<a[^>]*?href\s*=\s*[\"']([^\"']*)[\"']",
                    body,
                    re.IGNORECASE,
                )
                if links:
                    unique_links = list(
                        dict.fromkeys(
                            l
                            for l in links
                            if not l.startswith("#")
                            and not l.startswith("javascript:")
                        )
                    )
                    smart_parts.append(f"[LINKS] {', '.join(unique_links[:10])}")
                # Extract text content summary
                text = re.sub(
                    r"<script[^>]*>.*?</script>",
                    "",
                    body,
                    flags=re.IGNORECASE | re.DOTALL,
                )
                text = re.sub(
                    r"<style[^>]*>.*?</style>",
                    "",
                    text,
                    flags=re.IGNORECASE | re.DOTALL,
                )
                text = re.sub(r"<[^>]+>", " ", text)
                text = re.sub(r"\s+", " ", text).strip()
                if text:
                    smart_parts.append(f"[TEXT] {text[:300]}")

                if smart_parts:
                    resp_summary = (
                        f"[PAGE_SIZE {len(body)} bytes] "
                        + " | ".join(smart_parts)
                        + f"\n[RAW_PREFIX] {body[:500]}"
                    )

            result_parts.append(f"  HTTP {status} ({content_type[:40]})")
            result_parts.append(f"  Response: {resp_summary}")

            # Write sample response to DKG for sub-agent access
            existing = [
                n
                for n in orch.dkg.query_nodes("Endpoint")
                if n.get("url", "") == url
            ]
            if existing:
                orch.dkg.update_node(
                    existing[0]["id"],
                    {
                        "sample_status": status,
                        "sample_response": resp_summary,
                        "sample_content_type": content_type,
                    },
                )

            # Detect interesting behavior
            if status == 500:
                result_parts.append(
                    "  NOTE: endpoint returns 500 -- backend IS processing input"
                )
            elif body_format == "json" or content_type.startswith("application/json"):
                try:
                    parsed = _js.loads(body)
                    if isinstance(parsed, list):
                        result_parts.append(
                            f"  NOTE: returns JSON array with {len(parsed)} items"
                        )
                        if len(parsed) > 0 and isinstance(parsed[0], dict):
                            out_fields = list(parsed[0].keys())[:6]
                            result_parts.append(
                                f"  OUTPUT fields (NOT input params): {out_fields}"
                            )
                    elif isinstance(parsed, dict):
                        keys = list(parsed.keys())[:5]
                        result_parts.append(
                            f"  NOTE: returns JSON object with OUTPUT keys: {keys}"
                        )
                except Exception:
                    pass

        except Exception as e:
            result_parts.append(f"  ERROR: {str(e)[:150]}")

        lines.append("  ".join(result_parts))

    return "\n".join(lines) + "\n"


def format_vulnerability_summary(orch) -> str:
    """Format vulnerability hypotheses into a compact text block for LLM prompts."""
    if not orch.vulnerabilities:
        return "(none)"
    lines = []
    for i, v in enumerate(orch.vulnerabilities):
        line = f"  {i+1}. [{v.vuln_type}] {v.endpoint}"
        if v.param:
            line += f" param={v.param}"
        line += f" confidence={v.confidence:.2f}"
        if v.evidence:
            line += f"\n     Evidence: {v.evidence[:200]}"
        if v.research_techniques:
            line += (
                "\n     Research: "
                + "; ".join(str(t) for t in v.research_techniques[:5])
            )
        if v.research_cves:
            line += "\n     CVEs: " + ", ".join(str(c) for c in v.research_cves[:5])
        if v.suggested_tool:
            line += f"\n     Tool: {v.suggested_tool}"
            if v.tool_args:
                line += f" args={json.dumps(v.tool_args)[:200]}"
        if v.suggested_payloads:
            line += "\n     Payloads: " + "; ".join(v.suggested_payloads[:5])
        lines.append(line)
    return "\n".join(lines)


def format_vulnerability_summary_short(orch, max_items: int = 5) -> str:
    """Short format for retry prompts -- one line per vuln, no evidence."""
    if not orch.vulnerabilities:
        return "(none)"
    lines = []
    for v in orch.vulnerabilities[:max_items]:
        line = f"- [{v.vuln_type}] {v.endpoint}"
        if v.param:
            line += f" param={v.param}"
        line += f" (confidence={v.confidence:.2f})"
        if v.suggested_tool:
            line += f" → {v.suggested_tool}"
        lines.append(line)
    return "\n".join(lines)


def extract_links_from_html(html: str, base_url: str) -> list[str]:
    """Extract and normalize all navigable links from HTML body."""
    from urllib.parse import urljoin as _uj, urlparse as _up

    links: set[str] = set()
    pb = _up(base_url)
    origin = f"{pb.scheme}://{pb.netloc}"

    for pattern in [
        r'href=["\']([^"\']+)["\']',
        r"""action=["']([^"']+)["']""",
        r'src=["\']([^"\']+)["\']',
    ]:
        for m in re.findall(pattern, html, re.I):
            href = m.strip()
            if href.startswith(("javascript:", "mailto:", "tel:", "#")):
                continue
            absolute = _uj(base_url, href)
            if absolute.startswith(origin):
                frag = absolute.find("#")
                if frag > 0:
                    absolute = absolute[:frag]
                links.add(absolute)
    return list(links)


def extract_ids_from_url(orch, url: str, patterns: dict[str, set[int]]) -> None:
    """Extract numeric path segments as potential record IDs."""
    from urllib.parse import urlparse as _up

    segments = _up(url).path.split("/")
    for i, seg in enumerate(segments):
        if seg.isdigit():
            val = int(seg)
            if val < 1:
                continue
            ps = list(segments)
            ps[i] = "{}"
            pattern = "/".join(ps)
            patterns[pattern].add(val)


def extract_ids_from_body(
    orch, body: str, base_url: str, patterns: dict[str, set[int]]
) -> None:
    """Scan HTML body for numeric IDs in hrefs, data-* attrs, and JS strings."""
    from urllib.parse import urljoin as _uj

    base_norm = base_url.rstrip("/")

    # 1. Standard href links
    for m in re.findall(r'href=["\']([^"\']+)["\']', body):
        absolute = _uj(base_url, m)
        if absolute.startswith(base_norm):
            extract_ids_from_url(orch, absolute, patterns)

    # 2. data-*-id and data-*-resource attributes
    for attr, vid in re.findall(
        r'data-([\w-]*(?:id|order|user|account|resource|item|record)[\w-]*)\s*=\s*["\'](\d+)["\']',
        body,
        re.I,
    ):
        val = int(vid)
        if val < 1:
            continue
        resource = re.sub(
            r"[-_]?(?:id|order|user|account|resource|item|record)$",
            "",
            attr,
            flags=re.I,
        )
        if resource:
            for suffix in ("", "/receipt", "/archive", "/view", "/edit", "/detail"):
                patterns[f"/{resource}/{{}}{suffix}"].add(val)
        if "order" in attr.lower():
            for suffix in ("", "/receipt", "/archive"):
                patterns[f"/order/{{}}{suffix}"].add(val)

    # 3. JS URL fragments: extract path segments around concatenations
    for m in re.findall(
        r"""['"](/[\w/]+/)['"]\s*\+\s*\w+\s*\+\s*['"](/[\w/]*)['"]""",
        body,
    ):
        prefix, suffix = m
        patterns[f"{prefix}{{}}{suffix}"].update({})  # register pattern

    # 4. Path-like strings in JS/JSON: "/order/300123/receipt"
    for m in re.findall(r"""['"](/[\w/]*/\d{2,}/[\w/]*)['"]""", body):
        extract_ids_from_url(orch, _uj(base_norm, m), patterns)
