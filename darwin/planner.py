"""Plan generation, validation, review, and replan module.

Extracted from darwin.orchestrator to provide standalone functions
for plan lifecycle management. Each function takes *orch* (an Orchestrator
instance) as the first parameter and accesses its attributes/methods directly.

Reference:
  - Cochise src/cochise/planner.py:131 — Planner + temporary Executor
"""

from __future__ import annotations

import json
import logging
import re
import time
from collections import deque
from typing import Any

log = logging.getLogger(__name__)

from darwin.prompts.orchestrator import SYSTEM_PROMPT_ORCHESTRATOR_UNIFIED

# ── Static helper functions ──────────────────────────────────────────────────


def extract_json_array(text: str) -> list | None:
    """Extract the first complete JSON array using bracket counting.

    Handles nested brackets and trailing text — more robust than regex.
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


def guess_tool(vuln_type: str) -> str:
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


def topological_sort(tasks: list) -> list:
    """Sort tasks by dependency order using Kahn's algorithm."""
    task_map = {t.get("id") or str(id(t)): t for t in tasks}
    in_degree = {tid: 0 for tid in task_map}
    adj = {tid: [] for tid in task_map}
    for t in tasks:
        tid = t.get("id") or str(id(t))
        for dep_id in t.get("dependent_task_ids", []) or t.get("dependencies", []):
            if dep_id in task_map:
                adj[dep_id].append(tid)
                in_degree[t["id"]] += 1
            else:
                log.warning(
                    "Task '%s' depends on unknown task '%s' — ignored",
                    t.get("id", "?"),
                    dep_id,
                )
    queue = deque([tid for tid, deg in in_degree.items() if deg == 0])
    result = []
    while queue:
        tid = queue.popleft()
        result.append(task_map[tid])
        for neighbor in adj[tid]:
            in_degree[neighbor] -= 1
            if in_degree[neighbor] == 0:
                queue.append(neighbor)
    result.extend(
        [
            task_map[tid]
            for tid in in_degree
            if tid
            not in {r.get("id") or str(id(r)) for r in result}
        ]
    )
    return result


def detect_cycle(tasks: list) -> list[str]:
    """Detect cycles in task dependency graph using DFS.

    Returns list of task IDs involved in the first cycle found, or empty list.
    """
    task_map = {t.get("id") or str(id(t)): t for t in tasks}
    visited: set[str] = set()
    rec_stack: set[str] = set()
    parent_map: dict[str, str | None] = {}

    def _dfs(tid: str) -> list[str] | None:
        if tid in visited:
            return None
        if tid in rec_stack:
            cycle = [tid]
            cur = tid
            for _ in range(len(task_map) + 1):
                prev = parent_map.get(cur)
                if prev is None or prev == tid:
                    break
                cur = prev
                cycle.append(cur)
            cycle.append(tid)
            return cycle[::-1]
        if tid not in task_map:
            return None
        rec_stack.add(tid)
        for dep_id in (
            task_map[tid].get("dependent_task_ids", [])
            or task_map[tid].get("dependencies", [])
        ):
            if dep_id in task_map:
                parent_map[dep_id] = tid
                result = _dfs(dep_id)
                if result:
                    rec_stack.discard(tid)
                    return result
        rec_stack.discard(tid)
        visited.add(tid)
        return None

    for tid in task_map:
        if tid not in visited:
            result = _dfs(tid)
            if result:
                return result
    return []


def break_cycle(tasks: list, cycle: list[str]) -> None:
    """Break a dependency cycle by removing the last edge in the cycle."""
    if len(cycle) < 2:
        return
    last = cycle[-1]
    for t in tasks:
        deps = t.get("dependent_task_ids", []) or t.get("dependencies", [])
        if isinstance(deps, list) and last in deps:
            deps.remove(last)
            return


def is_duplicate_task(new_task: dict, existing_tasks: list[dict]) -> bool:
    """Check if *new_task* is a semantic duplicate of any pending task.

    Two checks:
    1. Same tool + same endpoint → definite duplicate
    2. Instruction word overlap > 75% → near-duplicate
    """
    _nt_inst = (new_task.get("instruction") or "").lower()
    _nt_tool = (new_task.get("tool") or "").lower()
    _nt_endpoint = (
        new_task.get("endpoint")
        or new_task.get("params", {}).get("target_url", "")
        or new_task.get("params", {}).get("url", "")
        or new_task.get("params", {}).get("target", "")
        or new_task.get("params", {}).get("host", "")
    ).lower()

    for pt in existing_tasks:
        if not isinstance(pt, dict):
            continue
        if pt.get("status") != "pending":
            continue
        # Same tool + same endpoint = definite duplicate
        _pt_tool = (pt.get("tool") or "").lower()
        _pt_endpoint = (
            pt.get("endpoint")
            or pt.get("params", {}).get("target_url", "")
            or pt.get("params", {}).get("url", "")
            or pt.get("params", {}).get("target", "")
            or pt.get("params", {}).get("host", "")
        ).lower()
        if _nt_tool and _pt_tool and _nt_endpoint and _pt_endpoint:
            if _nt_tool == _pt_tool and _nt_endpoint == _pt_endpoint:
                return True
        # Word overlap ratio check (fallback)
        _pt_inst = (pt.get("instruction") or "").lower()
        if _nt_inst and _pt_inst:
            _nt_words = set(_nt_inst.split())
            _pt_words = set(_pt_inst.split())
            if _nt_words and _pt_words:
                _overlap = len(_nt_words & _pt_words) / min(len(_nt_words), len(_pt_words))
                if _overlap > 0.75:
                    return True
    return False


# ── Plan generation ──────────────────────────────────────────────────────────


async def generate_exploitation_plan(
    orch, target_url: str, cteg_hints: dict | None = None
) -> "ExploitationPlan":
    """Generate a structured plan from bootstrap state (nmap results only).

    Called at the start of the unified LLM loop. The LLM receives bootstrap
    nmap data, all tools (recon + attack), and decides what to do first.
    """
    # Lazy import to avoid circular dependency
    from darwin.orchestrator import ExploitationPlan

    plan_id = f"plan-{int(time.time())}"
    plan = ExploitationPlan(
        plan_id=plan_id,
        phase="explore",
        goal=f"Capture flag on {target_url}",
        status="in_progress",
        created_at=time.strftime("%Y-%m-%dT%H:%M:%S"),
    )

    state = orch._get_state()
    # All tools: recon + attack, since LLM drives everything.
    # Filter blacklisted tools so the LLM never generates plans using them.
    all_tools = sorted(
        set(
            orch.attack_gateway.get_tool_names() + orch.recon_gateway.get_tool_names()
        )
    )
    # Include MCP tools (nvd_search_cves, github code search, etc.)
    try:
        for t in orch.mcp_pool.get_tool_names():
            if t not in all_tools:
                all_tools.append(t)
    except Exception:
        pass
    all_tools = [t for t in all_tools if t not in orch._BLACKLISTED_TOOLS]

    # Build a tool catalog with parameter schemas so the LLM generates
    # plans with correct parameter names (e.g. "host"+"port" not "target").
    _tool_catalog_parts = []
    _tdefs = list(
        orch.attack_gateway.get_tool_definitions()
        + orch.recon_gateway.get_tool_definitions()
    )
    # Include MCP tool definitions so the LLM knows correct parameters
    try:
        _tdefs += orch.mcp_pool.get_tool_definitions()
    except Exception:
        pass
    for tdef in _tdefs:
        tname = tdef["function"]["name"]
        if tname in orch._BLACKLISTED_TOOLS:
            continue
        params = tdef["function"].get("parameters", {})
        props = params.get("properties", {})
        required = params.get("required", [])
        param_strs = []
        for pname, pinfo in props.items():
            ptype = pinfo.get("type", "string")
            pdesc = (pinfo.get("description", "") or "")[:80]
            req = "required" if pname in required else "optional"
            param_strs.append(f"    {pname}: {ptype} ({req}) — {pdesc}")
        param_block = "\n".join(param_strs) if param_strs else "    (no parameters)"
        desc = (tdef["function"].get("description", "") or "")[:200]
        _tool_catalog_parts.append(
            f"### {tname}\n{desc}\nParameters:\n{param_block}"
        )
    tool_catalog = "\n\n".join(_tool_catalog_parts)

    # Services context
    services_lines = []
    for s in state.services:
        if s.port:
            skip = " [skip]" if s.skip_exploit else ""
            services_lines.append(
                f"  port {s.port}/{s.protocol}: {s.version or s.banner}{skip}"
            )

    # Phase summary from prior loops
    phase_summary = ""
    summaries = orch.dkg.query_nodes("PlanSummary")
    if summaries:
        phase_summary = "\n## Previous Loop Summary\n"
        for s in summaries[-2:]:
            phase_summary += (
                f"- {s.get('phase','')}: {s.get('key_findings','')[:300]}\n"
            )

    # ── RAG knowledge injection ──────────────────────────────────────
    rag_context = ""
    probed_rag_endpoints: list[str] = []
    try:
        from darwin.rag import get_rag

        rag = get_rag()
        if rag and rag.loaded:
            # Build search query: service banners + app type + vuln types.
            svc_terms = []
            for s in state.services[:3]:
                if s.version:
                    ver = s.version.split("(")[0].strip()
                    svc_terms.append(ver[:40])
                elif s.banner:
                    svc_terms.append(s.banner[:40])
            # Pull app-level context from analysis notes
            app_terms = []
            for note in state.analysis_notes:
                for kw in [
                    "WordPress",
                    "Drupal",
                    "Joomla",
                    "Tomcat",
                    "Jenkins",
                    "Django",
                    "Laravel",
                    "Rails",
                    "PHP",
                    "ASP.NET",
                    "Confluence",
                    "GitLab",
                    "Magento",
                    "PrestaShop",
                ]:
                    if kw.lower() in note.lower() and kw not in app_terms:
                        app_terms.append(kw)
            vuln_terms = list({v.vuln_type for v in orch.vulnerabilities[:4]})
            query = " ".join(app_terms + svc_terms + vuln_terms)
            if query.strip():
                results = rag.search(query, top_k=5, min_keyword_overlap=0.2)
                if app_terms:
                    _app_str = " ".join(app_terms)
                    _broad_queries = [
                        _app_str + " plugin exploit vulnerability",
                        _app_str + " unauthenticated file upload RCE",
                        _app_str + " arbitrary file upload vulnerability",
                        _app_str + " unrestricted file upload exploit",
                    ]
                    _broad_results: list[dict] = []
                    for _bq in _broad_queries:
                        try:
                            _br = rag.search(_bq, top_k=5, min_keyword_overlap=0.2)
                            _broad_results.extend(_br)
                        except Exception:
                            pass
                    seen_titles: set[str] = set()
                    merged: list[dict] = []
                    for r in results + _broad_results:
                        t = (r.get("title") or "").strip().lower()
                        if t and t not in seen_titles:
                            seen_titles.add(t)
                            merged.append(r)
                    merged.sort(key=lambda r: r.get("score", 0), reverse=True)
                    results = merged[:10]

                    # ── Cloud Platform Discovery enrichment ──────────
                    _pd_vulns = [
                        v
                        for v in orch.dkg.query_nodes("Vulnerability")
                        if v.get("vuln_type") == "PlatformDiscovery"
                    ]
                    if not _pd_vulns:
                        _cloud_svc_sigs = any(
                            cs in str(s).lower()
                            for cs in (
                                "imds",
                                "ec2 metadata",
                                "s3-compatible",
                                "aws sts",
                                "lambda",
                                "amazon ec2",
                            )
                            for s in orch.dkg.query_nodes("Service")
                        )
                        if _cloud_svc_sigs:
                            _pd_vulns = [
                                {"evidence": "cloud-service-banner-detected"}
                            ]
                    if _pd_vulns:
                        _pd_evidence = (
                            _pd_vulns[0].get("evidence", "") or ""
                        ).lower()
                        _platform_queries: list[str] = []
                        if "aws" in _pd_evidence or "s3" in _pd_evidence or "cloud-service" in _pd_evidence:
                            _platform_queries = [
                                "AWS IAM privilege escalation enumeration techniques",
                                "AWS cloud service discovery STS Lambda after S3 access",
                            ]
                        elif "kubernetes" in _pd_evidence or "k8s" in _pd_evidence:
                            _platform_queries = [
                                "Kubernetes RBAC enumeration privilege escalation",
                                "K8s API resource discovery after initial access",
                            ]
                        else:
                            _platform_queries = [
                                "cloud platform service enumeration privilege escalation",
                            ]
                        _cloud_merged: list[dict] = []
                        _cloud_seen: set[str] = set()
                        for _pq in _platform_queries:
                            try:
                                _cr = rag.search(
                                    _pq, top_k=4, min_keyword_overlap=0.1
                                )
                                for _r in _cr:
                                    _rt = (_r.get("title") or "").strip().lower()
                                    if _rt and _rt not in _cloud_seen:
                                        _cloud_seen.add(_rt)
                                        _cloud_merged.append(_r)
                            except Exception:
                                pass
                        if _cloud_merged:
                            _existing_titles = {
                                (r.get("title") or "").strip().lower()
                                for r in results
                            }
                            for _cr in _cloud_merged:
                                _crt = (_cr.get("title") or "").strip().lower()
                                if _crt and _crt not in _existing_titles:
                                    results.append(_cr)
                                    _existing_titles.add(_crt)
                            log.info(
                                "Cloud Platform RAG: %d results for platform %s",
                                len(_cloud_merged),
                                "AWS"
                                if "aws" in _pd_evidence
                                else "K8s"
                                if "kubernetes" in _pd_evidence
                                else "generic",
                            )

                    if results:
                        # ── Probe RAG-suggested endpoints ─────────────
                        _probe_paths: set[str] = set()
                        _path_re = re.compile(
                            r"(?:GET|POST|PUT|DELETE)\s+(/\S+)",
                            re.IGNORECASE,
                        )
                        _known_urls = {
                            e.get("url", "")
                            for e in orch.dkg.query_nodes("Endpoint")
                        }
                        _base = target_url.rstrip("/")
                        _http_eps = [
                            e.get("url", "")
                            for e in orch.dkg.query_nodes("Endpoint")
                            if e.get("url", "").startswith("http")
                        ]
                        if _http_eps:
                            from urllib.parse import urlparse as _up

                            _parsed = _up(_http_eps[0])
                            _base = f"{_parsed.scheme}://{_parsed.netloc}"
                        for r in results:
                            for tech in (r.get("techniques", []) or []):
                                for m in _path_re.finditer(str(tech)):
                                    path = m.group(1)
                                    if "{{" in path or "}}" in path:
                                        continue
                                    if path not in _probe_paths:
                                        _probe_paths.add(path)

                        _cookies = ""
                        if (
                            orch.client._session
                            and orch.client._session.cookie_jar
                        ):
                            jar = list(orch.client._session.cookie_jar)
                            if jar:
                                _cookies = "; ".join(
                                    f"{c.key}={c.value}" for c in jar
                                )

                        _probed: list[dict] = []
                        for path in list(_probe_paths)[:8]:
                            ep_url = f"{_base}{path}"
                            if ep_url in _known_urls:
                                continue
                            _known_urls.add(ep_url)
                            try:
                                curl_args: dict = {
                                    "url": ep_url,
                                    "follow_redirects": True,
                                    "insecure": True
                                    if "https" in _base
                                    else False,
                                }
                                if _cookies:
                                    curl_args[
                                        "headers"
                                    ] = f"Cookie: {_cookies}"
                                rp = await orch.recon_gateway.call(
                                    "curl_get", curl_args
                                )
                                if rp.success:
                                    out = getattr(rp, "stdout", "") or ""
                                    st = 200
                                    fl = (out or "").split("\n")[0] if out else ""
                                    if fl.startswith("HTTP/"):
                                        pts = fl.split()
                                        if len(pts) >= 2 and pts[1].isdigit():
                                            st = int(pts[1])
                                    _probed.append(
                                        {
                                            "url": ep_url,
                                            "status": st,
                                            "size": len(out),
                                        }
                                    )
                            except Exception:
                                pass

                        if _probed:
                            _found = [
                                p
                                for p in _probed
                                if p["status"] not in (404, 0)
                            ]
                            for p in _found:
                                label = (
                                    p["url"]
                                    .replace(_base, "")
                                    .replace("/", "-")[:50]
                                )
                                orch.dkg.add_node(
                                    "Endpoint",
                                    f"ep-rag-{label}",
                                    {
                                        "url": p["url"],
                                        "method": "GET",
                                        "params": "",
                                        "sample_status": p["status"],
                                        "sample_response": f"HTTP {p['status']} ({p['size']} bytes)",
                                        "discovered_by": "rag-endpoint-probe",
                                    },
                                )
                            _probed_lines = [
                                f"- {p['url']} → HTTP {p['status']} ({p['size']} bytes)"
                                for p in _probed[:8]
                            ]
                            probed_rag_endpoints = _probed_lines
                            log.info(
                                "RAG endpoint probe: %d/%d paths exist on target",
                                len(_found),
                                len(_probed),
                            )

                        lines = ["\n## Attack Pattern Knowledge (from RAG)\n"]
                        for r in results[:4]:
                            title = r.get("title", "") or ""
                            desc = r.get("description", "") or ""
                            techniques = r.get("techniques", []) or []
                            tech_str = (
                                (
                                    " Techniques: "
                                    + "; ".join(str(t) for t in techniques[:3])
                                )
                                if techniques
                                else ""
                            )
                            snippet = (desc[:250] + "...") if len(desc) > 250 else desc
                            lines.append(f"- **{title}**: {snippet}{tech_str}")
                            lines.append("")
                        lines.append(
                            "**CRITICAL: RAG results above contain proven attack techniques "
                            "and credential combinations for the detected services. "
                            "When the service name/type matches your target, the techniques "
                            "and specific credentials listed MUST be used in your tasks. "
                            "Only discard entries whose software/service type clearly does "
                            "not match the target (e.g., MySQL techniques for a PostgreSQL target)."
                        )

                        # Extract concrete payload patterns from RAG results
                        _rag_payloads: list[str] = []
                        for r in results[:4]:
                            for tech in (r.get("techniques", []) or []):
                                tech_str = str(tech)
                                if (
                                    re.search(r"\$\{[^}]+\}", tech_str)
                                    or "Fn::" in tech_str
                                    or "{{" in tech_str
                                ):
                                    _rag_payloads.append(tech_str[:200])
                            desc = r.get("description", "") or ""
                            if re.search(r"\$\{[^}]+\}", desc):
                                _rag_payloads.append(desc[:200])
                        if _rag_payloads:
                            _deduped = list(dict.fromkeys(_rag_payloads))
                            lines.append("")
                            lines.append(
                                "**Extracted Payloads (use verbatim in tasks):**"
                            )
                            for _p in _deduped[:5]:
                                lines.append(f"  - `{_p}`")

                        rag_context = "\n".join(lines)
    except Exception:
        pass

    if not rag_context:
        rag_context = (
            "\n## Attack Pattern Knowledge\n"
            "No stored attack patterns matched the target's "
            "technology stack. Use general exploitation knowledge "
            "and web search for technique guidance.\n"
        )

    # ── Artifact → Tool Bridge ──────────────────────────────────────
    _artifact_lines: list[str] = []
    _artifact_seen: set[str] = set()
    for cred in orch.dkg.query_nodes("Credential"):
        ct = str(cred.get("cred_type", "")).lower()
        cuser = str(cred.get("username", "") or "")
        cpass = str(cred.get("password", "") or "")
        if ("aws" in ct or "iam" in ct) and "aws_creds" not in _artifact_seen:
            _artifact_lines.append(
                "- **AWS credentials discovered** ("
                + (f"user={cuser}, " if cuser else "")
                + f"type={ct}): use `aws_cli` with `--endpoint-url` or "
                + "`aws_sts_query` to enumerate roles; "
                + "`aws_iam_federation` for assume-role"
            )
            _artifact_seen.add("aws_creds")
        if "private_key" in ct and "private_key" not in _artifact_seen:
            _artifact_lines.append(
                "- **Private key / PEM discovered**: use `saml_forge` to "
                + "build a SAML assertion, then `aws_cli` action=assume-role-with-saml "
                + "or `aws_iam_federation`"
            )
            _artifact_seen.add("private_key")
        if ("token" in ct or "jwt" in ct or "bearer" in ct) and "token" not in _artifact_seen:
            _artifact_lines.append(
                "- **Token / JWT discovered**: use `jwt_forge` to craft a "
                + "custom claim, then `aws_iam_federation` action=assume-role-with-web-identity"
            )
            _artifact_seen.add("token")
    for ep in orch.dkg.query_nodes("Endpoint"):
        banner = str(
            ep.get("banner", "") or ep.get("sample_response", "") or ""
        ).lower()
        url = str(ep.get("url", "") or "").lower()
        _ep_sig = f"{banner} {url}"
        if ("s3" in _ep_sig or "object" in banner or "bucket" in banner) and "s3_endpoint" not in _artifact_seen:
            _artifact_lines.append(
                "- **Object-storage / S3 endpoint detected**: use "
                + "`object_store_get` to enumerate and retrieve objects"
            )
            _artifact_seen.add("s3_endpoint")
        if ("oidc" in _ep_sig or "openid" in _ep_sig) and "oidc_endpoint" not in _artifact_seen:
            _artifact_lines.append(
                "- **OIDC IdP endpoint detected**: use `jwt_forge` with "
                + "wildcard/malformed claims, then `aws_iam_federation` "
                + "action=assume-role-with-web-identity"
            )
            _artifact_seen.add("oidc_endpoint")
        if ("saml" in _ep_sig or "federation" in _ep_sig) and "saml_endpoint" not in _artifact_seen:
            _artifact_lines.append(
                "- **SAML federation endpoint detected**: use `saml_forge` "
                + "to craft assertion, then `aws_iam_federation` "
                + "action=assume-role-with-saml"
            )
            _artifact_seen.add("saml_endpoint")
        if "sts" in _ep_sig and "sts_endpoint" not in _artifact_seen:
            _artifact_lines.append(
                "- **STS endpoint detected**: use `aws_sts_query` for "
                + "direct Query API calls (no AWS CLI needed). If SCP "
                + "blocks access, try `api_version=2010-05-08` (pre-SCP legacy)"
            )
            _artifact_seen.add("sts_endpoint")
        if (
            "docker-distribution" in _ep_sig
            or "docker registry" in _ep_sig
            or "registry/2.0" in _ep_sig
            or "/v2/" in _ep_sig
            or "docker-registry" in _ep_sig
        ) and "docker_registry" not in _artifact_seen:
            _artifact_lines.append(
                "- **Docker Registry v2 API detected**: use `docker_registry` "
                + "to pull, modify (backdoor), and push images. Then use "
                + "`kubectl_get_pods` + `kubectl_exec` to trigger pod restart "
                + "and read flag from the compromised container."
            )
            _artifact_seen.add("docker_registry")
    for an in orch.dkg.query_nodes("Analysis"):
        ev = str(
            an.get("evidence", "")
            or an.get("summary", "")
            or an.get("findings", "")
            or ""
        )
        if "-----BEGIN" in ev and "pem_key" not in _artifact_seen:
            _artifact_lines.append(
                "- **PEM/private key found in analysis output**: use "
                + "`saml_forge` to build SAML assertion, then "
                + "`aws_cli` action=assume-role-with-saml"
            )
            _artifact_seen.add("pem_key")
            break
    for vn in orch.dkg.query_nodes("Vulnerability"):
        vt = str(vn.get("vuln_type", "") or "").lower()
        if "ssrf" in vt and "ssrf_hint" not in _artifact_seen:
            _artifact_lines.append(
                "- **SSRF vulnerability confirmed**: probe internal "
                + "services (IMDS 169.254.169.254, localhost, Docker "
                + "bridge). If credentials are returned, feed them to "
                + "`aws_cli` / `object_store_get` / `aws_sts_query`"
            )
            _artifact_seen.add("ssrf_hint")
        if ("cloudformation" in vt or "template" in vt) and "cf_hint" not in _artifact_seen:
            _artifact_lines.append(
                "- **CloudFormation / template injection**: test "
                + "Fn::Sub payloads like `${/secure/flag}` or "
                + "`{{resolve:ssm:/secure/flag}}` via `send_payload`"
            )
            _artifact_seen.add("cf_hint")

    _artifact_bridge = ""
    if _artifact_lines:
        _artifact_bridge = (
            "\n## Discovered Artifacts → Recommended Tools\n"
            + "\n".join(_artifact_lines)
            + "\n"
            + "**CRITICAL: These tool mappings are derived from artifacts "
            + "you have ALREADY discovered.  Use them in your plan tasks.**\n"
        )
        log.info(
            "[ARTIFACT-BRIDGE] %d recommendations: %s",
            len(_artifact_lines),
            ", ".join(sorted(_artifact_seen)),
        )

    prompt = f"""Target: {target_url}

## Discovered Services (from nmap)
{chr(10).join(services_lines) if services_lines else '(none)'}

## Current State
- {len(state.endpoints)} endpoints discovered so far
- {len(state.services)} services detected
- Credentials: {len(state.credentials)} known
{phase_summary}
## Analyzed Vulnerabilities
{orch._format_vulnerability_summary()}
{rag_context}
{_artifact_bridge}
{orch._build_defense_evasion_context()}
## Synthesizing Knowledge into Attack Tasks
You have received multiple intelligence sources above:
- Vulnerability hypotheses from the analysis phase
- Attack pattern knowledge (if RAG results matched your target's technology stack)
- Service version information from reconnaissance

Your job: COMBINE these sources when designing each task.
**CRITICAL — Unfamiliar Services/Technologies:** If you are not 100% certain how to exploit a
discovered service or technology, call `knowledge_search` tool FIRST with an empty category
to search the knowledge base for concrete exploitation techniques before writing tasks for it.
Do NOT assume — services like Oracle TNS, CouchDB, Elasticsearch, Redis, and MongoDB each
have protocol-specific exploitation methods that differ from generic HTTP exploitation.
**CRITICAL for WeakAuth/default credentials:** When RAG results contain specific credential
combinations (username:password pairs), you MUST include EVERY listed combination in your
batch credential test. Do NOT rely on your own memory of "common passwords" — the RAG
entries are the authoritative source for service-specific defaults.
- When an attack pattern matches a discovered service: use the pattern's technique as the task's approach. The RAG result title and techniques field tell you exactly what to do.
- **Payload injection**: If a vulnerability lists "Payloads:" in its summary or the Attack Pattern Knowledge section contains "Extracted Payloads", those are proven exploitation strings validated against the target's technology. Include them verbatim in the corresponding task's params["data"] or params["payload"]. Do NOT modify or truncate them.
- When patterns do NOT match: rely on general vulnerability exploitation principles for that vulnerability type.
- Service versions are primary signals: an outdated service with known weaknesses should generate high-priority exploitation tasks targeting those specific weaknesses.
- If the analyze phase produced attack_paths, translate each path into a chain of tasks with dependent_task_ids reflecting the path's step ordering. A 4-step path becomes 4 tasks where each depends on the previous one.
- Tasks targeting DIFFERENT services or vulnerabilities with no shared prerequisites should have empty dependent_task_ids so they can execute in parallel.

## Available Tools (all recon + attack)
{', '.join(all_tools)}

{chr(10).join(['## RAG-Endpoint Probe Results (verified — these ENDPOINTS EXIST on the target):'] + probed_rag_endpoints) if probed_rag_endpoints else ''}

## Task
Generate a plan as a JSON array of EXPLOIT tasks. Reconnaissance and research
have already been completed. Each task should test or exploit a vulnerability:
- id: unique string (e.g. "task-1")
- dependent_task_ids: list of task IDs that must complete first
- instruction: what to exploit and how
- tool: exact exploit tool name (sqlmap_test, command_injection_test, etc.)
- params: tool parameters dict
- reason: which vulnerability this targets

**CRITICAL: Generate at most 15 tasks.** Include diverse attack strategies
(SQLi, XSS, CMDi, LFI, file upload, auth bypass, etc.) even for medium-confidence
vulnerabilities. The system can handle many parallel tasks.

**For WeakAuth / default credential vulnerabilities:** Do NOT create individual tasks
for each credential pair — this wastes iterations. Create a SINGLE shell_exec task
that uses a Python one-liner to batch-test ALL credential combinations at once.
Example for PostgreSQL:
```json
{{"id": "task-cred-batch", "dependent_task_ids": [],
 "instruction": "Batch-test all PostgreSQL credential combinations in ONE shell_exec call. Use Python subprocess with PGPASSWORD env var. Test common combos: (postgres,postgres), (postgres,''), (postgres,password), (postgres,admin), (postgres,password123), (postgres,postgresql). Print SUCCESS: for any working pair.",
 "tool": "shell_exec", "params": {{"command": "python3 -c \\"import subprocess,os; combos=[('postgres','postgres'),('postgres',''),('postgres','password'),('postgres','admin'),('postgres','password123')]; [print(f'SUCCESS: {{u}}:{{p}}') if subprocess.run(['psql','-h','HOST','-p','PORT','-U',u,'-w','-c','SELECT 1'],env={{**os.environ,'PGPASSWORD':p}},capture_output=True).returncode==0 else None for u,p in combos]\\""}}}}
```
This reduces 10+ sequential LLM roundtrips to 1 single tool execution.
Then add tasks for authenticated enumeration and data extraction depending on task-cred-batch.

## Dependency Rules (use dependent_task_ids to build a DAG)
Create meaningful task dependencies when:
1. **Credential-first**: tasks that use credentials (e.g. ssh, login) MUST depend
   on credential discovery/verification tasks.
2. **Foothold-first**: lateral movement tasks MUST depend on initial compromise.
3. **Parameter confirmation**: exploit tasks targeting a specific parameter SHOULD
   depend on tasks that confirm that parameter is injectable.
4. **Independent tasks**: exploit tasks targeting DIFFERENT endpoints/services with
   no shared prerequisites SHOULD have empty dependent_task_ids (run in parallel).

Example DAG for a target with SQLi + CMDi + SSH pivot:
```json
[
  {{"id": "task-1", "dependent_task_ids": [],
   "instruction": "Test SQLi on login endpoint", "tool": "sqlmap_test", ...}},
  {{"id": "task-2", "dependent_task_ids": [],
   "instruction": "Test CMDi on upload endpoint", "tool": "command_injection_test", ...}},
  {{"id": "task-3", "dependent_task_ids": ["task-1", "task-2"],
   "instruction": "Use obtained credentials for SSH pivot",
   "tool": "ssh_execute", ...}}
]
```
task-1 and task-2 run first (parallel, independent). task-3 waits for both.

## Strategy
1. CRITICAL: Create at least one EXPLOITATION task for EVERY vulnerability.
   Recon-only tasks (INFO, KEYS *, CONFIG GET) are NOT sufficient — you MUST
   include the actual exploit steps: CONFIG SET, SET key, SAVE, ssh_exec, etc.
   A plan with only recon tasks will FAIL.
2. Simple exploits needing one tool call (SQLi, XSS, CMDi) need 1 task. Complex
   multi-step exploits (SSH key injection via Redis CONFIG SET→dbfilename→
   SET→SAVE, container escape via check_caps→mount→release_agent, multi-stage
   lateral movement) require a SEPARATE task for EACH atomic step.
   dependencies. Consult the Research/CVEs fields above for technique guidance.
2. Prioritize high-confidence vulnerabilities first.
3. If an exploit succeeds or reveals new information, the plan will be
   updated after each task — new tasks can be added in replanning.
4. Do NOT add curl_get/http_post probing tasks — services have already been
   probed during reconnaissance.
5. **Flag location strategy**: After gaining RCE, try simple flag paths FIRST
   (/flag.txt, /flag, /root/flag.txt, /home/*/flag.txt) before launching
   complex recursive find/grep searches. Simple cat commands are faster and
   avoid timeouts.
6. If a vulnerability's suggested tool is curl_get (for LFI/IDOR/SSRF), use
   curl_get with the exact URL and parameter.

Output ONLY valid JSON array (3-20 tasks depending on complexity. More tasks != better — prefer focused, high-impact exploitation tasks over exhaustive probing)."""

    orch._maybe_compress()
    try:
        content, _ = orch.llm.generate(
            prompt=prompt,
            system_prompt=SYSTEM_PROMPT_ORCHESTRATOR_UNIFIED,
            timeout=180.0,
        )
    except Exception as e:
        log.warning(
            "Plan generation LLM call failed: %s — retrying with shorter prompt", e
        )
        orch._maybe_compress()
        try:
            short_prompt = prompt.split("## Analyzed Vulnerabilities")[0]
            if orch.vulnerabilities:
                short_vulns = orch._format_vulnerability_summary_short(max_items=5)
                short_prompt += f"## Analyzed Vulnerabilities\n{short_vulns}\n"
            short_prompt += (
                prompt.split("## Available Tools")[1]
                if "## Available Tools" in prompt
                else ""
            )
            content, _ = orch.llm.generate(
                prompt=short_prompt,
                system_prompt=SYSTEM_PROMPT_ORCHESTRATOR_UNIFIED,
                timeout=180.0,
            )
        except Exception as e2:
            log.warning(
                "Plan generation retry also failed: %s — using hardcoded fallback", e2
            )
            content = ""

    try:
        tasks = [
            t
            for t in (orch._extract_json_array(content) or [])
            if isinstance(t, dict)
        ]
        all_valid_tools = (
            orch.attack_gateway.get_tool_names() + orch.recon_gateway.get_tool_names()
        )
        try:
            all_valid_tools += orch.mcp_pool.get_tool_names()
        except Exception:
            pass
        for t in tasks:
            t.setdefault("status", "pending")
            t.setdefault("dependent_task_ids", t.pop("dependencies", []))
            tool = t.get("tool", "")
            if tool and tool not in all_valid_tools:
                from difflib import get_close_matches

                matches = get_close_matches(tool, all_valid_tools, n=1, cutoff=0.3)
                if matches:
                    log.info("Plan: corrected tool '%s' → '%s'", tool, matches[0])
                    t["tool"] = matches[0]
                else:
                    log.warning(
                        "Plan: unknown tool '%s' — removing from plan", tool
                    )
                    t["tool"] = guess_tool(t.get("vuln_type", ""))
        plan.tasks = tasks
    except Exception as e:
        log.warning("Plan generation JSON parse failed: %s — using fallback", e)

    # Fallback: create from vulnerability hypotheses
    if not plan.tasks and orch.vulnerabilities:
        plan.tasks = []
        for i, v in enumerate(orch.vulnerabilities):
            task = {
                "id": f"task-{i+1}",
                "instruction": f"Test {v.vuln_type} on {v.endpoint}"
                + (f" param={v.param}" if v.param else ""),
                "tool": v.suggested_tool or guess_tool(v.vuln_type),
                "params": v.tool_args
                if v.tool_args
                else (
                    {"url": v.endpoint, "param": v.param}
                    if v.param
                    else {"url": v.endpoint}
                ),
                "reason": v.evidence[:100]
                if v.evidence
                else f"Hypothesized {v.vuln_type}",
                "dependent_task_ids": [],
                "status": "pending",
            }
            if v.suggested_payloads:
                task["params"]["payload"] = v.suggested_payloads[0]
                if len(v.suggested_payloads) > 1:
                    task["params"]["payload_batch"] = v.suggested_payloads
            plan.tasks.append(task)

    plan.updated_at = time.strftime("%Y-%m-%dT%H:%M:%S")

    # Sanitize: replace blacklisted tools (e.g. hydra_ssh_brute → ssh_exec)
    sanitize_plan_tools(orch, plan.tasks)

    # ── Plan generation summary ──────────────────────────────────────
    done = sum(1 for t in plan.tasks if t.get("status") == "done")
    pending = sum(1 for t in plan.tasks if t.get("status") == "pending")
    print(
        f"\n[PLAN] Generated {len(plan.tasks)} tasks ({done} done, {pending} pending)"
    )
    for t in plan.tasks[:12]:
        status = t.get("status", "pending").upper()
        deps = t.get("dependent_task_ids", []) or t.get("dependencies", [])
        dep_str = f" (depends on: {', '.join(deps)})" if deps else ""
        print(f"  [{status:<8}] {t.get('instruction','')[:100]}{dep_str}")
    if len(plan.tasks) > 12:
        print(f"  ... and {len(plan.tasks) - 12} more tasks")

    return plan


# ── Plan sanitization ────────────────────────────────────────────────────────


def sanitize_plan_tools(orch, tasks: list[dict]) -> None:
    """Replace blacklisted tools in-place across ALL plan tasks.

    Called after every plan generation / review / replan to ensure
    time-wasting tools (e.g. hydra_ssh_brute) never reach execution,
    regardless of which code path injected them.
    """
    # Resolve $credentials.* placeholders from DKG state
    _dkg_creds = orch.dkg.query_nodes("Credential")
    _resolved_user = ""
    _resolved_pass = ""
    _resolved_host = ""
    _resolved_port = 0
    _resolved_cred_type = ""
    for c in _dkg_creds:
        if c.get("username"):
            _resolved_user = str(c.get("username"))
            _resolved_pass = str(c.get("password", "") or "")
            _resolved_host = str(c.get("host", "") or "")
            _resolved_cred_type = str(c.get("cred_type", "") or "").lower()
            _cp = c.get("port", 0)
            if _cp:
                _resolved_port = int(_cp)
            break
    if not _resolved_port:
        for s in orch.dkg.query_nodes("Service"):
            _svc_name = (s.get("service_name", "") or "").lower()
            if "ssh" in _svc_name or s.get("port") == 22:
                _p = s.get("port", 0)
                if _p and _p != 22:
                    _resolved_port = int(_p)
                    break

    # ── Protocol-aware tool validation ──
    _PORT_VALID_TOOLS: dict[str, set[str]] = {
        "1433": {"mssql_query", "mssqlclient_query", "shell_exec"},
        "3306": {"mysql_query", "shell_exec"},
        "5432": {"psql_query", "shell_exec"},
        "6379": {"redis_cmd", "shell_exec"},
        "1521": {"oracle_query", "shell_exec"},
        "27017": {"shell_exec"},
        "11211": {"shell_exec"},
        "22": {"ssh_exec", "ssh_key_exec", "test_credential"},
        "80": {
            "curl_get",
            "http_post",
            "send_payload",
            "ffuf_fuzz",
            "hydra_http_brute",
            "sqlmap_test",
        },
        "443": {
            "curl_get",
            "http_post",
            "send_payload",
            "ffuf_fuzz",
            "hydra_http_brute",
            "sqlmap_test",
        },
    }
    _PROTO_DEFAULT_TOOL: dict[str, str] = {
        "mssql": "mssqlclient_query",
        "mysql": "mysql_query",
        "postgres": "psql_query",
        "redis": "redis_cmd",
        "oracle": "oracle_query",
        "ssh": "ssh_exec",
        "http": "curl_get",
        "https": "curl_get",
    }
    _svc_port_to_proto: dict[str, str] = {}
    for s in orch.dkg.query_nodes("Service"):
        _port = str(s.get("port", ""))
        _name = (s.get("service_name", "") or "").lower()
        if _port and not _svc_port_to_proto.get(_port):
            if "mssql" in _name or "sql server" in _name:
                _svc_port_to_proto[_port] = "mssql"
            elif "mysql" in _name:
                _svc_port_to_proto[_port] = "mysql"
            elif "postgres" in _name:
                _svc_port_to_proto[_port] = "postgres"
            elif "redis" in _name:
                _svc_port_to_proto[_port] = "redis"
            elif "oracle" in _name:
                _svc_port_to_proto[_port] = "oracle"
            elif "ssh" in _name:
                _svc_port_to_proto[_port] = "ssh"
            elif "http" in _name:
                _svc_port_to_proto[_port] = "http"

    for t in tasks:
        if not isinstance(t, dict):
            continue
        tool = str(t.get("tool", "")).strip()

        # ── Post-generation tool inference ──────────────────────────
        if not tool:
            _instr = (t.get("instruction", "") or "").lower()
            for _svc in orch.dkg.query_nodes("Service"):
                _svc_name = (_svc.get("service_name", "") or "").lower()
                _svc_port = str(_svc.get("port", ""))
                if not _svc_name:
                    continue
                _svc_params: dict = {}
                if _svc_port:
                    _ep = f"localhost:{_svc_port}"
                    _svc_params["host"] = "localhost"
                    _svc_params["port"] = int(_svc_port)
                if "etcd" in _svc_name:
                    if any(
                        kw in _instr
                        for kw in ("key", "enum", "list", "all", "prefix")
                    ):
                        tool = "k8s_etcd_keys"
                    else:
                        tool = "etcdctl_get"
                    _svc_params["endpoint"] = f"https://{_ep}"
                    _svc_params["insecure"] = True
                    _svc_params["key"] = "/"
                elif "kubernetes-admission" in _svc_name:
                    tool = "send_payload"
                    _svc_params["url"] = f"https://{_ep}"
                elif "kubernetes" in _svc_name:
                    if "secret" in _instr:
                        tool = "kubectl_get_secrets"
                    elif "pod" in _instr:
                        tool = "kubectl_get_pods"
                    else:
                        tool = "kubectl_auth_check"
                elif "kubelet" in _svc_name:
                    if "exec" in _instr or "command" in _instr:
                        tool = "k8s_kubelet_exec"
                    else:
                        tool = "kubelet_probe"
                elif "tiller" in _svc_name:
                    tool = "helm"
                    _tiller_host = (
                        _svc.get("k8s_cluster_ip", "") or ""
                    )
                    _tiller_ns = (
                        _svc.get("k8s_namespace", "") or "kube-system"
                    )
                    _tiller_name = (
                        _svc_name.replace("k8s-", "")
                        if _svc_name.startswith("k8s-")
                        else _svc_name
                    )
                    if _tiller_name and _tiller_ns:
                        _tiller_host = (
                            f"{_tiller_name}.{_tiller_ns}:44134"
                        )
                    _svc_params["command"] = (
                        f"--host {_tiller_host} ls --all"
                        if _tiller_host
                        else "ls --all"
                    )
                if _svc_params:
                    _existing = dict(
                        t.get("params", {})
                        if isinstance(t.get("params"), dict)
                        else {}
                    )
                    for _k, _v in _svc_params.items():
                        _existing.setdefault(_k, _v)
                    t["params"] = _existing
                if tool:
                    t["tool"] = tool
                    break

        _params = (
            t.get("params", {}) if isinstance(t.get("params"), dict) else {}
        )
        _task_port = str(_params.get("port", ""))
        if not _task_port:
            _host = str(
                _params.get("host", _params.get("target", ""))
            )
            if ":" in _host:
                _maybe_port = _host.rsplit(":", 1)[-1]
                if _maybe_port.isdigit():
                    _task_port = _maybe_port

        _valid_tools: set[str] | None = None
        if _task_port and _task_port in _PORT_VALID_TOOLS:
            _valid_tools = _PORT_VALID_TOOLS[_task_port]
        elif _task_port and _task_port in _svc_port_to_proto:
            _proto = _svc_port_to_proto[_task_port]
            if _proto == "ssh":
                _valid_tools = {
                    "test_credential",
                    "ssh_exec",
                    "ssh_key_exec",
                    "hydra_ssh_brute",
                    "shell_exec",
                }
            elif _proto == "mssql":
                _valid_tools = {"mssql_query", "mssqlclient_query", "shell_exec"}
            elif _proto in ("mysql", "mariadb"):
                _valid_tools = {"mysql_query", "shell_exec"}
            elif _proto == "postgres":
                _valid_tools = {"psql_query", "shell_exec"}
            elif _proto == "redis":
                _valid_tools = {"redis_cmd", "shell_exec"}
            elif _proto == "oracle":
                _valid_tools = {"oracle_query", "shell_exec"}
            else:
                _valid_tools = _PORT_VALID_TOOLS.get(_task_port, set())

        if _valid_tools is not None and tool and tool not in _valid_tools:
            _proto = _svc_port_to_proto.get(_task_port, "")
            _replacement = _PROTO_DEFAULT_TOOL.get(_proto, "")
            if _replacement and _replacement in _valid_tools:
                if _replacement != tool and "query" in _replacement:
                    _params.setdefault("query", "SELECT 1 AS test")
                t["tool"] = _replacement
                t["instruction"] = (
                    t.get("instruction", "")
                    + f" [auto-corrected: {tool}→{_replacement} (protocol mismatch for port {_task_port})]"
                )
                tool = _replacement
            elif tool in {
                "test_credential",
                "ssh_exec",
                "ssh_key_exec",
                "hydra_ssh_brute",
            }:
                t["status"] = "skipped"
                continue

        if tool in orch._BLACKLISTED_TOOLS:
            replacement = orch._BLACKLISTED_TOOLS[tool]
            if not replacement:
                t["status"] = "skipped"
            else:
                t["tool"] = replacement
                t["instruction"] = (
                    t.get("instruction", "")
                    .replace("brute force", "authenticate")
                    .replace("brute-force", "authenticate")
                    .replace("Brute force", "Authenticate")
                )
                _rep_params = t.get("params", {})
                if isinstance(_rep_params, dict):
                    if tool == "hydra_ssh_brute" and replacement == "ssh_exec":
                        _target = str(_rep_params.get("target", ""))
                        if ":" in _target:
                            _parts = _target.rsplit(":", 1)
                            _rep_params["host"] = _parts[0]
                            try:
                                _rep_params["port"] = int(_parts[1])
                            except ValueError:
                                _rep_params["port"] = 22
                        else:
                            _rep_params["host"] = _target
                        _rep_params.pop("target", None)
                        t["params"] = _rep_params
        # Block raw SSH in shell_exec
        if tool == "shell_exec":
            _cmd = str(t.get("params", {}).get("command", ""))
            _ssh_match = list(
                re.finditer(r"\b(sshpass|ssh)\b(?![-\w]*=)", _cmd)
            )
            if _ssh_match:
                _m = _ssh_match[-1]
                _ssh_start = _m.start()
                _prefix = _cmd[:_ssh_start].strip()
                _prefix_last_line = (
                    _prefix.rsplit("\n", 1)[-1]
                    .rsplit(";", 1)[-1]
                    .rsplit("&&", 1)[-1]
                    .rsplit("||", 1)[-1]
                )
                _pre_words = _prefix_last_line.strip().split()
                if _pre_words and _pre_words[-1] in (
                    "echo",
                    "printf",
                    "which",
                    "apt",
                    "apt-get",
                    "yum",
                    "man",
                    "help",
                    "whereis",
                    "type",
                    "#",
                ):
                    pass
                else:
                    _rest = _cmd[_ssh_start:]
                    _cmd_words = _rest.split()
                    _ssh_host = ""
                    _ssh_port = 22
                    _ssh_user = ""
                    _ssh_cmd = "id"
                    _ssh_pass = ""
                    _is_sshpass = _cmd_words[0] == "sshpass"
                    for i, w in enumerate(_cmd_words):
                        if w in ("sshpass", "ssh", "ssh-copy-id") and i == 0:
                            continue
                        if w == "-p" and i + 1 < len(_cmd_words):
                            if _is_sshpass and i == 1:
                                _ssh_pass = _cmd_words[i + 1]
                            else:
                                try:
                                    _ssh_port = int(_cmd_words[i + 1])
                                except ValueError:
                                    pass
                        elif w == "-l" and i + 1 < len(_cmd_words):
                            _ssh_user = _cmd_words[i + 1]
                        elif "@" in w and not w.startswith("-"):
                            _user_host = w.split("@")
                            _ssh_user = _ssh_user or _user_host[0]
                            _ssh_host = _user_host[-1]
                        elif w == "-i":
                            pass
                    if _ssh_host:
                        t["tool"] = "ssh_exec"
                        _new_params: dict = {
                            "host": _ssh_host,
                            "port": _ssh_port,
                            "username": _ssh_user or "root",
                            "password": _ssh_pass,
                            "command": _ssh_cmd,
                        }
                        t["params"] = _new_params
                        t["instruction"] = (
                            t.get("instruction", "")
                            + " [auto-corrected: shell_exec→ssh_exec (SSH in shell_exec triggers interactive prompt)]"
                        )

        # ssh_exec is for simple remote commands, not local scripts.
        if tool == "ssh_exec":
            _instr = str(t.get("instruction", "")).lower()
            _cmd = str(t.get("params", {}).get("command", ""))
            _is_cred_test = any(
                kw in _instr
                for kw in (
                    "batch-test",
                    "batch test",
                    "brute force",
                    "brute-force",
                    "dictionary",
                    "wordlist",
                )
            )
            _is_script = "\n" in _cmd or "sshpass" in _cmd or len(_cmd) > 500
            if _is_cred_test or _is_script:
                t["tool"] = "shell_exec"
                t["params"] = {"command": _cmd}
                t["instruction"] = (
                    t.get("instruction", "")
                    + " [auto-corrected: ssh_exec→shell_exec (credential testing must run locally)]"
                )

        # Block CVE-2024-6387 (regreSSHion) tasks
        _instr = str(t.get("instruction", "")).lower()
        if "cve-2024-6387" in _instr or "regresshion" in _instr:
            t["status"] = "skipped"
            continue

        # Block local filesystem access via file:// URLs
        _params = t.get("params", {})
        if isinstance(_params, dict):
            _url_val = str(_params.get("url", ""))
            if (
                _url_val.startswith("file://")
                and t.get("tool", "") in ("curl_get", "http_post")
            ):
                t["status"] = "skipped"
                continue
        # Resolve $credentials.* placeholders in task params
        if isinstance(_params, dict):
            _has_cred_ref = any(
                isinstance(v, str) and "$credentials." in v
                for v in _params.values()
            )
            if _has_cred_ref:
                if _resolved_user:
                    for _key, _val in list(_params.items()):
                        if isinstance(_val, str) and "$credentials." in _val:
                            _params[_key] = (
                                _val.replace(
                                    "$credentials.username", _resolved_user
                                )
                                .replace(
                                    "$credentials.password", _resolved_pass
                                )
                            )
                    if _resolved_host and not str(
                        _params.get("host", "")
                    ).strip():
                        _params["host"] = _resolved_host
                    if _resolved_port and int(
                        _params.get("port", 0) or 0
                    ) in (0, 22):
                        _params["port"] = _resolved_port
                else:
                    t["status"] = "skipped"
                    continue

    # ── Cascade skip to dependent tasks ─────────────────────────────
    _skipped_ids = {
        t.get("id", "") for t in tasks if t.get("status") == "skipped"
    }
    _changed = True
    while _changed:
        _changed = False
        for t in tasks:
            if t.get("status") != "pending":
                continue
            _deps = t.get("dependent_task_ids", []) or t.get("dependencies", [])
            if not _deps:
                continue
            if all(d in _skipped_ids for d in _deps):
                t["status"] = "skipped"
                _skipped_ids.add(t.get("id", ""))
                _changed = True

    # ── Credential-aware hint: use discovered credentials ───────────
    if _resolved_user and _resolved_pass and tasks:
        _cred_tool = "ssh_exec"
        _cred_instruction = (
            f"SSH into {_resolved_host or orch.target_host}:{_resolved_port or 22} "
            f"as {_resolved_user} using the discovered password. Immediately hunt "
            f"for flag: cat /flag* /root/flag* /home/*/flag* /tmp/flag* 2>/dev/null; "
            f"find / -maxdepth 4 -name '*flag*' -type f 2>/dev/null | head -10"
        )
        _cred_params: dict = {
            "host": _resolved_host or orch.target_host,
            "port": _resolved_port or 22,
            "username": _resolved_user,
            "password": _resolved_pass,
            "command": (
                "cat /flag* /root/flag* /home/*/flag* /tmp/flag* 2>/dev/null; "
                "find / -maxdepth 4 -name '*flag*' -type f 2>/dev/null | head -10"
            ),
        }
        if _resolved_cred_type == "aws":
            _cred_tool = "aws_cli"
            _cred_instruction = (
                f"Use discovered AWS credentials ({_resolved_user} / "
                f"{_resolved_pass[:20]}...) to enumerate S3 buckets and "
                f"retrieve objects. Try: aws_cli s3 ls --endpoint-url "
                f"http://{_resolved_host or orch.target_host}:{_resolved_port or 10704}"
            )
            _cred_params = {
                "service": "s3",
                "action": "ls",
                "endpoint_url": (
                    f"http://{_resolved_host or orch.target_host}"
                    f":{_resolved_port or 10704}"
                ),
            }
        elif _resolved_cred_type in (
            "mysql",
            "postgres",
            "postgresql",
            "mssql",
            "redis",
            "oracle",
            "mongodb",
        ):
            _cred_tool = "shell_exec"
            _cred_instruction = (
                f"Use discovered {_resolved_cred_type} credentials "
                f"({_resolved_user}:****@{_resolved_host or orch.target_host}"
                f":{_resolved_port}) to connect and enumerate the database "
                f"for flags and sensitive data."
            )

        _has_login_task = any(
            str(t.get("tool", "")) == _cred_tool
            and str(t.get("params", {}).get("username", "")) == _resolved_user
            and t.get("status") == "pending"
            for t in tasks
        )
        if not _has_login_task:
            tasks.append(
                {
                    "id": f"task-credential-{_resolved_cred_type or 'ssh'}",
                    "instruction": _cred_instruction,
                    "tool": _cred_tool,
                    "params": _cred_params,
                    "dependent_task_ids": [],
                    "status": "pending",
                    "source": "credential-hint",
                }
            )

    # ── Session-aware hint: suggest network discovery ───────────────
    _sessions = orch.dkg.query_nodes("Session")
    if _sessions and tasks:
        _has_net_task = any(
            str(t.get("tool", "")).lower()
            in ("tcpdump_capture", "shell_exec")
            and any(
                kw
                in str(t.get("instruction", "")).lower()
                for kw in (
                    "tcpdump",
                    "ip addr",
                    "netstat",
                    "ss ",
                    "arp",
                    "network",
                    "sniff",
                    "ngrep",
                    "bridge",
                )
            )
            for t in tasks
        )
        if not _has_net_task:
            _sess = _sessions[0]
            _sess_host = _sess.get("host", orch.target_host)
            _sess_user = _sess.get("user", "")
            _sess_port = 22
            _sess_pass = _resolved_pass
            _creds = orch.dkg.query_nodes("Credential")
            for _c in _creds:
                if _c.get("username") == _sess_user or not _sess_user:
                    _sess_user = _sess_user or _c.get("username", "")
                    _sess_pass = _sess_pass or _c.get("password", "")
                    _cp = _c.get("port", 0)
                    if _cp:
                        _sess_port = int(_cp)
                    break
            _net_hint = (
                "You have an active shell session. Before hunting for "
                "flags locally, check the NETWORK — containers often "
                "share a bridge network with other services. Run: "
                "ip addr (discover interfaces/gateways), "
                "ss -tlnp / netstat -tlnp (listening ports on other hosts), "
                "and tcpdump_capture with filter='tcp port 5000 or tcp port 80' "
                "(sniff HTTP traffic for tokens/credentials). "
                "The flag may be in transit between containers, not on disk."
            )
            tasks.append(
                {
                    "id": "task-net-discovery-hint",
                    "instruction": _net_hint,
                    "tool": "ssh_exec",
                    "params": {
                        "host": _sess_host,
                        "port": _sess_port,
                        "username": _sess_user or "root",
                        "password": _sess_pass,
                        "command": "ip addr && ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null",
                    },
                    "dependent_task_ids": [],
                    "status": "pending",
                    "source": "session-hint",
                }
            )

    # ── Post-generation: shell_exec → specialized tool correction ───
    for t in tasks:
        if t.get("tool") != "shell_exec" or t.get("status") not in (
            None,
            "",
            "pending",
        ):
            continue
        _inst = str(t.get("instruction", "")).lower()
        _cmd = str(t.get("params", {}).get("command", "")).lower()
        _combined = f"{_inst} {_cmd}"

        if any(
            kw in _combined
            for kw in (
                "s3 ",
                "s3:",
                "bucket",
                "list-buckets",
                "list-objects",
                "aws s3",
                "object storage",
            )
        ):
            t["tool"] = "curl_get"
            t["instruction"] = (
                f"[auto-corrected: shell_exec->curl_get (S3/object storage)] "
                f"{t.get('instruction', '')}"
            )
            if "command" in t.get("params", {}):
                del t["params"]["command"]
            continue

        if any(
            kw in _combined
            for kw in (
                "aws ",
                "iam ",
                "sts ",
                "lambda ",
                "accesskeyid",
                "secretaccesskey",
                "list-roles",
                "get-caller-identity",
                "assume-role",
                "aws cli",
            )
        ):
            t["tool"] = "aws_cli"
            t["instruction"] = (
                f"[auto-corrected: shell_exec->aws_cli (AWS cloud operation)] "
                f"{t.get('instruction', '')}"
            )
            if "command" in t.get("params", {}):
                del t["params"]["command"]
            continue

        if _cmd.strip().startswith("curl ") and "aws " not in _cmd:
            t["tool"] = "curl_get"
            t["instruction"] = (
                f"[auto-corrected: shell_exec->curl_get (curl in shell_exec)] "
                f"{t.get('instruction', '')}"
            )
            if "command" in t.get("params", {}):
                del t["params"]["command"]
            continue


# ── Plan selection ───────────────────────────────────────────────────────────


def select_next_plan_task(
    orch, plan: "ExploitationPlan | None" = None
) -> dict | None:
    """Return the first pending task whose dependencies are all done.

    Exploit tasks (command_injection_test, sqlmap_test, etc.) are prioritized
    over probe tasks (curl_get, http_post) to ensure exploitation happens
    before passive reconnaissance in the plan loop.
    """
    plan = plan or orch.exploitation_plan
    if not plan or not plan.tasks:
        return None
    _EXPLOIT_PRIORITY = {
        "command_injection_test",
        "sqlmap_test",
        "send_payload",
        "xss_reflection_test",
        "ffuf_fuzz",
        "http_post",
        "form_extract",
        "redis_cmd",
        "mysql_query",
        "psql_query",
        "mssql_query",
        "mssqlclient_query",
        "oracle_query",
        "tomcat_exploit",
        "php_filter_chain",
        "jwt_forge",
        "impacket_psexec",
        "impacket_wmiexec",
        "impacket_pth",
        "impacket_ticketer",
        "impacket_silver_ticket",
        "impacket_secretsdump",
        "impacket_secretsdump_dcsync",
        "impacket_GetUserSPNs",
        "impacket_GetNPUsers",
        "container_escape_docker_sock",
        "container_escape_docker_api",
        "container_escape_cgroup",
        "container_escape_mount_disk",
        "container_escape_cap_dac",
        "container_escape_procfs",
        "container_escape_runc",
        "nsenter_exec",
        "crictl_cmd",
        "check_capabilities",
        "check_mounts",
        "container_find_sockets",
        "container_find_docker",
        "container_recon_env",
        "kubectl_exec",
        "kubectl_run",
        "k8s_secret_dump",
        "k8s_configmap_dump",
        "k8s_sa_token_steal",
        "k8s_kubelet_exec",
        "k8s_etcd_keys",
        "etcdctl_get",
        "k8s_backdoor_daemonset",
        "k8s_backdoor_cronjob",
        "kubectl_get_pods",
        "kubectl_get_secrets",
        "kubectl_get_clusterrolebindings",
        "kubectl_auth_check",
        "sa_token_read",
        "kubelet_probe",
        "aws_cli",
        "aws_iam_federation",
        "check_cloud_metadata",
        "ssrf_probe",
        "ssh_exec",
        "shell_exec",
        "ssh_key_exec",
        "linux_priv_check",
        "file_upload",
        "xxe_inject",
        "ssti_inject",
        "graphql_introspect",
        "wpscan_enum",
        "oracle_tns_poison",
        "smbmap_enum",
        "gpp_decrypt",
        "hash_crack",
        "smb_client",
        "test_credential",
    }
    _LOW_PRIORITY = {
        "hydra_http_brute",
        "hydra_ssh_brute",
    }
    ready_exploit = []
    ready_probe = []
    ready_low = []
    for task in topological_sort(plan.tasks):
        if (
            task.get("status") == "exhausted"
            or task.get("id") in orch._exhausted_task_ids
        ):
            continue
        if task.get("status") != "pending":
            continue
        dep_ids = task.get("dependent_task_ids", []) or task.get("dependencies", [])
        deps_met = True
        all_deps_failed = True if dep_ids else False
        for dep_id in dep_ids:
            dep_task = next(
                (t for t in plan.tasks if t.get("id") == dep_id), None
            )
            if not dep_task or dep_task.get("status") not in (
                "done",
                "failed",
                "exhausted",
                "skipped",
            ):
                deps_met = False
                break
            if dep_task.get("status") != "failed":
                all_deps_failed = False
        if deps_met and all_deps_failed:
            task["status"] = "skipped"
            continue
        if deps_met:
            tool = task.get("tool", "")
            source = task.get("source", "")
            _EXPLOIT_KEYWORDS = [
                "bypass",
                "exploit",
                "assume",
                "escalat",
                "inject",
                "takeover",
                "token",
                "flag",
                " privilege",
                "admin role",
                "forgery",
            ]

            def _has_exploit_semantics(t: dict) -> bool:
                inst = (t.get("instruction") or "").lower()
                return any(kw in inst for kw in _EXPLOIT_KEYWORDS)

            if (
                source == "credential-hint"
                or tool in _EXPLOIT_PRIORITY
                or _has_exploit_semantics(task)
            ):
                ready_exploit.append(task)
            elif tool in _LOW_PRIORITY:
                ready_low.append(task)
            else:
                ready_probe.append(task)
    return (
        ready_exploit[0]
        if ready_exploit
        else (ready_probe[0] if ready_probe else (ready_low[0] if ready_low else None))
    )


def cap_pending_tasks(
    orch,
    tasks: list[dict],
    max_total: int = 20,
    max_pending: int = 7,
) -> list[dict]:
    """Trim lowest-quality pending tasks when plan exceeds *max_total*.

    Quality heuristic (in priority order):
    1. Tasks WITH a tool sort before tasks without (higher quality)
    2. Tasks with fewer dependencies sort first
    3. After sorting, keep at most *max_total* total tasks; excess
       pending tasks are trimmed (done/failed are always preserved).

    Returns the (possibly trimmed) task list.
    """
    if len(tasks) <= max_total:
        return tasks

    _pending = [t for t in tasks if t.get("status") == "pending"]
    _non_pending = [t for t in tasks if t.get("status") != "pending"]
    _keep_pending = max(0, max_total - len(_non_pending))

    if len(_pending) <= _keep_pending:
        return tasks

    def _quality_key(t):
        deps = len(t.get("dependent_task_ids", []))
        has_tool = 1 if t.get("tool", "") else 0
        return (deps, -has_tool)

    _pending.sort(key=_quality_key)
    _to_remove = set(t["id"] for t in _pending[_keep_pending:])
    trimmed = _pending[:_keep_pending]
    _removed_count = len(_to_remove)

    if _removed_count > 0:
        _removed_tools = [
            t.get("tool", "?") for t in _pending[_keep_pending:]
        ]
        print(
            f"\n[PLAN-CAP] Trimmed {_removed_count} low-quality pending task(s): {_removed_tools}"
        )

    return [t for t in tasks if t.get("id") not in _to_remove]


# ── Plan review / update / replan ────────────────────────────────────────────


async def review_and_update_plan(
    orch, task: dict, success: bool, task_result: str = ""
) -> None:
    """LLM reviews and updates the plan after every task (VulnBot-style).

    Called after each task completes, regardless of success or failure.
    The LLM sees what was learned and can add/remove/reorder tasks.
    """
    if not getattr(orch, "exploitation_plan", None):
        return

    # Mark task status with retry enforcement
    task["attempts"] = task.get("attempts", 0) + 1
    if success:
        task["status"] = "done"
    elif task["attempts"] >= orch._task_attempt_limit:
        task["status"] = "exhausted"
        orch._exhausted_task_ids.add(task["id"])
        log.warning(
            "Task %s exhausted after %d attempts",
            task.get("id"),
            task["attempts"],
        )
    else:
        task["status"] = "failed"
    task["result_summary"] = task_result[:2000]

    # Build prompt: what just happened + current plan + new DKG state
    state = orch._get_state()
    new_discoveries = ""
    if state.endpoints:
        new_discoveries += "\n".join(
            f"  - {ep.method} {ep.url}"
            + (f" params={ep.params}" if ep.params else "")
            for ep in state.endpoints[-5:]
        )
        new_discoveries = f"\n## Latest Discoveries\n{new_discoveries}"
    if state.credentials:
        cred_text = "\n".join(
            f"  - {c.username}@{c.source_host}" for c in state.credentials
        )
        new_discoveries += f"\n## Credentials\n{cred_text}"

    cred_reminder = ""
    api_reminder = ""
    unexpected_data = ""
    _aws_fail_reminder = ""
    if success and task_result:
        task_result_lower = task_result.lower()
        if any(
            kw in task_result_lower
            for kw in (
                "token:",
                "client-certificate-data",
                "bearer",
                "password:",
                "apiVersion:",
                "server: https://",
                "success:",
                "login ok",
                "auth ok",
                "connected",
            )
        ):
            cred_reminder = (
                "\nIMPORTANT: The task output above CONTAINS WORKING CREDENTIALS. "
                "You MUST update ALL pending tasks that connect to this service "
                "to use the discovered credentials (username and password). "
                "If any pending task still has placeholder/wrong credentials in "
                "its params, CORRECT them now. "
                "If the output shows 'server: https://HOST:PORT', use that "
                "exact URL with the credentials from the same file. "
                "Send authenticated requests with curl_get: "
                'headers="Authorization: Bearer <token>", insecure=true.\n'
            )
            if any(
                kw in task_result_lower
                for kw in (
                    "accesskeyid",
                    "secretaccesskey",
                    "sessiontoken",
                    "aws_access_key",
                    "iam/security-credentials",
                    "assumerole",
                    "temporary credential",
                )
            ):
                cred_reminder += (
                    "\nCLOUD CREDENTIALS FOUND: The output contains AWS IAM "
                    "credentials (AccessKeyId/SecretAccessKey/Token). IMMEDIATELY "
                    "add tasks to use these with aws_cli:\n"
                    "  - aws sts get-caller-identity\n"
                    "  - aws s3 ls (for data access)\n"
                    "  - aws iam list-roles (for privilege escalation)\n"
                    "For local cloud simulators, use "
                    "--endpoint-url http://localhost:PORT in payload_json.\n"
                )
            if any(
                kw in task_result_lower
                for kw in (
                    "s3",
                    "bucket",
                    "object storage",
                    "listobjects",
                    "getobject",
                    ".s3.",
                )
            ):
                cred_reminder += (
                    "\nS3 / OBJECT STORAGE DETECTED: Try accessing with aws_cli:\n"
                    "  - aws s3 ls --no-sign-request (unauthenticated)\n"
                    "  - aws s3 cp s3://bucket/flag.txt - --no-sign-request\n"
                    "For local S3 simulators, add "
                    "--endpoint-url http://localhost:PORT to payload_json.\n"
                )
        _aws_fail_reminder = ""
        if (
            not success
            and task.get("tool") == "aws_cli"
            and any(
                kw in task_result_lower
                for kw in (
                    "could not connect",
                    "connection refused",
                    "not found",
                    "internal server error",
                    "reached max retries",
                )
            )
        ):
            _aws_fail_reminder = (
                "\nAWS CLI FAILURE: The aws_cli call failed against this "
                "local endpoint.  Local cloud simulators often implement "
                "only a subset of the full AWS API.  DO NOT retry aws_cli "
                "with the same parameters — switch to curl_get or http_post "
                "to access the endpoint via its REST API directly.  Try "
                "GET on the root path, GET on known object keys, and POST "
                "with JSON body.\n"
            )
        if any(
            kw in task_result_lower
            for kw in (
                "openapi",
                "swagger",
                '"kind"',
                '"apiVersion"',
                '"paths"',
                '"items"',
                '"metadata"',
                "namespaces",
            )
        ):
            api_reminder = (
                "\nIMPORTANT: The output above contains a REST API response or "
                "OpenAPI spec. You MUST add tasks to explore these API paths: "
                "list resources, access individual items by ID from the response, "
                "check nested sub-resources. If there's an OpenAPI spec, read it "
                "fully and use the documented paths. The flag is likely in a data "
                "field returned by one of these API calls.\n"
            )
        _structured_indicators = (
            '"arn:',
            '"policy',
            '"permission',
            '"principal"',
            '"statement"',
            '"effect"',
            '"action"',
            '"resource"',
        )
        if any(kw in task_result_lower for kw in _structured_indicators):
            unexpected_data = (
                "\nNOTE: The response contains structured permission/policy "
                "data that doesn't match the tool you just called. The service "
                "may have capabilities (access control, privilege management) "
                "beyond its apparent purpose. Consider whether your initial "
                "hypothesis about this application is correct — try tools and "
                "operations that match the UNEXPECTED data you're seeing.\n"
            )

    _absent_text = ""
    if orch._absent_services:
        _absent_text = (
            f"\n## Unreachable (do NOT probe again)\n"
            f"{', '.join(sorted(orch._absent_services)[:8])}\n"
        )

    focus_reminder = ""
    plan = orch.exploitation_plan
    if plan and plan.tasks:
        failed_primary = [
            t
            for t in plan.tasks
            if t.get("status") == "failed"
            and not any(
                kw in (t.get("instruction", "") or "").lower()
                for kw in ("probe ", "whatweb", "identify ", "check if port")
            )
        ]
        pending_primary = [
            t
            for t in plan.tasks
            if t.get("status") == "pending"
            and not any(
                kw in (t.get("instruction", "") or "").lower()
                for kw in ("probe ", "whatweb", "identify ", "check if port")
            )
        ]
        if failed_primary:
            failed_insts = [
                t.get("instruction", "")[:100] for t in failed_primary[:4]
            ]
            focus_reminder = (
                f"\nFOCUS: You have {len(failed_primary)} FAILED exploitation "
                f"tasks that MUST be retried with corrected tools/params:\n"
                + "\n".join(f"  - {inst}" for inst in failed_insts)
                + f"\nThese are your PRIMARY target. RETRY them with the tool "
                f"that previously succeeded for this target (check DONE tasks "
                f"for working tool/param patterns). "
                f"Do NOT add HTTP probe tasks for incidentally discovered "
                f"ports until these primary exploitation tasks are DONE.\n"
            )
        elif pending_primary:
            focus_reminder = (
                f"\nFOCUS: {len(pending_primary)} pending exploitation tasks "
                f"for the PRIMARY target must be completed BEFORE adding tasks "
                f"for incidentally discovered HTTP ports.\n"
            )

    # ── Post-exploitation flag hunt reminder ──
    _post_exploit_reminder = ""
    if plan and plan.tasks:
        _shell_tools = {"shell_exec", "ssh_exec", "ssh_key_exec", "docker_exec"}
        _has_shell = any(
            t.get("status") == "done" and t.get("tool", "") in _shell_tools
            for t in plan.tasks
        )
        if not _has_shell and task and task.get("tool", "") in _shell_tools and success:
            _has_shell = True

        if _has_shell:
            _done_flag_hunt = any(
                t.get("status") == "done"
                and "flag" in (t.get("instruction", "") or "").lower()
                and t.get("tool", "") in _shell_tools
                for t in plan.tasks
            )
            if not _done_flag_hunt:
                _post_exploit_reminder = (
                    f"\nFLAG HUNT (HIGHEST PRIORITY): You have shell/container access! "
                    f"IMMEDIATELY add tasks to search for flag files:\n"
                    f"  1. shell_exec: ls -la / && cat /flag* /root/flag* /tmp/flag* "
                    f"/home/*/flag* /app/flag* 2>/dev/null\n"
                    f"  2. shell_exec: find / -maxdepth 4 -name '*flag*' -type f 2>/dev/null\n"
                    f"  3. shell_exec: env | grep -i flag; cat /etc/hostname\n"
                    f"Flag files are the #1 CTF pattern. Do NOT enumerate databases or "
                    f"configure services before running these commands.\n"
                )

    prompt = (
        f"Just completed: {task.get('instruction','')}\n"
        f"Tool: {task.get('tool','')}\n"
        f"Result: {success and 'SUCCESS' or 'FAILED'}\n"
        f"Output: {task_result[:4000]}\n"
        f"{cred_reminder}"
        f"{_aws_fail_reminder}"
        f"{api_reminder}"
        f"{unexpected_data}"
        f"{focus_reminder}"
        f"{_post_exploit_reminder}\n"
        f"{orch._format_plan_status()}\n"
        f"{new_discoveries}"
        f"{_absent_text}\n\n"
        f"## Your Job: Update the Plan\n"
        f"Review the plan and apply relevant changes from:\n"
        f"- TOTAL tasks MUST NOT exceed 15. If the plan already has 12+ tasks, "
        f"you MUST REMOVE low-quality pending tasks before ADDING new ones\n"
        f"- **Target Consistency**: Only create tasks for services and ports that "
        f"were ACTUALLY discovered during reconnaissance (see Current State). "
        f"If you see credentials for a service whose port is NOT in the discovered "
        f"services list, do NOT create tasks for it — those credentials are from a "
        f"different target and are NOT relevant here.\n"
        f"- If credentials or tokens were obtained, ADD tasks that USE them immediately "
        f"(e.g., send authenticated requests to the relevant API endpoint)\n"
        f"- If a task discovered new endpoints/services, ADD exploration tasks for them\n"
        f"- If pending tasks target endpoints that returned errors, REMOVE or CHANGE them\n"
        f"- If a task partially succeeded (some calls worked, some failed), SPLIT it\n"
        f"- REMOVE duplicate tasks that test the same thing with slightly different params\n"
        f"- If 5+ enumeration tasks all returned empty/nothing, STOP adding more "
        f"enumeration tasks — switch to exploitation or credential testing instead\n"
        f"{'- This task FAILED — generate alternative approaches using different tools, parameters, or endpoints. Do NOT retry the same approach.' if not success else ''}\n"
        f"- If the plan has >40 tasks, aggressively CULL low-value/redundant pending "
        f"tasks. Prefer 10-20 high-quality exploitation tasks over 50+ probe tasks.\n\n"
        f"Output the COMPLETE updated task list as a JSON array. "
        f"Preserve done/failed tasks. Output ONLY valid JSON array."
    )

    try:
        orch._maybe_compress()
        content, _ = orch.llm.generate(
            prompt=prompt,
            system_prompt=SYSTEM_PROMPT_ORCHESTRATOR_UNIFIED,
        )
        new_tasks = orch._extract_json_array(content) or []
        if new_tasks and isinstance(new_tasks, list) and len(new_tasks) > 0:
            preserved = [
                t
                for t in orch.exploitation_plan.tasks
                if isinstance(t, dict)
                and t.get("status")
                in ("done", "failed", "skipped", "exhausted", "pending")
                and t.get("id") != task.get("id")
            ]
            preserved.append(task)
            existing_ids = {t["id"] for t in preserved}
            llm_dep_updates: dict[str, list] = {}
            _new_added_this_cycle = 0
            _MAX_NEW_PER_CYCLE = 8
            for nt in new_tasks:
                if not isinstance(nt, dict):
                    continue
                nt.setdefault("status", "pending")
                nt.setdefault("dependent_task_ids", nt.pop("dependencies", []))
                if nt["id"] not in existing_ids:
                    if is_duplicate_task(nt, preserved):
                        continue
                    if _new_added_this_cycle >= _MAX_NEW_PER_CYCLE:
                        print(
                            f"\n[PLAN-CAP] Review cycle new-task limit reached "
                            f"({_MAX_NEW_PER_CYCLE}).  Additional tasks deferred."
                        )
                        break
                    preserved.append(nt)
                    existing_ids.add(nt["id"])
                    _new_added_this_cycle += 1
                else:
                    if "dependent_task_ids" in nt:
                        pt = next(
                            (
                                t
                                for t in preserved
                                if t.get("id") == nt["id"]
                            ),
                            None,
                        )
                        if pt and pt.get("status") == "pending":
                            _orig_deps = pt.get("dependent_task_ids") or []
                            _new_deps = nt["dependent_task_ids"]
                            if not _orig_deps or set(_new_deps).issubset(set(_orig_deps)):
                                llm_dep_updates[nt["id"]] = _new_deps
                        else:
                            llm_dep_updates[nt["id"]] = nt["dependent_task_ids"]
            for t in preserved:
                tid = t.get("id", "")
                if tid in llm_dep_updates:
                    t["dependent_task_ids"] = llm_dep_updates[tid]
            orch.exploitation_plan.tasks = preserved
            orch.exploitation_plan.tasks = cap_pending_tasks(orch, preserved, max_total=20)

            # Dependency resolution
            _valid_ids = {
                t.get("id", "") for t in orch.exploitation_plan.tasks
            }
            _all_tasks = list(orch.exploitation_plan.tasks)
            for _t in orch.exploitation_plan.tasks:
                _deps = _t.get("dependent_task_ids", [])
                if not _deps:
                    continue
                _resolved = []
                for _dep_id in _deps:
                    if _dep_id in _valid_ids:
                        _dep_status = ""
                        for _ot in _all_tasks:
                            if _ot.get("id") == _dep_id:
                                _dep_status = _ot.get("status", "")
                                break
                        if _dep_status in (
                            "done",
                            "failed",
                            "skipped",
                            "exhausted",
                        ):
                            continue
                        _resolved.append(_dep_id)
                        continue
                    _dep_inst = ""
                    for _ot in _all_tasks:
                        if _ot.get("id") == _dep_id:
                            _dep_inst = (_ot.get("instruction") or "").lower()
                            break
                    _best, _best_score = None, 0.0
                    if _dep_inst:
                        _dep_words = set(_dep_inst.split())
                        for _ct in orch.exploitation_plan.tasks:
                            if _ct.get("id") == _t.get("id"):
                                continue
                            _ct_inst = (_ct.get("instruction") or "").lower()
                            _ct_words = set(_ct_inst.split())
                            if _dep_words and _ct_words:
                                _score = len(_dep_words & _ct_words) / len(_dep_words)
                                if _score > _best_score:
                                    _best_score = _score
                                    _best = _ct.get("id")
                    if _best and _best_score > 0.4:
                        _resolved.append(_best)
                    else:
                        log.warning(
                            "Task '%s' depends on unknown task '%s' — "
                            "dependency removed",
                            _t.get("id"),
                            _dep_id,
                        )
                _t["dependent_task_ids"] = _resolved

            sanitize_plan_tools(orch, orch.exploitation_plan.tasks)

            cycle = detect_cycle(orch.exploitation_plan.tasks)
            if cycle:
                log.warning(
                    "[PLAN REVIEW] cycle detected: %s — breaking",
                    " -> ".join(cycle),
                )
                break_cycle(orch.exploitation_plan.tasks, cycle)

            sync_plan_to_dkg(orch)
            log.info(
                "[PLAN REVIEW] plan updated: %d tasks (%d done, %d failed, %d exhausted, %d pending)",
                len(preserved),
                sum(1 for t in preserved if t.get("status") == "done"),
                sum(
                    1
                    for t in preserved
                    if t.get("status") in ("failed", "skipped")
                ),
                sum(1 for t in preserved if t.get("status") == "exhausted"),
                sum(1 for t in preserved if t.get("status") == "pending"),
            )

            if orch.phase_logger:
                _review_text = (
                    f"Task '{task.get('id','')}' → {task.get('status','?')}\n"
                    f"Plan: {len(preserved)} tasks — "
                    f"{sum(1 for t in preserved if t.get('status') == 'done')} done, "
                    f"{sum(1 for t in preserved if t.get('status') in ('failed','skipped'))} failed, "
                    f"{sum(1 for t in preserved if t.get('status') == 'pending')} pending"
                )
                orch.phase_logger.log_phase(
                    "plan_review",
                    _review_text,
                    metadata={
                        "task_id": task.get("id", ""),
                        "task_status": task.get("status", ""),
                        "total_tasks": len(preserved),
                    },
                )
    except Exception as e:
        log.warning("Plan review failed: %s — keeping current plan", e)
        sync_plan_to_dkg(orch)


async def replan_after_failure(
    orch, failed_task: dict, result: Any = None
) -> None:
    """LLM generates replacement tasks when a task fails."""
    tid = failed_task.get("id", "?")
    instr = failed_task.get("instruction", "")[:80]
    print(f"\n[REPLAN] Task '{tid}' failed: {instr}")
    print(f"  Generating alternative approaches...")

    prompt = f"""Task failed: {failed_task.get('instruction','')}
Tool: {failed_task.get('tool','')}
Params: {json.dumps(failed_task.get('params',{}))}
Result: {str(result)[:1000]}
Current plan: {orch._format_plan_status()}

Generate replacement tasks as JSON array. Consider different tools, parameters, or endpoints.
If defense was detected, prioritize bypass-first approaches.
Output ONLY valid JSON array."""

    try:
        orch._maybe_compress()
        content, _ = orch.llm.generate(prompt=prompt)
        new_tasks = orch._extract_json_array(content) or []
        if new_tasks:
            existing_ids = {
                t.get("id")
                for t in orch.exploitation_plan.tasks
                if t.get("id") != failed_task.get("id")
            }
            orch.exploitation_plan.tasks = [
                t
                for t in orch.exploitation_plan.tasks
                if t.get("id") != failed_task.get("id")
            ]
            _MAX_REPLACE = 5
            _added = 0
            for nt in new_tasks:
                if nt.get("id") not in existing_ids:
                    if _added >= _MAX_REPLACE:
                        print(
                            f"[REPLAN] Replacement limit reached ({_MAX_REPLACE}). Skipping: {nt.get('id','?')}"
                        )
                        break
                    if is_duplicate_task(nt, orch.exploitation_plan.tasks):
                        print(f"[REPLAN] Skipping duplicate: {nt.get('id','?')}")
                        continue
                    orch.exploitation_plan.tasks.append(nt)
                    existing_ids.add(nt.get("id"))
                    _added += 1
            orch.exploitation_plan.tasks = cap_pending_tasks(
                orch, orch.exploitation_plan.tasks, max_total=20
            )
            sanitize_plan_tools(orch, orch.exploitation_plan.tasks)
            print(f"[REPLAN] Added {len(new_tasks)} replacement task(s):")
            for nt in new_tasks[:5]:
                print(
                    f"  + {nt.get('id','?')}: {nt.get('instruction','')[:100]}"
                )
            sync_plan_to_dkg(orch)

            if orch.phase_logger:
                _replan_text = f"Replan for failed task '{tid}': "
                _replan_text += f"added {len(new_tasks)} task(s)\n"
                for _nt in new_tasks[:10]:
                    _replan_text += (
                        f"  + {_nt.get('id','?')}: "
                        f"{_nt.get('instruction','')[:120]}\n"
                    )
                orch.phase_logger.log_phase(
                    "replan",
                    _replan_text,
                    metadata={"failed_task": tid, "new_tasks": len(new_tasks)},
                )
    except Exception:
        failed_task["status"] = "skipped"


async def update_plan_after_task(
    orch, task: dict, success: bool, result: Any = None
) -> None:
    """Legacy: kept for sub-agent compatibility. Use review_and_update_plan instead."""
    if not getattr(orch, "exploitation_plan", None):
        return
    task["attempts"] = task.get("attempts", 0) + 1
    if success:
        task["status"] = "done"
    elif task["attempts"] >= orch._task_attempt_limit:
        task["status"] = "exhausted"
        orch._exhausted_task_ids.add(task["id"])
    else:
        task["status"] = "failed"
    if result:
        task["result_summary"] = str(result)[:500]


def sync_plan_to_dkg(orch) -> None:
    """Sync in-memory plan state to DKG nodes."""
    plan = getattr(orch, "exploitation_plan", None)
    if not plan:
        return
    done = sum(1 for t in plan.tasks if t.get("status") == "done")
    failed = sum(
        1
        for t in plan.tasks
        if t.get("status") in ("failed", "skipped", "exhausted")
    )
    orch.dkg.add_node(
        "Plan",
        plan.plan_id,
        {
            "plan_id": plan.plan_id,
            "phase": plan.phase,
            "goal": plan.goal,
            "total_tasks": len(plan.tasks),
            "completed": done,
            "failed": failed,
            "status": plan.status,
            "created_at": plan.created_at,
            "updated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        },
    )


def generate_phase_summary(orch, phase: str = "exploit") -> str:
    """Summarize completed phase for the next phase's planning context."""
    plan = getattr(orch, "exploitation_plan", None)
    if not plan or not plan.tasks:
        return ""
    completed = [
        t.get("instruction", "")
        for t in plan.tasks
        if t.get("status") == "done"
    ]
    failed = [
        t.get("instruction", "")
        for t in plan.tasks
        if t.get("status") in ("failed", "skipped", "exhausted")
    ]
    flags = [
        n.get("value", "")
        for n in orch.dkg.query_nodes("Flag")
        if n.get("value", "").startswith("flag{")
    ]
    summary_id = f"summary-{phase}-{plan.plan_id}"
    summary = {
        "summary_id": summary_id,
        "source_plan_id": plan.plan_id,
        "phase": phase,
        "completed_tasks": json.dumps(completed),
        "key_findings": json.dumps(
            {
                "flags_found": flags,
                "endpoints": len(orch.dkg.query_nodes("Endpoint")),
            }
        ),
        "failed_approaches": json.dumps(failed),
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
    }
    orch.dkg.add_node("PlanSummary", summary_id, summary)
    orch.dkg.add_edge(plan.plan_id, summary_id, "plan_successor")
    return json.dumps(summary)


# ── NEW: Plan validation ─────────────────────────────────────────────────────


def validate_plan(orch, tasks: list[dict]) -> list[str]:
    """Rule-based plan validation. Returns list of error messages (empty = valid)."""
    errors = []
    all_tool_names = set(
        orch.attack_gateway.get_tool_names() + orch.recon_gateway.get_tool_names()
    )
    try:
        all_tool_names |= set(orch.mcp_pool.get_tool_names())
    except Exception:
        pass

    task_ids = {
        t.get("id")
        for t in tasks
        if isinstance(t, dict) and t.get("id")
    }
    dkg_services = orch.dkg.query_nodes("Service")
    known_ports = {str(s.get("port")) for s in dkg_services if s.get("port")}

    for task in tasks:
        if not isinstance(task, dict):
            continue
        tid = task.get("id", "?")
        tool = str(task.get("tool", "") or "").strip()

        # 1. Tool existence (if specified)
        if tool and tool not in all_tool_names:
            errors.append(f"[{tid}] unknown tool: {tool}")

        # 2. Dependency validity
        for dep_id in task.get("dependent_task_ids", []) or []:
            if dep_id not in task_ids:
                errors.append(f"[{tid}] invalid dependency: {dep_id}")

        # 3. Target port consistency (warning)
        params = task.get("params", {}) or {}
        target_port = str(params.get("port", ""))
        if target_port and known_ports and target_port not in known_ports:
            errors.append(
                f"[{tid}] WARNING: port {target_port} not in discovered services"
            )

        # 4. Blacklisted tools
        if tool and tool in orch._BLACKLISTED_TOOLS:
            errors.append(f"[{tid}] blacklisted tool: {tool}")

    # 5. Cycle detection
    cycles = detect_cycle(tasks)
    if cycles:
        errors.append(f"dependency cycle detected: {' -> '.join(cycles)}")

    return errors


async def classify_and_replan(
    orch, failed_task: dict, result=None
) -> None:
    """Classify failure and generate appropriate recovery strategy."""
    instruction = failed_task.get("instruction", "")[:200]
    tool = failed_task.get("tool", "")
    output = str(result)[:1000] if result else ""
    output_lower = output.lower()

    EXPLORATORY_TOOLS = {
        "dirb_scan",
        "gobuster_dir",
        "curl_get",
        "whatweb_scan",
        "nikto_scan",
        "form_extract",
        "nmap_scan",
        "knowledge_search",
        "ddg_web_search",
        "searchsploit_search",
        "metasploit_search",
        "go_exploitdb_search",
        "cve_lookup",
        "nvd_search_cves",
        "check_capabilities",
        "check_mounts",
        "check_cloud_metadata",
        "container_find_sockets",
        "container_find_docker",
        "container_recon_env",
        "linux_priv_check",
        "kubectl_auth_check",
        "kubectl_get_pods",
        "kubectl_get_secrets",
    }
    DEAD_END_KEYWORDS = [
        "not vulnerable",
        "no vulnerability",
        "authentication failed",
        "credential rejected",
        "access denied",
        "403 forbidden",
        "connection refused",
        "no route to host",
        "could not connect",
        "not authorized",
        "permission denied",
    ]

    is_exploratory = tool in EXPLORATORY_TOOLS
    has_dead_end = any(kw in output_lower for kw in DEAD_END_KEYWORDS)

    if has_dead_end and not is_exploratory:
        # dead_end: mark exhausted, continue chain
        failed_task["status"] = "exhausted"
        orch._exhausted_task_ids.add(failed_task["id"])
        return
    elif has_dead_end and is_exploratory:
        # exploratory dead end: try alternative approach, keep chain
        pass  # fall through to replan
    elif is_exploratory:
        # pure exploratory failure: generate alternatives
        pass  # fall through to replan

    # Fall through to standard replan for exploratory failures
    await replan_after_failure(orch, failed_task, result)
