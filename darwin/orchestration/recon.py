"""ReconCoordinator — bootstrap and deep reconnaissance.

Owns port discovery, K8s cluster discovery, deep HTTP recon, defense detection and flag verification. State and cross-coordinator calls are forwarded to the shared Orchestrator context.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import shutil
import time
from dataclasses import dataclass, field, replace
from typing import Any, Dict, List, Optional

log = logging.getLogger(__name__)

from darwin.cteg import CTEG, TaskRecord, build_scenario_profile
from darwin.core.context import ContextManager
from darwin.core.contracts import (
    Budget,
    Objective,
    ReplanRecommendation,
    TaskOutcome,
    TaskStatus,
)
from darwin.core.evaluator import (
    Evaluation,
    Evaluator as CoreEvaluator,
    FailureType,
)
from darwin.core.executor import ToolExecutor, ExecutionResult as CoreExecutionResult
from darwin.core.memory import MemoryManager
from darwin.core.metrics import MetricsCalculator
from darwin.core.replan import Replanner
from darwin.core.runtime import Runtime
from darwin.core.scheduler import ParityScheduler
from darwin.core.schemas import (
    parse_analyze_output,
    parse_plan_tasks,
    parse_research_findings,
    parse_service_research_findings,
)
from darwin.core.task import Task, deps_from_task_ids
from darwin.core.task_graph import TaskGraph, dependency_task_ids
from darwin.core.belief import (
    node_ids_by_type,
    render_belief_snapshot,
    render_critical_facts,
    render_new_discoveries,
)
from darwin.data_model import (
    normalize_dkg_state, PipelineState, EndpointInfo,
    OrchestratorPhase, TaskResult, VulnerabilityHypothesis, ExploitationPlan,
)
from darwin.dkg import DKG
from darwin.dpm import DefensePerceptionModule, DefenseStateVector
from darwin.dave import DAVE, ExploitAttempt, parse_tool_stdout
from darwin.tools.mcp_client import MCPClientPool, load_mcp_config
from darwin.tools.mcp_gateway import ToolResult
from darwin.tools.recon_server import create_recon_gateway, parse_response
from darwin.tools.attack_server import create_attack_gateway
from darwin.utils.http_client import HTTPClient, ProbeClient, HTTPResponse
from darwin.utils.llm import LLMSession
from darwin.utils.phase_logger import PhaseLogger
from darwin.utils.thought_logger import ThoughtLogger


# -- System Prompts (imported from darwin.prompts) --------------------------
from darwin.prompts.orchestrator import (
    SYSTEM_PROMPT_ORCHESTRATOR_UNIFIED,
    SYSTEM_PROMPT_ANALYZE,
    SYSTEM_PROMPT_LOGIN,
    SYSTEM_PROMPT_BYPASS,
)
from darwin.prompts.planner import SYSTEM_PROMPT_PLANNER
from darwin.prompts.evaluator import SYSTEM_PROMPT_EVALUATOR
from darwin.prompts.research import SYSTEM_PROMPT_RESEARCH


from darwin.orchestration.context import CoordinatorContext

class ReconCoordinator(CoordinatorContext):
    async def _bootstrap_scan(self, target_url: str, port_range: str | None = None) -> None:
        """Minimal bootstrap: nmap port scan only. LLM drives all further recon.

        Records discovered ports as Host/Service nodes in DKG.
        Marks SSH ports as skip_exploit. Detects AD domain ports.
        Does NOT probe HTTP services — the LLM decides which ports to probe.

        Args:
            port_range: Optional nmap port range (e.g. "8080-8090,3306").
                        When set, scans only those ports. Full scan otherwise.
        """
        self.phase = OrchestratorPhase.BOOTSTRAP
        from urllib.parse import urlparse as _up

        # Normalize bare host:port URLs (e.g. "localhost:10205") so urlparse
        # correctly extracts hostname and port. Without this, urlparse would
        # treat "localhost" as the scheme and "10205" as the path.
        normalized_url = target_url
        if "://" not in target_url:
            normalized_url = f"http://{target_url}"

        parsed = _up(normalized_url)
        host = parsed.hostname or target_url
        self.target_host = host

        self._task_log_event("info", "bootstrap_nmap", host=host, port_range=port_range)
        # Cloud/K8s discovery is deliberately deferred until the base scan
        # produces a deterministic environment signal.
        k8s_discovery_task = None

        # Always include the target URL's port in the scan range
        target_port = parsed.port or (443 if parsed.scheme == "https" else 80)
        if port_range:
            ports = f"{target_port},{port_range}"
            nmap_result = await self._call_tool("nmap_port_range", {
                "target": host, "ports": ports,
            })
        else:
            nmap_result = await self._call_tool("nmap_full_scan", {"target": host})

        discovered_ports: list[dict] = []
        if nmap_result.success:
            discovered_ports = nmap_result.parsed_output.get("open_ports", [])
            log.info("nmap: %d open ports on %s", len(discovered_ports), host)
        else:
            common_ports = [80, 443, 8080, 8443, 3000, 5000]
            default_port = parsed.port or (443 if parsed.scheme == "https" else 80)
            if default_port not in common_ports:
                common_ports.insert(0, default_port)
            discovered_ports = [{"port": p, "state": "unknown", "service": "http"}
                                for p in common_ports]
            log.warning("nmap failed for %s, probing %d common HTTP ports",
                       host, len(common_ports))

        from darwin.environment import classify_environment
        classification = classify_environment(discovered_ports, self.dkg)
        self._scan_classification = classification
        self.dkg.set_scope(
            engagement_id=getattr(self, "engagement_id", ""),
            target_scope=host,
            environment_scope=classification.environment_scope,
        )
        self.dkg.add_node("Analysis", "environment-classification", {
            "phase": "bootstrap",
            "classification": classification.to_dict(),
            "coverage": "complete",
        }, source="scan-classifier")
        self._task_log_event(
            "info", "scan_classified", kind=classification.kind.value,
            provider=classification.provider, signals=classification.signals,
        )
        if classification.cloud_enabled and classification.kind.value in {
            "private_cloud", "hybrid"
        }:
            k8s_discovery_task = asyncio.create_task(self._k8s_cluster_discovery())

        # ── Port blacklist ────────────────────────────────────────────
        # Filter out infrastructure ports (IDE port forwarding, SSH tunnels,
        # debug proxies, etc.) that nmap discovers on localhost but are not
        # part of the target scenario.
        _BOOTSTRAP_PORT_BLACKLIST: set[int] = {
            12149,  # VS Code port forwarding
        }
        _before = len(discovered_ports)
        discovered_ports = [p for p in discovered_ports
                            if p.get("port") not in _BOOTSTRAP_PORT_BLACKLIST]
        if len(discovered_ports) < _before:
            log.info("bootstrap: filtered %d blacklisted port(s), %d remaining",
                     _before - len(discovered_ports), len(discovered_ports))

        # When nmap returns tcpwrapped for all ports (common in Docker
        # port-forwarding setups), detect whether the ports share a
        # consistent offset from known AD service ports.
        # E.g. 10088→88(Kerberos), 10389→389(LDAP), 10139→139(NetBIOS)
        # with an offset of +10000.
        _AD_STD_PORTS = {
            88: "kerberos-sec", 135: "msrpc", 139: "netbios-ssn",
            389: "ldap", 445: "microsoft-ds", 636: "ldaps",
        }
        _tcpwrapped = [p for p in discovered_ports
                       if p.get("service", "") == "tcpwrapped"]
        if len(_tcpwrapped) >= 2:
            _offsets: dict[int, int] = {}
            for _tp in _tcpwrapped:
                for _std in _AD_STD_PORTS:
                    if _tp["port"] > _std:
                        _off = _tp["port"] - _std
                        _offsets[_off] = _offsets.get(_off, 0) + 1
            if _offsets:
                _best_offset = max(_offsets, key=_offsets.get)
                if _offsets[_best_offset] >= 2:
                    for _tp in _tcpwrapped:
                        _std_port = _tp["port"] - _best_offset
                        if _std_port in _AD_STD_PORTS:
                            _tp["service"] = _AD_STD_PORTS[_std_port]
                    log.info("nmap: detected port offset +%d, resolved %d tcpwrapped ports",
                             _best_offset, _offsets[_best_offset])

        for p in discovered_ports:
            host_id = f"host-{host}"
            service_id = f"svc-{host}-{p['port']}"
            self.dkg.add_node("Host", host_id, {
                "ip": host, "is_reachable": True, "is_internal": False,
            })
            self.dkg.add_node("Service", service_id, {
                "port": p["port"], "protocol": "tcp",
                "version": p.get("version", "") or p.get("service", ""),
                "banner": p.get("service", ""),
                "service_name": p.get("service", ""),  # nmap service name for CTEG filtering
            })
            self.dkg.add_edge(host_id, service_id, "host_has_service",
                              source="bootstrap-nmap", evidence=f"open tcp/{p['port']}")

        # AD detection: if banner scan identified AD-related services,
        # create a Domain node to enable multi-agent mode.
        _AD_PORTS = {445, 389, 636, 3268, 3269}
        _AD_SVC_NAMES = {"ldap", "ldaps", "kerberos", "kerberos-sec",
                          "microsoft-ds", "netbios-ssn", "msrpc"}
        _has_ad = any(p["port"] in _AD_PORTS for p in discovered_ports)
        _has_ad = _has_ad or any(
            (p.get("service", "") or "").lower() in _AD_SVC_NAMES
            for p in discovered_ports
        )
        if _has_ad:
            self.dkg.add_node("Domain", f"domain-{host}", {
                "name": host, "dc_ip": host, "detected_by": "port_scan",
            })

        # SSH: always available for exploitation (LLM can brute-force or use provided creds)
        _has_ssh_creds = bool(self._provided_username and self._provided_password)
        for p in discovered_ports:
            if p["port"] in {22}:
                self.dkg.add_node("Service", f"svc-{host}-{p['port']}", {
                    "port": p["port"], "protocol": "tcp",
                    "version": p.get("version", "") or p.get("service", ""),
                    "banner": p.get("service", ""),
                    "skip_exploit": False,
                })

        # Register SSH credentials in DKG when provided, and test connection
        if _has_ssh_creds:
            self.dkg.add_node("Credential", f"cred-ssh-{host}", {
                "username": self._provided_username,
                "password": self._provided_password,
                "source_host": host,
                "cred_type": "ssh",
                "source": "user_provided",
            })
            # Test SSH connection to verify credentials work
            try:
                ssh_result = await self._call_tool("ssh_exec", {
                    "host": host, "username": self._provided_username,
                    "password": self._provided_password,
                    "command": "id && uname -a",
                })
                if ssh_result.success and "uid=" in (ssh_result.stdout or ""):
                    self.dkg.add_node("Session", f"session-ssh-{host}", {
                        "host": host, "user": self._provided_username,
                        "access_level": "user", "shell_type": "ssh",
                        "established_by": "bootstrap-ssh",
                    })
                    self._task_log_event("info", "ssh_session_established",
                        host=host, user=self._provided_username)
            except Exception:
                pass  # SSH test failure is non-fatal

        # ── Auto-try default credentials for database services ────────
        await self._try_db_default_credentials(host, discovered_ports)

        # Store provided credentials for DB ports too (not just SSH)
        _DB_PORT_PROTO_LOCAL = {3306: "mysql", 5432: "postgresql", 6379: "redis",
                                1433: "mssql", 1521: "oracle", 27017: "mongodb"}
        if self._provided_username and self._provided_password:
            for p in discovered_ports:
                if p["port"] in _DB_PORT_PROTO_LOCAL:
                    proto = _DB_PORT_PROTO_LOCAL[p["port"]]
                    self.dkg.add_node("Credential", f"cred-{proto}-{host}-{p['port']}", {
                        "username": self._provided_username,
                        "password": self._provided_password,
                        "source_host": host,
                        "cred_type": proto,
                        "port": p["port"],
                        "source": "user_provided",
                    })

        # ── Non-HTTP service classification ─────────────────────────
        # Map known ports to protocol types for database and cloud services.
        # Creates Endpoint nodes so the LLM knows these services are reachable
        # and can choose appropriate tools (mysql_query, redis_cmd, kubectl_*, etc.)
        _DB_PORT_PROTO = {
            3306: "mysql", 5432: "postgresql", 6379: "redis",
            1433: "mssql", 1521: "oracle", 27017: "mongodb",
        }
        _K8S_PORTS = {6443, 10250, 10255}
        _K8S_PROTO = "kubernetes"

        for p in discovered_ports:
            port = p["port"]
            if port in _DB_PORT_PROTO:
                proto = _DB_PORT_PROTO[port]
                endpoint_id = f"endpoint-{host}-{port}-{proto}"
                self.dkg.add_node("Endpoint", endpoint_id, {
                    "url": f"{proto}://{host}:{port}",
                    "method": proto, "params": proto,
                    "proto": proto,
                    "discovered_by": "bootstrap-nmap",
                })
                self.dkg.add_edge(f"host-{host}", endpoint_id, "host_has_endpoint",
                                  source="bootstrap-nmap", evidence=f"{proto} endpoint")
            elif port in _K8S_PORTS:
                endpoint_id = f"endpoint-{host}-{port}-k8s"
                self.dkg.add_node("Endpoint", endpoint_id, {
                    "url": f"https://{host}:{port}",
                    "method": "GET", "params": _K8S_PROTO,
                    "proto": _K8S_PROTO,
                    "discovered_by": "bootstrap-nmap",
                })

        # ── Identify unknown services via API probing ────────────
        # nmap cannot fingerprint etcd (0 entries in service-probes).
        # Two-phase identification: (1) openssl CN for TLS services,
        # (2) HTTP GET to /version for plain-HTTP API services.
        #
        # Known API fingerprints — add new services here as needed.
        # Each entry: (path, response_substring, service_name, proto)
        # API fingerprints: (path, needle, service_name, proto, method, post_body)
        # method and post_body are optional — defaults to GET with no body.
        _API_FINGERPRINTS: list[tuple] = [
            ("/version", '"etcdserver"', "etcd", "etcd", "GET", ""),
            ("/version", '"etcdcluster"', "etcd", "etcd", "GET", ""),
            ("/health", '{"health":"true"}', "etcd", "etcd", "GET", ""),
            # K8s admission webhook: POST /validate with minimal AdmissionReview.
            # A response (even an error) means this is a K8s admission controller
            # — pure TLS services or generic HTTPS servers return nothing or 404.
            ("/validate", "admission", "kubernetes-admission",
             "kubernetes", "POST",
             '{"apiVersion":"admission.k8s.io/v1","kind":"AdmissionReview","request":{"uid":"probe"}}'),
            # S3-compatible object storage API probes.
            # MinIO and other S3-compatible services expose REST paths.
            ("/minio/webrpc", "minio", "minio-s3", "s3", "GET", ""),
            ("/bucket", '"objects"', "s3-api", "s3", "GET", ""),
            ("/v1/objects", '"objects"', "s3-api", "s3", "GET", ""),
        ]

        for p in discovered_ports:
            _svc = (p.get("service", "") or "").lower()
            if "unknown" not in _svc and "tcpwrapped" not in _svc:
                continue
            _port = p["port"]
            _identified = False

            # Phase 1: TLS cert field extraction (works for HTTPS services)
            # Extracts CN, O, OU from the subject line and Subject
            # Alternative Names.  Matches against a broader keyword set
            # than just etcd/k8s — ingress-nginx admission controllers
            # use minimal test certs (O=nil2) but other deployments may
            # have identifiable fields.
            try:
                proc = await asyncio.create_subprocess_shell(
                    f"echo '' | openssl s_client -connect {host}:{_port} "
                    f"-servername {host} 2>&1",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=8)
                out = stdout.decode("utf-8", errors="replace")
                # Extract all cert identity: CN, O, OU, and the full subject line
                cn_match = re.search(r"\bCN\s*=\s*(\S+)", out)
                cn = cn_match.group(1) if cn_match else ""
                o_match = re.search(r"\bO\s*=\s*(\S+)", out)
                org = o_match.group(1) if o_match else ""
                # Subject line for broader matching
                subj_match = re.search(r"subject\s*=\s*(.+?)(?:\n|$)", out)
                subj = subj_match.group(1) if subj_match else ""
                _cert_text = f"{cn} {org} {subj}".lower()
                _name = ""
                if "etcd" in _cert_text:
                    _name = "etcd"
                elif any(kw in _cert_text for kw in ("k8s", "kubernetes")):
                    _name = "kubernetes"
                elif any(kw in _cert_text for kw in ("ingress", "nginx")):
                    _name = "ingress-nginx"
                if _name:
                    self.dkg.add_node("Service",
                        f"svc-{host}-{_port}", {
                            "port": _port, "protocol": "tcp",
                            "version": _name, "service_name": _name,
                            "banner": f"CN={cn}",
                    })
                    self.dkg.add_node("Endpoint",
                        f"endpoint-{host}-{_port}-{_name}", {
                            "url": f"https://{host}:{_port}",
                            "method": "GET", "params": "",
                            "proto": _name,
                            "discovered_by": "bootstrap-openssl",
                    })
                    log.info("openssl s_client cert=%s → identified as %s on port %d",
                             cn, _name, _port)
                    _identified = True
            except Exception:
                pass

            # Phase 2: HTTP API probe for unknown services (both HTTP
            # and HTTPS — tries HTTPS first for TLS ports, HTTP fallback).
            # Uses GET by default; POST with JSON body for endpoints
            # like K8s admission webhooks that only respond to POST.
            if not _identified:
                for _path, _needle, _svc_name, _proto, _method, _post_body in _API_FINGERPRINTS:
                    try:
                        _method_flag = "-X POST" if _method == "POST" else ""
                        _body_flag = f"-H 'Content-Type: application/json' -d '{_post_body}'" if _post_body else ""
                        _url = f"https://{host}:{_port}{_path}"
                        proc = await asyncio.create_subprocess_shell(
                            f"curl -sk --connect-timeout 3 {_method_flag} {_body_flag} '{_url}' 2>&1",
                            stdout=asyncio.subprocess.PIPE,
                            stderr=asyncio.subprocess.PIPE,
                        )
                        stdout, _ = await asyncio.wait_for(
                            proc.communicate(), timeout=5)
                        _body = stdout.decode("utf-8", errors="replace")
                        # POST probes match on HTTP success (server responded)
                        # rather than body content — admission webhooks return
                        # 500 with empty body for invalid AdmissionReviews.
                        _match = (proc.returncode == 0) if _method == "POST" else (_needle in _body)
                        if _match:
                            self.dkg.add_node("Service",
                                f"svc-{host}-{_port}", {
                                    "port": _port, "protocol": "tcp",
                                    "version": _svc_name,
                                    "service_name": _svc_name,
                                    "banner": _body[:200],
                            })
                            self.dkg.add_node("Endpoint",
                                f"endpoint-{host}-{_port}-{_proto}", {
                                    "url": f"https://{host}:{_port}",
                                    "method": "GET", "params": "",
                                    "proto": _proto,
                                    "discovered_by": "bootstrap-api-probe",
                            })
                            log.info("API probe %s → identified as %s on port %d",
                                     _path, _svc_name, _port)
                            _identified = True
                            break
                    except Exception:
                        continue

        # Probe HTTP ports discovered by nmap (parallel)
        # Exclude SSH, AD, and DB ports (not HTTP)
        _NON_HTTP_PORTS = {"22", "445", "389", "636", "3268", "3269",
                           "3306", "5432", "6379", "1433", "1521", "27017"}
        # Also exclude by service name to catch non-standard ports
        _NON_HTTP_SVC_NAMES = {"ssh", "redis", "mysql", "mariadb", "postgresql",
                               "mssql", "oracle", "mongodb", "memcached",
                               "ldap", "kerberos", "smb", "rdp", "vnc"}
        http_ports = []
        for p in discovered_ports:
            p_str = str(p.get("port"))
            if p_str in _NON_HTTP_PORTS:
                continue
            svc = (p.get("service", "") or p.get("version", "")).lower()
            if any(name in svc for name in _NON_HTTP_SVC_NAMES):
                continue
            http_ports.append(p)

        async def _probe_one_port(port: int) -> tuple:
            """Probe a single HTTP port, return (url, stdout, http_status, technologies, forms, api_paths)."""
            scheme = "https" if port in {443, 8443} else "http"
            url = f"{scheme}://{host}:{port}"
            is_tls = scheme == "https"
            try:
                curl_result = await self._call_tool("curl_get",
                    {"url": url, "follow_redirects": True,
                     "insecure": True if is_tls else False})
                if not curl_result.success and is_tls:
                    url = f"http://{host}:{port}"
                    curl_result = await self._call_tool("curl_get",
                        {"url": url, "follow_redirects": True})
                if not curl_result.success:
                    return (url, "", 0, [], [], [])
                stdout = getattr(curl_result, "stdout", "")
                resp_len = len(stdout)
                http_status = 200
                first_line = stdout.split("\n")[0] if stdout else ""
                if first_line.startswith("HTTP/"):
                    parts = first_line.split()
                    if len(parts) >= 2 and parts[1].isdigit():
                        http_status = int(parts[1])
                # Parse response
                forms = []
                api_paths = []
                parse_sample = stdout[:50000]
                if resp_len > 100000:
                    parse_sample += stdout[-10000:]
                try:
                    parse_result = await self._call_tool("response_parse",
                        {"content": parse_sample})
                    if parse_result.success:
                        parsed = getattr(parse_result, "parsed_output", {})
                        forms = parsed.get("forms", [])
                except Exception:
                    pass
                # Extract API paths from large JS bundles
                if resp_len > 100000:
                    import re as _re
                    for pattern in [r'["\x27](/api/[^"\x27]{2,60})["\x27]',
                                   r'fetch\(["\x27](/[^"\x27]{2,60})["\x27]\)']:
                        for m in _re.finditer(pattern, stdout[:200000]):
                            path = m.group(1)
                            if not path.endswith(('.js', '.css', '.png', '.ico')):
                                api_paths.append(path)
                # whatweb
                technologies = []
                try:
                    ww = await self._call_tool("whatweb_scan",
                        {"target_url": url})
                    if ww.success:
                        technologies = getattr(ww, "parsed_output", {}).get("technologies", [])
                except Exception:
                    pass
                return (url, stdout, http_status, technologies, forms, api_paths)
            except Exception:
                return (url, "", 0, [], [], [])

        # Run all port probes in parallel
        probe_tasks = [asyncio.create_task(_probe_one_port(p["port"])) for p in http_ports]
        probe_results = await asyncio.gather(*probe_tasks, return_exceptions=True)

        # Collect API paths to probe in a second pass
        api_endpoints_to_probe: list[str] = []
        for result in probe_results:
            if isinstance(result, Exception):
                continue
            url, stdout, http_status, technologies, forms, api_paths = result
            if not stdout:
                continue
            resp_len = len(stdout)
            root_endpoint_id = f"ep-{url}"
            self.dkg.add_node("Endpoint", root_endpoint_id, {
                "url": url, "method": "GET", "params": "",
                "sample_status": http_status,
                "sample_response": stdout[:5000],
                "response_size": resp_len,
                "discovered_by": "bootstrap",
            })
            self.dkg.add_edge(f"host-{host}", root_endpoint_id, "host_has_endpoint",
                              source="bootstrap", evidence=url)
            for form in forms:
                action = form.get("action", "")
                form_url = (action if action.startswith("http")
                            else f"{url.rstrip('/')}/{action.lstrip('/')}")
                params = ",".join(i.get("name", "") for i in form.get("inputs", []))
                form_endpoint_id = f"ep-form-{form_url[:40]}"
                self.dkg.add_node("Endpoint", form_endpoint_id, {
                    "url": form_url, "method": form.get("method", "POST"),
                    "params": params, "body_format": "form",
                    "discovered_by": "bootstrap",
                })
                self.dkg.add_edge(f"host-{host}", form_endpoint_id, "host_has_endpoint",
                                  source="bootstrap", evidence="html form")
            # ── When root is near-empty, probe common paths for real content ──
            if resp_len < 500 and len(discovered_ports) <= 3:
                _WEB_PATHS = ["/", "/index.html", "/home", "/login", "/admin",
                              "/api", "/app", "/status", "/health", "/metrics",
                              "/fetch", "/upload", "/dashboard", "/console",
                              "/files", "/objects", "/buckets"]
                async def _probe_web_path(path: str):
                    try:
                        r = await self._call_tool("curl_get",
                            {"url": f"{url.rstrip('/')}{path}", "follow_redirects": True})
                        if r.success:
                            out = getattr(r, "stdout", "")
                            if len(out) > 200:
                                path_endpoint_id = f"ep-path-{path.replace('/','-')[:30]}"
                                self.dkg.add_node("Endpoint", path_endpoint_id, {
                                    "url": f"{url.rstrip('/')}{path}", "method": "GET",
                                    "params": "",
                                    "sample_status": 200, "sample_response": out[:5000],
                                    "response_size": len(out),
                                    "discovered_by": "bootstrap-path-probe",
                                })
                                self.dkg.add_edge(f"host-{host}", path_endpoint_id, "host_has_endpoint",
                                                  source="bootstrap-path-probe", evidence=path)
                    except Exception:
                        pass
                path_tasks = [asyncio.create_task(_probe_web_path(p))
                              for p in _WEB_PATHS]
                await asyncio.gather(*path_tasks, return_exceptions=True)

            if technologies:
                log.info("bootstrap whatweb: %s → %s", url, technologies)
                # Enrich the existing nmap Service node with whatweb
                # fingerprint data instead of creating fake tech-* nodes.
                from urllib.parse import urlparse as _up2
                _p = _up2(url)
                _svc_port = _p.port or (443 if _p.scheme == "https" else 80)
                _svc_id = f"svc-{host}-{_svc_port}"
                _existing = self.dkg.get_node(_svc_id)
                if _existing:
                    self.dkg.update_node(_svc_id, {
                        "fingerprint": technologies,
                    })
            for path in api_paths[:20]:
                api_endpoints_to_probe.append(f"{url.rstrip('/')}{path}")

        # Second pass: probe discovered API paths (also parallel)
        probed_apis: set[str] = set()
        async def _probe_api_path(ep_url: str):
            if ep_url in probed_apis:
                return
            probed_apis.add(ep_url)
            try:
                r = await self._call_tool("curl_get",
                    {"url": ep_url, "follow_redirects": True})
                if r.success:
                    out = getattr(r, "stdout", "")
                    st = 200
                    fl = out.split("\n")[0] if out else ""
                    if fl.startswith("HTTP/"):
                        pts = fl.split()
                        if len(pts) >= 2 and pts[1].isdigit():
                            st = int(pts[1])
                    api_endpoint_id = f"ep-api-{ep_url[:50]}"
                    self.dkg.add_node("Endpoint", api_endpoint_id, {
                        "url": ep_url, "method": "GET", "params": "",
                        "sample_status": st, "sample_response": out[:5000],
                        "response_size": len(out),
                        "discovered_by": "bootstrap-api-probe",
                    })
                    self.dkg.add_edge(f"host-{host}", api_endpoint_id, "host_has_endpoint",
                                      source="bootstrap-api-probe", evidence=ep_url)
            except Exception:
                pass

        if api_endpoints_to_probe:
            api_tasks = [asyncio.create_task(_probe_api_path(u))
                         for u in api_endpoints_to_probe[:30]]
            await asyncio.gather(*api_tasks, return_exceptions=True)

        # Wait for K8S cluster discovery (launched in parallel with nmap)
        if k8s_discovery_task is not None:
            try:
                await k8s_discovery_task
            except Exception as exc:
                self._task_log_event("warning", "discovery_failure", domain="k8s", error=str(exc))
                self.dkg.update_node("environment-classification", {
                    "coverage": "incomplete", "discovery_failure": "k8s",
                })
                self.dkg.add_edge(f"host-{host}", endpoint_id, "host_has_endpoint",
                                  source="bootstrap-nmap", evidence=f"k8s tcp/{port}")

        # CTAGE: Cloud Topology & Attack Graph Engine — extend K8s discovery
        # with RBAC mapping, pod security analysis, and IAM enumeration.
        try:
            from darwin.cloud_topology import discover_cloud_topology
            if classification.cloud_enabled:
                self._cloud_topology = await discover_cloud_topology(
                    self.dkg, tool_port=self._call_tool
                )
            else:
                self._cloud_topology = None
            log.info("CTAGE: cloud topology mapped — %d pods, %d RBAC bindings, %d IAM roles",
                     len(self._cloud_topology.pods) if self._cloud_topology else 0,
                     len(self._cloud_topology.rbac_bindings) if self._cloud_topology else 0,
                     len(self._cloud_topology.iam_roles) if self._cloud_topology else 0)
            if self._cloud_topology and self._cloud_topology.high_risk_pods:
                log.info("CTAGE: %d high-risk pods identified", len(self._cloud_topology.high_risk_pods))
                for profile in self._cloud_topology.high_risk_pods[:5]:
                    log.info("  CTAGE high-risk: %s/%s risk=%.2f vectors=%s",
                             profile.namespace, profile.pod_name,
                             profile.risk_score, profile.escape_vectors)
        except Exception as e:
            self._task_log_event("warning", "discovery_failure", domain="cloud", error=str(e))
            self.dkg.update_node("environment-classification", {
                "coverage": "incomplete", "discovery_failure": "cloud",
            })
            log.debug("CTAGE: cloud topology mapping skipped (%s)", e)

        self._discovered_ports = discovered_ports

        # ── Bootstrap summary ─────────────────────────────────────────
        services = self.dkg.query_nodes("Service")
        hosts = self.dkg.query_nodes("Host")
        domains = self.dkg.query_nodes("Domain")
        db_ports = {3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis",
                    1433: "MSSQL", 1521: "Oracle", 27017: "MongoDB"}
        db_found = []
        for s in services:
            p = s.get("port")
            if p in db_ports:
                db_found.append(f"port {p} ({db_ports[p]})")

        print(f"\n[BOOTSTRAP] {len(hosts)} host(s), {len(services)} service(s)")
        for s in services:
            ver = s.get("version", "") or s.get("banner", "")
            print(f"  port {s.get('port'):>5}/{s.get('protocol','tcp'):<6} {ver[:55]}")
        if db_found:
            print(f"  Non-HTTP services: {', '.join(db_found)}")
        if domains:
            print(f"  Domain detected: {domains[0].get('name', '?')} (ports 389/445/636)")
        ssh_ok = any(s.get("port") == 22 and not s.get("skip_exploit", True)
                     for s in services)
        if ssh_ok:
            print(f"  SSH: credentials active")
        if self._provided_username and not ssh_ok:
            db_creds = [c for c in self.dkg.query_nodes("Credential")
                       if c.get("source") == "user_provided" and c.get("cred_type") != "ssh"]
            if db_creds:
                cred_parts = [f"{c.get('cred_type','?')}:{c.get('port','?')}" for c in db_creds]
                print(f"  DB credentials provided for: {', '.join(cred_parts)}")

        self.step_count += 1

    # ── K8s Cluster Discovery (runs in parallel with nmap) ─────────

    async def _k8s_cluster_discovery(self) -> None:
        """Discover local K8S cluster topology independently of nmap.

        Runs kubectl commands to enumerate nodes, pods, services, and
        namespaces. Populates DKG with Host/Service/Endpoint/Analysis
        nodes for discovered cluster resources. This is critical for
        KIND-based scenarios where only the API server port is mapped
        to localhost and the rest of the cluster is invisible to nmap.

        Runs unconditionally — if kubectl is unavailable or no cluster
        exists, fails silently in <2s. All commands have 8s timeouts.
        """
        import json as _json

        async def _discovery(command: str):
            """Run an allow-listed discovery command through the tool port."""
            return await self._call_tool("cloud_discovery_command", {"command": command})

        # ── Step 1: Verify kubectl is available and a cluster is reachable ──
        try:
            result = await _discovery("kubectl cluster-info")
            out = result.stdout or ""
            if not result.success or "is running at" not in out:
                return  # No K8S cluster available or kubectl not installed
            api_match = re.search(r"is running at (https?://\S+)", out)
            api_url = api_match.group(1) if api_match else ""
            log.info("K8S cluster discovery: cluster reachable at %s", api_url)
        except Exception:
            return

        # ── Step 2: Enumerate nodes (name, IP, labels, taints) ──
        nodes_data: dict = {}
        try:
            result = await _discovery("kubectl get nodes -o json")
            out = result.stdout or ""
            if result.success:
                nodes_data = _json.loads(out) if out.strip().startswith("{") else {}
        except Exception:
            pass

        k8s_nodes: list[dict] = []
        for item in nodes_data.get("items", []):
            meta = item.get("metadata", {})
            status = item.get("status", {})
            node_info: dict = {
                "name": meta.get("name", ""),
                "labels": meta.get("labels", {}),
                "taints": [],
                "is_control_plane": False,
                "internal_ip": "",
            }
            # Extract node IP
            for addr in status.get("addresses", []):
                if addr.get("type") == "InternalIP":
                    node_info["internal_ip"] = addr.get("address", "")
                    break
            # Extract taints
            for taint in item.get("spec", {}).get("taints", []):
                node_info["taints"].append(
                    f"{taint.get('key','')}={taint.get('value','')}:{taint.get('effect','')}"
                )
            # Detect control-plane role
            for label in node_info["labels"]:
                if "control-plane" in label or label == "node-role.kubernetes.io/master":
                    node_info["is_control_plane"] = True
            k8s_nodes.append(node_info)

        # ── Step 3: Enumerate pods (name, namespace, node, labels, status) ──
        pods_data: dict = {}
        try:
            result = await _discovery("kubectl get pods -A -o json")
            out = result.stdout or ""
            if result.success:
                pods_data = _json.loads(out) if out.strip().startswith("{") else {}
        except Exception:
            pass

        k8s_pods: list[dict] = []
        for item in pods_data.get("items", []):
            meta = item.get("metadata", {})
            spec = item.get("spec", {})
            k8s_pods.append({
                "name": meta.get("name", ""),
                "namespace": meta.get("namespace", ""),
                "node_name": spec.get("nodeName", ""),
                "labels": meta.get("labels", {}),
                "phase": item.get("status", {}).get("phase", "Unknown"),
                "containers": [
                    c.get("image", "") for c in spec.get("containers", [])
                ],
            })

        # ── Step 4: Enumerate services (name, namespace, clusterIP, ports) ──
        svcs_data: dict = {}
        try:
            result = await _discovery("kubectl get svc -A -o json")
            out = result.stdout or ""
            if result.success:
                svcs_data = _json.loads(out) if out.strip().startswith("{") else {}
        except Exception:
            pass

        k8s_svcs: list[dict] = []
        for item in svcs_data.get("items", []):
            meta = item.get("metadata", {})
            spec = item.get("spec", {})
            ports = spec.get("ports", [])
            k8s_svcs.append({
                "name": meta.get("name", ""),
                "namespace": meta.get("namespace", ""),
                "cluster_ip": spec.get("clusterIP", ""),
                "ports": [{"port": p.get("port", 0), "protocol": p.get("protocol", "TCP"),
                           "target_port": p.get("targetPort", "")} for p in ports],
                "selector": spec.get("selector", {}),
                "type": spec.get("type", "ClusterIP"),
            })

        # ── Step 5: Enumerate namespaces ──
        ns_list: list[str] = []
        try:
            result = await _discovery("kubectl get namespaces -o json")
            out = result.stdout or ""
            if result.success and out.strip().startswith("{"):
                ns_data = _json.loads(out)
                ns_list = [i.get("metadata", {}).get("name", "")
                           for i in ns_data.get("items", [])]
        except Exception:
            pass

        # ── Step 6: Check current permissions ──
        permissions: list[str] = []
        try:
            result = await _discovery("kubectl auth can-i --list -A")
            out = result.stdout or ""
            if result.success:
                for line in out.split("\n"):
                    line = line.strip()
                    if line and not line.startswith("Resources") and "yes" in line.lower():
                        permissions.append(line)
        except Exception:
            pass

        # ── Write DKG nodes ───────────────────────────────────────────

        # Host nodes for each K8S node
        for node in k8s_nodes:
            node_id = f"host-k8s-{node['name']}"
            self.dkg.add_node("Host", node_id, {
                "ip": node["internal_ip"] or node["name"],
                "is_reachable": True,
                "is_internal": True,
                "k8s_node_name": node["name"],
                "k8s_node_labels": node["labels"],
                "k8s_node_taints": node["taints"],
                "is_control_plane": node["is_control_plane"],
                "discovered_by": "k8s-cluster-discovery",
            })

        # Endpoint for the K8S API server
        if api_url:
            self.dkg.add_node("Endpoint", f"endpoint-k8s-api", {
                "url": api_url,
                "method": "GET",
                "params": "",
                "proto": "kubernetes",
                "discovered_by": "k8s-cluster-discovery",
            })

        # Service nodes for each K8S service (ClusterIP only)
        for svc in k8s_svcs:
            for port_info in svc["ports"]:
                svc_id = f"svc-k8s-{svc['namespace']}-{svc['name']}-{port_info['port']}"
                self.dkg.add_node("Service", svc_id, {
                    "port": port_info["port"],
                    "protocol": port_info["protocol"].lower(),
                    "service_name": f"k8s-{svc['name']}",
                    "version": f"ClusterIP {svc['cluster_ip']}:{port_info['port']}",
                    "banner": f"K8s Service {svc['name']}.{svc['namespace']}.svc.cluster.local",
                    "k8s_namespace": svc["namespace"],
                    "k8s_cluster_ip": svc["cluster_ip"],
                    "k8s_selector": svc["selector"],
                    "discovered_by": "k8s-cluster-discovery",
                })

        # Analysis node with cluster summary
        analysis_parts: list[str] = []
        analysis_parts.append(f"K8S cluster discovered with {len(k8s_nodes)} node(s)")
        for node in k8s_nodes:
            role = "control-plane" if node["is_control_plane"] else "worker"
            label_str = ", ".join(
                f"{k}={v}" for k, v in node["labels"].items()
                if k not in ("kubernetes.io/hostname", "kubernetes.io/os",
                             "kubernetes.io/arch", "beta.kubernetes.io/os",
                             "beta.kubernetes.io/arch", "node.kubernetes.io/instance-type")
            )
            analysis_parts.append(
                f"  Node {node['name']} ({role}): IP={node['internal_ip']}, labels={{ {label_str} }}"
            )
            if node["taints"]:
                analysis_parts.append(f"    taints: {', '.join(node['taints'])}")

        if k8s_pods:
            analysis_parts.append(f"{len(k8s_pods)} pod(s) running:")
            for pod in k8s_pods[:20]:
                analysis_parts.append(
                    f"  {pod['namespace']}/{pod['name']} [{pod['phase']}] "
                    f"on {pod['node_name']} images={pod['containers']}"
                )

        if k8s_svcs:
            analysis_parts.append(f"{len(k8s_svcs)} service(s):")
            for svc in k8s_svcs[:20]:
                port_str = ", ".join(
                    f"{p['port']}/{p['protocol']}" for p in svc["ports"]
                )
                analysis_parts.append(
                    f"  {svc['namespace']}/{svc['name']} "
                    f"type={svc['type']} clusterIP={svc['cluster_ip']} ports={port_str}"
                )

        if ns_list:
            analysis_parts.append(f"Namespaces: {', '.join(ns_list)}")

        if permissions:
            analysis_parts.append(f"Current permissions ({len(permissions)} allowed):")
            for perm in permissions[:20]:
                analysis_parts.append(f"  {perm}")

        if analysis_parts:
            self.dkg.add_node("Analysis", "analysis-k8s-cluster", {
                "content": "\n".join(analysis_parts),
                "source": "k8s-cluster-discovery",
                "phase": "analyze",
            })

        total_nodes = len(k8s_nodes)
        total_pods = len(k8s_pods)
        total_svcs = len(k8s_svcs)
        log.info(
            "K8S cluster discovery: %d nodes, %d pods, %d services, %d namespaces",
            total_nodes, total_pods, total_svcs, len(ns_list),
        )
        print(f"\n[K8S DISCOVERY] {total_nodes} node(s), {total_pods} pod(s), "
              f"{total_svcs} service(s), {len(ns_list)} namespace(s)")

    # ── Deep Recon (after bootstrap, before service research) ───────

    async def _deep_recon(self) -> None:
        """Deep reconnaissance on discovered HTTP endpoints.

        Runs after bootstrap (which only probes root URLs) and before
        service_research/analyze. Uses dirb, nikto, and form_extract to
        discover the full attack surface: directories, known vulns, forms.
        """
        endpoints = self.dkg.query_nodes("Endpoint")
        if not endpoints:
            return
        log.info("_deep_recon: scanning %d endpoints", len(endpoints))

        async def _probe_one(endpoint: dict):
            url = endpoint.get("url", "")
            ep_id = endpoint.get("id", "") or f"ep-{url[:50]}"
            if not url or not url.startswith("http"):
                return
            resp_len = endpoint.get("response_size", 0)
            sample = endpoint.get("sample_response", "")
            if "403 Forbidden" in sample or "connection refused" in sample.lower():
                return

            scanned = False

            # Fork based on response type (from bootstrap response_parse)
            if resp_len > 1000000:
                # SPA / large JS bundle — dirb/nikto useless.
                # Probe API paths already extracted by bootstrap.
                api_eps = [e for e in self.dkg.query_nodes("Endpoint")
                           if e.get("discovered_by", "").startswith("bootstrap-api-")
                           and e.get("url", "").startswith(url)]
                for api_ep in api_eps[:15]:
                    api_url = api_ep.get("url", "")
                    try:
                        r = await self._call_tool("curl_get",
                            {"url": api_url, "follow_redirects": True})
                        if r.success:
                            out = getattr(r, "stdout", "")
                            st = 200
                            fl = out.split("\n")[0] if out else ""
                            if fl.startswith("HTTP/"):
                                pts = fl.split()
                                if len(pts) >= 2 and pts[1].isdigit():
                                    st = int(pts[1])
                            self.dkg.add_node("Endpoint", f"ep-probe-{api_url[:50]}", {
                                "url": api_url, "method": "GET", "params": "",
                                "sample_status": st, "sample_response": out[:5000],
                                "response_size": len(out),
                                "discovered_by": "deep-recon-api-probe",
                            })
                            if 0 < len(out) < 100000:
                                rp = await self._call_tool("response_parse",
                                    {"content": out[:50000]})
                                if rp.success:
                                    parsed = getattr(rp, "parsed_output", {})
                                    for form in parsed.get("forms", []):
                                        _add_form_endpoint(form, url)
                    except Exception:
                        pass
                scanned = True

            elif resp_len < 500000:
                # Small/medium HTML page — full recon: gobuster + nikto + form_extract
                # Threshold raised from 200K to 500K to cover medium pages (200-500KB)
                # that previously fell into a gap and received no recon at all.
                # Only run expensive tools on primary HTTP endpoints discovered
                # by nmap or bootstrap whatweb. Skip derived/internal endpoints
                # (API probes, path probes, deep recon follow-ups, simulators)
                # that don't have directory structures to brute-force.
                _disc = endpoint.get("discovered_by", "")
                _is_primary = (
                    _disc == "bootstrap-nmap"      # nmap-discovered port
                    or _disc == "bootstrap"         # bootstrap whatweb on primary port
                    or _disc == ""                  # legacy endpoint without tag
                )
                if not _is_primary:
                    log.info("_deep_recon: skipping non-primary endpoint %s (discovered_by=%s)", url, _disc)
                    return  # skip gobuster/nikto/form for derived endpoints
                # Skip gobuster on REST API / JSON endpoints — these don't have
                # directory structures to brute-force. A JSON response means
                # this is a programmatic API, not a directory-browsable web app.
                _sample = endpoint.get("sample_response", "")
                if _sample.strip().startswith("{") or _sample.strip().startswith("["):
                    log.info("_deep_recon: skipping JSON/API endpoint %s", url)
                    return

                # Pre-flight curl check: verify the endpoint is reachable and
                # returns HTML (not JSON/empty) before running gobuster.
                # IMDS/S3 simulators and other non-directory HTTP services
                # timeout gobuster (90s+retry=225s per endpoint).
                try:
                    _pre = await self._call_tool("curl_get", {
                        "url": url, "method": "GET", "timeout": "5",
                    })
                    _pre_stdout = getattr(_pre, "stdout", "") or ""
                    if not _pre.success or not _pre_stdout.strip():
                        log.info("_deep_recon: pre-flight unreachable, skipping gobuster/nikto for %s", url)
                        return
                    if _pre_stdout.strip().startswith("{") or _pre_stdout.strip().startswith("["):
                        log.info("_deep_recon: pre-flight JSON/API, skipping gobuster/nikto for %s", url)
                        return
                    # Non-HTML response detection: plain-text APIs (IMDS,
                    # cloud simulators, etc.) return content without HTML
                    # tags.  gobuster/nikto are directory brute-forcers that
                    # only make sense for HTML web apps.
                    _body = _pre_stdout.strip()
                    _is_html = (
                        _body.startswith("<")
                        or "<!DOCTYPE" in _body[:200]
                        or "</" in _body
                    )
                    if not _is_html and len(_body) < 500:
                        log.info("_deep_recon: pre-flight non-HTML (plain text/API), "
                                 "skipping gobuster/nikto for %s", url)
                        return
                except Exception:
                    # If pre-flight itself fails, skip heavy tools
                    log.info("_deep_recon: pre-flight failed, skipping gobuster/nikto for %s", url)
                    return

                try:
                    bust_result = await self._call_tool("gobuster_dir",
                        {"target_url": url})
                    scanned = True
                    if bust_result.success:
                        paths = getattr(bust_result, "parsed_output", {}).get("discovered_paths", [])
                        for pi in paths[:15]:
                            path = pi.get("path", "")
                            if path:
                                ep_url = f"{url.rstrip('/')}{path}"
                                self.dkg.add_node("Endpoint", f"ep-dirb-{path[:40]}", {
                                    "url": ep_url, "method": "GET", "params": "",
                                    "sample_status": pi.get("code", 200),
                                    "discovered_by": "deep-recon-dirb",
                                })
                except Exception:
                    pass
                try:
                    nikto_result = await self._call_tool("nikto_scan",
                        {"target_url": url})
                    if nikto_result.success:
                        findings = getattr(nikto_result, "stdout", "")
                        if findings and "0 items" not in findings:
                            for line in findings.split("\n")[:10]:
                                line = line.strip()
                                if line and "OSVDB" not in line:
                                    self.dkg.add_node("Vulnerability", f"vuln-nikto-{len(line[:20])}", {
                                        "vuln_type": "XSS", "endpoint": url,
                                        "parameter": "", "severity": "low",
                                        "source": "nikto", "detail": line[:200],
                                    })
                except Exception:
                    pass
                try:
                    form_result = await self._call_tool("form_extract",
                        {"url": url})
                    if form_result.success:
                        parsed = getattr(form_result, "parsed_output", {})
                        for form in parsed.get("forms", []):
                            _add_form_endpoint(form, url)
                except Exception:
                    pass

            elif "json" in sample.lower() or sample.strip().startswith("{"):
                # JSON/API response — curl + response_parse to extract structure
                try:
                    rp = await self._call_tool("response_parse",
                        {"content": sample[:50000]})
                    if rp.success:
                        parsed = getattr(rp, "parsed_output", {})
                        for key in parsed.get("keys", [])[:10]:
                            probe_url = f"{url.rstrip('/')}/{key}"
                            r2 = await self._call_tool("curl_get",
                                {"url": probe_url, "follow_redirects": True})
                            if r2.success:
                                out = getattr(r2, "stdout", "")
                                self.dkg.add_node("Endpoint", f"ep-api-{key[:40]}", {
                                    "url": probe_url, "method": "GET", "params": "",
                                    "sample_status": 200, "sample_response": out[:5000],
                                    "discovered_by": "deep-recon-json-probe",
                                })
                    scanned = True
                except Exception:
                    pass

            else:
                # Medium/large HTML page (500KB-1MB) that isn't JSON/SPA.
                # Too large for full dirb/nikto but still likely has forms and
                # important content.  At minimum: run form_extract.
                try:
                    form_result = await self._call_tool("form_extract",
                        {"url": url})
                    if form_result.success:
                        parsed = getattr(form_result, "parsed_output", {})
                        for form in parsed.get("forms", []):
                            _add_form_endpoint(form, url)
                    scanned = True
                except Exception:
                    pass

            # Mark scanned to prevent redundant agent work
            if scanned:
                self.dkg.add_node("Endpoint", ep_id, {
                    "url": url, "deep_recon_done": True,
                    "discovered_by": "deep-recon",
                })

        def _add_form_endpoint(form: dict, base_url: str):
            action = form.get("action", "")
            form_url = (action if action.startswith("http")
                        else f"{base_url.rstrip('/')}/{action.lstrip('/')}")
            params = ",".join(i.get("name", "") for i in form.get("inputs", []))
            if params:
                self.dkg.add_node("Endpoint", f"ep-form-{form_url[:40]}", {
                    "url": form_url, "method": form.get("method", "POST"),
                    "params": params, "body_format": "form",
                    "discovered_by": "deep-recon-form",
                })

        # CMS entry-point auto-probe (after endpoint scanning, before deep recon)
        _CMS_PATHS = [
            "/wp-admin/", "/wp-login.php", "/wp-content/", "/wp-content/plugins/",
            "/wp-json/wp/v2/", "/administrator/", "/user/login",
            "/api/", "/.env", "/config.php",
        ]
        async def _probe_cms(endpoint: dict):
            url = endpoint.get("url", "")
            if not url or not url.startswith("http"):
                return
            base = url.rstrip("/")
            for path in _CMS_PATHS:
                try:
                    r = await self._call_tool("curl_get",
                        {"url": f"{base}{path}", "follow_redirects": True, "insecure": True})
                    if r.success:
                        out = getattr(r, "stdout", "")
                        st = 200
                        fl = out.split("\n")[0] if out else ""
                        if fl.startswith("HTTP/"):
                            pts = fl.split()
                            if len(pts) >= 2 and pts[1].isdigit():
                                st = int(pts[1])
                        # Only register CMS endpoints that return actual content
                        # (2xx/3xx) or auth-required responses (401/403).
                        # Exclude 400, 404, 405, 5xx — these are error pages, not
                        # real CMS endpoints (e.g. ingress-nginx returns 400 for
                        # unrecognized paths, which looks like a hit but isn't).
                        _is_content = 200 <= st < 400
                        _is_auth_wall = st in (401, 403)
                        if (_is_content or _is_auth_wall) and len(out) > 50:
                            self.dkg.add_node("Endpoint", f"ep-cms-{path.replace('/','-')[:30]}", {
                                "url": f"{base}{path}", "method": "GET", "params": "",
                                "sample_status": st, "sample_response": out[:2000],
                                "response_size": len(out),
                                "discovered_by": "cms-probe",
                            })
                except Exception:
                    pass

        # Run deep recon in parallel across endpoints (max 6 concurrent)
        batch = [ep for ep in endpoints[:8] if ep.get("url","").startswith("http")]
        if batch:
            tasks = [asyncio.create_task(_probe_one(ep)) for ep in batch]
            tasks += [asyncio.create_task(_probe_cms(ep)) for ep in batch]
            await asyncio.gather(*tasks, return_exceptions=True)
        log.info("_deep_recon: complete")

        # ── Deep recon summary ──────────────────────────────────────
        endpoints = self.dkg.query_nodes("Endpoint")
        vulns = self.dkg.query_nodes("Vulnerability")
        dirb_endpoints = [e for e in endpoints if "dirb" in str(e.get("discovered_by", ""))]
        nikto_vulns = [v for v in vulns if "nikto" in str(v.get("source", ""))]
        forms = [e for e in endpoints if e.get("params") and len(str(e.get("params", ""))) > 5]
        print(f"[DEEP RECON] {len(endpoints)} total endpoints")
        if dirb_endpoints:
            print(f"  dirb paths discovered: {len(dirb_endpoints)}")
        if nikto_vulns:
            print(f"  nikto findings: {len(nikto_vulns)}")
        if forms:
            print(f"  forms with parameters: {len(forms)}")
            for f in forms[:4]:
                pstr = str(f.get("params", ""))[:80]
                print(f"    {f.get('url','?')[:60]} params={pstr}")
            if len(forms) > 4:
                print(f"    ... and {len(forms) - 4} more forms")

    async def _detect_defenses(self) -> None:
        """Run DPM defense probes on discovered endpoints and update defense_state.

        Sends filter probes (classes A-E) to up to 6 GET endpoints with params,
        then runs the rule-based DPM detection pipeline (no LLM cost).
        """
        endpoints = self.dkg.query_nodes("Endpoint")
        get_endpoints = [
            e for e in endpoints
            if e.get("url", "").startswith("http") and e.get("method", "GET") == "GET"
            and e.get("params")  # prefer endpoints with parameters
        ][:6]
        if len(get_endpoints) < 3:
            # Fall back to any GET endpoints
            get_endpoints = [
                e for e in endpoints
                if e.get("url", "").startswith("http") and e.get("method", "GET") == "GET"
            ][:6]
        if not get_endpoints:
            print("[DEFENSE] No HTTP endpoints to probe — skipping defense detection "
                  f"({len(endpoints)} non-HTTP endpoints)")
            return

        all_probe_results = []
        all_responses = []
        for ep in get_endpoints:
            url = ep["url"]
            param = (ep.get("params") or ["q"])[0] if ep.get("params") else "q"
            try:
                probe_results = await self.probe_client.send_all_probe_classes(url, param)
                all_probe_results.extend(probe_results)
                all_responses.extend(
                    p.response for p in probe_results if hasattr(p, "response")
                )
            except Exception:
                continue

        if all_probe_results:
            self.defense_state = self.dpm.detect(
                all_probe_results, all_responses, use_llm=False,
            )
            self._task_log_event("info", "defense_detected",
                waf_type=self.defense_state.waf_type,
                defense_category=self.defense_state.defense_category,
                defense_complexity=self.defense_state.defense_complexity,
            )

        # ── Defense summary ─────────────────────────────────────────
        ds = self.defense_state
        if ds.waf_type and ds.waf_type != "unknown":
            print(f"\n[DEFENSE] WAF: {ds.waf_type} | "
                  f"Category: {ds.defense_category} | "
                  f"Complexity: {ds.defense_complexity:.2f}")
        else:
            print(f"\n[DEFENSE] No active WAF detected (complexity: {ds.defense_complexity:.2f})")
        if ds.honeypot_count > 0:
            print(f"  Honeypots detected: {ds.honeypot_count}")
        if ds.cloak_detected:
            print(f"  Cloaking detected: True")

    async def _verify_flag(
        self, flag: str, stdout: str, tc_args: dict, elapsed_ms: int = 0,
        tool_name: str = "",
    ) -> tuple[bool, str]:
        """Verify a flag with full DAVE L1+L4 when HTTP data is available.

        Falls back to verify_basic for non-HTTP tools (sqlmap, ffuf, etc.).
        """
        # Reject flags from local filesystem accesses — "shell_exec find /" or
        # "curl_get file://" searches the DARWIN host, not the target.
        # Flags must come from target interaction (remote host/port).
        if tool_name == "shell_exec":
            cmd = str(tc_args.get("command", "") or "")
            # Detect local filesystem search patterns
            _LOCAL_SEARCH_PATTERNS = [
                r'find\s+/', r'grep\s+-r.*flag', r'cat\s+/tmp/flag',
                r'cat\s+/var/.*flag', r'cat\s+/home/.*flag',
                r'ls\s+-la\s+/tmp/flag', r'locate\s+flag',
                r'strings\s+/', r'grep\s+-rn.*flag.*/(tmp|var|home|etc|root)',
            ]
            import re as _vre
            if any(_vre.search(p, cmd, _vre.IGNORECASE) for p in _LOCAL_SEARCH_PATTERNS):
                return False, f"local filesystem search — flag not from target: {flag[:40]}"
        if tool_name in ("curl_get", "http_post"):
            url = str(tc_args.get("url", "") or "")
            if url.startswith("file://"):
                return False, f"local file read via {tool_name} — flag not from target: {flag[:40]}"

        parsed = parse_tool_stdout(stdout)
        if parsed["status_code"] > 0:
            http_resp = HTTPResponse(
                url=str(tc_args.get("url", "")),
                status_code=parsed["status_code"],
                headers=parsed["headers"],
                body=parsed["body"],
                elapsed_ms=float(elapsed_ms),
            )
            attempt = ExploitAttempt(
                target_url=str(tc_args.get("url", "")),
                vuln_type=str(tc_args.get("tool", "")),
                payload=str(tc_args.get("payload", "")),
                http_response=http_resp,
                tool_stdout=stdout,
            )
            v_result = await self.dave.verify(attempt)
            if v_result.flag_value:
                return True, f"DAVE L1+L4: {v_result.flag_value}"
            return False, f"DAVE: {v_result.summary()}"
        return DAVE.verify_basic(flag, stdout)

    # ── Loop Termination ──────────────────────────────────────────


    # ── Chain Topology Detection ──────────────────────────────────
