"""Bootstrap and reconnaissance functions for DARWIN."""
from __future__ import annotations

import asyncio
import json
import logging
import re
from urllib.parse import urlparse

from darwin.orchestrator import OrchestratorPhase

log = logging.getLogger(__name__)

# Module-level constants — ports and service names that should never
# be probed as HTTP during bootstrap scan.
_NON_HTTP_PORTS: set[str] = {
    "22", "445", "389", "636", "3268", "3269",
    "3306", "5432", "6379", "1433", "1521", "27017",
}
_NON_HTTP_SVC_NAMES: set[str] = {
    "ssh", "redis", "mysql", "mariadb", "postgresql",
    "mssql", "oracle", "mongodb", "memcached",
    "ldap", "kerberos", "smb", "rdp", "vnc",
}

# ── Private helpers (extracted from nested functions) ──────────────────────


async def _probe_one_port(
    orch, host: str, port: int,
) -> tuple:
    """Probe a single HTTP port, return (url, stdout, http_status, technologies, forms, api_paths)."""
    scheme = "https" if port in {443, 8443} else "http"
    url = f"{scheme}://{host}:{port}"
    is_tls = scheme == "https"
    try:
        curl_result = await orch.recon_gateway.call("curl_get",
            {"url": url, "follow_redirects": True,
             "insecure": True if is_tls else False})
        if not curl_result.success and is_tls:
            url = f"http://{host}:{port}"
            curl_result = await orch.recon_gateway.call("curl_get",
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
            parse_result = await orch.recon_gateway.call("response_parse",
                {"content": parse_sample})
            if parse_result.success:
                parsed = getattr(parse_result, "parsed_output", {})
                forms = parsed.get("forms", [])
        except Exception:
            pass
        # Extract API paths from large JS bundles
        if resp_len > 100000:
            for pattern in [r'["\x27](/api/[^"\x27]{2,60})["\x27]',
                           r'fetch\(["\x27](/[^"\x27]{2,60})["\x27]\)']:
                for m in re.finditer(pattern, stdout[:200000]):
                    path = m.group(1)
                    if not path.endswith(('.js', '.css', '.png', '.ico')):
                        api_paths.append(path)
        # whatweb
        technologies = []
        try:
            ww = await orch.recon_gateway.call("whatweb_scan",
                {"target_url": url})
            if ww.success:
                technologies = getattr(ww, "parsed_output", {}).get("technologies", [])
        except Exception:
            pass
        return (url, stdout, http_status, technologies, forms, api_paths)
    except Exception:
        return (url, "", 0, [], [], [])


async def _probe_web_path(orch, base_url: str, path: str) -> None:
    """Probe a single web path and register if content is found."""
    try:
        r = await orch.recon_gateway.call("curl_get",
            {"url": f"{base_url.rstrip('/')}{path}", "follow_redirects": True})
        if r.success:
            out = getattr(r, "stdout", "")
            if len(out) > 200:
                orch.dkg.add_node("Endpoint", f"ep-path-{path.replace('/','-')[:30]}", {
                    "url": f"{base_url.rstrip('/')}{path}", "method": "GET",
                    "params": "",
                    "sample_status": 200, "sample_response": out[:5000],
                    "response_size": len(out),
                    "discovered_by": "bootstrap-path-probe",
                })
    except Exception:
        pass


async def _probe_api_path(orch, probed_apis: set, ep_url: str) -> None:
    """Probe a single API endpoint and register result in DKG."""
    if ep_url in probed_apis:
        return
    probed_apis.add(ep_url)
    try:
        r = await orch.recon_gateway.call("curl_get",
            {"url": ep_url, "follow_redirects": True})
        if r.success:
            out = getattr(r, "stdout", "")
            st = 200
            fl = out.split("\n")[0] if out else ""
            if fl.startswith("HTTP/"):
                pts = fl.split()
                if len(pts) >= 2 and pts[1].isdigit():
                    st = int(pts[1])
            orch.dkg.add_node("Endpoint", f"ep-api-{ep_url[:50]}", {
                "url": ep_url, "method": "GET", "params": "",
                "sample_status": st, "sample_response": out[:5000],
                "response_size": len(out),
                "discovered_by": "bootstrap-api-probe",
            })
    except Exception:
        pass


# ── K8s Cluster Discovery ──────────────────────────────────────────────


async def _k8s_cluster_discovery(orch) -> None:
    """Discover local K8S cluster topology independently of nmap.

    Runs kubectl commands to enumerate nodes, pods, services, and
    namespaces. Populates DKG with Host/Service/Endpoint/Analysis
    nodes for discovered cluster resources. This is critical for
    KIND-based scenarios where only the API server port is mapped
    to localhost and the rest of the cluster is invisible to nmap.

    Runs unconditionally — if kubectl is unavailable or no cluster
    exists, fails silently in <2s. All commands have 8s timeouts.
    """
    # ── Step 1: Verify kubectl is available and a cluster is reachable ──
    try:
        proc = await asyncio.create_subprocess_shell(
            "kubectl cluster-info 2>&1",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=8)
        out = stdout.decode("utf-8", errors="replace")
        if proc.returncode != 0 or "is running at" not in out:
            return  # No K8S cluster available or kubectl not installed
        api_match = re.search(r"is running at (https?://\S+)", out)
        api_url = api_match.group(1) if api_match else ""
        log.info("K8S cluster discovery: cluster reachable at %s", api_url)
    except Exception:
        return

    # ── Step 2: Enumerate nodes (name, IP, labels, taints) ──
    nodes_data: dict = {}
    try:
        proc = await asyncio.create_subprocess_shell(
            "kubectl get nodes -o json 2>&1",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=8)
        out = stdout.decode("utf-8", errors="replace")
        if proc.returncode == 0:
            nodes_data = json.loads(out) if out.strip().startswith("{") else {}
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
        proc = await asyncio.create_subprocess_shell(
            "kubectl get pods -A -o json 2>&1",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=8)
        out = stdout.decode("utf-8", errors="replace")
        if proc.returncode == 0:
            pods_data = json.loads(out) if out.strip().startswith("{") else {}
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
        proc = await asyncio.create_subprocess_shell(
            "kubectl get svc -A -o json 2>&1",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=8)
        out = stdout.decode("utf-8", errors="replace")
        if proc.returncode == 0:
            svcs_data = json.loads(out) if out.strip().startswith("{") else {}
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
        proc = await asyncio.create_subprocess_shell(
            "kubectl get namespaces -o json 2>&1",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=8)
        out = stdout.decode("utf-8", errors="replace")
        if proc.returncode == 0 and out.strip().startswith("{"):
            ns_data = json.loads(out)
            ns_list = [i.get("metadata", {}).get("name", "")
                       for i in ns_data.get("items", [])]
    except Exception:
        pass

    # ── Step 6: Check current permissions ──
    permissions: list[str] = []
    try:
        proc = await asyncio.create_subprocess_shell(
            "kubectl auth can-i --list -A 2>&1 | head -60",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=8)
        out = stdout.decode("utf-8", errors="replace")
        if proc.returncode == 0:
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
        orch.dkg.add_node("Host", node_id, {
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
        orch.dkg.add_node("Endpoint", "endpoint-k8s-api", {
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
            orch.dkg.add_node("Service", svc_id, {
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
        orch.dkg.add_node("Analysis", "analysis-k8s-cluster", {
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


# ── Deep Recon helpers (extracted from _deep_recon nested functions) ────


def _add_form_endpoint(orch, form: dict, base_url: str) -> None:
    """Add a form-derived endpoint node to DKG."""
    action = form.get("action", "")
    form_url = (action if action.startswith("http")
                else f"{base_url.rstrip('/')}/{action.lstrip('/')}")
    params = ",".join(i.get("name", "") for i in form.get("inputs", []))
    if params:
        orch.dkg.add_node("Endpoint", f"ep-form-{form_url[:40]}", {
            "url": form_url, "method": form.get("method", "POST"),
            "params": params, "body_format": "form",
            "discovered_by": "deep-recon-form",
        })


async def _probe_one_endpoint(orch, endpoint: dict) -> None:
    """Deep recon probe for a single endpoint."""
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
        api_eps = [e for e in orch.dkg.query_nodes("Endpoint")
                   if e.get("discovered_by", "").startswith("bootstrap-api-")
                   and e.get("url", "").startswith(url)]
        for api_ep in api_eps[:15]:
            api_url = api_ep.get("url", "")
            try:
                r = await orch.recon_gateway.call("curl_get",
                    {"url": api_url, "follow_redirects": True})
                if r.success:
                    out = getattr(r, "stdout", "")
                    st = 200
                    fl = out.split("\n")[0] if out else ""
                    if fl.startswith("HTTP/"):
                        pts = fl.split()
                        if len(pts) >= 2 and pts[1].isdigit():
                            st = int(pts[1])
                    orch.dkg.add_node("Endpoint", f"ep-probe-{api_url[:50]}", {
                        "url": api_url, "method": "GET", "params": "",
                        "sample_status": st, "sample_response": out[:5000],
                        "response_size": len(out),
                        "discovered_by": "deep-recon-api-probe",
                    })
                    if 0 < len(out) < 100000:
                        rp = await orch.recon_gateway.call("response_parse",
                            {"content": out[:50000]})
                        if rp.success:
                            parsed = getattr(rp, "parsed_output", {})
                            for form in parsed.get("forms", []):
                                _add_form_endpoint(orch, form, url)
            except Exception:
                pass
        scanned = True

    elif resp_len < 500000:
        # Small/medium HTML page — full recon: gobuster + nikto + form_extract
        _disc = endpoint.get("discovered_by", "")
        _is_primary = (
            _disc == "bootstrap-nmap"      # nmap-discovered port
            or _disc == "bootstrap"         # bootstrap whatweb on primary port
            or _disc == ""                  # legacy endpoint without tag
        )
        if not _is_primary:
            log.info("_deep_recon: skipping non-primary endpoint %s (discovered_by=%s)", url, _disc)
            return  # skip gobuster/nikto/form for derived endpoints
        # Skip gobuster on REST API / JSON endpoints
        _sample = endpoint.get("sample_response", "")
        if _sample.strip().startswith("{") or _sample.strip().startswith("["):
            log.info("_deep_recon: skipping JSON/API endpoint %s", url)
            return

        # Pre-flight curl check
        try:
            _pre = await orch.recon_gateway.call("curl_get", {
                "url": url, "method": "GET", "timeout": "5",
            })
            _pre_stdout = getattr(_pre, "stdout", "") or ""
            if not _pre.success or not _pre_stdout.strip():
                log.info("_deep_recon: pre-flight unreachable, skipping gobuster/nikto for %s", url)
                return
            if _pre_stdout.strip().startswith("{") or _pre_stdout.strip().startswith("["):
                log.info("_deep_recon: pre-flight JSON/API, skipping gobuster/nikto for %s", url)
                return
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
            log.info("_deep_recon: pre-flight failed, skipping gobuster/nikto for %s", url)
            return

        try:
            bust_result = await orch.recon_gateway.call("gobuster_dir",
                {"target_url": url})
            scanned = True
            if bust_result.success:
                paths = getattr(bust_result, "parsed_output", {}).get("discovered_paths", [])
                for pi in paths[:15]:
                    path = pi.get("path", "")
                    if path:
                        ep_url = f"{url.rstrip('/')}{path}"
                        orch.dkg.add_node("Endpoint", f"ep-dirb-{path[:40]}", {
                            "url": ep_url, "method": "GET", "params": "",
                            "sample_status": pi.get("code", 200),
                            "discovered_by": "deep-recon-dirb",
                        })
        except Exception:
            pass
        try:
            nikto_result = await orch.recon_gateway.call("nikto_scan",
                {"target_url": url})
            if nikto_result.success:
                findings = getattr(nikto_result, "stdout", "")
                if findings and "0 items" not in findings:
                    for line in findings.split("\n")[:10]:
                        line = line.strip()
                        if line and "OSVDB" not in line:
                            orch.dkg.add_node("Vulnerability", f"vuln-nikto-{len(line[:20])}", {
                                "vuln_type": "XSS", "endpoint": url,
                                "parameter": "", "severity": "low",
                                "source": "nikto", "detail": line[:200],
                            })
        except Exception:
            pass
        try:
            form_result = await orch.recon_gateway.call("form_extract",
                {"url": url})
            if form_result.success:
                parsed = getattr(form_result, "parsed_output", {})
                for form in parsed.get("forms", []):
                    _add_form_endpoint(orch, form, url)
        except Exception:
            pass

    elif "json" in sample.lower() or sample.strip().startswith("{"):
        # JSON/API response — curl + response_parse to extract structure
        try:
            rp = await orch.recon_gateway.call("response_parse",
                {"content": sample[:50000]})
            if rp.success:
                parsed = getattr(rp, "parsed_output", {})
                for key in parsed.get("keys", [])[:10]:
                    probe_url = f"{url.rstrip('/')}/{key}"
                    r2 = await orch.recon_gateway.call("curl_get",
                        {"url": probe_url, "follow_redirects": True})
                    if r2.success:
                        out = getattr(r2, "stdout", "")
                        orch.dkg.add_node("Endpoint", f"ep-api-{key[:40]}", {
                            "url": probe_url, "method": "GET", "params": "",
                            "sample_status": 200, "sample_response": out[:5000],
                            "discovered_by": "deep-recon-json-probe",
                        })
            scanned = True
        except Exception:
            pass

    else:
        # Medium/large HTML page (500KB-1MB) that isn't JSON/SPA.
        try:
            form_result = await orch.recon_gateway.call("form_extract",
                {"url": url})
            if form_result.success:
                parsed = getattr(form_result, "parsed_output", {})
                for form in parsed.get("forms", []):
                    _add_form_endpoint(orch, form, url)
            scanned = True
        except Exception:
            pass

    # Mark scanned to prevent redundant agent work
    if scanned:
        orch.dkg.add_node("Endpoint", ep_id, {
            "url": url, "deep_recon_done": True,
            "discovered_by": "deep-recon",
        })


async def _probe_cms(orch, endpoint: dict) -> None:
    """Probe CMS entry-point paths on an endpoint."""
    _CMS_PATHS = [
        "/wp-admin/", "/wp-login.php", "/wp-content/", "/wp-content/plugins/",
        "/wp-json/wp/v2/", "/administrator/", "/user/login",
        "/api/", "/.env", "/config.php",
    ]
    url = endpoint.get("url", "")
    if not url or not url.startswith("http"):
        return
    base = url.rstrip("/")
    for path in _CMS_PATHS:
        try:
            r = await orch.recon_gateway.call("curl_get",
                {"url": f"{base}{path}", "follow_redirects": True, "insecure": True})
            if r.success:
                out = getattr(r, "stdout", "")
                st = 200
                fl = out.split("\n")[0] if out else ""
                if fl.startswith("HTTP/"):
                    pts = fl.split()
                    if len(pts) >= 2 and pts[1].isdigit():
                        st = int(pts[1])
                _is_content = 200 <= st < 400
                _is_auth_wall = st in (401, 403)
                if (_is_content or _is_auth_wall) and len(out) > 50:
                    orch.dkg.add_node("Endpoint", f"ep-cms-{path.replace('/','-')[:30]}", {
                        "url": f"{base}{path}", "method": "GET", "params": "",
                        "sample_status": st, "sample_response": out[:2000],
                        "response_size": len(out),
                        "discovered_by": "cms-probe",
                    })
        except Exception:
            pass


# ── Main Public Functions ─────────────────────────────────────────────


async def bootstrap_scan(
    orch, target_url: str, port_range: str | None = None,
) -> None:
    """Minimal bootstrap: nmap port scan only. LLM drives all further recon.

    Records discovered ports as Host/Service nodes in DKG.
    Marks SSH ports as skip_exploit. Detects AD domain ports.
    Does NOT probe HTTP services — the LLM decides which ports to probe.

    Args:
        port_range: Optional nmap port range (e.g. "8080-8090,3306").
                    When set, scans only those ports. Full scan otherwise.
    """
    orch.phase = OrchestratorPhase.BOOTSTRAP

    # Normalize bare host:port URLs (e.g. "localhost:10205") so urlparse
    # correctly extracts hostname and port. Without this, urlparse would
    # treat "localhost" as the scheme and "10205" as the path.
    normalized_url = target_url
    if "://" not in target_url:
        normalized_url = f"http://{target_url}"

    parsed = urlparse(normalized_url)
    host = parsed.hostname or target_url
    orch.target_host = host

    orch._task_log_event("info", "bootstrap_nmap", host=host, port_range=port_range)
    # Launch K8S cluster discovery in parallel with nmap.
    # Both are independent data sources — nmap sees port mappings,
    # kubectl sees cluster topology. Runs unconditionally; fails
    # silently in <2s if no cluster exists.
    k8s_discovery_task = asyncio.create_task(_k8s_cluster_discovery(orch))

    # Always include the target URL's port in the scan range
    target_port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if port_range:
        ports = f"{target_port},{port_range}"
        nmap_result = await orch.recon_gateway.call("nmap_port_range", {
            "target": host, "ports": ports,
        })
    else:
        nmap_result = await orch.recon_gateway.call("nmap_full_scan", {"target": host})

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

    # ── Port blacklist ────────────────────────────────────────────
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
        orch.dkg.add_node("Host", f"host-{host}", {
            "ip": host, "is_reachable": True, "is_internal": False,
        })
        orch.dkg.add_node("Service", f"svc-{host}-{p['port']}", {
            "port": p["port"], "protocol": "tcp",
            "version": p.get("version", "") or p.get("service", ""),
            "banner": p.get("service", ""),
            "service_name": p.get("service", ""),
        })

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
        orch.dkg.add_node("Domain", f"domain-{host}", {
            "name": host, "dc_ip": host, "detected_by": "port_scan",
        })

    # SSH: always available for exploitation
    _has_ssh_creds = bool(orch._provided_username and orch._provided_password)
    for p in discovered_ports:
        if p["port"] in {22}:
            orch.dkg.add_node("Service", f"svc-{host}-{p['port']}", {
                "port": p["port"], "protocol": "tcp",
                "version": p.get("version", "") or p.get("service", ""),
                "banner": p.get("service", ""),
                "skip_exploit": False,
            })

    # Register SSH credentials in DKG when provided, and test connection
    if _has_ssh_creds:
        orch.dkg.add_node("Credential", f"cred-ssh-{host}", {
            "username": orch._provided_username,
            "password": orch._provided_password,
            "source_host": host,
            "cred_type": "ssh",
            "source": "user_provided",
        })
        # Test SSH connection to verify credentials work
        try:
            ssh_result = await orch.attack_gateway.call("ssh_exec", {
                "host": host, "username": orch._provided_username,
                "password": orch._provided_password,
                "command": "id && uname -a",
            })
            if ssh_result.success and "uid=" in (ssh_result.stdout or ""):
                orch.dkg.add_node("Session", f"session-ssh-{host}", {
                    "host": host, "user": orch._provided_username,
                    "access_level": "user", "shell_type": "ssh",
                    "established_by": "bootstrap-ssh",
                })
                orch._task_log_event("info", "ssh_session_established",
                    host=host, user=orch._provided_username)
        except Exception:
            pass  # SSH test failure is non-fatal

    # ── Auto-try default credentials for database services ────────
    await try_db_default_credentials(orch, host, discovered_ports)

    # Store provided credentials for DB ports too (not just SSH)
    _DB_PORT_PROTO_LOCAL = {3306: "mysql", 5432: "postgresql", 6379: "redis",
                            1433: "mssql", 1521: "oracle", 27017: "mongodb"}
    if orch._provided_username and orch._provided_password:
        for p in discovered_ports:
            if p["port"] in _DB_PORT_PROTO_LOCAL:
                proto = _DB_PORT_PROTO_LOCAL[p["port"]]
                orch.dkg.add_node("Credential", f"cred-{proto}-{host}-{p['port']}", {
                    "username": orch._provided_username,
                    "password": orch._provided_password,
                    "source_host": host,
                    "cred_type": proto,
                    "port": p["port"],
                    "source": "user_provided",
                })

    # ── Non-HTTP service classification ─────────────────────────
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
            orch.dkg.add_node("Endpoint", f"endpoint-{host}-{port}-{proto}", {
                "url": f"{proto}://{host}:{port}",
                "method": proto, "params": proto,
                "proto": proto,
                "discovered_by": "bootstrap-nmap",
            })
        elif port in _K8S_PORTS:
            orch.dkg.add_node("Endpoint", f"endpoint-{host}-{port}-k8s", {
                "url": f"https://{host}:{port}",
                "method": "GET", "params": _K8S_PROTO,
                "proto": _K8S_PROTO,
                "discovered_by": "bootstrap-nmap",
            })

    # ── Identify unknown services via API probing ────────────────
    _API_FINGERPRINTS: list[tuple] = [
        ("/version", '"etcdserver"', "etcd", "etcd", "GET", ""),
        ("/version", '"etcdcluster"', "etcd", "etcd", "GET", ""),
        ("/health", '{"health":"true"}', "etcd", "etcd", "GET", ""),
        ("/validate", "admission", "kubernetes-admission",
         "kubernetes", "POST",
         '{"apiVersion":"admission.k8s.io/v1","kind":"AdmissionReview","request":{"uid":"probe"}}'),
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
        try:
            proc = await asyncio.create_subprocess_shell(
                f"echo '' | openssl s_client -connect {host}:{_port} "
                f"-servername {host} 2>&1",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=8)
            out = stdout.decode("utf-8", errors="replace")
            cn_match = re.search(r"\bCN\s*=\s*(\S+)", out)
            cn = cn_match.group(1) if cn_match else ""
            o_match = re.search(r"\bO\s*=\s*(\S+)", out)
            org = o_match.group(1) if o_match else ""
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
                orch.dkg.add_node("Service",
                    f"svc-{host}-{_port}", {
                        "port": _port, "protocol": "tcp",
                        "version": _name, "service_name": _name,
                        "banner": f"CN={cn}",
                })
                orch.dkg.add_node("Endpoint",
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

        # Phase 2: HTTP API probe for unknown services
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
                    _match = (proc.returncode == 0) if _method == "POST" else (_needle in _body)
                    if _match:
                        orch.dkg.add_node("Service",
                            f"svc-{host}-{_port}", {
                                "port": _port, "protocol": "tcp",
                                "version": _svc_name,
                                "service_name": _svc_name,
                                "banner": _body[:200],
                        })
                        orch.dkg.add_node("Endpoint",
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
    http_ports = []
    for p in discovered_ports:
        p_str = str(p.get("port"))
        if p_str in _NON_HTTP_PORTS:
            continue
        svc = (p.get("service", "") or p.get("version", "")).lower()
        if any(name in svc for name in _NON_HTTP_SVC_NAMES):
            continue
        http_ports.append(p)

    # Run all port probes in parallel
    probe_tasks = [asyncio.create_task(_probe_one_port(orch, host, p["port"])) for p in http_ports]
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
        orch.dkg.add_node("Endpoint", f"ep-{url}", {
            "url": url, "method": "GET", "params": "",
            "sample_status": http_status,
            "sample_response": stdout[:5000],
            "response_size": resp_len,
            "discovered_by": "bootstrap",
        })
        for form in forms:
            action = form.get("action", "")
            form_url = (action if action.startswith("http")
                        else f"{url.rstrip('/')}/{action.lstrip('/')}")
            params = ",".join(i.get("name", "") for i in form.get("inputs", []))
            orch.dkg.add_node("Endpoint", f"ep-form-{form_url[:40]}", {
                "url": form_url, "method": form.get("method", "POST"),
                "params": params, "body_format": "form",
                "discovered_by": "bootstrap",
            })
        # ── When root is near-empty, probe common paths for real content ──
        if resp_len < 500 and len(discovered_ports) <= 3:
            _WEB_PATHS = ["/", "/index.html", "/home", "/login", "/admin",
                          "/api", "/app", "/status", "/health", "/metrics",
                          "/fetch", "/upload", "/dashboard", "/console",
                          "/files", "/objects", "/buckets"]
            path_tasks = [asyncio.create_task(_probe_web_path(orch, url, p))
                          for p in _WEB_PATHS]
            await asyncio.gather(*path_tasks, return_exceptions=True)

        if technologies:
            log.info("bootstrap whatweb: %s → %s", url, technologies)
            # Enrich the existing nmap Service node with whatweb data
            _p = urlparse(url)
            _svc_port = _p.port or (443 if _p.scheme == "https" else 80)
            _svc_id = f"svc-{host}-{_svc_port}"
            _existing = orch.dkg.get_node(_svc_id)
            if _existing:
                orch.dkg.update_node(_svc_id, {
                    "fingerprint": technologies,
                })
        for path in api_paths[:20]:
            api_endpoints_to_probe.append(f"{url.rstrip('/')}{path}")

    # Second pass: probe discovered API paths (also parallel)
    probed_apis: set[str] = set()
    if api_endpoints_to_probe:
        api_tasks = [asyncio.create_task(_probe_api_path(orch, probed_apis, u))
                     for u in api_endpoints_to_probe[:30]]
        await asyncio.gather(*api_tasks, return_exceptions=True)

    # Wait for K8S cluster discovery (launched in parallel with nmap)
    try:
        await k8s_discovery_task
    except Exception:
        pass  # K8S discovery failure is non-fatal

    # CTAGE: Cloud Topology & Attack Graph Engine
    try:
        from darwin.cloud_topology import discover_cloud_topology
        orch._cloud_topology = await discover_cloud_topology(orch.dkg)
        log.info("CTAGE: cloud topology mapped — %d pods, %d RBAC bindings, %d IAM roles",
                 len(orch._cloud_topology.pods) if orch._cloud_topology else 0,
                 len(orch._cloud_topology.rbac_bindings) if orch._cloud_topology else 0,
                 len(orch._cloud_topology.iam_roles) if orch._cloud_topology else 0)
        if orch._cloud_topology and orch._cloud_topology.high_risk_pods:
            log.info("CTAGE: %d high-risk pods identified", len(orch._cloud_topology.high_risk_pods))
            for profile in orch._cloud_topology.high_risk_pods[:5]:
                log.info("  CTAGE high-risk: %s/%s risk=%.2f vectors=%s",
                         profile.namespace, profile.pod_name,
                         profile.risk_score, profile.escape_vectors)
    except Exception as e:
        log.debug("CTAGE: cloud topology mapping skipped (%s)", e)

    orch._discovered_ports = discovered_ports

    # ── Bootstrap summary ─────────────────────────────────────────
    services = orch.dkg.query_nodes("Service")
    hosts = orch.dkg.query_nodes("Host")
    domains = orch.dkg.query_nodes("Domain")
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
    if orch._provided_username and not ssh_ok:
        db_creds = [c for c in orch.dkg.query_nodes("Credential")
                   if c.get("source") == "user_provided" and c.get("cred_type") != "ssh"]
        if db_creds:
            cred_parts = [f"{c.get('cred_type','?')}:{c.get('port','?')}" for c in db_creds]
            print(f"  DB credentials provided for: {', '.join(cred_parts)}")

    orch.step_count += 1


async def deep_recon(orch) -> None:
    """Deep reconnaissance on discovered HTTP endpoints.

    Runs after bootstrap (which only probes root URLs) and before
    service_research/analyze. Uses dirb, nikto, and form_extract to
    discover the full attack surface: directories, known vulns, forms.
    """
    endpoints = orch.dkg.query_nodes("Endpoint")
    if not endpoints:
        return
    log.info("_deep_recon: scanning %d endpoints", len(endpoints))

    # Run deep recon in parallel across endpoints (max 6 concurrent)
    batch = [ep for ep in endpoints[:8] if ep.get("url", "").startswith("http")]
    if batch:
        tasks = [asyncio.create_task(_probe_one_endpoint(orch, ep)) for ep in batch]
        tasks += [asyncio.create_task(_probe_cms(orch, ep)) for ep in batch]
        await asyncio.gather(*tasks, return_exceptions=True)
    log.info("_deep_recon: complete")

    # ── Deep recon summary ──────────────────────────────────────
    endpoints = orch.dkg.query_nodes("Endpoint")
    vulns = orch.dkg.query_nodes("Vulnerability")
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


async def detect_defenses(orch) -> None:
    """Run DPM defense probes on discovered endpoints and update defense_state.

    Sends filter probes (classes A-E) to up to 6 GET endpoints with params,
    then runs the rule-based DPM detection pipeline (no LLM cost).
    """
    endpoints = orch.dkg.query_nodes("Endpoint")
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
            probe_results = await orch.probe_client.send_all_probe_classes(url, param)
            all_probe_results.extend(probe_results)
            all_responses.extend(
                p.response for p in probe_results if hasattr(p, "response")
            )
        except Exception:
            continue

    if all_probe_results:
        orch.defense_state = orch.dpm.detect(
            all_probe_results, all_responses, use_llm=False,
        )
        orch._task_log_event("info", "defense_detected",
            waf_type=orch.defense_state.waf_type,
            defense_category=orch.defense_state.defense_category,
            defense_complexity=orch.defense_state.defense_complexity,
        )

    # ── Defense summary ─────────────────────────────────────────
    ds = orch.defense_state
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


async def cloud_discovery_hint(orch) -> None:
    """Add a PlatformDiscovery vulnerability when cloud signatures found.

    Checks DKG Endpoint sample responses for platform-specific
    patterns (response headers, API structures).  If a cloud
    platform is detected, adds a hint so the analyze LLM knows
    to explore additional services on the same endpoint.

    General — works for any cloud platform, not just AWS.
    """
    # Platform signatures: header/substring → platform name + hint
    _SIGNATURES: list[tuple[str, str, str]] = [
        ("x-amz-request-id", "AWS-compatible",
         "This endpoint returns AWS S3/API-Gateway headers. "
         "Explore what OTHER AWS services (IAM, STS, Lambda, KMS, "
         "DynamoDB, SQS) are available on the same endpoint — "
         "many AWS-compatible platforms run multiple services."),
        ("x-amz-id-2", "AWS S3-compatible",
         "AWS S3 signature header detected. The endpoint may also "
         "support other AWS services — probe IAM, STS, and KMS."),
        ('"kind"', "Kubernetes API",
         "K8s API detected. Explore all API groups: /api/v1/pods, "
         "/apis/rbac.authorization.k8s.io/, /apis/apps/v1/, etc."),
        ('"apiVersion"', "Kubernetes API",
         "K8s API detected. Enumerate available resources and RBAC."),
    ]

    endpoints = orch.dkg.query_nodes("Endpoint")
    if not endpoints:
        return

    for pattern, platform, hint in _SIGNATURES:
        for ep in endpoints:
            resp = (ep.get("sample_response", "") or "")[:3000]
            if pattern.lower() in resp.lower():
                # Found cloud signature — add a discovery hint to DKG
                ep_url = ep.get("url", "")
                # Derive the base URL (strip path)
                _p = urlparse(ep_url) if "://" in ep_url else None
                _base = f"{_p.scheme}://{_p.hostname}:{_p.port}" if _p and _p.port else (
                    ep_url.split("/")[0] + "//" + ep_url.split("/")[2]
                    if "://" in ep_url else ep_url
                )

                orch.dkg.add_node(
                    "Vulnerability",
                    f"vuln-platform-{platform.lower().replace(' ','-')}",
                    {
                        "vuln_type": "PlatformDiscovery",
                        "endpoint": _base,
                        "param": "",
                        "confidence": 0.7,
                        "evidence": f"Response contains '{pattern}' — "
                                    f"suggests {platform} platform. {hint}",
                        "suggested_tool": "",
                        "tool_args": {},
                        "source": "bootstrap-cloud-discovery",
                    },
                )
                # One match per platform is enough
                break


async def try_auto_login(
    orch, target_url: str, username: str | None, password: str | None,
) -> bool:
    """Try default credentials via the battle-tested auto_login.
    Only attempts ports that successfully responded to HTTP during recon.
    If this fails, the LLM in the solo cycle can use the try_login tool
    for more sophisticated attempts.

    Returns True if credentials were found and registered.
    """
    reachable = getattr(orch, '_http_ports_reachable', set())
    for port in getattr(orch, '_discovered_http_ports', []):
        if port not in reachable:
            continue  # skip ports that failed HTTP during recon
        host = getattr(orch, "target_host", None)
        if not host:
            continue
        scheme = "https" if port == 443 else "http"
        base = f"{scheme}://{host}" if port in (80, 443) else f"{scheme}://{host}:{port}"
        # Only try the 2 most common credential pairs for speed
        for u, p in [("test", "test"), ("admin", "admin")]:
            if username and password:
                u, p = username, password
            if orch._time_exceeded():
                return False
            try:
                if await orch.client.auto_login(base, u, p):
                    log.info("Auto-login SUCCESS: %s:%d as %s/%s", host, port, u, p)
                    orch._task_log_event("info", "auto_login_ok", url=base, username=u)
                    orch.dkg.add_node("Credential", f"cred-{u}@{host}:{port}", {
                        "username": u, "password": p, "url": base,
                        "host": host, "port": port, "source": "auto_login",
                    })
                    # Persist to CTEG for cross-task reuse
                    try:
                        orch.cteg.add_credential(
                            host=host, port=port, service_type="http",
                            username=u, password=p, source="auto_login",
                        )
                    except Exception:
                        pass
                    return True
                else:
                    log.info("Auto-login failed: %s:%d with %s/%s", host, port, u, p)
            except Exception as e:
                log.warning("Auto-login error %s:%d: %s", host, port, e)
            # Only try one pair if specific credentials were provided
            if username:
                break
    return False


async def try_db_default_credentials(orch, host: str, discovered_ports: list) -> None:
    """Try default credentials against discovered database services.

    Uses well-known default credential pairs for each DB type.  Results
    are written to DKG Credential nodes with source 'default_trial'.
    """
    _DB_DEFAULTS: dict[str, list[tuple[str, str]]] = {
        "mysql":      [("root", ""), ("root", "root"), ("root", "password")],
        "postgresql": [("postgres", "postgres"), ("postgres", ""), ("postgres", "password")],
        "redis":      [("", "")],
        "mssql":      [("sa", ""), ("sa", "sa"), ("sa", "Password123")],
        "oracle":     [("system", "oracle"), ("sys", "oracle")],
        "mongodb":    [("admin", "admin"), ("admin", ""), ("root", "root")],
    }
    _DB_PORT_PROTO = {3306: "mysql", 5432: "postgresql", 6379: "redis",
                     1433: "mssql", 1521: "oracle", 27017: "mongodb"}
    for p in discovered_ports:
        port = p.get("port", 0)
        proto = _DB_PORT_PROTO.get(port)
        if not proto or proto not in _DB_DEFAULTS:
            continue
        tool_map = {
            "mysql": "mysql_query", "postgresql": "psql_query",
            "redis": "redis_cmd", "mssql": "mssqlclient_query",
            "oracle": "oracle_query", "mongodb": "shell_exec",
        }
        tool = tool_map.get(proto)
        if not tool:
            continue
        for username, password in _DB_DEFAULTS[proto][:3]:
            try:
                if proto == "mongodb":
                    r = await orch.attack_gateway.call(
                        tool, {"command": f"echo 'db.runCommand({{ping:1}})' | mongosh mongodb://{username}:{password}@{host}:{port} --quiet 2>&1"}
                    )
                elif proto == "redis":
                    r = await orch.attack_gateway.call(
                        tool, {"command": "PING", "host": host, "port": port}
                    )
                else:
                    r = await orch.attack_gateway.call(
                        tool, {"host": host, "port": port, "user": username, "password": password, "query": "SELECT 1"}
                    )
                if r and getattr(r, 'success', False):
                    stdout = (getattr(r, 'stdout', '') or '').lower()
                    if any(kw in stdout for kw in ("ok", "1 row", "pong", "connected")):
                        log.info("[db_creds] Default creds WORK: %s:%s@%s:%d", username, password, host, port)
                        orch.dkg.add_node("Credential", f"cred-default-{proto}-{host}-{port}", {
                            "username": username, "password": password,
                            "source_host": host, "cred_type": proto,
                            "port": port, "source": "default_trial", "confirmed": True,
                        })
                        break
            except Exception:
                continue
