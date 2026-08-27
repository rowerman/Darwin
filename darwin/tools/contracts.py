"""Explicit v2 contract enrichment for the built-in tool registries.

The registration calls pre-date the v2 contract and intentionally keep their
small, readable parameter declarations.  This module turns those declarations
into explicit ``ToolSpec`` instances at the registry boundary.  The resulting
spec is the single source consumed by discovery, filtering and the manifest.
"""

from __future__ import annotations

import inspect
import shlex
from typing import Any

from darwin.tools.spec import ToolSpec


_DOMAIN_PREFIXES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("ad", ("impacket_", "netexec_", "certipy_", "pywhisker", "bloodyad", "krbrelayx", "gettgtpkinit", "getnthash", "ldapsearch_ad")),
    ("k8s", ("kubectl_", "k8s_", "kubelet_", "etcdctl_", "helm")),
    ("container", ("container_", "crictl_", "nsenter_")),
    ("cloud", ("aws_", "gcloud_", "az_", "object_store_")),
    ("db", ("mysql_", "psql_", "mssql_", "oracle_", "redis_", "mongodb_", "elasticsearch_", "couchdb_", "nosql_")),
    ("research", ("knowledge_", "ddg_", "cve_", "metasploit_", "searchsploit_", "go_exploitdb_")),
    ("lnx", ("linux_",)),
    ("network", ("smb_", "tcpdump_", "nmap", "masscan")),
)

_WEB_NAMES = {
    "sqlmap_test", "parallel_request", "ffuf_fuzz", "send_payload",
    "command_injection_test", "xss_reflection_test", "ssrf_probe",
    "ssti_inject", "xxe_inject", "hydra_http_brute", "tomcat_exploit",
    "file_upload", "wpscan_enum", "wp_xmlrpc_brute", "graphql_introspect",
    "jwt_forge", "saml_forge", "php_filter_chain", "php_serialize_generate",
    "curl_get", "http_post", "form_extract", "idor_header_test", "try_login",
    "whatweb_scan", "dirb_scan", "gobuster_dir", "nikto_scan",
}

_CAPABILITY_BY_NAME = {
    "curl_get": "fetch_url",
    "sqlmap_test": "verify_sql_injection", "test_credential": "test_credentials",
    "hydra_http_brute": "test_credentials", "ssh_exec": "acquire_shell",
    "ssh_key_exec": "acquire_shell", "shell_exec": "acquire_shell",
    "mysql_query": "sql_query", "psql_query": "sql_query",
    "mssql_query": "sql_query", "mssqlclient_query": "sql_query",
    "oracle_query": "sql_query", "redis_cmd": "sql_query",
    "mongodb_query": "sql_query", "nosql_inject": "sql_query",
    "send_payload": "web_exploit_send", "http_post": "web_exploit_send",
    "command_injection_test": "web_exploit_send", "xxe_inject": "web_exploit_send",
    "ssti_inject": "web_exploit_send", "graphql_introspect": "web_exploit_send",
    "check_capabilities": "container_escape", "check_mounts": "container_escape",
    "container_escape_docker_sock": "container_escape", "container_escape_docker_api": "container_escape",
    "container_escape_cgroup": "container_escape", "container_escape_procfs": "container_escape",
    "container_escape_cap_dac": "container_escape", "container_escape_mount_disk": "container_escape",
    "nsenter_exec": "container_escape", "kubectl_run": "k8s_apply", "kubectl_exec": "k8s_apply",
    "k8s_secret_dump": "secret_dump", "k8s_configmap_dump": "secret_dump",
    "kubectl_get_secrets": "secret_dump", "etcdctl_get": "secret_dump", "k8s_etcd_keys": "secret_dump",
    "docker_registry": "registry_push", "aws_sts_query": "cloud_iam_assume",
    "aws_iam_federation": "cloud_iam_assume", "aws_cli": "cloud_iam_assume",
    "saml_forge": "cloud_iam_assume", "jwt_forge": "cloud_iam_assume",
    "test_db_credential": "credential_test", "wp_xmlrpc_brute": "credential_test",
}

_ALIASES = {
    "url": ("target_url", "file_path"), "endpoint": ("target_url",),
    "host": ("target",), "hostname": ("host",), "dc_ip": ("target",),
    "username": ("user",), "login": ("user",),
    "pass": ("password",), "passwd": ("password",), "pwd": ("password",),
    "body": ("data",), "post_data": ("data",), "json_body": ("data",),
}


def _domain_for(name: str, entry: Any) -> list[str]:
    if name.startswith("tool_registry_"):
        return []
    if entry.domain:
        return [entry.domain]
    if name in {"ssh_exec", "ssh_key_exec", "hydra_ssh_brute", "test_credential", "test_db_credential"}:
        return ["network"]
    if name in _WEB_NAMES:
        return ["web"]
    for domain, prefixes in _DOMAIN_PREFIXES:
        if any(name == prefix or name.startswith(prefix) for prefix in prefixes):
            return [domain]
    if name in {"nmap_scan", "nmap_full_scan", "nmap_port_range", "nmap_vulners_scan", "masscan_scan"}:
        return ["network"]
    if name in {"cloud_discovery_aws", "cloud_discovery_command"}:
        return ["cloud" if name.endswith("_aws") else "k8s"]
    return ["web"]


def _capability_for(name: str, domain: str) -> str:
    if name.startswith("tool_registry_"):
        return "tool_discovery"
    if name in _CAPABILITY_BY_NAME:
        return _CAPABILITY_BY_NAME[name]
    if name.startswith(("nmap", "masscan", "dirb", "gobuster", "nikto", "whatweb")):
        return "recon_scan"
    if name.startswith(("searchsploit", "go_exploitdb", "metasploit", "cve_", "ddg_", "knowledge_")):
        return "research_lookup"
    if domain == "ad":
        return "ad_attack" if any(x in name for x in ("pth", "ticket", "req", "relay", "psexec", "wmiexec", "secretsdump", "dacl", "whisker")) else "ad_enum"
    if domain == "k8s":
        return "k8s_discovery" if any(x in name for x in ("get_", "probe", "auth", "keys")) else "k8s_apply"
    if domain == "container":
        return "container_discovery" if name.startswith("container_find") or name == "container_recon_env" else "container_escape"
    if domain == "cloud":
        return "cloud_discovery"
    if domain == "db":
        return "sql_query"
    if domain == "lnx":
        return "linux_privilege"
    if domain == "network":
        return "network_capture" if name == "tcpdump_capture" else "recon_scan"
    if name.endswith(("_generate", "_forge")):
        return "payload_generate"
    return "web_exploit_send"


def _sync_python_defaults(entry: Any, parameters: dict[str, dict]) -> dict[str, dict]:
    """Copy callable defaults into the public schema when inspectable."""
    try:
        sig = inspect.signature(entry.func)
    except (TypeError, ValueError):
        return parameters
    for name, param in sig.parameters.items():
        if name in parameters and param.default is not inspect.Parameter.empty:
            parameters[name] = dict(parameters[name])
            parameters[name].setdefault("default", param.default)
    return parameters


def _dependencies(name: str, spec: Any) -> list[str]:
    """Return the primary external executable(s) used by a tool."""
    command = spec.command_template or " ".join(spec.shell_args)
    try:
        tokens = shlex.split(command)
    except ValueError:
        tokens = []
    wrappers = {"timeout", "env", "sudo"}
    if tokens and tokens[0] in wrappers:
        tokens = tokens[2:] if tokens[0] == "timeout" and len(tokens) > 1 else tokens[1:]
    if tokens and tokens[0] not in {"bash", "sh", "python", "python3", "curl"}:
        return [tokens[0]]
    executable_by_name = {
        "sqlmap_test": "sqlmap", "hydra_http_brute": "hydra", "hydra_ssh_brute": "hydra",
        "test_credential": "sshpass", "test_db_credential": "nc",
        "aws_iam_federation": "aws", "aws_sts_query": "curl", "object_store_get": "curl",
        "curl_get": "curl",
    }
    return [executable_by_name[name]] if name in executable_by_name else []


def _flags_for(name: str, domains: list[str]) -> dict[str, bool]:
    destructive_tokens = (
        "escape", "backdoor", "push", "write", "upload", "exec", "run", "apply",
        "brute", "poison", "relay", "ticket", "forge", "psexec", "wmiexec",
    )
    return {
        "destructive": any(token in name for token in destructive_tokens),
        "interactive": False,
        "requires_network": bool(domains and domains[0] not in {"research", "lnx"}),
        "idempotent": not any(token in name for token in destructive_tokens),
    }


def apply_explicit_contracts(gateway: Any) -> None:
    """Replace auto-derived specs with explicit, enriched contracts in-place."""
    for name, entry in gateway._registry.items():
        old = entry.spec or gateway.get_tool_specs().get(name)
        parameters = _sync_python_defaults(entry, {k: dict(v) for k, v in entry.parameters.items()})
        domains = _domain_for(name, entry)
        capability = _capability_for(name, domains[0] if domains else "")
        aliases = {
            alias: [target for target in targets if target in parameters]
            for alias, targets in _ALIASES.items()
            if alias not in parameters and any(target in parameters for target in targets)
        }
        dependencies = _dependencies(name, old) if old else []
        entry.parameters = parameters
        entry.spec = ToolSpec(
            name=name,
            version=old.version if old else "1.0.0",
            description=entry.description.strip(),
            domains=domains,
            capability=capability,
            parameters=parameters,
            executor=old.executor if old else "python",
            command_template=old.command_template if old else "",
            shell_args=list(old.shell_args) if old else [],
            split_params=list(old.split_params) if old else [],
            dependencies=dependencies,
            flags=_flags_for(name, domains),
            output_contract={"type": "tool_result", "success_field": "success"},
            aliases=aliases,
            deprecated=False,
            auto=False,
        )
