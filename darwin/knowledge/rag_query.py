"""Query construction and runtime context for DarwinRAG retrieval.

All call sites (research, planning, fix analysis, the ``knowledge_search``
tool) share these helpers so a retrieval query always describes *the target
fingerprint and the technique class being pursued*, never a benchmark scenario
name.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional, Sequence

# Observed evidence -> canonical domain tag (aligned with tools_manifest domains).
DOMAIN_SIGNATURES: Dict[str, Sequence[str]] = {
    "k8s": ("kube", "kubernetes", "kubelet", "etcd", "rbac", "clusterrole",
            "serviceaccount", "namespace", "pod ", "cni", "helm", "tiller"),
    "container": ("docker", "container", "containerd", "runc", "cgroup",
                  "privileged", "overlayfs", "cri "),
    "cloud": ("aws", "amazon", "azure", "gcp", "google cloud", "imds", "metadata",
              "s3", "sts", "iam", "lambda", "cloudformation", "saml", "oidc",
              "ec2", "eks", "service tag", "sas token", "pickle"),
    "ad": ("active directory", "kerberos", "ldap", "smb", "ntlm", "domain controller",
           "adcs", "gpo", "bloodhound"),
    "db": ("mysql", "postgres", "mssql", "sql server", "oracle", "mongodb",
           "redis", "couchdb", "elasticsearch", "nosql", "database"),
    "web": ("http", "https", "nginx", "apache", "flask", "werkzeug", "php",
            "wordpress", "graphql", "jwt", "rest", "api"),
    "network": ("ssh", "ftp", "smb", "dns", "smtp", "snmp", "ldap", "rdp",
                "tcp", "port scan"),
}

# Technique-class keywords used to enrich the query with canonical English terms.
TECHNIQUE_TERMS: Dict[str, str] = {
    "sqli": "sql injection",
    "sql": "sql injection",
    "xss": "cross-site scripting",
    "ssrf": "server-side request forgery",
    "ssti": "server-side template injection",
    "xxe": "xml external entity",
    "lfi": "local file inclusion",
    "rfi": "remote file inclusion",
    "idor": "insecure direct object reference",
    "authbypass": "authentication bypass",
    "auth_bypass": "authentication bypass",
    "cmdi": "command injection",
    "rce": "remote code execution",
    "deserialization": "insecure deserialization",
    "path_traversal": "path traversal",
    "privesc": "privilege escalation",
    "misconfig": "security misconfiguration",
    "platformdiscovery": "cloud platform service discovery",
    "weak auth": "weak authentication default credentials",
    "weak_auth": "weak authentication default credentials",
}


def active_domains(texts: Iterable[str]) -> List[str]:
    """Canonical domains implied by observed service/banner/hypothesis text."""
    blob = " ".join(str(t or "").lower() for t in texts)
    found = [
        domain for domain, signature in DOMAIN_SIGNATURES.items()
        if any(term in blob for term in signature)
    ]
    return found


def build_capability_query(
    services: Optional[Sequence[Any]] = None,
    vulns: Optional[Sequence[Any]] = None,
    observations: Optional[Sequence[str]] = None,
    extra_terms: Optional[Sequence[str]] = None,
) -> str:
    """Compose an English-canonical retrieval query from runtime fingerprint."""
    terms: List[str] = []
    for service in services or []:
        version = getattr(service, "version", "") or ""
        banner = getattr(service, "banner", "") or ""
        if isinstance(service, dict):
            version = service.get("version") or ""
            banner = service.get("banner") or ""
        label = str(version or banner).split("(")[0].strip()
        if label and label.lower() not in ("unknown", "http", "https", "tcpwrapped"):
            terms.append(label[:60])
    for vuln in vulns or []:
        raw_type = str(getattr(vuln, "vuln_type", "") or (
            vuln.get("vuln_type", "") if isinstance(vuln, dict) else ""))
        key = raw_type.strip().lower()
        terms.append(TECHNIQUE_TERMS.get(key, raw_type))
        endpoint = str(getattr(vuln, "endpoint", "") or (
            vuln.get("endpoint", "") if isinstance(vuln, dict) else ""))
        if endpoint:
            terms.append(endpoint[:80])
    terms.extend(str(o)[:120] for o in observations or [])
    terms.extend(str(e)[:80] for e in extra_terms or [])
    seen: set = set()
    ordered: List[str] = []
    for term in terms:
        cleaned = term.strip()
        if cleaned and cleaned.lower() not in seen:
            seen.add(cleaned.lower())
            ordered.append(cleaned)
    return " ".join(ordered[:10])


def environment_from_dkg(dkg: Any) -> str:
    """Read the deterministic environment classification recorded during recon."""
    if dkg is None:
        return ""
    try:
        for node in dkg.query_nodes("Analysis"):
            classification = node.get("classification")
            if isinstance(classification, dict) and classification.get("kind"):
                return str(classification["kind"])
    except Exception:  # silent-ok: classification is an optional signal
        return ""
    return ""


def domains_from_dkg(dkg: Any) -> List[str]:
    """Domains implied by discovered services, endpoints and hypotheses."""
    if dkg is None:
        return []
    texts: List[str] = []
    try:
        for node_type in ("Service", "Endpoint", "Vulnerability", "Analysis"):
            for node in dkg.query_nodes(node_type):
                texts.append(" ".join(str(v) for v in node.values()))
    except Exception:  # silent-ok: best-effort domain inference
        return []
    return active_domains(texts)
