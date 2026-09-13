"""Unified RAG corpus: schema, legacy conversion, lint and search-text rendering.

Runtime retrieval reads one artifact: ``knowledge/corpus/*.jsonl`` produced by
``tools/build_rag_corpus.py``. Every entry — newly authored capabilities and
all converted legacy knowledge — shares the same ``darwin.rag.entry.v1`` shape
so they compete in the same retrieval pool.

The only knowledge that never enters the runtime corpus is
``knowledge/scenarios/**``: those files are benchmark GUIDE dumps that carry the
target-specific walkthrough and flag, so they are kept for offline evaluation
only.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

SCHEMA_VERSION = "darwin.rag.entry.v1"
BUILDER_VERSION = 1
CORPUS_DIRNAME = "corpus"

# Domain vocabulary aligned with tools_manifest.json tool domains.
DOMAINS = ("web", "cloud", "k8s", "container", "db", "ad", "network", "generic")

# Environment preconditions, aligned with darwin.environment.EnvironmentKind.
ENVIRONMENTS = ("public_cloud", "private_cloud", "hybrid", "web_db")

# Domain -> environment precondition applied when a converter cannot decide.
DOMAIN_ENVIRONMENTS: Dict[str, List[str]] = {
    "k8s": ["private_cloud", "hybrid"],
    "cloud": ["public_cloud", "hybrid"],
    "container": [],
    "ad": [],
    "web": [],
    "db": [],
    "network": [],
    "generic": [],
}

ENTRY_FIELDS = (
    "id", "title", "capability", "domains", "requires_environment",
    "applies_when", "signals", "technique_class", "verification",
    "failure_boundary", "tools", "cve_ids", "aliases", "confidence",
    "provenance", "search_text_dense", "search_text_sparse",
)

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)
_VERSION_RANGE_RES = (
    re.compile(r"(?:before|prior to|through|up to)\s+v?(\d[\w.\-]*)", re.I),
    re.compile(r"(\d+\.\d+(?:\.\d+)*)\s*(?:and earlier|before|through)", re.I),
    re.compile(r"(?:<=|<=|&lt;=)\s*v?(\d[\w.\-]*)", re.I),
)
_PAYLOAD_MARKERS = ("${", "{{", "}}", "<script", "bash -i", "nc -e", "/bin/sh",
                    "base64 -d", "curl http", "wget http", "powershell -enc",
                    "eyJ", "O:8:", "eval(", "exec(")
_SIGNAL_HINTS = ("indicates", "detect", "check whether", "if the response",
                 "returns", "reveals", "exposes", "observable", "verify")

_K8S_TERMS = ("kube", "kubernetes", "etcd", "pod ", "pods", "rbac", "clusterrole",
              "serviceaccount", "service account", "daemonset", "statefulset",
              "hostpath", "kubelet", "namespace")
_CONTAINER_TERMS = ("docker", "container", "containerd", "runc", "cgroup",
                    "cap_sys_admin", "privileged", "procfs", "image registry")
_DB_TERMS = ("mysql", "postgres", "mssql", "sql server", "oracle", "mongodb",
             "redis", "couchdb", "elasticsearch", "sqlite", "sql ", "nosql")
_AD_TERMS = ("active directory", "kerberos", "ldap", "domain controller", "adcs",
             "ntlm", "smb", "gpo", "bloodhound")

_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_HOST_PORT_RE = re.compile(r"\b(?:localhost|127\.0\.0\.1|0\.0\.0\.0)(?::\d{2,5})?")
_HOME_PATH_RE = re.compile(r"(?:/home|/root|/Users)/[\w.\-]+(?:/[\w.\-]+)*")
_FLAG_RE = re.compile(r"flag\{[^}]*\}", re.I)
_HTTP_SHAPE_RE = re.compile(r"^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(\S+)", re.I)
_OPEN_PORT_RE = re.compile(r"^(\d{1,5}/\w+)\s+open\s+(\S+)(?:\s+(.*))?$", re.M)
_HEADER_LINE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9-]{1,30}:\s")
_BODY_MARKERS = ("webkitformboundary", "content-disposition", "boundary=",
                 'name="', "accept:", "content-type:", "user-agent:", "origin:",
                 "referer:", "cookie:", "authorization:")
_VULN_CLASSES = (
    ("sql injection", "sql_injection"), ("sqli", "sql_injection"),
    ("cross-site scripting", "xss"), ("xss", "xss"),
    ("remote code execution", "rce"), ("rce", "rce"), ("command execution", "rce"),
    ("file upload", "file_upload"), ("directory traversal", "path_traversal"),
    ("local file inclusion", "path_traversal"), ("lfi", "path_traversal"),
    ("path traversal", "path_traversal"), ("ssrf", "ssrf"),
    ("xml external entity", "xxe"), ("xxe", "xxe"),
    ("authentication bypass", "auth_bypass"), ("auth bypass", "auth_bypass"),
    ("unauthorized access", "auth_bypass"), ("default login", "default_credentials"),
    ("default credentials", "default_credentials"), ("weak password", "default_credentials"),
    ("information disclosure", "information_disclosure"), ("disclosure", "information_disclosure"),
    ("directory listing", "information_disclosure"), ("exposure", "information_disclosure"),
    ("deserialization", "deserialization"), ("open redirect", "open_redirect"),
    ("privilege escalation", "privilege_escalation"), ("backdoor", "backdoor"),
    ("injection", "injection"), ("csrf", "csrf"), ("idor", "idor"),
    ("heap overflow", "memory_corruption"), ("buffer overflow", "memory_corruption"),
)


def _slug(text: str, max_len: int = 48) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", (text or "").lower()).strip("-")
    return slug[:max_len] or "misc"


def _as_list(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value] if value.strip() else []
    if isinstance(value, (list, tuple, set)):
        return [str(v).strip() for v in value if str(v).strip()]
    return [str(value)]


def _blob(entry: Dict[str, Any]) -> str:
    parts = [str(entry.get("title", ""))]
    parts.extend(_as_list(entry.get("techniques")))
    parts.extend(_as_list(entry.get("tags")))
    parts.append(str(entry.get("description", "")))
    return " ".join(parts).lower()


def sanitize_text(text: str) -> str:
    """Strip environment-specific values so converted entries stay transferable."""
    cleaned = str(text or "")
    cleaned = _FLAG_RE.sub("<flag>", cleaned)
    cleaned = re.sub(r"\{\{[^}]*\}\}", " ", cleaned)
    cleaned = _HOME_PATH_RE.sub("<path>", cleaned)
    cleaned = _HOST_PORT_RE.sub("<host>", cleaned)
    cleaned = _IP_RE.sub("<host>", cleaned)
    return re.sub(r"\s+", " ", cleaned).strip()


# ── Legacy parsers ───────────────────────────────────────────────────


def parse_json_file(path: Path) -> List[Dict[str, Any]]:
    """Parse a legacy JSON knowledge file into raw dicts."""
    data = json.loads(path.read_text(encoding="utf-8"))
    items = data if isinstance(data, list) else [data]
    return [i for i in items if isinstance(i, dict)]


def parse_markdown_file(path: Path) -> Optional[Dict[str, Any]]:
    """Parse a knowledge Markdown file into a raw dict.

    Handles the ``**元数据**:`` footer format when present; otherwise the whole
    body is treated as description with headings/lists extracted.
    """
    text = path.read_text(encoding="utf-8", errors="replace")
    parts = re.split(r"\*\*(?:元数据|Metadata)\*\*\s*:", text, maxsplit=1)
    content = parts[0].strip()
    metadata: Dict[str, str] = {}
    if len(parts) > 1:
        for line in parts[1].strip().split("\n"):
            kv = line.strip().lstrip("-*").strip().split(":", 1)
            if len(kv) == 2:
                metadata[kv[0].strip().lower().replace(" ", "_")] = kv[1].strip().strip('"\'')
    if not content:
        return None

    title = metadata.get("title") or path.stem
    for line in content.split("\n"):
        if line.startswith("# "):
            title = line[2:].strip()
            break

    inline: Dict[str, str] = {}
    techniques: List[str] = []
    for line in content.split("\n"):
        stripped = line.strip()
        pair = re.match(r"^\*\*(.+?)\*\*\s*[:：]\s*(.+)$", stripped)
        if pair:
            inline[pair.group(1).strip()] = pair.group(2).strip()
        if stripped.startswith(("- ", "* ")) or (
            stripped.startswith("**") and stripped.endswith("**") and len(stripped) > 4
        ):
            item = stripped.lstrip("-*").strip()
            if item:
                techniques.append(item)

    return {
        "id": metadata.get("technique_id") or metadata.get("id") or path.stem,
        "title": title,
        "category": metadata.get("category", ""),
        "subcategory": metadata.get("tactics", metadata.get("subcategory", "")),
        "description": content[:1200],
        "techniques": techniques[:12],
        "indicators": [],
        "tags": _as_list(metadata.get("platform")) + _as_list(metadata.get("tags")),
        "tools": _as_list(metadata.get("tools")),
        "mitre_attack": metadata.get("technique_id", ""),
        "confidence": 0.7,
        "_inline_fields": inline,
    }


# ── Source classification ────────────────────────────────────────────


def source_kind_for(path: Path) -> str:
    name = path.name.lower()
    stem = path.stem.lower()
    rel = path.as_posix()
    if path.suffix == ".md":
        if "attck-containers" in rel:
            return "attck_md"
        if "cis-benchmark" in rel:
            return "cis_md"
        if "remediation-templates" in rel:
            return "remediation_md"
        if "attack-cases" in rel:
            return "case_md"
        return "article_md"
    if name == "nuclei_cve_templates.json":
        return "nuclei_template"
    if "hacktricks" in stem:
        return "hacktricks"
    if stem.endswith("_pat") or "_pat" in stem:
        return "pat_notes"
    if stem.endswith("_oscp") or "_oscp" in stem:
        return "oscp_notes"
    if "converted" in stem:
        return "article"
    if name == "cloudformation_injection.json":
        return "cloudformation_json"
    parent = path.parent.name
    return {
        "cloud": "cloud_json",
        "windows_ad": "ad_json",
        "network": "network_json",
        "web": "web_json",
    }.get(parent, "web_json")


def domains_for(path: Path) -> Tuple[str, ...]:
    """Domain tags implied by the source file location."""
    rel = path.as_posix()
    name = path.name.lower()
    if "/cloud/attck-containers/" in rel or "/cloud/attack-cases/" in rel:
        return ("container",)
    if "/cloud/cis-benchmark/" in rel or "/cloud/remediation-templates/" in rel:
        return ("k8s", "container")
    if ("k8s" in name or "kubernetes" in name or "container" in name):
        return ("k8s", "container")
    if "/cloud/" in rel:
        return ("cloud",)
    if "/windows_ad/" in rel:
        return ("ad",)
    if "/network/" in rel:
        if any(k in name for k in ("database", "nosql", "default_credentials")):
            return ("db",)
        return ("network",)
    if name == "db_exploitation.json":
        return ("db",)
    return ("web",)


def _refine_domains(domains: Sequence[str], entry: Dict[str, Any]) -> List[str]:
    """Add k8s/container/db/ad/cloud tags implied by entry text."""
    found = list(domains)
    blob = _blob(entry)
    if any(k in blob for k in _K8S_TERMS) and "k8s" not in found:
        found.append("k8s")
    if any(k in blob for k in _CONTAINER_TERMS) and "container" not in found:
        found.append("container")
    if any(k in blob for k in _DB_TERMS) and "db" not in found:
        found.append("db")
    if any(k in blob for k in _AD_TERMS) and "ad" not in found:
        found.append("ad")
    if not found:
        found = ["generic"]
    return found


# ── Field derivation ─────────────────────────────────────────────────


def extract_cve_ids(entry: Dict[str, Any]) -> List[str]:
    blob = " ".join([
        str(entry.get("title", "")),
        str(entry.get("description", "")),
        " ".join(_as_list(entry.get("references"))),
        " ".join(_as_list(entry.get("tags"))),
    ])
    return sorted({m.upper() for m in _CVE_RE.findall(blob)})


def extract_version_hints(entry: Dict[str, Any]) -> List[str]:
    blob = f"{entry.get('title', '')} {entry.get('description', '')}"
    hints: List[str] = []
    for regex in _VERSION_RANGE_RES:
        for match in regex.findall(blob):
            hints.append(str(match))
    return list(dict.fromkeys(hints))[:3]


def sanitize_technique(text: str) -> Optional[str]:
    """Keep technique *classes*; drop entries that are really concrete payloads."""
    cleaned = re.sub(r"\{\{[^}]*\}\}", "<target-path>", str(text)).strip()
    cleaned = re.sub(r"\s+", " ", cleaned)
    if not cleaned:
        return None
    lowered = cleaned.lower()
    if any(marker in lowered for marker in _PAYLOAD_MARKERS):
        return None
    if any(marker in lowered for marker in _BODY_MARKERS):
        return None
    if _HEADER_LINE_RE.match(cleaned) or "---" in cleaned:
        return None
    if cleaned[:1] in "{[(" and ":" in cleaned:
        return None
    if re.match(r"^[A-Z]+ \S+ HTTP/\d", cleaned):
        return None
    if cleaned.startswith(("- ", "* ")):
        cleaned = cleaned[2:].strip()
    if len(cleaned) < 8:
        return None
    if len(cleaned) > 200:
        cleaned = cleaned[:197] + "..."
    return cleaned


def derive_signals(entry: Dict[str, Any], limit: int = 4) -> List[str]:
    indicators = _as_list(entry.get("indicators"))
    if indicators:
        return [sanitize_text(i)[:160] for i in indicators[:limit]]
    signals: List[str] = []
    for sentence in re.split(r"(?<=[。.!?])\s+", str(entry.get("description", ""))):
        stripped = sentence.strip()
        if stripped.startswith(("- ", "* ", "#", "|")) or "```" in stripped:
            continue
        lowered = stripped.lower()
        if any(hint in lowered for hint in _SIGNAL_HINTS) and 20 < len(stripped) < 200:
            signals.append(sanitize_text(stripped)[:160])
        if len(signals) >= limit:
            break
    return signals


def derive_applies_when(entry: Dict[str, Any], title: str,
                        signals: Sequence[str]) -> Tuple[List[str], bool]:
    """Return (applies_when, used_generic_fallback)."""
    prerequisites = _as_list(entry.get("prerequisites"))
    if prerequisites:
        return prerequisites[:4], False
    conditions: List[str] = []
    versions = extract_version_hints(entry)
    if versions:
        conditions.append(f"目标组件版本落在受影响范围（{'/'.join(versions)}）")
    if signals:
        conditions.append(f"目标出现可观测特征：{signals[0][:100]}")
    if conditions:
        return conditions[:4], False
    tags = [t for t in _as_list(entry.get("tags")) if t.lower() not in DOMAINS]
    if tags:
        return [f"目标存在「{title[:60]}」对应的技术/组件（关键词：{'/'.join(tags[:3])}）"], True
    return [f"适用于与「{title[:60]}」同类技术/组件的目标"], True


def derive_verification(entry: Dict[str, Any], source_kind: str,
                        signals: Sequence[str], cve_ids: Sequence[str]) -> str:
    if source_kind == "nuclei_template":
        cve = cve_ids[0] if cve_ids else "该条目"
        return f"按该请求复现并确认响应与 {cve} 描述的可观测结果一致"
    if source_kind == "remediation_md":
        return "对照目标配置确认该缓解措施是否已生效；未生效则视为可利用面"
    if source_kind == "cis_md":
        return "对照集群配置审计项确认该控制是否缺失；缺失即为可利用面"
    if signals:
        return f"构造最小请求复现后，观察是否出现：{signals[0][:100]}"
    return "构造最小请求复现，观察响应是否出现条目描述的可观测结果"


def derive_failure_boundary(entry: Dict[str, Any], source_kind: str) -> List[str]:
    if source_kind == "nuclei_template":
        return ["目标版本不在受影响范围，或已安装对应补丁"]
    if source_kind == "remediation_md":
        title = str(entry.get("title", ""))
        stripped = re.sub(r"^(修复方案[:：]\s*)", "", title).strip()
        return [f"目标已实施「{stripped}」对应的加固"]
    boundaries: List[str] = []
    for sentence in re.split(r"(?<=[。.!?])\s+", str(entry.get("description", ""))):
        lowered = sentence.lower()
        if any(k in lowered for k in ("patched", "fixed in", "not vulnerable",
                                      "requires authentication", "已修复", "不适用")):
            boundaries.append(sentence.strip()[:160])
        if len(boundaries) >= 3:
            break
    return boundaries


def _normalize_capability(raw: str, domains: Sequence[str]) -> str:
    slug = _slug(raw, 32)
    if slug in ("misc", "general", "n-a", ""):
        return f"{domains[0]}_technique" if domains else "generic_technique"
    return slug


def _vuln_class(text: str) -> str:
    lowered = text.lower()
    for needle, slug in _VULN_CLASSES:
        if needle in lowered:
            return slug
    return ""


def _looks_like_scan_dump(raw: Dict[str, Any]) -> bool:
    title = str(raw.get("title", ""))
    if title.lower().startswith("nmap ") or "nmap scan report" in str(raw.get("description", "")).lower():
        return True
    techniques = _as_list(raw.get("techniques"))
    return any(_OPEN_PORT_RE.search(t) for t in techniques[:6])


def _scan_signals(raw: Dict[str, Any], limit: int = 5) -> List[str]:
    text = str(raw.get("description", "")) + "\n" + "\n".join(_as_list(raw.get("techniques")))
    signals: List[str] = []
    for match in _OPEN_PORT_RE.finditer(text):
        service = match.group(2)
        version = (match.group(3) or "").strip()
        signal = f"目标开放端口 {match.group(1)} {service} {version}".strip()
        if signal not in signals:
            signals.append(sanitize_text(signal)[:140])
        if len(signals) >= limit:
            break
    return signals


def source_fields(raw: Dict[str, Any], source_kind: str) -> Dict[str, Any]:
    """Per-source structured-field extraction for converted entries."""
    title = str(raw.get("title", "")).strip()
    if source_kind == "nuclei_template":
        product, vuln_part = title, ""
        for sep in (" - ", ": ", " : "):
            if sep in title:
                product, vuln_part = title.split(sep, 1)
                break
        product = product.strip()
        version = ""
        match = re.search(r"\bv?(\d+(?:\.\d+)+)\b", product)
        if match:
            version = match.group(1)
        klass = _vuln_class(f"{vuln_part} {title}")
        methods = []
        for technique in _as_list(raw.get("techniques")):
            shape = _HTTP_SHAPE_RE.match(str(technique).strip())
            if shape and shape.group(1).upper() not in methods:
                methods.append(shape.group(1).upper())
        applies = [f"目标运行 {sanitize_text(product)}" + (f"（版本 {version}）" if version else "")]
        versions = extract_version_hints(raw)
        if versions:
            applies.append(f"版本落在受影响范围：{'/'.join(versions)}")
        technique_class = [f"HTTP {'/'.join(methods) or 'GET'} 请求已知易受影响的端点"]
        if klass:
            technique_class.append(klass.replace("_", " "))
        return {
            "applies_when": applies,
            "technique_class": technique_class,
            "capability": klass or "known_vulnerability",
            "aliases": {"en": ([klass.replace("_", " ")] if klass else []) + [product]},
        }
    if _looks_like_scan_dump(raw):
        signals = _scan_signals(raw)
        return {
            "applies_when": ["处于信息收集阶段、需要对目标做端口/服务指纹识别的场景"],
            "signals": signals,
            "technique_class": ["端口与服务版本识别（扫描结果记录）"],
            "capability": "recon_scan",
        }
    if source_kind == "attck_md":
        stripped = title.replace("MITRE ATT&CK:", "").strip()
        ttp = stripped.split("-", 1)[0].strip()
        ttp_name = stripped.split("-", 1)[1].strip() if "-" in stripped else stripped
        detection = [sanitize_text(t)[:160] for t in _as_list(raw.get("techniques"))[:3]]
        return {
            "applies_when": [f"目标环境出现 {ttp} 所描述的对手行为或可观测面"],
            "technique_class": [ttp_name],
            "signals": detection,
            "capability": "attack_technique",
        }
    if source_kind == "cis_md":
        control = title.split(":", 1)[-1].strip()
        return {
            "applies_when": [f"集群存在未加固项：{control}"],
            "technique_class": [control],
            "capability": "misconfig_assessment",
        }
    if source_kind == "remediation_md":
        inline = raw.get("_inline_fields") or {}
        risk = str(inline.get("风险类型") or "").strip()
        stripped = re.sub(r"^(修复方案[:：]\s*)", "", title).strip()
        return {
            "applies_when": [
                f"目标容器/集群未实施「{stripped}」对应加固"
                + (f"，风险类型：{sanitize_text(risk)}" if risk else "")
            ],
            "technique_class": [sanitize_text(risk)] if risk else [stripped],
            "capability": "misconfig_assessment",
        }
    return {}


_REGISTERED_TOOLS: Optional[set] = None


def registered_tools(manifest_path: Optional[Path] = None) -> set:
    """Tool names from tools_manifest.json, used to drop hallucinated tool refs."""
    global _REGISTERED_TOOLS
    if _REGISTERED_TOOLS is not None:
        return _REGISTERED_TOOLS
    path = manifest_path or Path(__file__).resolve().parent.parent / "tools_manifest.json"
    names: set = set()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        names = {str(t.get("name", "")) for t in data.get("tools", []) if t.get("name")}
    except Exception:  # silent-ok: manifest is optional for corpus building
        names = set()
    _REGISTERED_TOOLS = names
    return names


# ── Entry construction ───────────────────────────────────────────────


def render_search_texts(entry: Dict[str, Any]) -> Tuple[str, str]:
    """Build (dense_text, sparse_text).

    Dense text is natural language for the embedding channel; sparse text
    repeats high-signal fields to approximate per-field BM25 boosts.
    """
    aliases = entry.get("aliases") or {}
    alias_terms = _as_list(aliases.get("zh")) + _as_list(aliases.get("en"))
    dense_parts = [
        str(entry.get("title", "")),
        " ".join(_as_list(entry.get("applies_when"))),
        " ".join(_as_list(entry.get("signals"))),
        " ".join(_as_list(entry.get("technique_class"))),
        str(entry.get("verification", "")),
        " ".join(_as_list(entry.get("failure_boundary"))),
        " ".join(alias_terms),
    ]
    dense = " 。 ".join(p.strip() for p in dense_parts if p and p.strip())

    sparse_parts = [
        " ".join([str(entry.get("title", ""))] * 3),
        " ".join(alias_terms * 2),
        " ".join(_as_list(entry.get("cve_ids")) * 2),
        " ".join(_as_list(entry.get("tools")) * 2),
        " ".join(_as_list(entry.get("technique_class"))),
        " ".join(_as_list(entry.get("signals"))),
        " ".join(_as_list(entry.get("domains"))),
    ]
    sparse = " ".join(p.strip() for p in sparse_parts if p and p.strip())
    return dense.strip(), sparse.strip()


def build_entry(raw: Dict[str, Any], *, path: Path, knowledge_root: Path,
                source_kind: str, domains: Sequence[str],
                provenance_kind: str) -> Dict[str, Any]:
    """Convert one raw (legacy or curated) record into a unified entry."""
    converted = provenance_kind == "converted"
    overrides = source_fields(raw, source_kind) if converted else {}
    title = str(raw.get("title") or raw.get("id") or "").strip()
    entry_domains = _refine_domains(domains, raw)
    signals = _as_list(raw.get("signals")) or overrides.get("signals") or derive_signals(raw)
    if raw.get("applies_when"):
        applies_when, generic_fallback = _as_list(raw["applies_when"]), False
    elif overrides.get("applies_when"):
        applies_when, generic_fallback = list(overrides["applies_when"]), False
    else:
        applies_when, generic_fallback = derive_applies_when(raw, title, signals)
    techniques: List[str] = []
    if not converted and raw.get("technique_class"):
        techniques = _as_list(raw["technique_class"])
    elif overrides.get("technique_class"):
        for item in _as_list(overrides["technique_class"]):
            cleaned = sanitize_technique(item)
            if cleaned and cleaned not in techniques:
                techniques.append(cleaned)
    else:
        for item in _as_list(raw.get("techniques")) + _as_list(raw.get("technique")):
            cleaned = sanitize_technique(item)
            if cleaned and cleaned not in techniques:
                techniques.append(cleaned)
    for item in _as_list(raw.get("technique_class")):
        cleaned = sanitize_technique(item)
        if cleaned and cleaned not in techniques:
            techniques.append(cleaned)
    cve_ids = extract_cve_ids(raw) or _as_list(raw.get("cve_ids"))
    verification = str(raw.get("verification") or "").strip() or derive_verification(
        raw, source_kind, signals, cve_ids
    )
    failure_boundary = _as_list(raw.get("failure_boundary")) or derive_failure_boundary(
        raw, source_kind
    )

    tools = [t for t in _as_list(raw.get("tools")) if t in registered_tools()]
    requires = _as_list(raw.get("requires_environment"))
    if not requires:
        # Environment preconditions come from the source domain (file location or
        # the curated entry's own tags); content-derived tags only refine topics.
        for domain in domains:
            for env in DOMAIN_ENVIRONMENTS.get(domain, []):
                if env not in requires:
                    requires.append(env)

    aliases = raw.get("aliases") if isinstance(raw.get("aliases"), dict) else {}
    alias_en = _as_list(aliases.get("en")) or [
        t for t in _as_list(raw.get("tags"))
        if t.lower() not in DOMAINS and not t.lower().startswith(("cve-",))
    ][:6]
    for item in (overrides.get("aliases") or {}).get("en", []):
        if item and item not in alias_en:
            alias_en.append(item)
    alias_zh = _as_list(aliases.get("zh"))

    provenance = {
        "kind": provenance_kind,
        "source_kind": source_kind,
        "source_file": path.relative_to(knowledge_root).as_posix()
        if path.is_relative_to(knowledge_root) else path.as_posix(),
        "derived_from": str(raw.get("derived_from") or ""),
        "reviewed": provenance_kind == "curated",
        "applies_when_derived": generic_fallback,
    }

    entry: Dict[str, Any] = {
        "id": str(raw.get("id") or _slug(title)),
        "title": title,
        "capability": _normalize_capability(
            str(overrides.get("capability") or raw.get("capability") or raw.get("category") or ""),
            entry_domains,
        ),
        "domains": entry_domains,
        "requires_environment": requires,
        "applies_when": applies_when,
        "signals": signals,
        "technique_class": techniques[:6],
        "verification": verification,
        "failure_boundary": failure_boundary,
        "tools": tools,
        "cve_ids": cve_ids,
        "aliases": {"zh": alias_zh, "en": alias_en},
        "confidence": float(raw.get("confidence") or 0.5),
        "provenance": provenance,
    }
    if converted:
        for key in ("title", "verification"):
            entry[key] = sanitize_text(entry[key])
        for key in ("applies_when", "signals", "technique_class", "failure_boundary"):
            entry[key] = [sanitize_text(v) for v in entry[key]]
        entry["aliases"] = {
            "zh": [sanitize_text(v) for v in entry["aliases"]["zh"]],
            "en": [sanitize_text(v) for v in entry["aliases"]["en"]],
        }
        if not entry["technique_class"]:
            entry["technique_class"] = [sanitize_text(entry["title"])[:120]]
    dense, sparse = render_search_texts(entry)
    entry["search_text_dense"] = dense
    entry["search_text_sparse"] = sparse
    return entry


# ── Lint ─────────────────────────────────────────────────────────────


_TARGET_VALUE_RE = re.compile(
    r"(flag\{|127\.0\.0\.1|localhost:\d{2,5}|\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b|"
    r"\b192\.168\.\d{1,3}\.\d{1,3}\b|\{\{[^}]*\}\})", re.I
)


def lint_entry(entry: Dict[str, Any]) -> List[str]:
    """Return schema/quality violations for a unified entry."""
    problems: List[str] = []
    if not entry.get("id"):
        problems.append("missing_id")
    if not entry.get("title"):
        problems.append("missing_title")
    if not entry.get("capability"):
        problems.append("missing_capability")
    domains = entry.get("domains")
    if not isinstance(domains, list) or not domains:
        problems.append("missing_domains")
    elif any(d not in DOMAINS for d in domains):
        problems.append("unknown_domain")
    requires = entry.get("requires_environment")
    if not isinstance(requires, list):
        problems.append("bad_requires_environment")
    elif any(e not in ENVIRONMENTS for e in requires):
        problems.append("unknown_environment")
    for key in ("applies_when", "signals", "technique_class", "failure_boundary"):
        if not isinstance(entry.get(key), list):
            problems.append(f"bad_{key}")
    if not entry.get("applies_when"):
        problems.append("empty_applies_when")
    if not str(entry.get("verification") or "").strip():
        problems.append("empty_verification")
    provenance = entry.get("provenance")
    if not isinstance(provenance, dict) or provenance.get("kind") not in ("curated", "converted"):
        problems.append("bad_provenance")
    haystack = " ".join([
        str(entry.get("title", "")),
        " ".join(_as_list(entry.get("technique_class"))),
        " ".join((entry.get("aliases") or {}).get("zh", [])),
        " ".join((entry.get("aliases") or {}).get("en", [])),
    ])
    if _TARGET_VALUE_RE.search(haystack):
        problems.append("target_specific_value")
    if not entry.get("search_text_dense") or not entry.get("search_text_sparse"):
        problems.append("missing_search_text")
    return problems


# ── Corpus build ─────────────────────────────────────────────────────


@dataclass
class CorpusBuild:
    entries: List[Dict[str, Any]] = field(default_factory=list)
    excluded: List[Dict[str, Any]] = field(default_factory=list)
    problems: List[Dict[str, Any]] = field(default_factory=list)
    weak_applies_when: int = 0


def _iter_source_files(knowledge_root: Path) -> Iterable[Path]:
    for path in sorted(list(knowledge_root.rglob("*.json")) + list(knowledge_root.rglob("*.md"))):
        rel_parts = path.relative_to(knowledge_root).parts
        if rel_parts and rel_parts[0] in ("scenarios", CORPUS_DIRNAME, "eval"):
            continue
        if path.name == "taxonomy.json":
            continue
        if path.name == "index_policy.json":
            continue
        yield path


def build_corpus(knowledge_root: Path) -> CorpusBuild:
    """Convert every knowledge source under ``knowledge_root`` into entries."""
    result = CorpusBuild()
    seen_ids: Dict[str, int] = {}

    for path in _iter_source_files(knowledge_root):
        if path.suffix == ".json":
            try:
                raw_items = parse_json_file(path)
            except Exception as exc:
                result.problems.append({"file": path.as_posix(), "reason": f"parse_error:{exc}"})
                continue
        else:
            parsed = parse_markdown_file(path)
            raw_items = [parsed] if parsed else []

        source_kind = source_kind_for(path)
        domains = domains_for(path)
        is_curated = "capabilities" in path.parts and path.parent.name == "capabilities"
        for raw in raw_items:
            if is_curated:
                domains = tuple(_as_list(raw.get("domains"))) or domains
            entry = build_entry(
                raw, path=path, knowledge_root=knowledge_root,
                source_kind="curated" if is_curated else source_kind,
                domains=domains,
                provenance_kind="curated" if is_curated else "converted",
            )
            problems = lint_entry(entry) if is_curated else [
                p for p in lint_entry(entry) if p in ("empty_applies_when", "empty_verification")
            ]
            if not entry["title"]:
                # Source rendered no usable title (for example a bare Markdown
                # include directive); the entry carries nothing to retrieve on.
                result.problems.append({"file": path.as_posix(), "reason": "dropped:empty_title"})
                continue
            if problems:
                result.problems.append(
                    {"file": path.as_posix(), "id": entry.get("id"), "problems": problems}
                )
            if entry["provenance"].get("applies_when_derived"):
                result.weak_applies_when += 1
            base_id = entry["id"]
            if base_id in seen_ids:
                seen_ids[base_id] += 1
                entry["id"] = f"{base_id}#{seen_ids[base_id]}"
            else:
                seen_ids[base_id] = 1
            result.entries.append(entry)

    # Benchmark GUIDE dumps never enter the runtime corpus.
    scenarios_root = knowledge_root / "scenarios"
    if scenarios_root.exists():
        for path in sorted(scenarios_root.rglob("*.json")):
            try:
                count = len(parse_json_file(path))
            except Exception:
                count = 0
            result.excluded.append(
                {"file": path.relative_to(knowledge_root).as_posix(),
                 "reason": "answer_leak", "entries": count}
            )
    return result


def corpus_manifest(entries: Sequence[Dict[str, Any]], knowledge_root: Path,
                    build: Optional[CorpusBuild] = None) -> Dict[str, Any]:
    by_domain: Dict[str, int] = {}
    by_source: Dict[str, int] = {}
    for entry in entries:
        by_domain[entry["domains"][0]] = by_domain.get(entry["domains"][0], 0) + 1
        kind = entry["provenance"]["source_kind"]
        by_source[kind] = by_source.get(kind, 0) + 1
    source_hashes = {}
    for path in _iter_source_files(knowledge_root):
        rel = path.relative_to(knowledge_root).as_posix()
        source_hashes[rel] = hashlib.sha256(path.read_bytes()).hexdigest()[:16]
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "builder_version": BUILDER_VERSION,
        "counts": {
            "total": len(entries),
            "curated": sum(1 for e in entries if e["provenance"]["kind"] == "curated"),
            "by_domain": dict(sorted(by_domain.items())),
            "by_source_kind": dict(sorted(by_source.items())),
        },
        "source_hashes": source_hashes,
    }
    if build is not None:
        manifest["excluded"] = build.excluded
        manifest["problems"] = build.problems[:50]
        manifest["problem_count"] = len(build.problems)
        manifest["weak_applies_when"] = build.weak_applies_when
    return manifest


def corpus_files(knowledge_root: Path) -> List[Path]:
    corpus_dir = knowledge_root / CORPUS_DIRNAME
    return sorted(corpus_dir.glob("*.jsonl"))


def write_corpus(entries: Sequence[Dict[str, Any]], knowledge_root: Path,
                 build: Optional[CorpusBuild] = None) -> Dict[str, Any]:
    """Write ``knowledge/corpus/*.jsonl`` plus the manifest."""
    corpus_dir = knowledge_root / CORPUS_DIRNAME
    corpus_dir.mkdir(parents=True, exist_ok=True)
    by_domain: Dict[str, List[Dict[str, Any]]] = {}
    for entry in entries:
        by_domain.setdefault(entry["domains"][0], []).append(entry)
    for domain, items in by_domain.items():
        items.sort(key=lambda e: e["id"])
        lines = [json.dumps(e, ensure_ascii=False, sort_keys=True) for e in items]
        (corpus_dir / f"{domain}.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")
    for stale in corpus_dir.glob("*.jsonl"):
        if stale.stem not in by_domain:
            stale.unlink()
    manifest = corpus_manifest(entries, knowledge_root, build)
    (corpus_dir / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return manifest


def load_corpus(knowledge_root: Path) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Load the built corpus. Returns (entries, manifest)."""
    corpus_dir = knowledge_root / CORPUS_DIRNAME
    manifest_path = corpus_dir / "manifest.json"
    if not manifest_path.exists():
        return [], {}
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    entries: List[Dict[str, Any]] = []
    for path in sorted(corpus_dir.glob("*.jsonl")):
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                entries.append(json.loads(line))
    return entries, manifest
