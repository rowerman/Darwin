"""Ingest benchmark GUIDE.md files into RAG scenario entries.

Phase 2 (hierarchical knowledge): each single-scenario GUIDE becomes a
leaf knowledge entry under ``knowledge/scenarios/<domain>/`` so the
taxonomy can route queries to a concrete scenario and the RAG can return
its exploitation steps.

Usage:
    python tools/ingest_benchmark_guides.py
    python tools/ingest_benchmark_guides.py --benchmark ../benchmark/cve_challenges/scenarios
"""

from __future__ import annotations

import argparse
import json
import os
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Binaries / clients that show up in the guides; used to tag each leaf with
# the client-side tools the scenario expects.
_BINS = [
    "curl", "kubectl", "docker", "helm", "etcdctl", "redis-cli", "redis",
    "psql", "mysql", "mongosh", "mongo", "sqlcmd", "oracle", "java",
    "python", "node", "go", "php", "ysoserial", "socat", "nc", "openssl",
    "crictl", "gcloud", "aws", "az", "sqlmap", "wpscan", "gdb", "odat",
    "grpcurl", "tiller", "kind",
]

# Guide binaries -> Darwin registered tool names (used for taxonomy linkage).
BIN_TO_TOOLS: dict[str, list[str]] = {
    "curl": ["curl_get", "http_post", "send_payload"],
    "kubectl": ["kubectl_exec", "kubectl_run", "kubectl_get_pods", "k8s_secret_dump"],
    "docker": ["docker_registry", "container_escape_docker_sock", "shell_exec"],
    "helm": ["helm"],
    "etcdctl": ["etcdctl_get", "k8s_etcd_keys"],
    "redis-cli": ["redis_cmd"],
    "redis": ["redis_cmd"],
    "psql": ["psql_query"],
    "mysql": ["mysql_query", "mysql_file_write"],
    "mongosh": ["mongodb_query", "nosql_inject"],
    "mongo": ["mongodb_query", "nosql_inject"],
    "sqlcmd": ["mssqlclient_query", "mssql_query"],
    "oracle": ["oracle_query", "oracle_tns_poison"],
    "java": ["ysoserial_generate", "tomcat_exploit"],
    "ysoserial": ["ysoserial_generate"],
    "python": ["shell_exec", "send_payload", "php_serialize_generate"],
    "node": ["kubectl_exec", "shell_exec"],
    "go": ["shell_exec"],
    "php": ["php_serialize_generate", "php_filter_chain"],
    "socat": ["shell_exec"],
    "nc": ["shell_exec"],
    "openssl": ["shell_exec"],
    "crictl": ["crictl_cmd"],
    "gcloud": ["gcloud_cli"],
    "aws": ["aws_cli", "aws_sts_query", "aws_iam_federation"],
    "az": ["az_cli"],
    "sqlmap": ["sqlmap_test"],
    "wpscan": ["wpscan_enum", "wp_xmlrpc_brute"],
    "gdb": ["kubectl_exec", "shell_exec"],
    "odat": ["oracle_tns_poison"],
    "grpcurl": ["shell_exec"],
    "tiller": ["helm"],
    "kind": ["shell_exec"],
}


def _grab(lines: list[str], pattern: str) -> str:
    for ln in lines:
        m = re.search(pattern, ln)
        if m:
            return m.group(1).strip()
    return ""


def _extract_steps(text: str) -> list[str]:
    """Extract numbered exploitation steps from the steps section only.

    Continuation lines (e.g. a code snippet on its own line after a numbered
    item, like ``cat /root/flag.txt``) are folded into the preceding step so
    techniques keep the commands that make them actionable.
    """
    lines = text.splitlines()
    start = None
    end = len(lines)
    for i, ln in enumerate(lines):
        heading = re.match(r"^\s*#{1,6}\s*(.*)$", ln)
        if heading is None:
            continue
        title = heading.group(1).lower()
        if start is None and ("利用步骤" in title or "exploit" in title
                              or "steps" in title):
            start = i + 1
        elif start is not None:
            end = i
            break
    if start is None:
        return []

    steps: list[str] = []
    current: list[str] | None = None
    for ln in lines[start:end]:
        numbered = re.match(r"^\s*(?:Step\s*)?\d+\.\s+(.*)$", ln)
        if numbered and numbered.group(1).strip():
            if current is not None:
                steps.append(" ".join(current).strip()[:240])
            current = [numbered.group(1).strip()]
        elif current is not None and ln.strip():
            current.append(ln.strip())
    if current is not None:
        steps.append(" ".join(current).strip()[:240])
    return [s for s in steps if s][:8]


def _steps_section_text(text: str) -> str:
    """Raw text of the numbered exploitation steps section (for tool scan)."""
    lines = text.splitlines()
    start = None
    end = len(lines)
    for i, ln in enumerate(lines):
        heading = re.match(r"^\s*#{1,6}\s*(.*)$", ln)
        if heading is None:
            continue
        title = heading.group(1).lower()
        if start is None and ("利用步骤" in title or "exploit" in title
                              or "steps" in title):
            start = i + 1
        elif start is not None:
            end = i
            break
    return "\n".join(lines[start:end]) if start is not None else ""


def _looks_like_http_steps(steps_text: str, title: str) -> bool:
    blob = f"{steps_text}\n{title}".lower()
    return any(k in blob for k in (
        "get /", "post /", "put /", "delete /", "curl ", "http://",
        "https://", "/api/", "/wsman", "/token",
    ))


def _detect_tools(text: str) -> list[str]:
    found: list[str] = []
    for b in _BINS:
        if re.search(
            rf"(?im)(^|[^a-z0-9_-]){re.escape(b)}(?=[^a-z0-9_-]|$)", text
        ):
            found.extend(BIN_TO_TOOLS.get(b, []))
    seen: set[str] = set()
    return [t for t in found if not (t in seen or seen.add(t))]


def parse_guide(path: Path) -> dict:
    """Parse one GUIDE.md into a RAG-compatible scenario entry."""
    text = path.read_text(encoding="utf-8", errors="replace")
    lines = text.splitlines()
    directory = path.parent.name
    domain_dir = path.parent.parent.name  # web / db / k8s / cloud
    title = _grab(lines, r"^#\s+(.+)") or directory
    tech = (
        _grab(lines, r"\| 技术/CVE \|\s*(.+?)\s*\|")
        or _grab(lines, r"\| Technique \|\s*(.+?)\s*\|")
    )
    core = _grab(lines, r"\| 核心漏洞与利用 \|\s*(.+?)\s*\|")
    flag = re.search(r"flag\{[^}\n]*\}", text)
    steps_text = _steps_section_text(text)
    steps = _extract_steps(text)
    tools = _detect_tools(steps_text)
    if not tools and _looks_like_http_steps(steps_text, title):
        tools = ["curl_get", "http_post", "send_payload"]
    subcategory = (tech or core or title)[:80]
    description = "\n".join(
        part for part in (core, *steps) if part
    )[:1500]
    return {
        "id": f"scenario-{directory}",
        "guid": title.split(":")[0].strip() if ":" in title else "",
        "title": title,
        "category": domain_dir,
        "subcategory": subcategory,
        "description": description or f"Benchmark scenario: {title}",
        "techniques": steps,
        "indicators": [],
        "tags": [domain_dir, directory] + ([tech] if tech else []),
        "tools": tools,
        "prerequisites": [],
        "confidence": 0.6,  # guide-sourced, pending live verification
        "mitre_attack": "",
        "references": [],
        "flag": flag.group(0) if flag else "",
        "source": (
            str(path.relative_to(ROOT))
            if path.is_relative_to(ROOT)
            else os.path.relpath(path, ROOT)
        ).replace("\\", "/"),
    }


def _load_registry_mapping(scenarios_yaml: Path) -> dict[str, str]:
    """Map scenario directory -> registry id (e.g. actor-token -> cloud-21)."""
    mapping: dict[str, str] = {}
    if not scenarios_yaml.exists():
        return mapping
    current: str | None = None
    for line in scenarios_yaml.read_text(encoding="utf-8").splitlines():
        m = re.match(r"^  ([\w-]+):\s*$", line)
        if m:
            current = m.group(1)
            continue
        if current:
            pm = re.search(
                r"path:\s*scenarios/(?:cloud|web|db|k8s)/([\w-]+)", line
            )
            if pm:
                mapping[pm.group(1)] = current
    return mapping


def check_entries(
    entries: list[dict],
    guide_paths: list[Path],
    registry_mapping: dict[str, str],
) -> list[str]:
    """Return validation errors; an empty list means the knowledge is OK."""
    errors: list[str] = []
    notes: list[str] = []
    seen_ids: set[str] = set()
    for e in entries:
        eid = str(e.get("id", ""))
        if eid in seen_ids:
            errors.append(f"duplicate entry id: {eid}")
        seen_ids.add(eid)
        flag = str(e.get("flag", ""))
        if not flag.startswith("flag{") or not flag.endswith("}"):
            source = str(e.get("source", ""))
            guide = Path(source) if os.path.isabs(source) else ROOT / source
            if guide.exists() and "flag{" in guide.read_text(
                encoding="utf-8", errors="replace"
            ):
                errors.append(f"{eid}: flag missing or truncated: {flag!r}")
            else:
                notes.append(f"{eid}: no flag pattern in GUIDE.md (accepted)")
        if not str(e.get("description", "")).strip():
            errors.append(f"{eid}: empty description")
        directory = eid.replace("scenario-", "")
        reg_id = registry_mapping.get(directory, "")
        if reg_id and reg_id.split("-", 1)[0].upper() == "CLOUD":
            reg_prefix = reg_id.split("-", 1)[0].upper() + "-" + reg_id.split("-", 1)[1]
            title = str(e.get("title", ""))
            if not title.startswith(reg_prefix):
                errors.append(
                    f"{eid}: title {title!r} does not start with registry id "
                    f"{reg_prefix}"
                )
    guide_ids = {f"scenario-{p.parent.name}" for p in guide_paths}
    for eid in sorted(guide_ids - seen_ids):
        errors.append(f"missing KB entry for guide: {eid}")
    for note in notes:
        print(f"  note: {note}")
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--benchmark",
        default=str(ROOT / ".." / "benchmark" / "cve_challenges" / "scenarios"),
        help="benchmark scenarios root",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="validate knowledge entries against the benchmark without writing",
    )
    args = parser.parse_args(argv)

    scenarios_root = Path(args.benchmark).resolve()
    if not scenarios_root.is_dir():
        print(f"benchmark scenarios root not found: {scenarios_root}", file=__import__("sys").stderr)
        return 1

    by_domain: dict[str, list[dict]] = {}
    total = 0
    for guide in sorted(scenarios_root.rglob("GUIDE.md")):
        entry = parse_guide(guide)
        by_domain.setdefault(entry["category"], []).append(entry)
        total += 1

    registry_mapping = _load_registry_mapping(
        scenarios_root.parent / "scripts" / "scenarios.yaml"
    )
    errors: list[str] = []
    for domain, entries in by_domain.items():
        guide_paths = [
            g for g in sorted(scenarios_root.rglob("GUIDE.md"))
            if g.parent.parent.name == domain
        ]
        errors.extend(check_entries(entries, guide_paths, registry_mapping))
    if errors:
        print("knowledge check failed:")
        for err in errors[:40]:
            print(f"  - {err}")
        return 1
    if args.check:
        print(f"knowledge check OK ({total} scenario guides)")
        return 0

    out_root = ROOT / "knowledge" / "scenarios"
    out_root.mkdir(parents=True, exist_ok=True)
    for domain, entries in sorted(by_domain.items()):
        target = out_root / domain / "benchmark_guides.json"
        target.parent.mkdir(parents=True, exist_ok=True)
        entries.sort(key=lambda e: e["id"])
        target.write_text(
            json.dumps(entries, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        print(f"wrote {target} ({len(entries)} entries)")

    print(f"total scenarios ingested: {total}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
