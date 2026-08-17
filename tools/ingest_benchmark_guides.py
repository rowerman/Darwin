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
    steps: list[str] = []
    for ln in text.splitlines():
        m = re.match(r"^\s*(?:Step\s*)?\d+\.\s+(.+)", ln)
        if m and not re.match(r"^\s*\d+\.\s*$", ln):
            steps.append(m.group(1).strip()[:240])
    return steps[:8]


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
    flag = re.search(r"flag\{[^}\n]*", text)
    steps = _extract_steps(text)
    tools = _detect_tools(text)
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
        "source": str(path.relative_to(ROOT)).replace("\\", "/"),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--benchmark",
        default=str(ROOT / ".." / "benchmark" / "cve_challenges" / "scenarios"),
        help="benchmark scenarios root",
    )
    args = parser.parse_args(argv)

    scenarios_root = Path(args.benchmark)
    if not scenarios_root.is_dir():
        print(f"benchmark scenarios root not found: {scenarios_root}", file=__import__("sys").stderr)
        return 1

    out_root = ROOT / "knowledge" / "scenarios"
    out_root.mkdir(parents=True, exist_ok=True)

    by_domain: dict[str, list[dict]] = {}
    total = 0
    for guide in sorted(scenarios_root.rglob("GUIDE.md")):
        entry = parse_guide(guide)
        by_domain.setdefault(entry["category"], []).append(entry)
        total += 1

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
