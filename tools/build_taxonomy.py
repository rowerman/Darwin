"""Build the explicit knowledge taxonomy (Phase 2).

The taxonomy is a domain -> technique-class -> scenario-leaf tree that
drives two-stage retrieval (route first, then search inside the subtree).
Leaves are the benchmark scenarios ingested by
``tools/ingest_benchmark_guides.py``; their ``id`` matches the RAG entry
id (``scenario-<directory>``).

Usage:
    python tools/build_taxonomy.py
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _load_scenario_entries() -> list[dict]:
    entries: list[dict] = []
    for path in sorted((ROOT / "knowledge" / "scenarios").rglob("*.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        items = data if isinstance(data, list) else [data]
        entries.extend(item for item in items if isinstance(item, dict))
    return entries


def _slug(text: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return slug[:40] or "misc"


def _capability_for(entry: dict, guid: str) -> str:
    """Coarse capability mapping from the benchmark scenario domain/guid."""
    root = entry.get("category") or ""
    if root == "db":
        return "sql_query"
    if root == "k8s":
        name = (entry.get("title") or "").lower()
        if any(k in name for k in ("secret", "rbac", "token", "etcd", "kubelet")):
            return "secret_dump"
        if any(k in name for k in ("escape", "breakout", "hostpath", "runc", "socket", "cgroup", "seccomp", "ptrace")):
            return "container_escape"
        return "k8s_apply"
    if root == "cloud":
        name = (entry.get("title") or "").lower()
        if any(k in name for k in ("iam", "role", "saml", "oidc", "scp", "passrole", "assume", "token", "lambda", "federation")):
            return "cloud_iam_assume"
        if any(k in name for k in ("registry", "image", "supply")):
            return "registry_push"
        if any(k in name for k in ("secret", "credential", "key")):
            return "secret_dump"
        return "web_exploit_send"
    return "web_exploit_send"


def _leaf_path(entry: dict) -> list[str]:
    root = entry.get("category") or "misc"
    sub = _slug(entry.get("subcategory") or entry.get("title") or "misc")
    return [root, sub]


def build_taxonomy(entries: list[dict]) -> dict:
    """Build {version, roots, leaves} from scenario entries."""
    roots: dict[str, dict] = {}
    leaves: list[dict] = []
    for entry in sorted(entries, key=lambda e: e.get("id", "")):
        path = _leaf_path(entry)
        root = roots.setdefault(path[0], {"name": path[0], "children": []})
        child_names = [c["name"] for c in root["children"]]
        if path[1] not in child_names:
            root["children"].append({"name": path[1], "children": []})
        leaves.append(
            {
                "id": entry.get("id", ""),
                "guid": entry.get("guid", ""),
                "title": entry.get("title", ""),
                "path": path,
                "tools": list(entry.get("tools") or []),
                "capability": _capability_for(entry, entry.get("guid", "")),
                "source": entry.get("source", ""),
            }
        )
    return {
        "version": 1,
        "roots": [roots[k] for k in sorted(roots)],
        "leaves": leaves,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--out", default=str(ROOT / "knowledge" / "taxonomy.json"),
        help="taxonomy output path",
    )
    args = parser.parse_args(argv)

    entries = _load_scenario_entries()
    if not entries:
        print(
            "no scenario entries found — run tools/ingest_benchmark_guides.py first",
            file=__import__("sys").stderr,
        )
        return 1

    taxonomy = build_taxonomy(entries)
    out = Path(args.out)
    out.write_text(
        json.dumps(taxonomy, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(
        f"wrote {out}: {len(taxonomy['leaves'])} leaves, "
        f"{len(taxonomy['roots'])} roots"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
