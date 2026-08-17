"""Automated coverage audit: taxonomy leaves vs tools, capabilities, knowledge.

Phase 3 (linkage): for every taxonomy leaf (benchmark scenario) verify:

    - leaf.tools      ⊆ registered gateway tool names
    - leaf.capability ∈ CapabilityRegistry
    - a knowledge entry exists for leaf.id in knowledge/scenarios/**

Output: TOOL_COVERAGE_AUDIT.md at the repo root.

Usage:
    python -m tools.audit_coverage
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _load_scenario_ids() -> set[str]:
    ids: set[str] = set()
    for path in sorted((ROOT / "knowledge" / "scenarios").rglob("*.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        items = data if isinstance(data, list) else [data]
        for item in items:
            if isinstance(item, dict) and item.get("id"):
                ids.add(str(item["id"]))
    return ids


def audit() -> dict:
    from darwin.core.capabilities import default_registry
    from darwin.tools.attack_server import create_attack_gateway
    from darwin.tools.recon_server import create_recon_gateway

    taxonomy = json.loads(
        (ROOT / "knowledge" / "taxonomy.json").read_text(encoding="utf-8")
    )
    leaves = taxonomy.get("leaves", [])
    registered = (
        set(create_attack_gateway().get_tool_names())
        | set(create_recon_gateway().get_tool_names())
    )
    capabilities = {c.name for c in default_registry().list()}
    scenario_ids = _load_scenario_ids()

    rows = []
    for leaf in sorted(leaves, key=lambda l: str(l.get("id", ""))):
        tools = [str(t) for t in (leaf.get("tools") or [])]
        capability = str(leaf.get("capability") or "")
        entry_id = str(leaf.get("id") or "")
        problems = []
        missing_tools = [t for t in tools if t not in registered]
        if missing_tools:
            problems.append(f"tools_gap:{','.join(missing_tools)}")
        if capability and capability not in capabilities:
            problems.append(f"capability_gap:{capability}")
        if entry_id and entry_id not in scenario_ids:
            problems.append("knowledge_gap")
        rows.append(
            {
                "id": entry_id,
                "guid": str(leaf.get("guid") or ""),
                "path": "/".join(str(p) for p in (leaf.get("path") or [])),
                "capability": capability,
                "tools": tools,
                "status": "OK" if not problems else ";".join(problems),
            }
        )
    return {
        "leaves": rows,
        "summary": {
            "total": len(rows),
            "ok": sum(1 for r in rows if r["status"] == "OK"),
            "with_problems": sum(1 for r in rows if r["status"] != "OK"),
        },
    }


def render_markdown(result: dict) -> str:
    lines = [
        "# Darwin 覆盖率自动巡检（taxonomy 叶子 → 工具/能力/知识）",
        "",
        f"- 叶子总数：{result['summary']['total']}",
        f"- 完全 OK：{result['summary']['ok']}",
        f"- 存在问题：{result['summary']['with_problems']}",
        "",
        "| id | guid | path | capability | tools | status |",
        "|---|---|---|---|---|---|",
    ]
    for row in result["leaves"]:
        lines.append(
            f"| {row['id']} | {row['guid']} | {row['path']} | "
            f"{row['capability']} | {', '.join(row['tools']) or '-'} | {row['status']} |"
        )
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", default=str(ROOT / "TOOL_COVERAGE_AUDIT.md"))
    args = parser.parse_args(argv)
    result = audit()
    Path(args.out).write_text(
        render_markdown(result), encoding="utf-8"
    )
    print(
        f"audit: {result['summary']['total']} leaves, "
        f"{result['summary']['ok']} OK, "
        f"{result['summary']['with_problems']} with problems"
    )
    for row in result["leaves"]:
        if row["status"] != "OK":
            print(f"  {row['id']}: {row['status']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
