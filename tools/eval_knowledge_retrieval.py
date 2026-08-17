"""A/B evaluation of flat RAG vs hierarchical (Phase 2) retrieval.

Builds one query per benchmark GUIDE (title + core exploitation row),
with the gold leaf id ``scenario-<directory>``, then compares:

    - flat:  DarwinRAG.search()
    - hier:  DarwinRAG.search_hierarchical()

Metrics: Recall@1 / Recall@5 / MRR / injected-token estimate (sum of
description lengths in the top-k window).

Usage:
    python tools/eval_knowledge_retrieval.py
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _build_queries(scenarios_root: Path) -> list[dict]:
    queries: list[dict] = []
    for guide in sorted(scenarios_root.rglob("GUIDE.md")):
        text = guide.read_text(encoding="utf-8", errors="replace")
        title = ""
        core = ""
        for ln in text.splitlines():
            if ln.startswith("# ") and not title:
                title = ln[2:].strip()
            m = re.search(r"\| 核心漏洞与利用 \|\s*(.+?)\s*\|", ln)
            if m and not core:
                core = m.group(1).strip()
        query = f"{title}. {core}".strip()
        queries.append(
            {
                "query": query,
                "gold": f"scenario-{guide.parent.name}",
                "scenario": guide.parent.name,
            }
        )
    return queries


def _evaluate(rag, queries: list[dict], hierarchical: bool, top_k: int) -> dict:
    recalls = {1: 0, top_k: 0}
    mrrs: list[float] = []
    injected = 0
    for item in queries:
        if hierarchical:
            results = rag.search_hierarchical(item["query"], top_k=top_k)
        else:
            results = rag.search(item["query"], top_k=top_k)
        ids = [str(r.get("id", "")) for r in results]
        injected += sum(len(str(r.get("description", ""))) for r in results)
        if item["gold"] in ids:
            recalls[1] += 1
            recalls[top_k] += 1
            mrrs.append(1.0 / (ids.index(item["gold"]) + 1))
        elif ids:
            recalls[top_k] += 0  # gold not found; count exact gold only
        else:
            recalls[top_k] += 0
    n = len(queries) or 1
    return {
        "mode": "hierarchical" if hierarchical else "flat",
        "queries": n,
        f"recall_at_1": round(recalls[1] / n, 4),
        f"recall_at_{top_k}": round(recalls[top_k] / n, 4),
        "mrr": round(sum(mrrs) / n, 4),
        "avg_injected_chars": round(injected / n, 1),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--benchmark",
        default=str(ROOT / ".." / "benchmark" / "cve_challenges" / "scenarios"),
    )
    parser.add_argument("--top-k", type=int, default=5)
    parser.add_argument("--out-dir", default=str(ROOT / "checkpoints" / "knowledge_eval"))
    args = parser.parse_args(argv)

    queries = _build_queries(Path(args.benchmark))
    if not queries:
        print("no queries built", file=__import__("sys").stderr)
        return 1

    from darwin.rag import DarwinRAG

    rag = DarwinRAG()
    loaded = rag.load(str(ROOT / "knowledge"))
    print(f"RAG loaded {loaded} entries; taxonomy leaves: {len(rag._taxonomy_leaves)}")

    flat = _evaluate(rag, queries, hierarchical=False, top_k=args.top_k)
    hier = _evaluate(rag, queries, hierarchical=True, top_k=args.top_k)

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "flat.json").write_text(
        json.dumps(flat, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    (out_dir / "hierarchical.json").write_text(
        json.dumps(hier, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    summary = {
        "flat": flat,
        "hierarchical": hier,
        "delta": {
            f"recall_at_{args.top_k}": round(
                hier[f"recall_at_{args.top_k}"] - flat[f"recall_at_{args.top_k}"], 4
            ),
            "mrr": round(hier["mrr"] - flat["mrr"], 4),
            "avg_injected_chars": round(
                hier["avg_injected_chars"] - flat["avg_injected_chars"], 1
            ),
        },
    }
    (out_dir / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
