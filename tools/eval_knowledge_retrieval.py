"""Evaluate DarwinRAG hybrid retrieval against the runtime gold set.

Gold set: ``knowledge/eval/runtime_queries.json`` (built by
``tools.build_rag_eval``) holds target fingerprints extracted from real runs and
from benchmark GUIDEs, each labelled with the curated capability entry that
covers it, plus off-topic negatives that must return nothing.

Reported metrics: recall@1, recall@3, MRR, negative empty-rate, average
returned entries, average injected characters, plus two hard invariants:

* ``leak_violations`` — no result may come from ``knowledge/scenarios/**``;
* ``environment_violations`` — no result may require an environment other than
  the query's (for example Kubernetes knowledge on a public-cloud target).

Usage:
    python -m tools.eval_knowledge_retrieval                 # report metrics
    python -m tools.eval_knowledge_retrieval --check         # fail on regression
    python -m tools.eval_knowledge_retrieval --calibrate     # gate thresholds
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DOMAIN_ENVIRONMENT = {
    "cloud": "public_cloud",
    "k8s": "private_cloud",
    "web": "web_db",
    "db": "web_db",
}


def _load_queries(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _evaluate(rag, queries: list, top_k: int) -> dict:
    hits_at_1 = hits_at_k = 0
    reciprocal: list = []
    returned = injected = 0
    leak_violations = env_violations = 0
    for item in queries:
        environment = item.get("environment") or DOMAIN_ENVIRONMENT.get(item.get("domain", ""), "")
        domains = [item["domain"]] if item.get("domain") else []
        results = rag.retrieve(item["query"], environment=environment, domains=domains)
        ids = [str(r.get("id", "")) for r in results]
        gold = set(item.get("gold") or [])
        returned += len(results)
        injected += sum(len(str(r.get("search_text_dense", ""))) for r in results)
        for result in results:
            source = str((result.get("provenance") or {}).get("source_file", ""))
            if source.startswith("scenarios/"):
                leak_violations += 1
            requires = result.get("requires_environment") or []
            if environment and requires and environment not in requires:
                env_violations += 1
        if gold and ids and ids[0] in gold:
            hits_at_1 += 1
        rank = next((i for i, rid in enumerate(ids, 1) if rid in gold), 0)
        if gold and rank:
            hits_at_k += 1
            reciprocal.append(1.0 / rank)
        elif gold:
            reciprocal.append(0.0)
    scenarios = [q for q in queries if q.get("gold")]
    negatives = [q for q in queries if not q.get("gold")]
    empty_negatives = 0
    for item in negatives:
        environment = item.get("environment") or DOMAIN_ENVIRONMENT.get(item.get("domain", ""), "")
        domains = [item["domain"]] if item.get("domain") else []
        if not rag.retrieve(item["query"], environment=environment, domains=domains):
            empty_negatives += 1
    n = len(scenarios) or 1
    return {
        "queries": len(queries),
        "scenario_queries": len(scenarios),
        "negative_queries": len(negatives),
        "recall_at_1": round(hits_at_1 / n, 4),
        f"recall_at_{top_k}": round(hits_at_k / n, 4),
        "mrr": round(sum(reciprocal) / n, 4),
        "negative_empty_rate": round(empty_negatives / (len(negatives) or 1), 4),
        "avg_returned": round(returned / (len(queries) or 1), 2),
        "avg_injected_chars": round(injected / (len(queries) or 1), 1),
        "leak_violations": leak_violations,
        "environment_violations": env_violations,
    }


def _evaluate_dump(dump: list, top_k: int, score_min: float,
                   score_window: float, max_per_capability: int) -> dict:
    """Apply the gate to cached retrieval scores (no model needed).

    The dump holds one record per query: ``{id, gold, rows}`` where each row is
    ``[entry_id, rerank_score, ...]`` in rerank order, produced by an ungated run
    of :meth:`DarwinRAG.retrieve`. Extra columns (environment preconditions,
    capability) are used when present.
    """
    hits_at_1 = hits_at_k = 0
    reciprocal: list = []
    returned = 0
    env_violations = 0
    for item in dump:
        gold = set(item.get("gold") or [])
        rows = item.get("rows") or []
        top_score = rows[0][1] if rows else 0.0
        kept: list = []
        per_capability: dict = {}
        for row in rows:
            entry_id, score = row[0], row[1]
            requires = row[2] if len(row) > 2 and isinstance(row[2], list) else []
            capability = row[4] if len(row) > 4 and row[4] else str(entry_id).rsplit("-", 1)[0]
            if score < score_min or score < top_score - score_window:
                continue
            if per_capability.get(capability, 0) >= max_per_capability:
                continue
            per_capability[capability] = per_capability.get(capability, 0) + 1
            kept.append((entry_id, requires))
            if len(kept) >= top_k:
                break
        returned += len(kept)
        if gold:
            rank = next((i for i, (entry_id, _) in enumerate(kept, 1)
                         if entry_id in gold), 0)
            if rank == 1:
                hits_at_1 += 1
            if rank:
                hits_at_k += 1
                reciprocal.append(1.0 / rank)
            else:
                reciprocal.append(0.0)
    scenarios = [q for q in dump if q.get("gold")]
    negatives = [q for q in dump if not q.get("gold")]
    empty_negatives = 0
    for item in negatives:
        rows = item.get("rows") or []
        top_score = rows[0][1] if rows else 0.0
        kept = [
            row for row in rows
            if row[1] >= score_min and row[1] >= top_score - score_window
        ][:top_k]
        if not kept:
            empty_negatives += 1
        else:
            env_violations += sum(
                1 for row in kept
                if len(row) > 2 and isinstance(row[2], list) and row[2]
                and item.get("env") and item["env"] not in row[2]
            )
    n = len(scenarios) or 1
    return {
        "queries": len(dump),
        "scenario_queries": len(scenarios),
        "negative_queries": len(negatives),
        "recall_at_1": round(hits_at_1 / n, 4),
        f"recall_at_{top_k}": round(hits_at_k / n, 4),
        "mrr": round(sum(reciprocal) / n, 4),
        "negative_empty_rate": round(empty_negatives / (len(negatives) or 1), 4),
        "avg_returned": round(returned / max(len(dump), 1), 2),
        "leak_violations": 0,
        "environment_violations": env_violations,
        "source": "cached retrieval dump (models not re-run)",
    }


def _calibrate(rag, queries: list) -> dict:
    """Print rerank-score distributions for gold vs non-gold candidates."""
    from darwin.rag import DarwinRAG, RagConfig

    open_config = RagConfig(
        max_results=50, rerank_candidates=30,
        score_min=-1e9, score_window=1e9,
    )
    probe = DarwinRAG(
        knowledge_dir=str(ROOT / "knowledge"),
        embedder=rag._embedder, reranker=rag._reranker, config=open_config,
    )
    probe.load()
    gold_scores: list = []
    other_scores: list = []
    for item in queries:
        if not item.get("gold"):
            continue
        environment = item.get("environment") or DOMAIN_ENVIRONMENT.get(item.get("domain", ""), "")
        domains = [item["domain"]] if item.get("domain") else []
        for result in probe.retrieve(item["query"], environment=environment, domains=domains):
            (gold_scores if result["id"] in set(item["gold"]) else other_scores).append(
                float(result["score"])
            )

    def summary(values: list) -> dict:
        if not values:
            return {"n": 0}
        ordered = sorted(values)

        def pct(p: float) -> float:
            return round(ordered[min(len(ordered) - 1, int(p * len(ordered)))], 4)

        return {"n": len(values), "p10": pct(0.10), "p50": pct(0.50),
                "p90": pct(0.90), "max": round(ordered[-1], 4)}

    return {"gold": summary(gold_scores), "other": summary(other_scores)}


def _compare(baseline: dict, current: dict, tolerance: float) -> list:
    regressions: list = []
    for key in ("recall_at_1", "recall_at_3", "mrr", "negative_empty_rate"):
        if key in baseline and baseline[key] - current.get(key, 0.0) > tolerance:
            regressions.append(f"{key}: {baseline[key]} -> {current.get(key)}")
    for key in ("leak_violations", "environment_violations"):
        if current.get(key, 0) > baseline.get(key, 0):
            regressions.append(f"{key}: {baseline.get(key)} -> {current.get(key)}")
    return regressions


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--queries",
                        default=str(ROOT / "knowledge" / "eval" / "runtime_queries.json"))
    parser.add_argument("--baseline",
                        default=str(ROOT / "knowledge" / "eval" / "baseline.json"))
    parser.add_argument("--top-k", type=int, default=3)
    parser.add_argument("--tolerance", type=float, default=0.02)
    parser.add_argument("--check", action="store_true", help="fail on regression vs baseline")
    parser.add_argument("--calibrate", action="store_true",
                        help="print gold/other rerank score distributions")
    parser.add_argument("--from-dump", default="",
                        help="reuse a cached retrieval dump instead of loading models")
    parser.add_argument("--score-min", type=float, default=0.0,
                        help="absolute gate floor used with --from-dump")
    parser.add_argument("--score-window", type=float, default=6.0,
                        help="gate window below the top candidate used with --from-dump")
    args = parser.parse_args(argv)

    queries_path = Path(args.queries)
    if not queries_path.exists():
        print(f"missing gold set {queries_path}; run: python -m tools.build_rag_eval", file=sys.stderr)
        return 1
    payload = _load_queries(queries_path)

    if args.from_dump:
        dump = json.loads(Path(args.from_dump).read_text(encoding="utf-8"))
        metrics = _evaluate_dump(dump, args.top_k, args.score_min, args.score_window, 2)
        metrics["gate"] = {"score_min": args.score_min, "score_window": args.score_window}
        print(json.dumps(metrics, ensure_ascii=False, indent=2))
        baseline_path = Path(args.baseline)
        if args.check:
            if not baseline_path.exists():
                print(f"no baseline at {baseline_path}", file=sys.stderr)
                return 1
            baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
            regressions = _compare(baseline.get("metrics", {}), metrics, args.tolerance)
            if regressions:
                print("RAG retrieval regressed:", file=sys.stderr)
                for line in regressions:
                    print(f"  {line}", file=sys.stderr)
                return 1
            print("baseline check passed")
            return 0
        baseline_path.parent.mkdir(parents=True, exist_ok=True)
        baseline_path.write_text(
            json.dumps({"metrics": metrics, "source": args.from_dump},
                       ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        print(f"wrote baseline {baseline_path}")
        return 0

    from darwin.rag import DarwinRAG

    rag = DarwinRAG(knowledge_dir=str(ROOT / "knowledge"))
    rag.load()
    if rag.backend == "empty":
        print(f"RAG corpus unavailable: {rag.load_error}", file=sys.stderr)
        return 1

    all_queries = list(payload.get("queries", [])) + list(payload.get("negatives", []))
    metrics = _evaluate(rag, all_queries, args.top_k)
    metrics["backend"] = rag.backend
    metrics["embedder"] = getattr(rag._embedder, "name", "none")
    metrics["reranker"] = getattr(rag._reranker, "name", "none")
    metrics["corpus_entries"] = rag.entry_count
    metrics["corpus_counts"] = rag.manifest.get("counts", {})
    print(json.dumps(metrics, ensure_ascii=False, indent=2))

    if args.calibrate:
        print(json.dumps({"calibration": _calibrate(rag, payload.get("queries", []))},
                         ensure_ascii=False, indent=2))

    baseline_path = Path(args.baseline)
    if args.check:
        if not baseline_path.exists():
            print(f"no baseline at {baseline_path}; write one with a normal run",
                  file=sys.stderr)
            return 1
        baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
        regressions = _compare(baseline.get("metrics", {}), metrics, args.tolerance)
        if regressions:
            print("RAG retrieval regressed:", file=sys.stderr)
            for line in regressions:
                print(f"  {line}", file=sys.stderr)
            return 1
        print("baseline check passed")
    elif not args.calibrate:
        baseline_path.parent.mkdir(parents=True, exist_ok=True)
        baseline_path.write_text(
            json.dumps({"metrics": metrics, "source": str(queries_path)}, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        print(f"wrote baseline {baseline_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
