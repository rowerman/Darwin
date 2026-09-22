"""One-off calibration for graph-similarity weights and the reuse threshold.

Run manually after new benchmark runs are available; the result feeds the
``memory`` section of ``config/darwin.yaml``.  It is not part of the test
suite and not part of the default regression.

    python -m tools.calibrate_graph_similarity
    python -m tools.calibrate_graph_similarity --out knowledge/eval/graph_similarity.json

Fingerprints come from the DKG checkpoints written during runs
(``checkpoints/checkpoint_*_loop_*.json``).  "Same family" means the two
checkpoints came from runs against the same target scope; the recommended
threshold is placed between the highest cross-family score and the lowest
same-family score, and reported as unreliable when the two overlap.
"""

from __future__ import annotations

import argparse
import itertools
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from darwin.dkg import DKG  # noqa: E402
from darwin.graph_fingerprint import (  # noqa: E402
    DEFAULT_WEIGHTS, build_snapshot, fingerprint, similarity,
)
from darwin.memory_config import MemoryConfig  # noqa: E402

CHECKPOINT_DIR = Path("checkpoints")


def load_fingerprints(checkpoint_dir: Path) -> List[Dict[str, Any]]:
    """Fingerprint every DKG checkpoint that has a usable graph."""
    records: List[Dict[str, Any]] = []
    for path in sorted(checkpoint_dir.glob("checkpoint_*.json")):
        if path.name.endswith("_bootstrap.json"):
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            dkg = DKG.from_dict(data)
        except (OSError, json.JSONDecodeError, KeyError, ValueError) as exc:
            print(f"  skip {path.name}: {exc}")
            continue
        if dkg.graph.number_of_nodes() == 0:
            continue
        scope = str((dkg.scope or {}).get("target_scope", "") or path.name)
        snapshot = build_snapshot(dkg, labels={"scope": scope})
        records.append({
            "source": path.name,
            "scope": scope,
            "fingerprint": fingerprint(snapshot),
        })
    return records


def pair_scores(records: List[Dict[str, Any]], weights: Dict[str, float]) -> Tuple[List[float], List[float], List[dict]]:
    same, cross, rows = [], [], []
    for left, right in itertools.combinations(records, 2):
        result = similarity(left["fingerprint"], right["fingerprint"], weights)
        row = {
            "left": left["source"], "right": right["source"],
            "same_scope": left["scope"] == right["scope"],
            "score": result["score"], "components": result["components"],
        }
        rows.append(row)
        (same if row["same_scope"] else cross).append(result["score"])
    return same, cross, rows


def summarize(same: List[float], cross: List[float]) -> Dict[str, Any]:
    def stats(values: List[float]) -> Dict[str, Any]:
        if not values:
            return {"n": 0}
        ordered = sorted(values)
        return {
            "n": len(ordered),
            "min": round(ordered[0], 4),
            "median": round(ordered[len(ordered) // 2], 4),
            "max": round(ordered[-1], 4),
        }

    report: Dict[str, Any] = {"same_scope": stats(same), "cross_scope": stats(cross)}
    if same and cross:
        report["recommended_threshold"] = round(
            (max(cross) + min(same)) / 2.0, 4
        )
        report["separable"] = min(same) > max(cross)
    else:
        report["recommended_threshold"] = None
        report["separable"] = False
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checkpoints", default=str(CHECKPOINT_DIR))
    parser.add_argument("--out", default="", help="Write the report as JSON here")
    args = parser.parse_args()

    config = MemoryConfig.from_files()
    records = load_fingerprints(Path(args.checkpoints))
    print(f"fingerprints: {len(records)}")
    if len(records) < 2:
        print("Not enough graphs to calibrate; keeping the configured defaults.")
        return 1

    same, cross, rows = pair_scores(records, config.similarity_weights)
    report = {
        "graphs": [{"source": r["source"], "scope": r["scope"],
                    "nodes": r["fingerprint"]["totals"]["nodes"]} for r in records],
        "weights": config.similarity_weights,
        "configured_threshold": config.reuse_threshold,
        **summarize(same, cross),
    }
    print(json.dumps(report, indent=2, ensure_ascii=False))
    if not report.get("separable"):
        print(
            "\nWARNING: same-scope and cross-scope scores overlap — the available "
            "graphs do not separate cleanly.  Keep the configured threshold and "
            "collect more runs before trusting reuse."
        )
    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(
            json.dumps({**report, "pairs": rows}, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        print(f"written: {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
