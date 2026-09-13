"""Lint the unified RAG corpus for schema and target-value violations.

Usage:
    python -m tools.rag_lint                 # lint the built corpus artifact
    python -m tools.rag_lint --sources       # lint freshly converted sources
"""

from __future__ import annotations

import argparse
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--knowledge-dir", default=str(ROOT / "knowledge"))
    parser.add_argument("--sources", action="store_true",
                        help="convert sources in memory instead of reading the artifact")
    parser.add_argument("--max-report", type=int, default=25)
    args = parser.parse_args(argv)

    from darwin.rag_corpus import build_corpus, lint_entry, load_corpus

    knowledge_root = Path(args.knowledge_dir)
    if args.sources:
        build = build_corpus(knowledge_root)
        entries = build.entries
    else:
        entries, _ = load_corpus(knowledge_root)

    counter: Counter = Counter()
    offenders = []
    blocking = {"empty_applies_when", "empty_verification", "missing_domains",
                "unknown_environment", "bad_provenance", "target_specific_value"}
    blocked = 0
    for entry in entries:
        problems = lint_entry(entry)
        if not problems:
            continue
        counter.update(problems)
        curated = entry.get("provenance", {}).get("kind") == "curated"
        if curated and any(p in blocking for p in problems):
            blocked += 1
        offenders.append((entry.get("id", ""), problems, curated))

    print(f"linted {len(entries)} entries; {len(offenders)} with notes")
    for name, count in counter.most_common():
        print(f"  {name}: {count}")
    for entry_id, problems, curated in offenders[:args.max_report]:
        tag = "curated" if curated else "converted"
        print(f"  - [{tag}] {entry_id}: {','.join(problems)}")
    if blocked:
        print(f"blocking problems in {blocked} curated entr(ies)", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
