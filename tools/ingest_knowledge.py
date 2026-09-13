"""Knowledge maintenance CLI for the unified DarwinRAG corpus.

The runtime reads only ``knowledge/corpus/*.jsonl``, which is generated from the
authoring sources. Adding knowledge therefore means either:

* authoring a curated capability entry under ``knowledge/capabilities/*.json``
  (validated against ``darwin.rag.entry.v1``), or
* adding a legacy knowledge file under ``knowledge/**`` (converted mechanically).

Both paths end with this tool: validate, rebuild the corpus artifact, refresh
the vector cache.

Usage:
    python -m tools.ingest_knowledge --check          # lint sources + artifact sync
    python -m tools.ingest_knowledge --rebuild        # rebuild corpus + vector cache
    python -m tools.ingest_knowledge --stats          # corpus/backend summary
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true",
                        help="run the corpus lint and artifact sync check")
    parser.add_argument("--rebuild", action="store_true",
                        help="rebuild the corpus artifact and vector cache")
    parser.add_argument("--stats", action="store_true", help="print corpus statistics")
    parser.add_argument("--knowledge-dir", default=str(ROOT / "knowledge"))
    args = parser.parse_args(argv)

    if not any((args.check, args.rebuild, args.stats)):
        parser.print_help()
        return 1

    from tools.build_rag_corpus import main as build_main
    from tools.rag_lint import main as lint_main

    knowledge_dir = args.knowledge_dir
    status = 0

    if args.check or args.rebuild:
        status |= lint_main(["--knowledge-dir", knowledge_dir])
        if status:
            print("corpus lint failed — fix the reported entries first", file=sys.stderr)
            return status

    if args.check:
        status |= build_main(["--knowledge-dir", knowledge_dir, "--check"])
    if args.rebuild or args.check:
        if args.rebuild:
            status |= build_main(["--knowledge-dir", knowledge_dir])
        from tools.build_rag_index import main as index_main
        index_args = ["--knowledge-dir", knowledge_dir, "--stats"]
        if args.rebuild:
            index_args.append("--rebuild")
        status |= index_main(index_args)
    if args.stats:
        from darwin.rag import DarwinRAG

        rag = DarwinRAG(knowledge_dir=knowledge_dir)
        rag.load()
        stats = rag.stats()
        print(f"entries={stats['entries']} backend={stats['backend']}")
        print(f"  embedder: {stats['embedder']}")
        print(f"  reranker: {stats['reranker']}")
        print(f"  by domain: {stats['by_domain']}")
    return status


if __name__ == "__main__":
    raise SystemExit(main())
