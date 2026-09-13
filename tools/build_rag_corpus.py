"""Build the unified RAG corpus artifact (``knowledge/corpus/*.jsonl``).

Converts every legacy knowledge source plus the authored capability entries in
``knowledge/capabilities/**`` into the single ``darwin.rag.entry.v1`` schema so
all entries compete in one retrieval pool. ``knowledge/scenarios/**`` (benchmark
GUIDE dumps) is recorded as excluded and never enters the runtime corpus.

Usage:
    python -m tools.build_rag_corpus                 # rebuild the artifact
    python -m tools.build_rag_corpus --check         # assert artifact is in sync
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _render(entries) -> dict[str, str]:
    by_domain: dict[str, list] = {}
    for entry in entries:
        by_domain.setdefault(entry["domains"][0], []).append(entry)
    return {
        domain: "\n".join(
            json.dumps(e, ensure_ascii=False, sort_keys=True)
            for e in sorted(items, key=lambda e: e["id"])
        ) + "\n"
        for domain, items in by_domain.items()
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--knowledge-dir", default=str(ROOT / "knowledge"))
    parser.add_argument("--check", action="store_true",
                        help="verify the committed corpus matches the sources")
    args = parser.parse_args(argv)

    from darwin.rag_corpus import build_corpus, corpus_manifest, write_corpus

    knowledge_root = Path(args.knowledge_dir)
    build = build_corpus(knowledge_root)
    manifest = corpus_manifest(build.entries, knowledge_root, build)

    curated_problems = [
        p for p in build.problems
        if isinstance(p.get("problems"), list) and any(
            x in ("empty_applies_when", "empty_verification", "target_specific_value",
                  "missing_domains", "unknown_environment", "bad_provenance")
            for x in p["problems"]
        )
    ]
    if curated_problems:
        print(f"corpus lint: {len(curated_problems)} blocking problem(s)", file=sys.stderr)
        for problem in curated_problems[:20]:
            print(f"  {problem.get('file')} {problem.get('id', '')}: "
                  f"{','.join(problem['problems'])}", file=sys.stderr)
        return 1

    if args.check:
        expected = _render(build.entries)
        mismatches = []
        for domain, text in expected.items():
            path = knowledge_root / "corpus" / f"{domain}.jsonl"
            actual = path.read_text(encoding="utf-8") if path.exists() else ""
            if actual != text:
                mismatches.append(domain)
        committed = knowledge_root / "corpus" / "manifest.json"
        if committed.exists():
            old = json.loads(committed.read_text(encoding="utf-8"))
            if old.get("counts") != manifest["counts"] or \
                    old.get("source_hashes") != manifest["source_hashes"]:
                mismatches.append("manifest")
        else:
            mismatches.append("manifest")
        for path in (knowledge_root / "corpus").glob("*.jsonl"):
            if path.stem not in expected:
                mismatches.append(f"stale:{path.stem}")
        if mismatches:
            print(f"corpus out of sync: {', '.join(sorted(set(mismatches)))}", file=sys.stderr)
            print("run: python -m tools.build_rag_corpus", file=sys.stderr)
            return 1
        print(f"corpus in sync: {manifest['counts']['total']} entries "
              f"({manifest['counts']['curated']} curated)")
        return 0

    write_corpus(build.entries, knowledge_root, build)
    print(f"wrote {manifest['counts']['total']} entries "
          f"({manifest['counts']['curated']} curated) to {knowledge_root / 'corpus'}")
    print(f"  by domain: {manifest['counts']['by_domain']}")
    print(f"  by source: {manifest['counts']['by_source_kind']}")
    print(f"  excluded: {sum(e['entries'] for e in build.excluded)} guide entries "
          f"from {len(build.excluded)} file(s)")
    print(f"  generic applies_when fallback: {build.weak_applies_when}")
    if build.problems:
        print(f"  lint notes: {len(build.problems)} (see manifest.problems)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
