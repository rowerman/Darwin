#!/usr/bin/env python3
"""Knowledge ingestion CLI — import files into DarwinRAG vector database.

Mirrors container-pentester-agent's: cmd/ingest/main.go

Usage:
    # Import a single JSON knowledge file
    python tools/ingest_knowledge.py --file knowledge/cloud/cloud_metadata.json

    # Import a single Markdown file with auto-detection
    python tools/ingest_knowledge.py --file attacks/kerberoasting.md

    # Import all files in a directory recursively
    python tools/ingest_knowledge.py --dir knowledge/windows_ad/

    # Import with explicit collection override
    python tools/ingest_knowledge.py --file my_attack.md --collection windows_ad

    # Rebuild all indices after batch import
    python tools/ingest_knowledge.py --rebuild

    # Show collection statistics
    python tools/ingest_knowledge.py --stats

Steps (ETL Pipeline):
    1. Load: read raw file bytes
    2. Process: parse JSON or Markdown into _Document objects
    3. Embed: encode text via SentenceTransformer or TfidfVectorizer
    4. Store: add to per-collection Faiss/TF-IDF index
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Ensure darwin is on sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from darwin.rag import COLLECTIONS, DarwinRAG, get_rag


def cmd_ingest_file(rag: DarwinRAG, file_path: str, collection: str) -> int:
    """Import a single knowledge file."""
    fpath = Path(file_path)
    if not fpath.exists():
        print(f"Error: file not found: {file_path}")
        return 0

    print(f"Ingesting: {fpath}")
    coll = collection or "auto"
    n = rag.ingest_file(str(fpath), collection)
    if n > 0:
        coll_name = collection or rag._collections  # actual collection used
        print(f"  OK  {n} entries added")
    else:
        print(f"  SKIP  (no new entries or unsupported format)")
    return n


def cmd_ingest_dir(rag: DarwinRAG, dir_path: str, collection: str) -> int:
    """Import all knowledge files from a directory."""
    root = Path(dir_path)
    if not root.is_dir():
        print(f"Error: directory not found: {dir_path}")
        return 0

    files = sorted(list(root.rglob("*.json")) + list(root.rglob("*.md")))
    print(f"Directory mode: scanning {dir_path}")
    print(f"Found {len(files)} files (.json + .md)")
    print()

    total = 0
    for i, fpath in enumerate(files, 1):
        print(f"[{i}/{len(files)}] {fpath}")
        n = rag.ingest_file(str(fpath), collection)
        if n > 0:
            total += n
            print(f"  OK  {n} entries")
        else:
            print(f"  SKIP")
        print()

    return total


def cmd_rebuild(rag: DarwinRAG, collection: str) -> int:
    """Rebuild all search indices."""
    print("Rebuilding indices...")
    n = rag.rebuild_indices(collection)
    print(f"  OK  {n} docs indexed across collections")
    return n


def cmd_stats(rag: DarwinRAG) -> None:
    """Print collection statistics."""
    sizes = rag.collection_sizes()
    print("Collection Sizes:")
    print("-" * 40)
    total = 0
    for coll in COLLECTIONS:
        count = sizes.get(coll, 0)
        total += count
        bar = "█" * min(count, 40)
        print(f"  {coll:<15} {count:>4}  {bar}")
    print("-" * 40)
    print(f"  {'TOTAL':<15} {total:>4}")
    print()

    embedder = rag._get_embedder()
    backend = "SentenceTransformer + Faiss" if embedder else "TfidfVectorizer"
    print(f"Search backend: {backend}")
    print(f"Model path: {rag._model_dir}")


def main():
    parser = argparse.ArgumentParser(
        description="DarwinRAG Knowledge Ingestion Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --file knowledge/cloud/cloud_metadata.json
  %(prog)s --dir knowledge/windows_ad/
  %(prog)s --file attack.md --collection windows_ad
  %(prog)s --rebuild
  %(prog)s --stats
        """,
    )
    parser.add_argument("--file", help="Path to a single knowledge file (.json or .md)")
    parser.add_argument("--dir", help="Path to a directory of knowledge files")
    parser.add_argument(
        "--collection", default="",
        help="Target collection (web, windows_ad, cloud, network). "
             "Auto-detected from path if omitted.",
    )
    parser.add_argument(
        "--model-dir", default=DarwinRAG._DEFAULT_MODEL_DIR,
        help="Path to sentence-transformers model directory",
    )
    parser.add_argument("--rebuild", action="store_true", help="Rebuild all search indices")
    parser.add_argument("--stats", action="store_true", help="Show collection statistics")

    args = parser.parse_args()

    # Stats-only: no ingestion needed
    if args.stats and not args.file and not args.dir and not args.rebuild:
        rag = get_rag(model_dir=args.model_dir)
        cmd_stats(rag)
        return

    # Use singleton pre-loaded with all knowledge
    rag = get_rag(model_dir=args.model_dir)

    total_added = 0

    if args.file:
        n = cmd_ingest_file(rag, args.file, args.collection)
        total_added += n

    if args.dir:
        n = cmd_ingest_dir(rag, args.dir, args.collection)
        total_added += n

    if args.rebuild:
        n = cmd_rebuild(rag, args.collection)
        print(f"Indexed {n} total docs")

    if not args.file and not args.dir and not args.rebuild and not args.stats:
        parser.print_help()
        return

    # Summary
    print()
    print("=" * 50)
    print("Ingestion Summary")
    print("=" * 50)
    if args.file or args.dir:
        print(f"New entries added: {total_added}")
    cmd_stats(rag)

    if total_added > 0:
        print("\nDone. New knowledge is now searchable via DarwinRAG.")


if __name__ == "__main__":
    main()
