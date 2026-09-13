"""Build (or verify) the DarwinRAG vector index cache.

The cache lives in ``checkpoints/rag_index/`` and is keyed by corpus identity
plus embedder identity, so it is rebuilt automatically when either changes.

Embedding the full corpus on one CPU core takes ~10 minutes, so the build tool
shards the corpus across worker processes (each with its own model instance) and
assembles the vector matrix in order. Runtime loading stays single-process: it
hits the cache written here.

Usage:
    python -m tools.build_rag_index                   # build if missing
    python -m tools.build_rag_index --rebuild -j 6    # drop cache, rebuild in parallel
    python -m tools.build_rag_index --stats           # corpus/backend summary
"""

from __future__ import annotations

import argparse
import os
import shutil
import sys
import time
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parent.parent


def _embed_shard(payload: tuple) -> tuple:
    """Worker entry point: embed one shard and return (start, vectors)."""
    model_dir, texts, max_seq_length, batch_size, start = payload
    # Each worker loads its own copy of the model (~0.5 GB); keep per-process
    # thread pools small so parallel workers stay inside the memory budget.
    os.environ.setdefault("OMP_NUM_THREADS", "2")
    import torch

    torch.set_num_threads(2)
    from darwin.rag_embedder import SentenceTransformerEmbedder

    embedder = SentenceTransformerEmbedder(
        model_dir, batch_size=batch_size, max_seq_length=max_seq_length
    )
    return start, embedder.encode(texts)


def build_vectors(texts: list, model_dir: str, workers: int,
                  max_seq_length: int, batch_size: int) -> np.ndarray:
    if workers <= 1:
        from darwin.rag_embedder import SentenceTransformerEmbedder

        embedder = SentenceTransformerEmbedder(
            model_dir, batch_size=batch_size, max_seq_length=max_seq_length
        )
        return embedder.encode(texts)

    import multiprocessing as mp

    workers = max(1, min(workers, len(texts)))
    step = (len(texts) + workers - 1) // workers
    shards = [
        (model_dir, texts[i:i + step], max_seq_length, batch_size, i)
        for i in range(0, len(texts), step)
    ]
    context = mp.get_context("spawn")
    vectors = np.zeros((len(texts), 0), dtype=np.float32)
    with context.Pool(processes=len(shards)) as pool:
        parts = pool.map(_embed_shard, shards)
    for start, part in sorted(parts, key=lambda item: item[0]):
        if vectors.shape[1] == 0:
            vectors = np.zeros((len(texts), part.shape[1]), dtype=np.float32)
        vectors[start:start + part.shape[0]] = part
    return vectors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--knowledge-dir", default=str(ROOT / "knowledge"))
    parser.add_argument("--rebuild", action="store_true", help="discard the cache first")
    parser.add_argument("--stats", action="store_true", help="print corpus/backend summary")
    parser.add_argument("-j", "--workers", type=int,
                        default=max(1, min(4, (os.cpu_count() or 4) // 2)),
                        help="parallel embedding workers (default: cores/2, max 4; "
                             "each worker holds its own model copy)")
    args = parser.parse_args(argv)

    from darwin.rag import DarwinRAG, RagConfig, corpus_cache_key
    from darwin.rag_corpus import load_corpus
    from darwin.rag_embedder import SentenceTransformerEmbedder, resolve_embedder

    entries, manifest = load_corpus(Path(args.knowledge_dir))
    if not entries:
        print("no corpus artifact — run: python -m tools.build_rag_corpus", file=sys.stderr)
        return 1

    config = RagConfig()
    model_dir = DarwinRAG._resolve_dir(config.model_dir)
    embedder = resolve_embedder(model_dir, config.embedder_kind)
    if embedder is None:
        print("dense channel disabled by config (embedder_kind=none); nothing to build",
              file=sys.stderr)
        return 2
    if not isinstance(embedder, SentenceTransformerEmbedder):
        print(f"embedder {embedder.name} needs no cache; nothing to build")
        return 0

    cache_dir = ROOT / "checkpoints" / "rag_index"
    cache_path = cache_dir / f"{corpus_cache_key(manifest, embedder.name)}.npz"
    if args.rebuild:
        shutil.rmtree(cache_dir, ignore_errors=True)
    if cache_path.exists():
        print(f"cache already present: {cache_path.name}")
    else:
        texts = [e.get("search_text_dense", "") for e in entries]
        started = time.time()
        vectors = build_vectors(texts, model_dir, args.workers,
                                embedder._model.max_seq_length, embedder.batch_size)
        cache_dir.mkdir(parents=True, exist_ok=True)
        np.savez_compressed(cache_path, vectors=np.asarray(vectors, dtype=np.float16))
        elapsed = time.time() - started
        print(f"embedded {len(texts)} entries in {elapsed:.0f}s "
              f"({len(texts) / max(elapsed, 1e-6):.1f} docs/s, {args.workers} workers) "
              f"-> {cache_path.name}")

    rag = DarwinRAG(knowledge_dir=args.knowledge_dir)
    started = time.time()
    rag.load()
    stats = rag.stats()
    print(f"entries={stats['entries']} backend={stats['backend']} "
          f"embedder={Path(stats['embedder'].split(':', 1)[-1]).name} "
          f"reranker={Path(stats['reranker'].split(':', 1)[-1]).name} "
          f"load={time.time() - started:.1f}s")
    if args.stats:
        print(f"  by domain: {stats['by_domain']}")
        print(f"  manifest: {manifest.get('counts', {})}")
    if stats["backend"] == "sparse_only":
        print("dense channel unavailable — check models/ and rag.model_dir", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
