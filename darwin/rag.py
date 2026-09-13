"""DarwinRAG — hybrid retrieval over the unified static knowledge corpus.

Pipeline (see ``plans/refactor_20260913_1.md``):

    query ──┬─ dense  : multilingual embedding + Faiss inner product ─┐
            └─ sparse : BM25 over title/aliases/CVE/tool terms        ┤
                                                                      ▼
                              RRF fusion → environment hard filter → domain penalty
                              → cross-encoder rerank → gate → ≤ max_results

Retrieval returns *fewer* entries when nothing passes the gate, and an empty
list when the corpus has nothing that fits the target environment — the agent
must then rely on its own reconnaissance instead of on unrelated knowledge.

Corpus: ``knowledge/corpus/*.jsonl`` built by ``tools.build_rag_corpus``.
Index cache: ``checkpoints/rag_index/`` keyed by corpus + embedder identity.
"""

from __future__ import annotations

import hashlib
import json
import logging
import math
import os
import time
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

import numpy as np

from darwin.rag_corpus import CORPUS_DIRNAME, load_corpus
from darwin.rag_embedder import (
    DEFAULT_EMBEDDER_DIR,
    DEFAULT_RERANKER_DIR,
    resolve_embedder,
    resolve_reranker,
    tokenize_mixed,
)

rag_log = logging.getLogger("darwin.rag")

ROOT = Path(__file__).resolve().parent.parent


@dataclass
class RagConfig:
    """Retrieval tunables; defaults are the frozen calibration values."""

    model_dir: str = DEFAULT_EMBEDDER_DIR
    reranker_dir: str = DEFAULT_RERANKER_DIR
    embedder_kind: str = "auto"
    reranker_kind: str = "auto"
    dense_top_k: int = 30
    sparse_top_k: int = 30
    rerank_candidates: int = 16
    max_results: int = 3
    max_per_capability: int = 2
    domain_penalty: float = 0.15
    undeclared_environment_penalty: float = 0.05
    score_min: Optional[float] = None
    score_window: Optional[float] = None
    rrf_k: int = 60
    batch_size: int = 64
    use_cache: bool = True

    @classmethod
    def from_mapping(cls, data: Optional[Dict[str, Any]]) -> "RagConfig":
        cfg = cls()
        if not isinstance(data, dict):
            return cfg
        gate = data.get("gate") if isinstance(data.get("gate"), dict) else {}
        for key in ("model_dir", "reranker_dir", "embedder_kind", "reranker_kind",
                    "dense_top_k", "sparse_top_k", "rerank_candidates", "max_results",
                    "max_per_capability", "domain_penalty",
                    "undeclared_environment_penalty", "rrf_k", "batch_size",
                    "use_cache"):
            if data.get(key) is not None:
                setattr(cfg, key, data[key])
        if gate.get("score_min") is not None:
            cfg.score_min = float(gate["score_min"])
        if gate.get("score_window") is not None:
            cfg.score_window = float(gate["score_window"])
        return cfg


def corpus_cache_key(manifest: Dict[str, Any], embedder_name: str) -> str:
    """Cache key for the dense vectors: corpus identity + embedder identity."""
    digest = hashlib.sha256()
    digest.update(json.dumps(manifest.get("counts", {}), sort_keys=True).encode())
    digest.update(json.dumps(manifest.get("source_hashes", {}), sort_keys=True).encode())
    digest.update(str(embedder_name).encode())
    return digest.hexdigest()[:16]


class BM25:
    """Okapi BM25 over pre-tokenized documents (sparse channel)."""

    def __init__(self, tokenized: Sequence[Sequence[str]], k1: float = 1.2, b: float = 0.75):
        self.k1, self.b = k1, b
        self.n_docs = len(tokenized)
        self.postings: Dict[str, List[Tuple[int, int]]] = {}
        self.doc_len = np.zeros(self.n_docs, dtype=np.float32)
        for idx, tokens in enumerate(tokenized):
            counts = Counter(tokens)
            self.doc_len[idx] = max(1, len(tokens))
            for term, freq in counts.items():
                self.postings.setdefault(term, []).append((idx, freq))
        self.avgdl = float(self.doc_len.mean()) if self.n_docs else 1.0
        self.idf: Dict[str, float] = {
            term: math.log(1.0 + (self.n_docs - len(postings) + 0.5) / (len(postings) + 0.5))
            for term, postings in self.postings.items()
        }

    def scores(self, query_tokens: Sequence[str]) -> Dict[int, float]:
        """Return ``{doc_index: score}`` for documents sharing at least one term."""
        scored: Dict[int, float] = {}
        for term in set(query_tokens):
            postings = self.postings.get(term)
            if not postings:
                continue
            idf = self.idf[term]
            for doc_idx, freq in postings:
                norm = self.k1 * (1.0 - self.b + self.b * self.doc_len[doc_idx] / self.avgdl)
                scored[doc_idx] = scored.get(doc_idx, 0.0) + (
                    idf * freq * (self.k1 + 1.0) / (freq + norm)
                )
        return scored


@dataclass
class RetrievalTrace:
    """Per-entry retrieval scores, kept for logging and debugging."""

    dense_rank: Optional[int] = None
    sparse_rank: Optional[int] = None
    fused: float = 0.0
    rerank: float = 0.0
    dropped: str = ""

    def to_dict(self) -> Dict[str, Any]:
        data: Dict[str, Any] = {"fused": round(self.fused, 4), "rerank": round(self.rerank, 4)}
        if self.dense_rank is not None:
            data["dense_rank"] = self.dense_rank
        if self.sparse_rank is not None:
            data["sparse_rank"] = self.sparse_rank
        if self.dropped:
            data["dropped"] = self.dropped
        return data


class DarwinRAG:
    """Hybrid retriever over the unified knowledge corpus."""

    def __init__(
        self,
        knowledge_dir: str = "",
        model_dir: str = "",
        reranker_dir: str = "",
        embedder: Any = None,
        reranker: Any = None,
        config: Optional[RagConfig | Dict[str, Any]] = None,
        config_path: str = "config/darwin.yaml",
    ):
        self._knowledge_dir = Path(knowledge_dir) if knowledge_dir else ROOT / "knowledge"
        self._config_path = config_path
        self._config = self._resolve_config(config)
        if model_dir:
            self._config.model_dir = model_dir
        if reranker_dir:
            self._config.reranker_dir = reranker_dir
        self._embedder = embedder
        self._embedder_fixed = embedder is not None
        self._reranker = reranker
        self._reranker_fixed = reranker is not None

        self._entries: List[Dict[str, Any]] = []
        self._manifest: Dict[str, Any] = {}
        self._bm25: Optional[BM25] = None
        self._vectors: Optional[np.ndarray] = None
        self._faiss = None
        self._backend = "unloaded"
        self._loaded = False
        self._load_error = ""

    # ── Configuration ────────────────────────────────────────────────

    def _resolve_config(self, config: Optional[RagConfig | Dict[str, Any]]) -> RagConfig:
        if isinstance(config, RagConfig):
            return config
        if isinstance(config, dict):
            return RagConfig.from_mapping(config)
        file_cfg: Dict[str, Any] = {}
        path = Path(self._config_path)
        if path.exists():
            try:
                import yaml

                data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
                if isinstance(data, dict) and isinstance(data.get("rag"), dict):
                    file_cfg = data["rag"]
            except Exception as exc:  # silent-ok: config file is optional
                rag_log.warning("Failed to read RAG config %s: %s", path, exc)
        cfg = RagConfig.from_mapping(file_cfg)
        cfg.model_dir = os.environ.get("DARWIN_RAG_MODEL_DIR", cfg.model_dir)
        cfg.reranker_dir = os.environ.get("DARWIN_RAG_RERANKER_DIR", cfg.reranker_dir)
        return cfg

    @staticmethod
    def _resolve_dir(value: str) -> str:
        if not value:
            return ""
        path = Path(value)
        return str(path if path.is_absolute() else ROOT / path)

    # ── Loading ──────────────────────────────────────────────────────

    def load(self, knowledge_dir: str = "") -> int:
        """Load the corpus and build both retrieval channels."""
        if self._loaded:
            return len(self._entries)
        if knowledge_dir:
            self._knowledge_dir = Path(knowledge_dir)

        t0 = time.time()
        entries, manifest = load_corpus(self._knowledge_dir)
        if not entries:
            self._load_error = (
                f"no corpus at {self._knowledge_dir / CORPUS_DIRNAME}; "
                "run: python -m tools.build_rag_corpus"
            )
            rag_log.error("DarwinRAG: %s", self._load_error)
            self._loaded = True
            self._backend = "empty"
            return 0
        self._entries = entries
        self._manifest = manifest
        self._bm25 = BM25([tokenize_mixed(e.get("search_text_sparse", "")) for e in entries])

        if not self._embedder_fixed:
            self._embedder = resolve_embedder(
                self._resolve_dir(self._config.model_dir), self._config.embedder_kind
            )
        if not self._reranker_fixed:
            self._reranker = resolve_reranker(
                self._resolve_dir(self._config.reranker_dir), self._config.reranker_kind
            )

        if self._embedder is None:
            self._backend = "sparse_only"
            rag_log.error(
                "DarwinRAG dense channel disabled (embedder kind=%s, dir=%s) — "
                "sparse-only retrieval; download the embedder model to restore vector search",
                self._config.embedder_kind, self._config.model_dir,
            )
        else:
            self._vectors = self._load_or_build_vectors()
            self._backend = "hybrid" if self._vectors is not None else "sparse_only"

        self._loaded = True
        rag_log.info(
            "DarwinRAG loaded %d entries backend=%s reranker=%s in %.2fs",
            len(entries), self._backend, getattr(self._reranker, "name", "none"),
            time.time() - t0,
        )
        return len(entries)

    def _corpus_key(self) -> str:
        return corpus_cache_key(self._manifest, getattr(self._embedder, "name", "none"))

    def _cache_path(self) -> Path:
        return ROOT / "checkpoints" / "rag_index" / f"{self._corpus_key()}.npz"

    def _load_or_build_vectors(self) -> Optional[np.ndarray]:
        cache_path = self._cache_path()
        if self._config.use_cache and cache_path.exists():
            try:
                vectors = np.load(cache_path, allow_pickle=False)["vectors"].astype(np.float32)
                if vectors.shape[0] == len(self._entries):
                    rag_log.info("DarwinRAG dense vectors loaded from cache %s", cache_path.name)
                    self._build_faiss(vectors)
                    return vectors
            except Exception as exc:  # silent-ok: stale or broken cache is rebuilt
                rag_log.warning("RAG vector cache unusable (%s); rebuilding", exc)

        t0 = time.time()
        try:
            vectors = np.asarray(
                self._embedder.encode([e.get("search_text_dense", "") for e in self._entries]),
                dtype=np.float32,
            )
        except Exception as exc:
            rag_log.error("DarwinRAG embedding failed (%s); falling back to sparse-only", exc)
            return None
        rag_log.info("DarwinRAG embedded %d entries in %.1fs", len(vectors), time.time() - t0)
        if self._config.use_cache:
            try:
                cache_path.parent.mkdir(parents=True, exist_ok=True)
                np.savez_compressed(cache_path, vectors=vectors.astype(np.float16))
            except Exception as exc:  # silent-ok: caching is an optimization
                rag_log.warning("Failed to write RAG vector cache: %s", exc)
        self._build_faiss(vectors)
        return vectors

    def _build_faiss(self, vectors: np.ndarray) -> None:
        self._faiss = None
        try:
            import faiss

            index = faiss.IndexFlatIP(int(vectors.shape[1]))
            index.add(vectors)
            self._faiss = index
        except Exception as exc:  # silent-ok: numpy fallback keeps dense channel alive
            rag_log.warning("Faiss unavailable (%s); using numpy inner product", exc)

    # ── Retrieval ────────────────────────────────────────────────────

    def retrieve(
        self,
        query: str,
        environment: str = "",
        domains: Optional[Iterable[str]] = None,
        top_k: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """Hybrid retrieval with environment filtering, reranking and gating."""
        if not self._loaded:
            self.load()
        if not self._entries or not str(query).strip():
            return []

        cfg = self._config
        max_results = int(top_k or cfg.max_results)
        traces: Dict[int, RetrievalTrace] = {}

        sparse_scores = self._bm25.scores(tokenize_mixed(query)) if self._bm25 else {}
        for rank, (idx, _score) in enumerate(
            sorted(sparse_scores.items(), key=lambda kv: kv[1], reverse=True)[: cfg.sparse_top_k], 1
        ):
            traces.setdefault(idx, RetrievalTrace()).sparse_rank = rank

        if self._vectors is not None:
            query_vec = np.asarray(self._embedder.encode([query]), dtype=np.float32)
            fetch_k = min(cfg.dense_top_k, len(self._entries))
            if self._faiss is not None:
                scores, indices = self._faiss.search(query_vec, fetch_k)
                dense_ranked = [
                    (int(idx), float(score))
                    for score, idx in zip(scores[0], indices[0])
                    if 0 <= idx < len(self._entries)
                ]
            else:
                sims = self._vectors @ query_vec[0]
                dense_ranked = [
                    (int(idx), float(sims[idx])) for idx in np.argsort(-sims)[:fetch_k]
                ]
            for rank, (idx, _score) in enumerate(dense_ranked, 1):
                traces.setdefault(idx, RetrievalTrace()).dense_rank = rank

        for trace in traces.values():
            if trace.dense_rank:
                trace.fused += 1.0 / (cfg.rrf_k + trace.dense_rank)
            if trace.sparse_rank:
                trace.fused += 1.0 / (cfg.rrf_k + trace.sparse_rank)

        allowed_domains = {d for d in (domains or []) if d}
        candidates: List[int] = []
        for idx, trace in traces.items():
            entry = self._entries[idx]
            if not self._environment_allows(entry, environment):
                trace.dropped = "environment"
                continue
            if allowed_domains and entry.get("domains"):
                if not (set(entry["domains"]) & allowed_domains):
                    trace.fused *= (1.0 - cfg.domain_penalty)
            elif environment and not entry.get("requires_environment"):
                trace.fused *= (1.0 - cfg.undeclared_environment_penalty)
            candidates.append(idx)

        candidates.sort(key=lambda idx: traces[idx].fused, reverse=True)
        candidates = candidates[: cfg.rerank_candidates]
        if not candidates:
            return []

        if self._reranker is not None:
            docs = [self._entries[idx].get("search_text_dense", "") for idx in candidates]
            try:
                for idx, score in zip(candidates, self._reranker.score(query, docs)):
                    traces[idx].rerank = float(score)
            except Exception as exc:
                rag_log.warning("Reranker failed (%s); falling back to fused scores", exc)
        if not any(traces[idx].rerank for idx in candidates):
            for idx in candidates:
                traces[idx].rerank = traces[idx].fused

        score_min, score_window = self._gate_thresholds(candidates, traces)
        top_score = max(traces[idx].rerank for idx in candidates)
        selected: List[int] = []
        per_capability: Counter = Counter()
        seen_keys: set = set()
        for idx in sorted(candidates, key=lambda i: traces[i].rerank, reverse=True):
            trace, entry = traces[idx], self._entries[idx]
            if trace.rerank < score_min or trace.rerank < top_score - score_window:
                trace.dropped = trace.dropped or "gate"
                continue
            key = (entry.get("title", ""), (entry.get("applies_when") or [""])[0])
            if key in seen_keys:
                trace.dropped = "duplicate"
                continue
            capability = entry.get("capability", "")
            if capability and per_capability[capability] >= cfg.max_per_capability:
                trace.dropped = "capability_cap"
                continue
            seen_keys.add(key)
            per_capability[capability] += 1
            selected.append(idx)
            if len(selected) >= max_results:
                break

        results: List[Dict[str, Any]] = []
        for idx in selected:
            entry = dict(self._entries[idx])
            entry["score"] = round(traces[idx].rerank, 4)
            entry["retrieval"] = traces[idx].to_dict()
            results.append(entry)

        rag_log.info(
            "RAG_RETRIEVE query=%r env=%r candidates=%d selected=%d backend=%s",
            str(query)[:120], environment or "unknown", len(candidates), len(results),
            self._backend,
        )
        for rank, entry in enumerate(results, 1):
            rag_log.info(
                "RAG_HIT #%d id=%s score=%.4f dense=%s sparse=%s title=%r",
                rank, entry.get("id", ""), entry.get("score", 0.0),
                entry["retrieval"].get("dense_rank"), entry["retrieval"].get("sparse_rank"),
                str(entry.get("title", ""))[:80],
            )
        return results

    @staticmethod
    def _environment_allows(entry: Dict[str, Any], environment: str) -> bool:
        requires = entry.get("requires_environment") or []
        if not requires or not environment or environment == "unknown":
            return True
        return environment in requires

    def _gate_thresholds(self, candidates: Sequence[int],
                         traces: Dict[int, RetrievalTrace]) -> Tuple[float, float]:
        cfg = self._config
        if cfg.score_min is not None and cfg.score_window is not None:
            return float(cfg.score_min), float(cfg.score_window)
        reranker_name = getattr(self._reranker, "name", "")
        if reranker_name.startswith("ce:"):
            # Calibrated on knowledge/eval/runtime_queries.json: gold candidates
            # score p50=3.9 while unrelated candidates sit at p50=-4.1 / p90=1.0.
            # The absolute floor is what keeps off-topic queries empty (宁缺毋滥);
            # the window only controls how deep the top cluster is taken.
            return (0.0 if cfg.score_min is None else float(cfg.score_min),
                    6.0 if cfg.score_window is None else float(cfg.score_window))
        if reranker_name == "token-overlap":
            # Weight-free stand-in: require real token evidence, not one lucky term.
            return (0.35 if cfg.score_min is None else float(cfg.score_min),
                    0.4 if cfg.score_window is None else float(cfg.score_window))
        top = max((traces[idx].fused for idx in candidates), default=0.0)
        if top <= 0:
            return 1.0, 0.0
        return (0.6 * top if cfg.score_min is None else float(cfg.score_min),
                0.4 * top if cfg.score_window is None else float(cfg.score_window))

    # ── Introspection ────────────────────────────────────────────────

    @property
    def loaded(self) -> bool:
        return self._loaded

    @property
    def entry_count(self) -> int:
        return len(self._entries)

    @property
    def backend(self) -> str:
        return self._backend

    @property
    def load_error(self) -> str:
        return self._load_error

    @property
    def manifest(self) -> Dict[str, Any]:
        return dict(self._manifest)

    def domain_counts(self) -> Dict[str, int]:
        counts: Counter = Counter()
        for entry in self._entries:
            counts[(entry.get("domains") or ["generic"])[0]] += 1
        return dict(sorted(counts.items()))

    def stats(self) -> Dict[str, Any]:
        return {
            "entries": len(self._entries),
            "backend": self._backend,
            "embedder": getattr(self._embedder, "name", "none"),
            "reranker": getattr(self._reranker, "name", "none"),
            "by_domain": self.domain_counts(),
            "manifest": self._manifest.get("counts", {}),
        }


# ── Singleton ────────────────────────────────────────────────────────

_rag_instance: Optional[DarwinRAG] = None
_rag_environment: str = ""


def set_environment(kind: str) -> None:
    """Record the engagement environment for gateway tools.

    ``knowledge_search`` is invoked through the tool gateway, which has no
    handle on the orchestrator's DKG; the lifecycle/recon phases publish the
    classification here so retrieval can gate on it.
    """
    global _rag_environment
    _rag_environment = str(kind or "")


def get_environment() -> str:
    return _rag_environment


def get_rag(knowledge_dir: str = "", model_dir: str = "",
            reranker_dir: str = "") -> DarwinRAG:
    """Get or create the shared DarwinRAG instance."""
    global _rag_instance
    if _rag_instance is None:
        _rag_instance = DarwinRAG(
            knowledge_dir=knowledge_dir,
            model_dir=model_dir,
            reranker_dir=reranker_dir,
        )
        _rag_instance.load()
    return _rag_instance


def reset_rag() -> None:
    """Drop the singleton (used by tests and long-running processes)."""
    global _rag_instance, _rag_environment
    _rag_instance = None
    _rag_environment = ""
