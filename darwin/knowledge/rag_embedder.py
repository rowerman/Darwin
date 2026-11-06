"""Embedding and reranking backends for DarwinRAG.

Three embedder implementations share one interface:

* :class:`SentenceTransformerEmbedder` — the production multilingual encoder
  (``paraphrase-multilingual-MiniLM-L12-v2``) loaded from a local directory.
* :class:`HashEmbedder` — deterministic bag-of-token hashing with no weights.
  Used by tests and as the dev fallback so the dense channel stays exercised on
  machines without model weights.
* ``None`` (resolved by :func:`resolve_embedder`) — sparse-only mode, logged.

Reranking uses a cross-encoder (``mmarco-mMiniLMv2-L12-H384-v1``);
:class:`TokenOverlapReranker` is the deterministic stand-in for tests.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any, List, Optional, Protocol, Sequence

import numpy as np

DEFAULT_EMBEDDER_DIR = "models/paraphrase-multilingual-MiniLM-L12-v2"
DEFAULT_RERANKER_DIR = "models/mmarco-mMiniLMv2-L12-H384-v1"

_ASCII_TOKEN_RE = re.compile(r"[a-z0-9][a-z0-9_.\-/]*")
_CJK_RE = re.compile(r"[\u4e00-\u9fff]+")


def tokenize_mixed(text: str) -> List[str]:
    """Tokenizer for the sparse channel: ASCII words + CJK character bigrams."""
    lowered = str(text or "").lower()
    tokens = _ASCII_TOKEN_RE.findall(lowered)
    for chunk in _CJK_RE.findall(lowered):
        if len(chunk) == 1:
            tokens.append(chunk)
        else:
            tokens.extend(chunk[i:i + 2] for i in range(len(chunk) - 1))
    return tokens


class Embedder(Protocol):
    name: str
    dim: int

    def encode(self, texts: Sequence[str]) -> np.ndarray:
        """Return an (n, dim) float32 matrix of L2-normalized vectors."""


class Reranker(Protocol):
    name: str

    def score(self, query: str, docs: Sequence[str]) -> List[float]:
        """Return one relevance score per document (higher = more relevant)."""


class SentenceTransformerEmbedder:
    """Production embedder backed by a locally downloaded SentenceTransformer."""

    def __init__(self, model_dir: str, batch_size: int = 64, max_seq_length: int = 128):
        from sentence_transformers import SentenceTransformer

        self._model = SentenceTransformer(model_dir)
        # The multilingual MiniLM sentence encoders are trained at 128 tokens;
        # leaving the 512 default multiplies CPU cost for no retrieval gain.
        self._model.max_seq_length = max_seq_length
        self.dim = int(self._model.get_embedding_dimension())
        self.batch_size = batch_size
        self.max_chars = max_seq_length * 3
        self.name = f"st:{model_dir}"

    def encode(self, texts: Sequence[str]) -> np.ndarray:
        vectors = self._model.encode(
            [str(t)[: self.max_chars] for t in texts],
            normalize_embeddings=True, show_progress_bar=False,
            batch_size=self.batch_size,
        )
        return np.asarray(vectors, dtype=np.float32)


class HashEmbedder:
    """Weight-free deterministic embedder over hashed tokens (tests / fallback)."""

    name = "hash"

    def __init__(self, dim: int = 384):
        self.dim = dim

    def encode(self, texts: Sequence[str]) -> np.ndarray:
        matrix = np.zeros((len(texts), self.dim), dtype=np.float32)
        for row, text in enumerate(texts):
            for token in tokenize_mixed(text):
                digest = hashlib.blake2b(token.encode("utf-8"), digest_size=8).digest()
                matrix[row, int.from_bytes(digest, "big") % self.dim] += 1.0
        norms = np.linalg.norm(matrix, axis=1, keepdims=True)
        norms[norms == 0.0] = 1.0
        return matrix / norms


class CrossEncoderReranker:
    """Cross-encoder reranker backed by a locally downloaded model."""

    def __init__(self, model_dir: str, max_length: int = 256, max_chars: int = 400):
        from sentence_transformers import CrossEncoder

        self._model = CrossEncoder(model_dir, max_length=max_length)
        self.max_chars = max_chars
        self.name = f"ce:{model_dir}"

    def score(self, query: str, docs: Sequence[str]) -> List[float]:
        if not docs:
            return []
        pairs = [(query[:300], str(doc)[: self.max_chars]) for doc in docs]
        raw = self._model.predict(pairs)
        return [float(v) for v in np.asarray(raw, dtype=np.float32).reshape(-1)]


class TokenOverlapReranker:
    """Deterministic token-overlap reranker for tests and weight-free runs."""

    name = "token-overlap"

    def score(self, query: str, docs: Sequence[str]) -> List[float]:
        query_tokens = set(tokenize_mixed(query))
        scores: List[float] = []
        for doc in docs:
            doc_tokens = set(tokenize_mixed(doc))
            if not query_tokens or not doc_tokens:
                scores.append(0.0)
                continue
            overlap = len(query_tokens & doc_tokens)
            scores.append(float(overlap) / float(len(query_tokens)))
        return scores


def resolve_embedder(model_dir: str = "", kind: str = "auto") -> Optional[Any]:
    """Resolve an embedder instance.

    ``kind``: ``auto`` (SentenceTransformer when the directory exists, else the
    hash embedder), ``st``/``sentence-transformer`` (must exist), ``hash``, or
    ``none`` for sparse-only mode.
    """
    if kind == "none":
        return None
    if kind == "hash":
        return HashEmbedder()
    if model_dir:
        from pathlib import Path

        if Path(model_dir).is_dir():
            try:
                return SentenceTransformerEmbedder(model_dir)
            except Exception:
                if kind in ("st", "sentence-transformer"):
                    raise
        elif kind in ("st", "sentence-transformer"):
            raise FileNotFoundError(f"embedder model directory not found: {model_dir}")
    return HashEmbedder()


def resolve_reranker(model_dir: str = "", kind: str = "auto") -> Optional[Any]:
    """Resolve a reranker instance (``auto`` falls back to token overlap)."""
    if kind == "none":
        return None
    if kind == "token-overlap":
        return TokenOverlapReranker()
    if model_dir:
        from pathlib import Path

        if Path(model_dir).is_dir():
            try:
                return CrossEncoderReranker(model_dir)
            except Exception:
                if kind in ("ce", "cross-encoder"):
                    raise
        elif kind in ("ce", "cross-encoder"):
            raise FileNotFoundError(f"reranker model directory not found: {model_dir}")
    return TokenOverlapReranker()
