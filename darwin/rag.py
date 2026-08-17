"""DarwinRAG — Static Knowledge Retrieval-Augmented Generation.

Loads pre-authored attack technique knowledge from knowledge/*.json files,
indexes them per domain collection, and provides semantic search.

Separate from CTEG's dynamic cross-task learning:
- CTEG: dynamic patterns learned from actual penetration tests
- DarwinRAG: static reference knowledge (attack techniques, vulnerability
  patterns, MITRE ATT&CK)

Architecture matches container-pentester-agent's RAG:
- Multi-collection design (web, windows_ad, cloud, network)
- ETL pipeline: Load → Parse → Index
- Two LLM interaction paths: automatic enrichment (summarize) + on-demand tool
- Metadata filtering (collection, category, subcategory)

Primary vectorizer: TfidfVectorizer (fast, reliable, zero network).
Optional: sentence-transformers all-MiniLM-L6-v2 when model is locally cached.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

import numpy as np

rag_log = logging.getLogger("darwin.rag")

COLLECTIONS = ["web", "windows_ad", "cloud", "network"]

# Path → collection mapping for knowledge/ directory layout
_COLLECTION_MAP = {
    "web_vulnerabilities": "web",
    "advanced_exploitation": "web",
    "windows_ad": "windows_ad",
    "cloud": "cloud",
    "network": "network",
    # Phase 2: benchmark scenario domains map onto existing collections.
    "k8s": "cloud",
    "db": "network",
}


def _path_to_collection(fpath: Path) -> str:
    """Map a knowledge file path to its collection name."""
    parts = fpath.parts
    # knowledge/cloud/kubernetes_attacks.json → "cloud"
    # knowledge/web_vulnerabilities.json → "web"
    for i, part in enumerate(parts):
        if part in _COLLECTION_MAP and part not in ("knowledge",):
            return _COLLECTION_MAP[part]
    # Try parent dir name
    if len(parts) >= 2:
        parent = parts[-2]
        if parent in _COLLECTION_MAP:
            return _COLLECTION_MAP[parent]
    # Try filename stem
    stem = fpath.stem
    for key, coll in _COLLECTION_MAP.items():
        if key in stem:
            return coll
    return "web"  # default


def _doc_id(content: str, metadata: dict) -> str:
    """SHA256-based unique ID for idempotent upsert."""
    h = hashlib.sha256()
    h.update(content.encode("utf-8"))
    h.update(json.dumps(metadata, sort_keys=True).encode("utf-8"))
    return h.hexdigest()[:32]


class DarwinRAG:
    """Static knowledge RAG with multi-collection TF-IDF vector search.

    Usage:
        rag = DarwinRAG()
        rag.load("knowledge/")
        results = rag.search("Kerberoasting techniques", top_k=5)
        summary = rag.summarize("SQL injection bypass WAF", collection="web")
    """

    # Default path for the sentence-transformers model
    _DEFAULT_MODEL_DIR = "/home/kianabin/utils/all-MiniLM-L6-v2"

    def __init__(self, model_dir: str = ""):
        self._collections: Dict[str, List[Dict[str, Any]]] = {
            c: [] for c in COLLECTIONS
        }
        self._vectorizers: Dict[str, Any] = {}
        self._matrices: Dict[str, Any] = {}
        self._entry_index: Dict[str, Dict[str, int]] = {}
        self._loaded = False
        self._entry_count = 0
        # Phase 2: explicit taxonomy (domain -> class -> scenario leaf).
        self._taxonomy: Optional[Dict[str, Any]] = None
        self._taxonomy_leaves: List[Dict[str, Any]] = []
        self._leaf_embeddings: Dict[str, np.ndarray] = {}

        self._model_dir = model_dir or self._DEFAULT_MODEL_DIR
        self._embedder = None
        self._embedder_checked = False
        self._faiss_indices: Dict[str, Any] = {}
        self._dim = 384

    # ── Embedder ──────────────────────────────────────────────────

    def _get_embedder(self):
        """Load sentence-transformers from local model directory.

        Uses the model at self._model_dir if it exists on disk.
        Falls back to TF-IDF when model is unavailable.
        """
        if self._embedder_checked:
            return self._embedder
        self._embedder_checked = True

        import os
        model_path = self._model_dir
        if model_path and os.path.isdir(model_path):
            try:
                from sentence_transformers import SentenceTransformer
                self._embedder = SentenceTransformer(model_path)
                self._dim = self._embedder.get_embedding_dimension()
                rag_log.info("SentenceTransformer loaded from %s (dim=%d)", model_path, self._dim)
                return self._embedder
            except Exception as e:
                rag_log.warning("Failed to load model from %s: %s", model_path, e)

        rag_log.info("No local model, using TF-IDF fallback")
        self._embedder = None
        return self._embedder

    # ── ETL: Load ──────────────────────────────────────────────────

    def load(self, knowledge_dir: str = "knowledge/") -> int:
        """Load all knowledge files (JSON + Markdown) and build indices.

        JSON files: structured array of knowledge entries.
        Markdown files: content + metadata footer (**元数据**:).

        Returns total number of entries loaded.
        """
        if self._loaded:
            return self._entry_count

        t0 = time.time()
        root = Path(knowledge_dir)
        if not root.exists():
            rag_log.warning("Knowledge directory not found: %s", root)
            return 0

        raw_entries: Dict[str, List[Dict[str, Any]]] = {c: [] for c in COLLECTIONS}
        seen_ids: set = set()

        # Scan both JSON and Markdown files
        all_files = sorted(list(root.rglob("*.json")) + list(root.rglob("*.md")))
        for fpath in all_files:
            try:
                if fpath.suffix == ".json":
                    entries = self._parse_json_file(fpath)
                else:
                    entries = self._parse_markdown_file(fpath)

                collection = _path_to_collection(fpath)
                for entry in entries:
                    entry["collection"] = collection
                    entry["_search_text"] = _build_search_text(entry)
                    uid = _doc_id(entry["_search_text"], {
                        "id": entry.get("id", ""), "collection": collection,
                    })
                    if uid in seen_ids:
                        continue
                    seen_ids.add(uid)
                    raw_entries[collection].append(entry)
            except Exception as e:
                rag_log.warning("Failed to load %s: %s", fpath, e)

        # Build indices per collection
        total = 0
        embedder = self._get_embedder()

        for coll in COLLECTIONS:
            entries = raw_entries[coll]
            if not entries:
                continue
            self._collections[coll] = entries
            self._entry_index[coll] = {
                str(e.get("id", "")): i for i, e in enumerate(entries)
            }
            total += len(entries)

            texts = [e["_search_text"] for e in entries]

            if embedder:
                # Neural: embed and build Faiss index
                try:
                    embeddings = embedder.encode(
                        texts, show_progress_bar=False,
                        normalize_embeddings=True,
                    )
                    embeddings = np.array(embeddings, dtype=np.float32)
                    import faiss
                    idx = faiss.IndexFlatIP(self._dim)
                    idx.add(embeddings)
                    self._faiss_indices[coll] = idx
                    rag_log.info("Collection %s: %d vectors (Faiss IP, dim=%d)",
                                 coll, idx.ntotal, self._dim)
                except Exception as e:
                    rag_log.warning("Faiss indexing failed for %s: %s, using TF-IDF", coll, e)
                    embedder = None  # fall through to TF-IDF

            if not embedder:
                # TF-IDF: fit vectorizer and build sparse matrix
                from sklearn.feature_extraction.text import TfidfVectorizer
                vec = TfidfVectorizer(
                    max_features=None, analyzer="word",
                    ngram_range=(1, 2), stop_words="english",
                )
                matrix = vec.fit_transform(texts)
                self._vectorizers[coll] = vec
                self._matrices[coll] = matrix
                rag_log.info("Collection %s: %d docs, vocab=%d (TF-IDF)",
                             coll, len(entries), len(vec.vocabulary_))

        self._entry_count = total
        self._loaded = True
        self.load_taxonomy()
        rag_log.info("DarwinRAG loaded %d entries across %d collections in %.2fs",
                     total, sum(1 for c in COLLECTIONS if raw_entries[c]), time.time() - t0)
        return total

    def _parse_json_file(self, fpath: Path) -> List[Dict[str, Any]]:
        """Parse a JSON knowledge file into entry dicts."""
        with open(fpath, encoding="utf-8") as f:
            data = json.load(f)
        items = data if isinstance(data, list) else [data]
        entries = []
        for item in items:
            if not isinstance(item, dict) or "id" not in item:
                continue
            entries.append({
                "id": item.get("id", ""),
                "title": item.get("title", ""),
                "category": item.get("category", ""),
                "subcategory": item.get("subcategory", ""),
                "description": item.get("description", ""),
                "techniques": item.get("techniques", []),
                "indicators": item.get("indicators", []),
                "tags": item.get("tags", []),
                "tools": item.get("tools", []),
                "prerequisites": item.get("prerequisites", []),
                "confidence": item.get("confidence", 0.5),
                "mitre_attack": item.get("mitre_attack", ""),
                "references": item.get("references", []),
            })
        return entries

    def _parse_markdown_file(self, fpath: Path) -> List[Dict[str, Any]]:
        """Parse a Markdown knowledge file into a single entry dict.

        Matches container-pentester-agent's format: content body + **元数据**: footer.
        """
        with open(fpath, encoding="utf-8") as f:
            text = f.read()

        # Split content from metadata footer
        parts = text.split("**元数据**:", 1)
        if len(parts) < 2:
            parts = text.split("**Metadata**:", 1)

        content = parts[0].strip()
        metadata: Dict[str, str] = {}
        if len(parts) >= 2:
            for line in parts[1].strip().split("\n"):
                line = line.strip()
                if line.startswith("- ") or line.startswith("* "):
                    kv = line[2:].split(":", 1)
                    if len(kv) == 2:
                        key = kv[0].strip().lower().replace(" ", "_")
                        val = kv[1].strip().strip('"').strip("'")
                        metadata[key] = val

        # Extract title from first heading
        title = fpath.stem
        for line in content.split("\n"):
            if line.startswith("# "):
                title = line[2:].strip()
                break

        # Collect key sentences from content body as "techniques"
        techniques = []
        for line in content.split("\n"):
            line = line.strip()
            if line.startswith("- ") or line.startswith("* ") or line.startswith("**"):
                techniques.append(line.lstrip("- *").strip())

        # Extract category from path (e.g., privilege-escalation, defense-evasion)
        subcategory = ""
        for part in fpath.parts:
            part_lower = part.lower().replace("_", "-")
            if part_lower in ("credential-access", "defense-evasion", "discovery",
                              "execution", "impact", "initial-access", "lateral-movement",
                              "persistence", "privilege-escalation", "pod-sec", "rbac",
                              "network", "storage", "backdoor", "cryptomining", "data-breach"):
                subcategory = part_lower
                break

        doc_id = metadata.get("technique_id", metadata.get("id", fpath.stem))
        return [{
            "id": doc_id,
            "title": metadata.get("title", title),
            "category": metadata.get("category", subcategory or "cloud"),
            "subcategory": metadata.get("tactics", subcategory),
            "description": content[:800],
            "techniques": techniques[:20],
            "indicators": [],
            "tags": (metadata.get("platform", "") + "," + metadata.get("source", "")).strip(",").split(","),
            "tools": [],
            "confidence": 0.85,
            "mitre_attack": metadata.get("technique_id", ""),
        }]

    # ── Search ─────────────────────────────────────────────────────

    def search(
        self, query: str, top_k: int = 5,
        collection: str = "", category: str = "",
        subcategory: str = "", min_keyword_overlap: float = 0.0,
    ) -> List[Dict[str, Any]]:
        """Semantic search over static knowledge.

        Args:
            query: Natural language query.
            top_k: Max results to return.
            collection: Optional collection filter (web, windows_ad, cloud, network).
            category: Optional category filter.
            subcategory: Optional subcategory filter.
            min_keyword_overlap: Minimum fraction of query words that must appear
                in the result text. Results below this threshold get a 0.3x score
                penalty to prevent irrelevant vector matches from polluting results.
                Default 0.0 = no filtering, for backward compatibility.

        Returns:
            List of dicts with id, title, category, subcategory, description,
            techniques, indicators, tags, tools, mitre_attack, collection, score.
        """
        if not self._loaded:
            return []

        t0 = time.time()
        targets = [collection] if collection and collection in COLLECTIONS else COLLECTIONS
        all_scored: List[tuple[float, Dict[str, Any]]] = []

        embedder = self._get_embedder()

        for coll in targets:
            entries = self._collections.get(coll, [])
            if not entries:
                continue

            if embedder and coll in self._faiss_indices:
                # Neural search
                try:
                    q_vec = embedder.encode(
                        [query], normalize_embeddings=True,
                        show_progress_bar=False,
                    )
                    q_vec = np.array(q_vec, dtype=np.float32)
                    idx = self._faiss_indices[coll]
                    fetch_k = min(top_k * 3, len(entries))
                    scores, indices = idx.search(q_vec, fetch_k)
                    for score, i in zip(scores[0], indices[0]):
                        if i < 0 or i >= len(entries):
                            continue
                        if score > 0:
                            all_scored.append((float(score), entries[i]))
                except Exception:
                    pass  # fall through to TF-IDF
            elif coll in self._vectorizers:
                # TF-IDF search
                vec = self._vectorizers[coll]
                matrix = self._matrices[coll]
                q_vec = vec.transform([query])
                from sklearn.metrics.pairwise import cosine_similarity
                sims = cosine_similarity(q_vec, matrix)[0]
                for i, sim in enumerate(sims):
                    if sim > 0.01:
                        all_scored.append((float(sim), entries[i]))

        # Post-filter: metadata + keyword overlap quality check
        all_scored.sort(key=lambda x: x[0], reverse=True)
        results = []

        # Compute keyword overlap ratio for each result (once, not per iteration)
        if min_keyword_overlap > 0:
            query_words = _tokenize(query)
            if query_words:
                for i, (score, entry) in enumerate(all_scored):
                    search_text = entry.get("_search_text", "")
                    if search_text:
                        overlap = _keyword_overlap(query_words, search_text)
                        if overlap < min_keyword_overlap:
                            # Soft penalty: low overlap results drop below genuine matches
                            all_scored[i] = (score * 0.3, entry)

        # Re-sort after penalty
        if min_keyword_overlap > 0:
            all_scored.sort(key=lambda x: x[0], reverse=True)

        for score, entry in all_scored:
            if category and entry.get("category", "") != category:
                continue
            if subcategory and entry.get("subcategory", "") != subcategory:
                continue
            r = {k: v for k, v in entry.items() if not k.startswith("_")}
            r["score"] = round(score, 3)
            results.append(r)
            if len(results) >= top_k:
                break

        rag_log.info(
            "RAG_SEARCH query=%r results=%d collection=%r category=%r elapsed=%.3fs",
            query[:120], len(results), collection or "any",
            category or "any", time.time() - t0,
        )
        for i, r in enumerate(results[:5]):
            rag_log.info("RAG_HIT #%d title=%r score=%.3f collection=%r category=%r",
                         i + 1, r.get("title", ""), r.get("score", 0),
                         r.get("collection", ""), r.get("category", ""))

        return results

    # ── Phase 2: hierarchical retrieval ─────────────────────────────

    def load_taxonomy(self, path: str = "") -> int:
        """Load the explicit taxonomy (domain -> class -> scenario leaf).

        Returns the number of leaves loaded. Missing/invalid taxonomy files
        are tolerated — hierarchical search then falls back to flat search.
        """
        self._taxonomy = None
        self._taxonomy_leaves = []
        self._leaf_embeddings = {}
        candidate = path or str(
            Path(__file__).resolve().parent.parent / "knowledge" / "taxonomy.json"
        )
        taxonomy_path = Path(candidate)
        if not taxonomy_path.exists():
            rag_log.info("No taxonomy file at %s — hierarchical search disabled", taxonomy_path)
            return 0
        try:
            data = json.loads(taxonomy_path.read_text(encoding="utf-8"))
        except Exception as e:
            rag_log.warning("Failed to load taxonomy %s: %s", taxonomy_path, e)
            return 0
        leaves = data.get("leaves", []) if isinstance(data, dict) else []
        leaves = [leaf for leaf in leaves if isinstance(leaf, dict) and leaf.get("id")]
        self._taxonomy = data
        self._taxonomy_leaves = leaves
        rag_log.info("Taxonomy loaded: %d leaves from %s", len(leaves), taxonomy_path)
        return len(leaves)

    @property
    def taxonomy_loaded(self) -> bool:
        return bool(self._taxonomy_leaves)

    def _leaf_text(self, leaf: Dict[str, Any]) -> str:
        parts = [str(p) for p in (leaf.get("path") or [])]
        parts.extend([str(leaf.get("title") or ""), str(leaf.get("guid") or "")])
        return " ".join(parts)

    def _route_leaves(
        self, query: str, route_k: int, min_route_score: float = 0.0,
    ) -> List[Dict[str, Any]]:
        """Score every taxonomy leaf and return the top ``route_k``."""
        if not self._taxonomy_leaves:
            return []
        query_words = _tokenize(query)
        embedder = self._get_embedder()
        q_vec = None
        if embedder is not None:
            q_vec = embedder.encode(
                [query], normalize_embeddings=True,
                show_progress_bar=False,
            )[0]

        scored: List[tuple[float, Dict[str, Any]]] = []
        for leaf in self._taxonomy_leaves:
            text = self._leaf_text(leaf)
            keyword = (
                _keyword_overlap(query_words, text)
                if query_words else 0.0
            )
            emb = 0.0
            if q_vec is not None:
                vec = self._leaf_embeddings.get(leaf["id"])
                if vec is None:
                    vec = embedder.encode(
                        [text], normalize_embeddings=True,
                        show_progress_bar=False,
                    )[0]
                    self._leaf_embeddings[leaf["id"]] = vec
                emb = float(np.dot(q_vec, vec))
            score = 0.5 * keyword + (0.5 * max(emb, 0.0) if q_vec is not None else 0.0)
            scored.append((score, leaf))

        scored.sort(key=lambda x: x[0], reverse=True)
        return [
            leaf for score, leaf in scored[:route_k]
            if score > min_route_score
        ]

    def _score_subset(
        self,
        collection: str,
        entries: List[Dict[str, Any]],
        selected_ids: set[str],
        query: str,
        query_words: list[str],
    ) -> List[tuple[float, Dict[str, Any]]]:
        """Score only the entries whose id is in ``selected_ids``."""
        subset = [
            (i, e) for i, e in enumerate(entries)
            if str(e.get("id", "")) in selected_ids
        ]
        if not subset:
            return []
        embedder = self._get_embedder()
        sims: list[float] = []
        if embedder is not None and collection in self._faiss_indices:
            idx = self._faiss_indices[collection]
            q_vec = embedder.encode(
                [query], normalize_embeddings=True,
                show_progress_bar=False,
            )[0]
            vectors = np.vstack(
                [idx.reconstruct(i).astype(np.float32) for i, _ in subset]
            )
            sims = list((vectors @ q_vec).tolist())
        elif collection in self._vectorizers:
            vec = self._vectorizers[collection]
            q_vec = vec.transform([query])
            matrix = vec.transform([e["_search_text"] for _, e in subset])
            from sklearn.metrics.pairwise import cosine_similarity
            sims = list(cosine_similarity(q_vec, matrix)[0])
        else:
            return []

        scored: List[tuple[float, Dict[str, Any]]] = []
        for (_, entry), sim in zip(subset, sims):
            if sim <= 0.0:
                continue
            overlap = _keyword_overlap(query_words, entry.get("_search_text", ""))
            confidence = float(entry.get("confidence") or 0.5)
            score = 0.6 * sim + 0.2 * overlap + 0.2 * confidence
            scored.append((score, entry))
        return scored

    def search_hierarchical(
        self,
        query: str,
        top_k: int = 5,
        route_k: int = 2,
        min_route_score: float = 0.0,
        min_keyword_overlap: float = 0.0,
    ) -> List[Dict[str, Any]]:
        """Two-stage retrieval: route to taxonomy leaves, then score inside
        the selected subtree. Falls back to the flat :meth:`search` when the
        taxonomy is unavailable or no leaf routes above ``min_route_score``.

        Rerank: 0.6 * vector/cosine + 0.2 * keyword overlap + 0.2 * confidence.
        Results carry ``path`` and ``guid`` for explainability.
        """
        if not self.taxonomy_loaded:
            return self.search(
                query, top_k=top_k, min_keyword_overlap=min_keyword_overlap
            )

        leaves = self._route_leaves(
            query, route_k=route_k, min_route_score=min_route_score
        )
        if not leaves:
            return self.search(
                query, top_k=top_k, min_keyword_overlap=min_keyword_overlap
            )

        selected_ids = {str(leaf["id"]) for leaf in leaves}
        leaf_by_id = {str(leaf["id"]): leaf for leaf in leaves}
        query_words = _tokenize(query)
        all_scored: List[tuple[float, Dict[str, Any]]] = []

        for coll in COLLECTIONS:
            entries = self._collections.get(coll, [])
            if not entries:
                continue
            all_scored.extend(
                self._score_subset(
                    coll, entries, selected_ids, query, query_words
                )
            )

        if not all_scored:
            return self.search(
                query, top_k=top_k, min_keyword_overlap=min_keyword_overlap
            )

        all_scored.sort(key=lambda x: x[0], reverse=True)
        results: List[Dict[str, Any]] = []
        seen: set[str] = set()
        for score, entry in all_scored:
            entry_id = str(entry.get("id", ""))
            if entry_id in seen:
                continue
            seen.add(entry_id)
            leaf = leaf_by_id.get(entry_id, {})
            r = {k: v for k, v in entry.items() if not k.startswith("_")}
            r["score"] = round(score, 3)
            r["path"] = leaf.get("path", [])
            r["guid"] = leaf.get("guid", "")
            results.append(r)
            if len(results) >= top_k:
                break

        if not results:
            return self.search(
                query, top_k=top_k, min_keyword_overlap=min_keyword_overlap
            )
        rag_log.info(
            "RAG_HIER_SEARCH query=%r route_leaves=%d results=%d elapsed=%.3fs",
            query[:120], len(leaves), len(results), 0.0,
        )
        return results

    def summarize(
        self, query: str, top_k: int = 3,
        collection: str = "", category: str = "",
        subcategory: str = "", min_keyword_overlap: float = 0.0,
    ) -> str:
        """Formatted text summary for direct LLM context injection.

        Used by orchestrator for automatic context enrichment (Path A).
        """
        results = self.search(
            query, top_k=top_k, collection=collection,
            category=category, subcategory=subcategory,
            min_keyword_overlap=min_keyword_overlap,
        )
        if not results:
            return ""
        parts = []
        for i, r in enumerate(results, 1):
            header = (
                f"### {i}. {r['title']} "
                f"[{r.get('collection','')}/{r.get('category','')}/{r.get('subcategory','')}] "
                f"(score={r['score']:.3f})"
            )
            if r.get("mitre_attack"):
                header += f" MITRE:{r['mitre_attack']}"
            parts.append(header)
            parts.append(r["description"][:300])
            if r.get("techniques"):
                parts.append("Commands: " + "; ".join(r["techniques"][:3]))
            if r.get("tools"):
                parts.append("Tools: " + ", ".join(r["tools"]))
            parts.append("")
        return "\n".join(parts)

    # ── Document ingestion ─────────────────────────────────────────

    def add_documents(
        self, docs: List[Dict[str, Any]], collection: str = "web",
    ) -> int:
        """Add or update documents. Returns count of new docs added.

        Matches container-pentester-agent's VectorStore.AddDocuments interface.
        Each doc dict must have: title, description, category.
        Optional: subcategory, techniques, indicators, tags, tools, mitre_attack.
        """
        if collection not in COLLECTIONS:
            rag_log.warning("Unknown collection: %s", collection)
            return 0

        entries = self._collections[collection]
        existing_ids = {
            _doc_id(e["_search_text"], {"id": e["id"], "collection": collection})
            for e in entries
        }
        new_count = 0

        for doc in docs:
            entry = {
                "id": doc.get("id", f"doc-{len(entries) + new_count}"),
                "title": doc.get("title", ""),
                "category": doc.get("category", ""),
                "subcategory": doc.get("subcategory", ""),
                "description": doc.get("description", ""),
                "techniques": doc.get("techniques", []),
                "indicators": doc.get("indicators", []),
                "tags": doc.get("tags", []),
                "tools": doc.get("tools", []),
                "prerequisites": doc.get("prerequisites", []),
                "confidence": doc.get("confidence", 0.5),
                "mitre_attack": doc.get("mitre_attack", ""),
                "references": doc.get("references", []),
                "collection": collection,
                "_search_text": _build_search_text(doc),
            }
            uid = _doc_id(entry["_search_text"], {
                "id": entry["id"], "collection": collection,
            })
            if uid in existing_ids:
                continue
            existing_ids.add(uid)
            entries.append(entry)
            new_count += 1

        if new_count > 0:
            # Rebuild index for this collection
            self._entry_index[collection] = {
                str(e.get("id", "")): i for i, e in enumerate(entries)
            }
            texts = [e["_search_text"] for e in entries]
            embedder = self._get_embedder()
            if embedder:
                try:
                    embeddings = embedder.encode(
                        texts, show_progress_bar=False,
                        normalize_embeddings=True,
                    )
                    embeddings = np.array(embeddings, dtype=np.float32)
                    import faiss
                    idx = faiss.IndexFlatIP(self._dim)
                    idx.add(embeddings)
                    self._faiss_indices[collection] = idx
                except Exception:
                    embedder = None
            if not embedder:
                from sklearn.feature_extraction.text import TfidfVectorizer
                vec = TfidfVectorizer(
                    max_features=None, analyzer="word",
                    ngram_range=(1, 2), stop_words="english",
                )
                matrix = vec.fit_transform(texts)
                self._vectorizers[collection] = vec
                self._matrices[collection] = matrix

            self._entry_count += new_count
            rag_log.info("add_documents: +%d to %s (total=%d)",
                         new_count, collection, len(entries))

        return new_count

    # ── Ingestion (mirrors container-pentester-agent's ETL) ───────

    def ingest_file(self, file_path: str, collection: str = "") -> int:
        """Import a single knowledge file (JSON or Markdown).

        Mirrors container-pentester-agent's: ingest --file <path> --type <type>

        For JSON files: parses array of entries directly.
        For Markdown files: extracts content + metadata footer.

        Returns number of new entries added.
        """
        fpath = Path(file_path)
        if not fpath.exists():
            rag_log.error("File not found: %s", file_path)
            return 0

        coll = collection or _path_to_collection(fpath)
        if coll not in COLLECTIONS:
            rag_log.warning("Unknown collection %s, defaulting to web", coll)
            coll = "web"

        if fpath.suffix == ".json":
            return self._ingest_json(fpath, coll)
        elif fpath.suffix in (".md", ".markdown"):
            return self._ingest_markdown(fpath, coll)
        else:
            rag_log.warning("Unsupported file type: %s", fpath.suffix)
            return 0

    def ingest_directory(self, dir_path: str, collection: str = "") -> int:
        """Import all knowledge files from a directory recursively.

        Mirrors container-pentester-agent's directory mode.
        Scans for .json and .md files.

        Returns number of new entries added.
        """
        root = Path(dir_path)
        if not root.is_dir():
            rag_log.error("Directory not found: %s", dir_path)
            return 0

        total = 0
        files = sorted(list(root.rglob("*.json")) + list(root.rglob("*.md")))
        for fpath in files:
            coll = collection or _path_to_collection(fpath)
            n = self.ingest_file(str(fpath), coll)
            total += n
            if n > 0:
                rag_log.info("  ingested %s → %s (%d entries)", fpath.name, coll, n)
        return total

    def _ingest_json(self, fpath: Path, collection: str) -> int:
        """Parse JSON knowledge file into documents and add to collection."""
        with open(fpath, encoding="utf-8") as f:
            data = json.load(f)
        items = data if isinstance(data, list) else [data]
        docs = []
        for item in items:
            if not isinstance(item, dict) or "id" not in item:
                continue
            docs.append({
                "id": item.get("id", ""),
                "title": item.get("title", ""),
                "category": item.get("category", collection),
                "subcategory": item.get("subcategory", ""),
                "description": item.get("description", ""),
                "techniques": item.get("techniques", []),
                "indicators": item.get("indicators", []),
                "tags": item.get("tags", []),
                "tools": item.get("tools", []),
                "prerequisites": item.get("prerequisites", []),
                "confidence": item.get("confidence", 0.5),
                "mitre_attack": item.get("mitre_attack", ""),
                "references": item.get("references", []),
            })
        if docs:
            return self.add_documents(docs, collection)
        return 0

    def _ingest_markdown(self, fpath: Path, collection: str) -> int:
        """Parse Markdown knowledge file with metadata footer.

        Matches container-pentester-agent's Markdown format:
        ```
        # Title
        Content...

        **元数据**:
        - category: "technique"
        - title: "Technique Name"
        - technique_id: "T1234"
        ```
        """
        with open(fpath, encoding="utf-8") as f:
            text = f.read()

        # Split content from metadata footer
        parts = text.split("**元数据**:", 1)
        if len(parts) < 2:
            parts = text.split("**Metadata**:", 1)
        if len(parts) < 2:
            parts = text.split("---", 1)

        content = parts[0].strip()
        metadata = {}
        if len(parts) >= 2:
            for line in parts[1].strip().split("\n"):
                line = line.strip()
                if line.startswith("- ") or line.startswith("* "):
                    kv = line[2:].split(":", 1)
                    if len(kv) == 2:
                        key = kv[0].strip().lower().replace(" ", "_")
                        val = kv[1].strip().strip('"').strip("'")
                        metadata[key] = val

        # Extract title from first heading
        title = fpath.stem
        for line in content.split("\n"):
            if line.startswith("# "):
                title = line[2:].strip()
                break

        doc_id = metadata.get("technique_id", metadata.get("id", fpath.stem))
        doc = {
            "id": doc_id,
            "title": metadata.get("title", title),
            "category": metadata.get("category", collection),
            "subcategory": metadata.get("subcategory", metadata.get("tactics", "")),
            "description": content[:500],
            "techniques": [content],
            "indicators": [],
            "tags": metadata.get("tags", "").split(",") if metadata.get("tags") else [],
            "tools": metadata.get("tools", "").split(",") if metadata.get("tools") else [],
            "confidence": float(metadata.get("confidence", 0.7)),
            "mitre_attack": metadata.get("technique_id", ""),
        }
        return self.add_documents([doc], collection)

    def rebuild_indices(self, collection: str = "") -> int:
        """Rebuild Faiss/TF-IDF indices for one or all collections.

        Call after batch ingestion to ensure search consistency.
        """
        targets = [collection] if collection and collection in COLLECTIONS else COLLECTIONS
        total = 0
        for coll in targets:
            entries = self._collections.get(coll, [])
            if not entries:
                continue
            self._entry_index[coll] = {
                str(e.get("id", "")): i for i, e in enumerate(entries)
            }
            texts = [e["_search_text"] for e in entries]
            total += len(entries)

            embedder = self._get_embedder()
            if embedder:
                try:
                    embeddings = embedder.encode(
                        texts, show_progress_bar=False,
                        normalize_embeddings=True,
                    )
                    embeddings = np.array(embeddings, dtype=np.float32)
                    import faiss
                    idx = faiss.IndexFlatIP(self._dim)
                    idx.add(embeddings)
                    self._faiss_indices[coll] = idx
                    rag_log.info("Rebuilt Faiss index for %s: %d vectors", coll, len(entries))
                    continue
                except Exception as e:
                    rag_log.warning("Faiss rebuild failed for %s: %s", coll, e)

            from sklearn.feature_extraction.text import TfidfVectorizer
            vec = TfidfVectorizer(
                max_features=None, analyzer="word",
                ngram_range=(1, 2), stop_words="english",
            )
            matrix = vec.fit_transform(texts)
            self._vectorizers[coll] = vec
            self._matrices[coll] = matrix
            rag_log.info("Rebuilt TF-IDF index for %s: %d docs", coll, len(entries))

        return total

    # ── Properties ─────────────────────────────────────────────────

    @property
    def loaded(self) -> bool:
        return self._loaded

    @property
    def entry_count(self) -> int:
        return self._entry_count

    def collection_sizes(self) -> Dict[str, int]:
        return {c: len(self._collections[c]) for c in COLLECTIONS}


# ── Helpers ──────────────────────────────────────────────────────────

# Common English stop words — short, high-frequency words that carry
# little semantic meaning for keyword overlap computation.
_STOP_WORDS = frozenset({
    "a", "an", "the", "is", "are", "was", "were", "be", "been", "being",
    "have", "has", "had", "do", "does", "did", "will", "would", "could",
    "should", "may", "might", "can", "shall", "to", "of", "in", "for",
    "on", "with", "at", "by", "from", "as", "into", "through", "during",
    "before", "after", "above", "below", "between", "under", "and", "but",
    "or", "not", "no", "if", "then", "else", "when", "where", "which",
    "who", "whom", "this", "that", "these", "those", "it", "its", "he",
    "she", "they", "we", "you", "i", "me", "my", "your", "our", "all",
    "each", "every", "both", "few", "more", "most", "other", "some",
    "such", "only", "about", "up", "out", "than", "too", "very", "just",
})


def _tokenize(text: str) -> list[str]:
    """Extract meaningful words from text for keyword overlap check."""
    words = []
    for w in text.lower().split():
        w = w.strip('.,;:!?()[]{}"\'/\\-')
        if len(w) > 1 and w not in _STOP_WORDS:
            words.append(w)
    return words


def _keyword_overlap(query_words: list[str], result_text: str) -> float:
    """Fraction of query words found in result text (0.0 to 1.0)."""
    if not query_words:
        return 0.0
    result_lower = result_text.lower()
    hits = sum(1 for w in query_words if w in result_lower)
    return hits / len(query_words)

def _build_search_text(item: dict) -> str:
    """Build a searchable text blob from a knowledge entry."""
    parts = []
    if item.get("category"):
        parts.append(item["category"])
    if item.get("subcategory"):
        parts.append(item["subcategory"])
    if item.get("title"):
        parts.append(item["title"])
    if item.get("description"):
        parts.append(item["description"])
    if item.get("indicators"):
        parts.append("Indicators: " + "; ".join(item["indicators"]))
    if item.get("tags"):
        parts.append("Tags: " + ", ".join(item["tags"]))
    return ". ".join(parts) + "."


# ── Singleton ────────────────────────────────────────────────────────

_rag_instance: Optional[DarwinRAG] = None


def get_rag(knowledge_dir: str = "knowledge/",
            model_dir: str = "") -> DarwinRAG:
    """Get or create the singleton DarwinRAG instance.

    Args:
        knowledge_dir: Path to the knowledge/ directory with JSON files.
        model_dir: Path to sentence-transformers model directory.
                   Defaults to /home/kianabin/utils/all-MiniLM-L6-v2
    """
    global _rag_instance
    if _rag_instance is None:
        _rag_instance = DarwinRAG(
            model_dir=model_dir or DarwinRAG._DEFAULT_MODEL_DIR,
        )
        _rag_instance.load(knowledge_dir)
    return _rag_instance
