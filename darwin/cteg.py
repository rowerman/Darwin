"""Cross-Task Experience Graph — pattern abstraction and retrieval across tasks.

Reference:
  - AWE MemoryStorage (SQLite tables: payload_attempts, detected_filters,
    successful_bypasses, strategy_effectiveness)
  - VulnBot rag/ (Milvus vector DB + Embedding + Reranker)
  - DARWIN framework spec — abstract patterns across task boundaries
"""

from __future__ import annotations

import json
import math
import os
import threading
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import networkx as nx


# ── Pattern Types ───────────────────────────────────────────────────

@dataclass
class BypassPattern:
    """Abstract bypass technique pattern."""
    pattern_id: str
    mechanism: str           # e.g., "double_URL_encode", "case_alternation"
    abstract_description: str  # e.g., "Double URL encoding bypasses ModSecurity CRS"
    applicable_defense_types: List[str] = field(default_factory=list)
    applicable_vuln_types: List[str] = field(default_factory=list)
    preconditions: List[str] = field(default_factory=list)
    total_attempts: int = 0
    total_successes: int = 0
    avg_attempts_to_success: float = 0.0
    last_successful_use: str = ""
    half_life_days: int = 30
    reinforcement_count: int = 0
    created_from_task: str = ""

    @property
    def success_rate(self) -> float:
        if self.total_attempts == 0:
            return 0.0
        return self.total_successes / self.total_attempts

    @property
    def is_active(self) -> bool:
        """Pattern is still active (has been used recently)."""
        return self.reinforcement_count > 0 or self.total_attempts > 0


@dataclass
class ExploitPattern:
    """Abstract exploitation technique pattern with concrete steps."""
    pattern_id: str
    mechanism: str
    abstract_description: str
    vulnerability_type: str
    required_context: str = ""
    total_attempts: int = 0
    total_successes: int = 0
    last_successful_use: str = ""
    half_life_days: int = 30
    created_from_task: str = ""
    concrete_techniques: List[str] = field(default_factory=list)  # actual steps that worked
    technology_stack: List[str] = field(default_factory=list)  # what tech this applies to

    @property
    def success_rate(self) -> float:
        if self.total_attempts == 0:
            return 0.0
        return self.total_successes / self.total_attempts


@dataclass
class TaskRecord:
    """Record of a completed penetration test task for pattern extraction."""
    task_id: str
    benchmark: str
    vulnerability_types: List[str]
    outcome: str  # "success" | "partial" | "failure"
    defense_encountered: Dict[str, Any] = field(default_factory=dict)
    successful_bypasses: List[Dict[str, Any]] = field(default_factory=list)
    failed_bypasses: List[Dict[str, Any]] = field(default_factory=list)
    exploit_chain: List[Dict[str, Any]] = field(default_factory=list)
    technology_stack: List[str] = field(default_factory=list)  # e.g. ["FastAPI","JWT","Jinja2","MySQL"]
    key_findings: List[str] = field(default_factory=list)  # e.g. ["default creds demo:demo","OpenAPI at /openapi.json"]
    timestamp: str = ""

    def summary(self) -> str:
        return (
            f"Task {self.task_id} ({self.benchmark}): {self.outcome}\n"
            f"  Vulns: {self.vulnerability_types}\n"
            f"  Tech: {self.technology_stack}\n"
            f"  Defense: {self.defense_encountered}\n"
            f"  Bypasses: {len(self.successful_bypasses)} success / {len(self.failed_bypasses)} fail\n"
            f"  Chain: {len(self.exploit_chain)} steps"
        )


# ── CTEG Core ───────────────────────────────────────────────────────

class CTEG:
    """Cross-Task Experience Graph.

    Stores abstract exploit and bypass patterns that survive task boundaries.
    Unlike AWE MemoryStorage (per-task persistence), CTEG generalizes patterns
    across tasks, stripping challenge-specific details.

    Implementation:
      Phase 1: JSON file + NetworkX (lightweight, no external DB)
      Phase 2: Milvus/Qdrant vector DB + Neo4j (production scale)
    """

    def __init__(self, storage_path: str = "cteg_state.json"):
        self.graph = nx.MultiDiGraph()
        self.storage_path = storage_path
        self._lock = threading.RLock()
        self._created_at = datetime.now().isoformat()
        self._task_count = 0

        # Lazy-init embedder for semantic search
        self._embedder = None
        self._embedding_cache: Dict[str, Any] = {}  # node_id -> embedding vector

        # Load existing state if available
        if os.path.exists(storage_path):
            self._load(storage_path)

    def _get_embedder(self):
        """Lazy-init the embedder.

        Uses SentenceTransformer (neural semantic search) when model is cached.
        Falls back to TF-IDF vectorizer (lightweight, no model download).
        Set DARWIN_USE_NEURAL=1 to enable neural embeddings.
        """
        if self._embedder is None:
            import os
            if os.environ.get("DARWIN_USE_NEURAL") == "1":
                try:
                    from sentence_transformers import SentenceTransformer
                    self._embedder = SentenceTransformer(
                        'all-MiniLM-L6-v2', local_files_only=True,
                    )
                except Exception:
                    self._embedder = None
            else:
                self._embedder = None  # use TF-IDF by default
        return self._embedder

    def _build_vocabulary(self) -> Dict[str, int]:
        """Build shared vocabulary from all knowledge patterns for TF-IDF."""
        vocab: Dict[str, int] = {}
        with self._lock:
            for nid, data in self.graph.nodes(data=True):
                if data.get("type") != "KnowledgePattern":
                    continue
                text = data.get("embed_text", data.get("description", ""))
                for word in text.lower().split():
                    word = word.strip('.,;:!?()[]{}"\'')
                    if len(word) > 1 and word not in vocab:
                        vocab[word] = len(vocab)
        return vocab

    def _tfidf_vector(self, text: str, vocab: Dict[str, int],
                      idf: Dict[str, float]) -> "np.ndarray":
        """Convert text to TF-IDF vector using shared vocabulary."""
        import numpy as np
        vec = np.zeros(len(vocab))
        words = text.lower().split()
        if not words:
            return vec
        for word in words:
            word = word.strip('.,;:!?()[]{}"\'')
            if word in vocab:
                tf = 1.0  # binary term frequency for short queries
                vec[vocab[word]] = tf * idf.get(word, 1.0)
        norm = np.linalg.norm(vec)
        if norm > 0:
            vec = vec / norm
        return vec

    # ── Pattern Storage ──────────────────────────────────────────

    def add_bypass_pattern(self, pattern: BypassPattern) -> str:
        """Store a bypass pattern in the graph."""
        with self._lock:
            self.graph.add_node(pattern.pattern_id, **{
                "type": "BypassPattern",
                "mechanism": pattern.mechanism,
                "abstract_description": pattern.abstract_description,
                "applicable_defense_types": pattern.applicable_defense_types,
                "applicable_vuln_types": pattern.applicable_vuln_types,
                "preconditions": pattern.preconditions,
                "total_attempts": pattern.total_attempts,
                "total_successes": pattern.total_successes,
                "success_rate": pattern.success_rate,
                "last_successful_use": pattern.last_successful_use,
                "half_life_days": pattern.half_life_days,
                "reinforcement_count": pattern.reinforcement_count,
                "created_at": datetime.now().isoformat(),
            })
            self._persist()
        return pattern.pattern_id

    def add_exploit_pattern(self, pattern: ExploitPattern) -> str:
        """Store an exploit pattern in the graph."""
        with self._lock:
            self.graph.add_node(pattern.pattern_id, **{
                "type": "ExploitPattern",
                "mechanism": pattern.mechanism,
                "abstract_description": pattern.abstract_description,
                "vulnerability_type": pattern.vulnerability_type,
                "required_context": pattern.required_context,
                "total_attempts": pattern.total_attempts,
                "total_successes": pattern.total_successes,
                "success_rate": pattern.success_rate,
                "last_successful_use": pattern.last_successful_use,
                "half_life_days": pattern.half_life_days,
                "created_at": datetime.now().isoformat(),
            })
            self._persist()
        return pattern.pattern_id

    def update_pattern_attempt(
        self, pattern_id: str, success: bool, attempts: int = 1
    ) -> None:
        """Update attempt/success counts for a pattern."""
        with self._lock:
            if pattern_id in self.graph:
                node = self.graph.nodes[pattern_id]
                node["total_attempts"] = node.get("total_attempts", 0) + attempts
                node["total_successes"] = node.get("total_successes", 0) + (1 if success else 0)
                node["success_rate"] = (
                    node["total_successes"] / node["total_attempts"]
                    if node["total_attempts"] > 0 else 0.0
                )
                if success:
                    node["last_successful_use"] = datetime.now().isoformat()
                    node["reinforcement_count"] = node.get("reinforcement_count", 0) + 1
                self._persist()

    # ── Pattern Abstraction ──────────────────────────────────────

    def extract_patterns(self, task_record: TaskRecord) -> List[Tuple[BypassPattern | ExploitPattern, str]]:
        """Extract abstract patterns from a completed task record.

        Strips all challenge-specific details (IPs, hostnames, specific payloads)
        and retains only the abstract mechanism.

        Returns:
            List of (pattern, edge_type) tuples for insertion into the graph.
        """
        patterns = []

        # Extract bypass patterns
        for bp in task_record.successful_bypasses:
            mechanism = bp.get("strategy", "unknown")
            defense_type = task_record.defense_encountered.get("type", "unknown")

            pattern = BypassPattern(
                pattern_id=f"bp-{mechanism}-{defense_type}",
                mechanism=mechanism,
                abstract_description=bp.get("abstract", bp.get("notes", f"{mechanism} bypass for {defense_type}")),
                applicable_defense_types=[defense_type],
                applicable_vuln_types=task_record.vulnerability_types,
                total_attempts=1,
                total_successes=1,
                last_successful_use=task_record.timestamp or datetime.now().isoformat(),
                created_from_task=task_record.task_id,
            )
            patterns.append((pattern, "bypass_applies_to_defense"))

        # Extract failed bypass patterns (negative examples)
        for fb in task_record.failed_bypasses:
            mechanism = fb.get("strategy", "unknown")
            defense_type = task_record.defense_encountered.get("type", "unknown")

            pattern = BypassPattern(
                pattern_id=f"bp-fail-{mechanism}-{defense_type}",
                mechanism=mechanism,
                abstract_description=f"{mechanism} FAILED against {defense_type}",
                applicable_defense_types=[defense_type],
                applicable_vuln_types=task_record.vulnerability_types,
                total_attempts=1,
                total_successes=0,
                created_from_task=task_record.task_id,
            )
            patterns.append((pattern, "bypass_failed_against"))

        # Extract exploit patterns with concrete techniques
        for step in task_record.exploit_chain:
            vuln_type = step.get("vuln_type", task_record.vulnerability_types[0] if task_record.vulnerability_types else "unknown")
            mechanism = step.get("mechanism", "") or step.get("tool", "") or step.get("action", "unknown")
            tool = step.get("tool", "")
            url = step.get("url", "")
            method = step.get("method", "GET")

            # Build a rich description from concrete step details
            desc_parts = [f"{vuln_type} exploitation"]
            if tool:
                desc_parts.append(f"via {tool}")
            if url:
                desc_parts.append(f"on {url}")
            if method:
                desc_parts.append(f"({method})")

            # Collect concrete techniques from all steps
            concrete = []
            for s in task_record.exploit_chain:
                parts = [s.get('tool', ''), s.get('method', 'GET'),
                         s.get('url', s.get('params', '')), "→",
                         (s.get('result', '') or '')[:80]]
                concrete.append(" ".join(p for p in parts if p))

            pattern = ExploitPattern(
                pattern_id=f"ep-{vuln_type}-{task_record.task_id[:8]}",
                mechanism=mechanism,
                abstract_description="; ".join(desc_parts),
                vulnerability_type=vuln_type,
                required_context=step.get("context", ""),
                total_attempts=1,
                total_successes=1 if task_record.outcome == "success" else 0,
                last_successful_use=task_record.timestamp if task_record.outcome == "success" else "",
                created_from_task=task_record.task_id,
                concrete_techniques=concrete,
                technology_stack=task_record.technology_stack,
            )
            patterns.append((pattern, "exploit_applies_to_vuln"))

        return patterns

    def commit_task(self, task_record: TaskRecord) -> int:
        """Extract and store all patterns from a completed task.

        Returns:
            Number of new patterns added.
        """
        patterns = self.extract_patterns(task_record)
        new_count = 0

        with self._lock:
            for pattern, edge_type in patterns:
                pid = pattern.pattern_id
                if pid not in self.graph:
                    if isinstance(pattern, BypassPattern):
                        self.add_bypass_pattern(pattern)
                    else:
                        self.add_exploit_pattern(pattern)
                    new_count += 1
                else:
                    # Merge: update existing pattern
                    if isinstance(pattern, BypassPattern):
                        self.update_pattern_attempt(
                            pid, pattern.total_successes > 0, pattern.total_attempts,
                        )
                    else:
                        self.update_pattern_attempt(
                            pid, pattern.total_successes > 0, pattern.total_attempts,
                        )

            self._task_count += 1
            self._persist()

        return new_count

    # ── Pattern Retrieval ────────────────────────────────────────

    def query_bypass_patterns(
        self, defense_type: str, vuln_type: str = "", top_k: int = 5
    ) -> List[BypassPattern]:
        """Query bypass patterns effective against a specific defense type."""
        candidates = []

        with self._lock:
            for nid, data in self.graph.nodes(data=True):
                if data.get("type") != "BypassPattern":
                    continue
                defense_types = data.get("applicable_defense_types", [])
                if defense_type not in defense_types and "any" not in defense_types:
                    continue
                if vuln_type:
                    vuln_types = data.get("applicable_vuln_types", [])
                    if vuln_type not in vuln_types and "any" not in vuln_types:
                        continue

                success_rate = data.get("success_rate", 0.0)
                decay = self._compute_decay(data)
                score = success_rate * decay
                candidates.append((score, data))

        candidates.sort(key=lambda x: x[0], reverse=True)

        results = []
        for score, data in candidates[:top_k]:
            results.append(BypassPattern(
                pattern_id=data.get("pattern_id", ""),
                mechanism=data.get("mechanism", ""),
                abstract_description=data.get("abstract_description", ""),
                applicable_defense_types=data.get("applicable_defense_types", []),
                applicable_vuln_types=data.get("applicable_vuln_types", []),
                total_attempts=data.get("total_attempts", 0),
                total_successes=data.get("total_successes", 0),
                last_successful_use=data.get("last_successful_use", ""),
                half_life_days=data.get("half_life_days", 30),
                reinforcement_count=data.get("reinforcement_count", 0),
            ))
        return results

    def query_exploit_patterns(
        self, vuln_type: str, top_k: int = 5
    ) -> List[ExploitPattern]:
        """Query exploit patterns for a specific vulnerability type."""
        candidates = []

        with self._lock:
            for nid, data in self.graph.nodes(data=True):
                if data.get("type") != "ExploitPattern":
                    continue
                if data.get("vulnerability_type") != vuln_type:
                    continue

                success_rate = data.get("success_rate", 0.0)
                decay = self._compute_decay(data)
                score = success_rate * decay
                candidates.append((score, data))

        candidates.sort(key=lambda x: x[0], reverse=True)

        results = []
        for score, data in candidates[:top_k]:
            results.append(ExploitPattern(
                pattern_id=data.get("pattern_id", ""),
                mechanism=data.get("mechanism", ""),
                abstract_description=data.get("abstract_description", ""),
                vulnerability_type=data.get("vulnerability_type", ""),
                required_context=data.get("required_context", ""),
                total_attempts=data.get("total_attempts", 0),
                total_successes=data.get("total_successes", 0),
                last_successful_use=data.get("last_successful_use", ""),
                half_life_days=data.get("half_life_days", 30),
            ))
        return results

    def get_suggestions(
        self, defense_type: str = "", vuln_type: str = "",
        query: str = "", top_k: int = 3,
    ) -> Dict[str, Any]:
        """Get combined suggestions: static RAG knowledge + dynamic CTEG patterns.

        Queries both:
        1. RAG knowledge base (static, pre-loaded patterns)
        2. CTEG learned patterns (dynamic, from prior tasks)

        Merges, deduplicates, and returns ranked results.
        Used by _run_solo_cycle to provide the LLM with relevant exploitation guidance.

        Args:
            defense_type: Optional defense type filter for bypass patterns
            vuln_type: Optional vulnerability type filter
            query: Natural language query for RAG search (e.g. "FastAPI IDOR")
            top_k: Max patterns to return per category

        Returns:
            Dict with static_knowledge, learned_patterns, bypass_strategies, exploit_strategies
        """
        # 1. Query CTEG learned patterns (from prior tasks)
        bypass = self.query_bypass_patterns(defense_type, vuln_type, top_k)
        exploit = self.query_exploit_patterns(vuln_type, top_k) if vuln_type else []

        # 2. Query RAG knowledge base (static patterns)
        rag_results: List[Dict[str, Any]] = []
        if query:
            rag_results = self.query_rag(query, top_k=top_k)

        # 3. Build learned exploit strategies with concrete techniques
        exploit_strategies = []
        for e in exploit:
            strat = {
                "mechanism": e.mechanism,
                "description": e.abstract_description,
                "success_rate": e.success_rate,
                "context": e.required_context,
                "techniques": e.concrete_techniques,
                "source": "learned",
            }
            exploit_strategies.append(strat)

        # 4. Merge: learned patterns first (higher confidence), then RAG
        static_knowledge = []
        for r in rag_results:
            static_knowledge.append({
                "title": r.get("title", ""),
                "description": r.get("description", ""),
                "techniques": r.get("techniques", []),
                "category": r.get("category", ""),
                "score": r.get("score", 0),
                "source": "static_knowledge",
            })

        return {
            "bypass_strategies": [
                {"mechanism": b.mechanism, "description": b.abstract_description,
                 "success_rate": b.success_rate, "preconditions": b.preconditions}
                for b in bypass
            ],
            "exploit_strategies": exploit_strategies,
            "static_knowledge": static_knowledge,
            "combined_count": len(exploit_strategies) + len(static_knowledge),
        }

    # ── Decay & Maintenance ──────────────────────────────────────

    def _compute_decay(self, node_data: Dict[str, Any]) -> float:
        """Compute time-based decay factor. Half-life = 30 days by default."""
        last_use = node_data.get("last_successful_use", "")
        half_life = node_data.get("half_life_days", 30)

        if not last_use:
            return 0.5  # never used successfully

        try:
            last_dt = datetime.fromisoformat(last_use)
            days_since = (datetime.now() - last_dt).days
        except (ValueError, TypeError):
            return 0.5

        if days_since < 0:
            return 1.0

        return math.pow(0.5, days_since / half_life)

    def prune_stale_patterns(self, stale_threshold_days: int = 90) -> int:
        """Remove patterns that haven't been used in a long time."""
        removed = 0
        with self._lock:
            nodes_to_remove = []
            for nid, data in self.graph.nodes(data=True):
                last_use = data.get("last_successful_use", "")
                if not last_use:
                    continue
                try:
                    last_dt = datetime.fromisoformat(last_use)
                    days_since = (datetime.now() - last_dt).days
                except (ValueError, TypeError):
                    continue
                if days_since > stale_threshold_days and data.get("reinforcement_count", 0) < 3:
                    nodes_to_remove.append(nid)

            for nid in nodes_to_remove:
                self.graph.remove_node(nid)
                removed += 1

            if removed > 0:
                self._persist()
        return removed

    # ── Persistence ──────────────────────────────────────────────

    def _persist(self):
        if self.storage_path:
            with open(self.storage_path, "w", encoding="utf-8") as f:
                json.dump(self.to_dict(), f, indent=2, default=str)

    def _load(self, path: str):
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            for node in data.get("nodes", []):
                nid = node.pop("id", node.pop("pattern_id", ""))
                if nid:
                    self.graph.add_node(nid, **node)
            for edge in data.get("edges", []):
                u = edge.pop("from", edge.pop("source", ""))
                v = edge.pop("to", edge.pop("target", ""))
                if u and v:
                    self.graph.add_edge(u, v, **edge)
            self._task_count = data.get("task_count", 0)
        except (FileNotFoundError, json.JSONDecodeError):
            pass

    def load_knowledge_base(self, knowledge_path: str = "knowledge/") -> int:
        """Load pre-built penetration testing patterns from JSON files.

        Each JSON file contains an array of pattern objects with:
        id, type, category, title, description, techniques, indicators, tags.
        Stored as KnowledgePattern nodes in the CTEG graph.
        Pre-computes embeddings for semantic search.

        Returns number of patterns loaded.
        """
        import glob
        count = 0
        embedder = self._get_embedder()
        texts_to_embed: List[tuple[str, str]] = []  # (node_id, text)

        for fpath in sorted(glob.glob(f"{knowledge_path}*.json")):
            try:
                with open(fpath, encoding="utf-8") as f:
                    patterns = json.load(f)
                for p in patterns:
                    node_id = p.get("id", f"kb-{count}")
                    if self.graph.has_node(node_id):
                        continue
                    # Build rich text for embedding
                    embed_text = (
                        f"{p.get('category','')}: {p.get('title','')}. "
                        f"{p.get('description','')} "
                        f"Indicators: {'; '.join(p.get('indicators',[]))}. "
                        f"Tags: {', '.join(p.get('tags',[]))}."
                    )
                    self.graph.add_node(
                        node_id,
                        type="KnowledgePattern",
                        category=p.get("category", ""),
                        title=p.get("title", ""),
                        description=p.get("description", ""),
                        techniques=p.get("techniques", []),
                        indicators=p.get("indicators", []),
                        tags=p.get("tags", []),
                        confidence=p.get("confidence", 0.5),
                        source="knowledge_base",
                        embed_text=embed_text,
                    )
                    texts_to_embed.append((node_id, embed_text))
                    count += 1
            except Exception:
                pass

        # Pre-compute embeddings in batch
        if embedder and texts_to_embed:
            try:
                texts = [t for _, t in texts_to_embed]
                embeddings = embedder.encode(texts, show_progress_bar=False)
                for (nid, _), emb in zip(texts_to_embed, embeddings):
                    self._embedding_cache[nid] = emb
            except Exception:
                pass

        return count

    def query_rag(self, query: str, top_k: int = 5,
                  category: str | None = None) -> List[Dict[str, Any]]:
        """Semantic search over knowledge patterns using cosine similarity.

        Uses SentenceTransformer embeddings (all-MiniLM-L6-v2, 384-dim).
        Falls back to keyword matching if embedder is unavailable.

        Args:
            query: Natural language query (e.g. "IDOR in FastAPI edit profile")
            top_k: Number of results to return
            category: Optional filter by category (IDOR, SQLI, AUTH, etc.)

        Returns:
            List of matching pattern dicts with similarity scores.
        """
        embedder = self._get_embedder()

        if embedder:
            return self._semantic_search(query, top_k, category)
        else:
            return self._keyword_search(query, top_k, category)

    def _semantic_search(self, query: str, top_k: int,
                         category: str | None) -> List[Dict[str, Any]]:
        """Vector-based semantic search.

        Uses SentenceTransformer if available (real semantic search).
        Falls back to TF-IDF + cosine similarity (lightweight, no model download).
        """
        import numpy as np
        embedder = self._get_embedder()

        if embedder:
            # Neural embedding path
            query_vec = embedder.encode([query], show_progress_bar=False)[0]
            q_norm = np.linalg.norm(query_vec)
            results: List[tuple[float, Dict]] = []
            with self._lock:
                for nid, data in self.graph.nodes(data=True):
                    if data.get("type") != "KnowledgePattern":
                        continue
                    if category and data.get("category", "") != category:
                        continue
                    if nid in self._embedding_cache:
                        node_vec = self._embedding_cache[nid]
                    else:
                        try:
                            embed_text = data.get("embed_text", data.get("description", ""))
                            node_vec = embedder.encode([embed_text], show_progress_bar=False)[0]
                            self._embedding_cache[nid] = node_vec
                        except Exception:
                            continue
                    n_norm = np.linalg.norm(node_vec)
                    sim = float(np.dot(query_vec, node_vec) / (q_norm * n_norm)) if q_norm > 0 and n_norm > 0 else 0.0
                    tag_boost = 0.15 if any(t.lower() in query.lower() for t in data.get("tags", [])) else 0.0
                    results.append((sim + tag_boost, dict(data)))
        else:
            # TF-IDF vector path (lightweight, no model download)
            vocab = self._build_vocabulary()
            if not vocab:
                return self._keyword_search(query, top_k, category)

            # Compute IDF for all terms
            N = sum(1 for _, d in self.graph.nodes(data=True)
                    if d.get("type") == "KnowledgePattern")
            df: Dict[str, int] = {}
            for word in vocab:
                for _, d in self.graph.nodes(data=True):
                    if d.get("type") == "KnowledgePattern":
                        text = d.get("embed_text", d.get("description", ""))
                        if word in text.lower():
                            df[word] = df.get(word, 0) + 1
            idf = {w: np.log((N + 1) / (df.get(w, 0) + 1)) + 1 for w in vocab}

            query_vec = self._tfidf_vector(query, vocab, idf)
            results: List[tuple[float, Dict]] = []
            with self._lock:
                for nid, data in self.graph.nodes(data=True):
                    if data.get("type") != "KnowledgePattern":
                        continue
                    if category and data.get("category", "") != category:
                        continue
                    embed_text = data.get("embed_text", data.get("description", ""))
                    node_vec = self._tfidf_vector(embed_text, vocab, idf)
                    sim = float(np.dot(query_vec, node_vec))
                    tag_boost = 0.15 if any(t.lower() in query.lower() for t in data.get("tags", [])) else 0.0
                    results.append((sim + tag_boost, dict(data)))

        results.sort(key=lambda x: x[0], reverse=True)
        return [
            {"id": r[1].get("id", ""), "title": r[1].get("title", ""),
             "description": r[1].get("description", ""),
             "techniques": r[1].get("techniques", []),
             "indicators": r[1].get("indicators", []),
             "score": round(r[0], 3), "category": r[1].get("category", "")}
            for r in results[:top_k]
        ]

    def _keyword_search(self, query: str, top_k: int,
                        category: str | None) -> List[Dict[str, Any]]:
        """Fallback keyword-based search when embedder unavailable."""
        results: List[tuple[float, Dict]] = []
        query_lower = query.lower()
        query_words = set(query_lower.split())

        with self._lock:
            for nid, data in self.graph.nodes(data=True):
                if data.get("type") != "KnowledgePattern":
                    continue
                if category and data.get("category", "") != category:
                    continue

                search_text = (
                    f"{data.get('title','')} {data.get('description','')} "
                    f"{' '.join(data.get('tags',[]))} "
                    f"{' '.join(data.get('indicators',[]))}"
                ).lower()
                text_words = set(search_text.split())
                overlap = len(query_words & text_words)
                tag_match = any(t in query_lower for t in data.get("tags", []))
                score = overlap * 1.0 + (2.0 if tag_match else 0)
                if score > 0:
                    results.append((score, dict(data)))

        results.sort(key=lambda x: x[0], reverse=True)
        return [
            {"id": r[1].get("id", ""), "title": r[1].get("title", ""),
             "description": r[1].get("description", ""),
             "techniques": r[1].get("techniques", []),
             "indicators": r[1].get("indicators", []),
             "score": r[0], "category": r[1].get("category", "")}
            for r in results[:top_k]
        ]

    def to_dict(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "nodes": [
                    {"id": nid, **data}
                    for nid, data in self.graph.nodes(data=True)
                ],
                "edges": [
                    {"from": u, "to": v, **data}
                    for u, v, data in self.graph.edges(data=True)
                ],
                "task_count": self._task_count,
                "created_at": self._created_at,
            }

    def reset(self):
        """Clear all patterns (for CTEG ablation experiments)."""
        with self._lock:
            self.graph.clear()
            self._task_count = 0
            self._created_at = datetime.now().isoformat()
            self._persist()

    @property
    def pattern_count(self) -> int:
        return self.graph.number_of_nodes()
