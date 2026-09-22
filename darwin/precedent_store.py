"""Cross-task memory: graph snapshots, knowledge bindings and retrieval priors.

Replaces CTEG's retrieval channel.  CTEG abstracted a task into
``(mechanism, vuln_type)`` strings and matched them against a hand-written
scenario fingerprint; here the whole *environment graph* is the index key:

    task ends ──> snapshot + fingerprint + knowledge ledger ──> store
    task starts ──> fingerprint(dkg) ──> similarity ──> prior{RAG entry id: boost}

Neo4j is the primary store (``config/neo4j.yaml``).  When it is unreachable the
same records go to local JSON and the run continues; the memory layer must
never be able to break a penetration test.

Only *verified* outcomes earn positive credit: a knowledge entry injected in a
run that later failed does not become reusable just because it matched.
"""

from __future__ import annotations

import json
import logging
import os
import threading
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

from darwin.graph_fingerprint import similarity
from darwin.memory_config import MemoryConfig

log = logging.getLogger(__name__)

DEFAULT_HALF_LIFE_DAYS = 30

__all__ = [
    "PrecedentStore", "publish_prior", "current_prior", "clear_prior",
    "build_knowledge_record", "knowledge_decay",
]

_prior_lock = threading.RLock()
_published_prior: Dict[str, float] = {}


def publish_prior(prior: Dict[str, float] | None) -> None:
    """Publish the task-wide retrieval prior consumed by RAG call sites."""
    with _prior_lock:
        _published_prior.clear()
        for key, value in (prior or {}).items():
            try:
                _published_prior[str(key)] = float(value)
            except (TypeError, ValueError):
                continue


def current_prior() -> Dict[str, float]:
    """Copy of the published prior; empty dict when no precedent matched."""
    with _prior_lock:
        return dict(_published_prior)


def clear_prior() -> None:
    publish_prior({})


def knowledge_decay(
    last_success: str, half_life_days: int = DEFAULT_HALF_LIFE_DAYS
) -> float:
    """Exponential decay on the last verified success (1.0 when fresh)."""
    if not last_success:
        return 0.5
    try:
        age_days = max(0.0, (datetime.now() - datetime.fromisoformat(last_success)).total_seconds() / 86400.0)
    except (TypeError, ValueError):
        return 0.5
    if half_life_days <= 0:
        return 1.0
    return float(0.5 ** (age_days / float(half_life_days)))


def build_knowledge_record(
    knowledge_id: str,
    *,
    surfaced: bool = False,
    used: bool = False,
    verified_success: bool = False,
    failed: bool = False,
    timestamp: str = "",
) -> Dict[str, Any]:
    """One knowledge entry's accounting for a single task."""
    stamp = timestamp or datetime.now().isoformat()
    attempts = 1 if (used or verified_success or failed) else 0
    successes = 1 if verified_success else 0
    return {
        "id": str(knowledge_id),
        "surfaced": bool(surfaced),
        "used": bool(used),
        "attempts": attempts,
        "successes": successes,
        "last_success": stamp if verified_success else "",
        "last_used": stamp if attempts else "",
        "half_life_days": DEFAULT_HALF_LIFE_DAYS,
    }


class _JsonBackend:
    """Local snapshot store.  Always available, used as Neo4j fallback."""

    name = "json"

    def __init__(self, storage_dir: str):
        self.dir = Path(storage_dir)

    def store(self, record: Dict[str, Any]) -> None:
        self.dir.mkdir(parents=True, exist_ok=True)
        path = self.dir / f"{_safe_name(record['task_id'])}.json"
        path.write_text(
            json.dumps(record, ensure_ascii=False, indent=2, default=str),
            encoding="utf-8",
        )

    def load_all(self) -> List[Dict[str, Any]]:
        if not self.dir.exists():
            return []
        records = []
        for path in sorted(self.dir.glob("*.json")):
            try:
                records.append(json.loads(path.read_text(encoding="utf-8")))
            except (OSError, json.JSONDecodeError) as exc:
                log.warning("Precedent: skipping unreadable snapshot %s (%s)", path, exc)
        return records


class _Neo4jBackend:
    """Neo4j store: one ``GraphSnapshot`` node per task plus knowledge bindings.

    Similarity is computed in Python over the stored fingerprints rather than
    in Cypher: the weights live in Darwin's config, the graph library has no
    GDS plugin installed, and this keeps both backends behaviorally identical.
    """

    name = "neo4j"

    def __init__(self, config: MemoryConfig):
        self._config = config
        self._driver = None
        self._unavailable = ""

    def _connect(self):
        if self._driver is not None or self._unavailable:
            return self._driver
        if not self._config.neo4j.usable:
            self._unavailable = "neo4j connection not configured (config/neo4j.yaml)"
            return None
        try:
            from neo4j import GraphDatabase
        except ImportError:
            self._unavailable = "neo4j driver not installed"
            log.warning("Precedent: %s; using JSON store", self._unavailable)
            return None
        try:
            self._driver = GraphDatabase.driver(
                self._config.neo4j.uri,
                auth=(self._config.neo4j.user, self._config.neo4j.password),
            )
            self._driver.verify_connectivity()
        except Exception as exc:
            self._unavailable = str(exc)
            self._driver = None
            log.warning("Precedent: Neo4j unavailable (%s); using JSON store", exc)
        return self._driver

    def store(self, record: Dict[str, Any]) -> None:
        driver = self._connect()
        if driver is None:
            raise ConnectionError(self._unavailable or "neo4j unavailable")
        fingerprint = record.get("fingerprint") or {}
        knowledge = record.get("knowledge") or []
        with driver.session(database=self._config.neo4j.database) as session:
            session.run(
                """
                MERGE (snapshot:GraphSnapshot {task_id: $task_id})
                SET snapshot.created_at = $created_at,
                    snapshot.family = $family,
                    snapshot.environment = $environment,
                    snapshot.node_count = $node_count,
                    snapshot.edge_count = $edge_count,
                    snapshot.fingerprint_json = $fingerprint_json
                """,
                task_id=record["task_id"],
                created_at=record.get("created_at", ""),
                family=record.get("labels", {}).get("family", ""),
                environment=record.get("labels", {}).get("environment", ""),
                node_count=int(fingerprint.get("totals", {}).get("nodes", 0)),
                edge_count=int(fingerprint.get("totals", {}).get("edges", 0)),
                fingerprint_json=json.dumps(fingerprint, ensure_ascii=False, default=str),
            )
            for coarse, count in (fingerprint.get("node_hist") or {}).items():
                session.run(
                    """
                    MATCH (snapshot:GraphSnapshot {task_id: $task_id})
                    MERGE (resource:ResourceType {name: $coarse})
                    MERGE (snapshot)-[r:HAS_NODE_TYPE]->(resource)
                    SET r.count = $count
                    """,
                    task_id=record["task_id"], coarse=coarse, count=int(count),
                )
            for entry in knowledge:
                session.run(
                    """
                    MATCH (snapshot:GraphSnapshot {task_id: $task_id})
                    MERGE (knowledge:Knowledge {id: $knowledge_id})
                    MERGE (snapshot)-[r:USED_KNOWLEDGE]->(knowledge)
                    SET r.surfaced = $surfaced,
                        r.used = $used,
                        r.attempts = $attempts,
                        r.successes = $successes,
                        r.last_success = $last_success
                    """,
                    task_id=record["task_id"],
                    knowledge_id=entry.get("id", ""),
                    surfaced=bool(entry.get("surfaced")),
                    used=bool(entry.get("used")),
                    attempts=int(entry.get("attempts", 0)),
                    successes=int(entry.get("successes", 0)),
                    last_success=entry.get("last_success", ""),
                )

    def load_all(self) -> List[Dict[str, Any]]:
        driver = self._connect()
        if driver is None:
            raise ConnectionError(self._unavailable or "neo4j unavailable")
        records: Dict[str, Dict[str, Any]] = {}
        with driver.session(database=self._config.neo4j.database) as session:
            for row in session.run(
                """
                MATCH (snapshot:GraphSnapshot)
                OPTIONAL MATCH (snapshot)-[r:USED_KNOWLEDGE]->(knowledge:Knowledge)
                RETURN snapshot.task_id AS task_id,
                       snapshot.created_at AS created_at,
                       snapshot.family AS family,
                       snapshot.environment AS environment,
                       snapshot.fingerprint_json AS fingerprint_json,
                       collect({id: knowledge.id, surfaced: r.surfaced, used: r.used,
                                attempts: r.attempts, successes: r.successes,
                                last_success: r.last_success}) AS knowledge
                """
            ):
                try:
                    stored = json.loads(row["fingerprint_json"] or "{}")
                except json.JSONDecodeError:
                    stored = {}
                records[row["task_id"]] = {
                    "task_id": row["task_id"],
                    "created_at": row["created_at"] or "",
                    "labels": {
                        "family": row["family"] or "",
                        "environment": row["environment"] or "",
                    },
                    "fingerprint": stored,
                    "knowledge": [item for item in (row["knowledge"] or []) if item.get("id")],
                }
        return list(records.values())


def _safe_name(task_id: str) -> str:
    return "".join(ch if ch.isalnum() or ch in "-_." else "_" for ch in str(task_id)) or "task"


class PrecedentStore:
    """Graph-similarity memory over past tasks."""

    def __init__(self, config: MemoryConfig | None = None):
        self.config = config or MemoryConfig.from_files()
        self._json = _JsonBackend(self.config.storage_dir)
        self._neo4j = _Neo4jBackend(self.config)
        self._lock = threading.RLock()

    @property
    def enabled(self) -> bool:
        return bool(self.config.enabled)

    def record_task_snapshot(
        self,
        task_id: str,
        *,
        fingerprint: Dict[str, Any],
        snapshot: Dict[str, Any] | None = None,
        knowledge: List[Dict[str, Any]] | None = None,
        labels: Dict[str, Any] | None = None,
    ) -> Dict[str, Any]:
        """Persist one task's graph, fingerprint and knowledge ledger."""
        if not self.enabled:
            return {}
        record = {
            "task_id": str(task_id),
            "created_at": datetime.now().isoformat(),
            "labels": {**dict(fingerprint.get("labels", {})), **dict(labels or {})},
            "fingerprint": fingerprint,
            "knowledge": list(knowledge or []),
            "snapshot": snapshot or {},
        }
        with self._lock:
            try:
                self._neo4j.store(record)
                record["stored_in"] = self._neo4j.name
            except Exception as exc:
                log.warning("Precedent: Neo4j write failed (%s); falling back to JSON", exc)
                self._json.store(record)
                record["stored_in"] = self._json.name
            if record["stored_in"] == self._neo4j.name:
                # Keep the local audit trail even when Neo4j owns the record.
                self._json.store(record)
        return record

    def query(
        self,
        fingerprint: Dict[str, Any],
        *,
        top_k: int | None = None,
        threshold: float | None = None,
        exclude_same_family: bool = False,
    ) -> List[Dict[str, Any]]:
        """Similarity-ranked precedents above the reuse threshold."""
        if not self.enabled or not fingerprint:
            return []
        cutoff = float(self.config.reuse_threshold if threshold is None else threshold)
        limit = int(self.config.precedent_top_k if top_k is None else top_k)
        family = str((fingerprint.get("labels") or {}).get("family", ""))
        hits: List[Dict[str, Any]] = []
        with self._lock:
            for record in self._load_records():
                if str(record.get("task_id", "")) == str(fingerprint.get("task_id", "")):
                    continue
                if exclude_same_family and family:
                    stored_family = str((record.get("labels") or {}).get("family", ""))
                    if stored_family == family:
                        continue
                stored = record.get("fingerprint") or {}
                if not stored:
                    continue
                result = similarity(stored, fingerprint, self.config.similarity_weights)
                if result["score"] < cutoff:
                    continue
                hits.append({
                    "task_id": record.get("task_id", ""),
                    "created_at": record.get("created_at", ""),
                    "labels": dict(record.get("labels") or {}),
                    "score": result["score"],
                    "components": result["components"],
                    "knowledge": list(record.get("knowledge") or []),
                })
        hits.sort(key=lambda item: item["score"], reverse=True)
        return hits[:limit]

    def prior(self, fingerprint: Dict[str, Any], **kwargs) -> Dict[str, float]:
        """Retrieval prior (corpus entry id -> boost) built from precedents."""
        boosts: Dict[str, float] = {}
        for hit in self.query(fingerprint, **kwargs):
            for entry in hit.get("knowledge", []):
                if int(entry.get("successes", 0)) <= 0:
                    continue
                reliability = (
                    int(entry["successes"]) / int(entry["attempts"])
                    if int(entry.get("attempts", 0)) > 0 else 0.0
                )
                decay = knowledge_decay(
                    str(entry.get("last_success", "")),
                    int(entry.get("half_life_days", DEFAULT_HALF_LIFE_DAYS)),
                )
                boost = self.config.prior_weight * hit["score"] * reliability * decay
                if boost > 0:
                    boosts[str(entry["id"])] = max(boosts.get(str(entry["id"]), 0.0), boost)
        return boosts

    def _load_records(self) -> List[Dict[str, Any]]:
        try:
            records = self._neo4j.load_all()
            if records:
                return records
        except Exception as exc:
            log.debug("Precedent: Neo4j read failed (%s); using JSON store", exc)
        return self._json.load_all()

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            records = self._load_records()
        return {
            "enabled": self.enabled,
            "storage_dir": self.config.storage_dir,
            "snapshots": len(records),
            "reuse_threshold": self.config.reuse_threshold,
        }
