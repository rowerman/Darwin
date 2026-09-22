"""Configuration for the cross-task graph memory (precedent store).

Two files, matching the existing ``config/llm.yaml`` convention:

* ``config/darwin.yaml`` → ``memory`` section: weights, thresholds, storage.
* ``config/neo4j.yaml``  → connection only (``config/`` is gitignored, so
  credentials never reach the repository).

Both are optional: missing files fall back to the defaults below, which keep
the feature inert until it is explicitly configured.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Dict

from darwin.graph_fingerprint import DEFAULT_WEIGHTS

DEFAULT_DARWIN_CONFIG = "config/darwin.yaml"
DEFAULT_NEO4J_CONFIG = "config/neo4j.yaml"


@dataclass
class Neo4jConfig:
    uri: str = "bolt://127.0.0.1:7687"
    user: str = "neo4j"
    password: str = ""
    database: str = "neo4j"

    @property
    def usable(self) -> bool:
        return bool(self.uri and self.password)


@dataclass
class MemoryConfig:
    enabled: bool = True
    storage_dir: str = "memory/graphs"
    #: Cross-task credential store (same scope/host/port/service only).
    credentials_path: str = "memory/credentials.json"
    #: Above this similarity a historical graph contributes a knowledge prior.
    reuse_threshold: float = 0.85
    #: How many precedents to consider when building the prior.
    precedent_top_k: int = 5
    #: Prior strength: boost = prior_weight * similarity * reliability.
    prior_weight: float = 0.25
    similarity_weights: Dict[str, float] = field(default_factory=lambda: dict(DEFAULT_WEIGHTS))
    projection_max_hops: int = 3
    projection_max_nodes: int = 400
    neo4j: Neo4jConfig = field(default_factory=Neo4jConfig)

    @classmethod
    def from_files(
        cls,
        darwin_path: str = DEFAULT_DARWIN_CONFIG,
        neo4j_path: str = DEFAULT_NEO4J_CONFIG,
    ) -> "MemoryConfig":
        config = cls()
        section = _read_yaml(darwin_path).get("memory")
        if isinstance(section, dict):
            config._apply(section)
        connection = _read_yaml(neo4j_path).get("neo4j")
        if isinstance(connection, dict):
            config.neo4j = Neo4jConfig(
                uri=str(connection.get("uri") or config.neo4j.uri),
                user=str(connection.get("user") or config.neo4j.user),
                password=str(connection.get("password") or ""),
                database=str(connection.get("database") or config.neo4j.database),
            )
        config.neo4j.password = (
            os.environ.get("NEO4J_PASSWORD") or config.neo4j.password
        )
        config.neo4j.uri = os.environ.get("NEO4J_URI") or config.neo4j.uri
        return config

    def _apply(self, section: Dict[str, Any]) -> None:
        self.enabled = bool(section.get("enabled", self.enabled))
        self.storage_dir = str(section.get("storage_dir") or self.storage_dir)
        self.credentials_path = str(
            section.get("credentials_path") or self.credentials_path
        )
        for key in ("reuse_threshold", "prior_weight"):
            if isinstance(section.get(key), (int, float)):
                setattr(self, key, float(section[key]))
        for key in ("precedent_top_k", "projection_max_hops", "projection_max_nodes"):
            if isinstance(section.get(key), int):
                setattr(self, key, int(section[key]))
        weights = section.get("similarity_weights")
        if isinstance(weights, dict):
            merged = dict(DEFAULT_WEIGHTS)
            merged.update({
                str(k): float(v) for k, v in weights.items()
                if k in merged and isinstance(v, (int, float))
            })
            self.similarity_weights = merged


def _read_yaml(path: str) -> Dict[str, Any]:
    if not path or not os.path.exists(path):
        return {}
    try:
        import yaml

        with open(path, encoding="utf-8") as handle:
            data = yaml.safe_load(handle)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}
