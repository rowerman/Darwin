"""Unified research evidence format shared by RAG and web retrieval.

Both ``knowledge_search`` (RAG) and ``ddg_web_search`` return their findings
as the same JSON envelope (schema ``darwin.research_evidence.v1``).  The LLM
therefore sees one standard structure during the research phase and can use
RAG and web evidence interchangeably as the basis for analysis.

Envelope shape::

    {
      "schema": "darwin.research_evidence.v1",
      "source": "rag" | "web",
      "query": "...",
      "total": 2,
      "results": [
        {
          "rank": 1,
          "title": "...",
          "url": "https://... or knowledge:path/to/entry",
          "snippet": "...",
          "relevance": 0.82,          # RAG score; null for web results
          "techniques": [...],        # RAG only
          "metadata": {...}           # source-specific extras
        }
      ]
    }
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

SCHEMA = "darwin.research_evidence.v1"

_MAX_ITEMS = 15


def _evidence_item(
    rank: int,
    title: str,
    url: str = "",
    snippet: str = "",
    relevance: Optional[float] = None,
    techniques: Optional[List[str]] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    return {
        "rank": rank,
        "title": (title or "").strip() or f"Result {rank}",
        "url": (url or "").strip(),
        "snippet": (snippet or "").strip(),
        "relevance": relevance,
        "techniques": list(techniques or []),
        "metadata": dict(metadata or {}),
    }


def format_evidence(source: str, query: str, items: List[Dict[str, Any]]) -> str:
    """Render a list of evidence items as the unified JSON envelope."""
    return json.dumps(
        {
            "schema": SCHEMA,
            "source": source,
            "query": query,
            "total": len(items),
            "results": items[:_MAX_ITEMS],
        },
        ensure_ascii=False,
        indent=2,
    )


def empty_evidence(source: str, query: str) -> str:
    """Render an empty unified envelope (search executed, nothing matched)."""
    return format_evidence(source, query, [])


def format_rag_evidence(query: str, results: List[Dict[str, Any]]) -> str:
    """Map DarwinRAG result dicts to the unified envelope."""
    items: List[Dict[str, Any]] = []
    for rank, r in enumerate(results, 1):
        path = r.get("path") or []
        if r.get("source"):
            url = str(r["source"])
        elif path:
            url = "knowledge:" + "/".join(str(p) for p in path)
        else:
            url = f"knowledge:{r.get('category', '')}/{r.get('id', '')}"
        metadata = {
            "category": r.get("category", ""),
            "subcategory": r.get("subcategory", ""),
            "guid": r.get("guid", ""),
            "path": path,
            "confidence": r.get("confidence"),
            "mitre_attack": r.get("mitre_attack", ""),
            "tools": r.get("tools", []),
        }
        items.append(_evidence_item(
            rank=rank,
            title=r.get("title", ""),
            url=url,
            snippet=r.get("description", ""),
            relevance=float(r["score"]) if r.get("score") is not None else None,
            techniques=list(r.get("techniques") or []),
            metadata={k: v for k, v in metadata.items() if v not in (None, "", [], {})},
        ))
    return format_evidence("rag", query, items)


def format_web_evidence(query: str, items: List[Dict[str, Any]]) -> str:
    """Map normalized web-search items to the unified envelope.

    Each item must provide ``title`` and at least one of ``url``/``snippet``.
    """
    normalized: List[Dict[str, Any]] = []
    for rank, it in enumerate(items, 1):
        normalized.append(_evidence_item(
            rank=rank,
            title=it.get("title", ""),
            url=it.get("url", it.get("href", "")),
            snippet=it.get("snippet", it.get("body", it.get("description", ""))),
            relevance=it.get("relevance"),
            metadata=it.get("metadata") or {},
        ))
    return format_evidence("web", query, normalized)
