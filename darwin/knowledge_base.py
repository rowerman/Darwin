"""Category + tag + keyword knowledge retrieval for DARWIN.

Lightweight alternative to vector DB — uses inverted index for fast lookup.
Inspired by container-pentester-agent's 7-collection RAG system.

Loads all JSON knowledge files from the knowledge/ directory tree.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class KnowledgeEntry:
    """A single knowledge entry covering an attack technique or vulnerability pattern."""
    id: str
    category: str            # windows_ad, cloud, web, network
    subcategory: str         # enumeration, lateral_movement, privilege_escalation, persistence
    title: str
    description: str         # What the technique does
    techniques: List[str] = field(default_factory=list)   # Step-by-step commands or approaches
    indicators: List[str] = field(default_factory=list)   # How to detect this is possible
    prerequisites: List[str] = field(default_factory=list)  # What's needed before this can work
    tools: List[str] = field(default_factory=list)        # Tools that implement this
    tags: List[str] = field(default_factory=list)         # Searchable tags
    confidence: float = 0.5   # 0.0-1.0 reliability
    references: List[str] = field(default_factory=list)   # URLs or document references
    mitre_attack: str = ""    # MITRE ATT&CK technique ID (e.g., T1558.003)


class KnowledgeBase:
    """Category + tag + keyword knowledge retrieval.

    Loads knowledge entries from structured JSON files in the knowledge/ directory.
    Uses an inverted index for O(1) tag/category lookups and scored keyword search.
    """

    def __init__(self, knowledge_dir: str | None = None):
        if knowledge_dir is None:
            knowledge_dir = str(Path(__file__).parent.parent / "knowledge")
        self.entries: List[KnowledgeEntry] = []
        self._index: Dict[str, List[int]] = {}  # tag/category/subcategory -> entry indices
        self._load_all(knowledge_dir)

    def _load_all(self, directory: str) -> None:
        """Load all JSON knowledge files recursively."""
        root = Path(directory)
        if not root.exists():
            return
        for path in root.rglob("*.json"):
            try:
                with open(path) as f:
                    data = json.load(f)
                entries = data if isinstance(data, list) else [data]
                for entry_data in entries:
                    if isinstance(entry_data, dict):
                        ke = KnowledgeEntry(**{k: entry_data.get(k, v.default if hasattr(v, 'default') else None)
                                               if hasattr(v, 'default') else entry_data.get(k)
                                               for k, v in KnowledgeEntry.__dataclass_fields__.items()})
                        # Handle list defaults properly
                        for field_name in ["techniques", "indicators", "prerequisites",
                                          "tools", "tags", "references"]:
                            val = entry_data.get(field_name)
                            if val is not None:
                                setattr(ke, field_name, val)
                        self.entries.append(ke)
                        self._index_entry(ke, len(self.entries) - 1)
            except Exception:
                pass  # Skip malformed files

    def _index_entry(self, entry: KnowledgeEntry, idx: int) -> None:
        """Build inverted index for fast tag/category lookup."""
        for tag in entry.tags:
            self._index.setdefault(tag.lower(), []).append(idx)
        if entry.category:
            self._index.setdefault(entry.category.lower(), []).append(idx)
        if entry.subcategory:
            self._index.setdefault(entry.subcategory.lower(), []).append(idx)

    def search(self, query: str, category: str = "", top_k: int = 5) -> List[KnowledgeEntry]:
        """Keyword + tag search. Returns top_k most relevant entries.

        Scoring:
        - Title exact match: +10
        - Description substring: +5
        - Tag exact match: +8
        - Technique keyword match: +3 per matching word
        """
        query_lower = query.lower()
        scores: List[tuple] = []
        for i, entry in enumerate(self.entries):
            if category and entry.category != category:
                continue
            score = 0
            if query_lower in entry.title.lower():
                score += 10
            if query_lower in entry.description.lower():
                score += 5
            for tag in entry.tags:
                if query_lower in tag.lower() or tag.lower() in query_lower:
                    score += 8
            for tech in entry.techniques:
                if query_lower in tech.lower():
                    score += 3
            if score > 0:
                scores.append((score, entry))
        scores.sort(key=lambda x: x[0], reverse=True)
        return [entry for _, entry in scores[:top_k]]

    def get_by_mitre(self, technique_id: str) -> List[KnowledgeEntry]:
        """Look up entries by MITRE ATT&CK technique ID (e.g., T1558.003)."""
        return [e for e in self.entries if e.mitre_attack == technique_id]

    def get_by_tool(self, tool_name: str) -> List[KnowledgeEntry]:
        """Find knowledge entries relevant to a specific DARWIN tool."""
        return [e for e in self.entries if tool_name in e.tools]

    def get_by_category(self, category: str) -> List[KnowledgeEntry]:
        """Get all entries in a category."""
        cat = category.lower()
        return [e for e in self.entries if e.category.lower() == cat]

    def summarize(self, query: str, category: str = "", top_k: int = 3) -> str:
        """Return a formatted text summary of matching knowledge entries."""
        entries = self.search(query, category, top_k)
        if not entries:
            return ""
        parts = []
        for i, e in enumerate(entries):
            parts.append(f"**{e.title}** [{e.category}/{e.subcategory}] (confidence={e.confidence:.2f})")
            if e.mitre_attack:
                parts[-1] += f" MITRE:{e.mitre_attack}"
            parts.append(f"  {e.description[:300]}")
            if e.techniques:
                parts.append(f"  Commands: {'; '.join(e.techniques[:3])}")
            if e.tools:
                parts.append(f"  Tools: {', '.join(e.tools)}")
            parts.append("")
        return "\n".join(parts)
