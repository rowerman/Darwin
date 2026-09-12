"""LLM-tolerant parameter shaping shared by the HTTP tools.

A parameter declared as ``string`` in a ToolSpec still arrives as a dict or
list from the planner LLM (``headers={"X-Api-Key": "k"}``,
``data={"name": "pkg"}``). Normalizing those shapes in one place keeps every
HTTP tool tolerant of the same inputs instead of each registration
re-implementing — and mis-implementing — its own split.
"""

from __future__ import annotations

import json
from typing import Any


def normalize_headers(value: Any) -> dict[str, str]:
    """Return ``{name: value}`` for str / dict / list header declarations.

    Accepted shapes:
      - dict: ``{"X-Api-Key": "k"}``
      - list/tuple: ``["A: 1", "B: 2"]`` or ``[("A", "1")]``
      - str: one or more headers separated by newline or ``|``
    """
    headers: dict[str, str] = {}
    if not value:
        return headers
    if isinstance(value, dict):
        for name, val in value.items():
            name = str(name).strip()
            if name:
                headers[name] = str(val).strip()
        return headers
    if isinstance(value, (list, tuple)):
        for item in value:
            if isinstance(item, (list, tuple)) and len(item) == 2:
                name = str(item[0]).strip()
                if name:
                    headers[name] = str(item[1]).strip()
            else:
                headers.update(normalize_headers(item))
        return headers
    for chunk in str(value).replace("\r", "\n").split("\n"):
        for part in chunk.split("|"):
            part = part.strip()
            if not part or ":" not in part:
                continue
            name, val = part.split(":", 1)
            name = name.strip()
            if name:
                headers[name] = val.strip()
    return headers


def headers_to_lines(value: Any) -> str:
    """Normalize any header shape to newline-separated ``Name: value`` lines."""
    return "\n".join(f"{k}: {v}" for k, v in normalize_headers(value).items())


def coerce_body(value: Any) -> tuple[bytes | None, str]:
    """Return ``(body_bytes, inferred_content_type)`` for a request body.

    ``inferred_content_type`` is empty when the caller passed a raw
    string/bytes body and no type could be inferred.
    """
    if value is None or value == "":
        return None, ""
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False).encode("utf-8"), "application/json"
    if isinstance(value, bytes):
        return value, ""
    return str(value).encode("utf-8"), ""
