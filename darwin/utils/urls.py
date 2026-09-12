"""URL/path helpers for evidence-driven REST route exploration.

A REST API answers 404/405 for a wrong path SHAPE (collection route vs
detail route) even when the verb is right. These helpers extract
identifier-looking values already observed in a response and derive the
bounded neighbour paths a human would try next. Pure functions, no
dependency on the gateway/orchestrator stack.
"""

from __future__ import annotations

import json
from typing import Any, Iterable

import re

#: Upper bound on derived candidates per failed call.
ROUTE_VARIANT_MAX = 6
#: Upper bound on appended path segments per candidate.
ROUTE_VARIANT_MAX_SEGMENTS = 2
#: Upper bound on identifiers harvested from params/responses.
ROUTE_VARIANT_MAX_IDENTIFIERS = 4

IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$")
_QUOTED_VALUE_RE = re.compile(r'"([^"\\\s]{1,64})"')


def _flatten_identifiers(value: Any, out: list[str], limit: int) -> None:
    if len(out) >= limit:
        return
    if isinstance(value, dict):
        for item in value.values():
            _flatten_identifiers(item, out, limit)
    elif isinstance(value, (list, tuple)):
        for item in value:
            _flatten_identifiers(item, out, limit)
    elif isinstance(value, (str, int, float)) and not isinstance(value, bool):
        token = str(value)
        if IDENTIFIER_RE.match(token) and token not in out:
            out.append(token)


def observed_identifiers(text: str, limit: int = 8) -> list[str]:
    """Identifier-looking scalars observed in a response body / JSON blob.

    JSON *values* are preferred (a key name is rarely a path segment); a
    quoted-value scan is the fallback when the payload is not parseable.
    """
    blob = str(text or "")
    start = blob.find("{")
    if start < 0:
        start = blob.find("[")
    if start >= 0:
        try:
            data, _ = json.JSONDecoder().raw_decode(blob[start:])
        except (ValueError, TypeError):
            data = None
        if data is not None:
            out: list[str] = []
            _flatten_identifiers(data, out, limit)
            return out
    return [
        m.group(1) for m in _QUOTED_VALUE_RE.finditer(blob)
        if IDENTIFIER_RE.match(m.group(1))
    ][:limit]


def response_body(text: str) -> str:
    """Body of a curl/urllib style output (everything after the header block)."""
    blob = str(text or "")
    for separator in ("\r\n\r\n", "\n\n"):
        index = blob.find(separator)
        if index >= 0:
            return blob[index + len(separator):]
    return blob


def route_variants(
    url: str, identifiers: Iterable[str],
    max_candidates: int = ROUTE_VARIANT_MAX,
    max_extra_segments: int = ROUTE_VARIANT_MAX_SEGMENTS,
) -> list[str]:
    """Neighbour paths of ``url`` built from already-observed identifiers.

    Depth is bounded (``len(path) <= 4``) and only identifier-looking tokens
    become segments, so a banner or a sentence can never grow the path.
    """
    from urllib.parse import urlsplit, urlunsplit

    parts = urlsplit(str(url or ""))
    segments = [s for s in parts.path.split("/") if s]
    if not segments or len(segments) > 4:
        return []
    wanted: list[str] = []
    for value in identifiers or []:
        token = str(value).strip()
        if (not token or token in segments or token in wanted
                or not IDENTIFIER_RE.match(token)):
            continue
        wanted.append(token)
        if len(wanted) >= ROUTE_VARIANT_MAX_IDENTIFIERS:
            break
    if not wanted:
        return []
    paths: list[str] = []
    if max_extra_segments >= 1:
        paths.extend(["/" + "/".join(segments + [v]) for v in wanted])
    if max_extra_segments >= 2:
        for i, first in enumerate(wanted):
            for second in wanted[i + 1:]:
                paths.append("/" + "/".join(segments + [first, second]))
    original = parts.path.rstrip("/") or "/"
    out: list[str] = []
    for path in paths:
        if path == original or path in out:
            continue
        out.append(path)
        if len(out) >= max_candidates:
            break
    return [urlunsplit((parts.scheme, parts.netloc, p, "", "")) for p in out]
