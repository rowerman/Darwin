"""Shared argument contract for every tool call.

Both ends of a call read this one table:

* producers (recon, the systematic fallback pass, the fix loop) bind a domain
  intent onto a tool's declared parameters through :func:`project_args`;
* the gateway projects the incoming call through the same function before it
  dispatches anything.

The mapping is explicit by design.  The previous substring fuzzy phase
rewrote ``content`` into ``response_parse.content_type`` — both declared
parameters contain the string — while the caller meant the raw response body.
It never helped with the names that actually drifted (``param``,
``credentials``) because those share no substring with a declared parameter.
"""

from __future__ import annotations

import re
from typing import Any, Iterable

# alias -> priority-ordered canonical candidates; the first one the tool
# actually declares wins.  Sourced from real drift between the planner, the
# fix loop and the registrations (cloud-29/30 logs plus the v2 contract).
PARAM_ALIASES: dict[str, tuple[str, ...]] = {
    # URL / target concept
    "url":          ("target_url", "file_path"),
    "target_url":   ("url", "ssrf_url"),
    "base_url":     ("url",),
    "endpoint":     ("target_url", "url"),
    "ssrf_url":     ("target_url", "url"),
    "target":       ("target_url", "host"),
    "service":      ("service_name",),
    # Host concept
    "host":         ("target",),
    "server":       ("host", "target"),
    "hostname":     ("host", "target"),
    "dc_ip":        ("target",),
    # Credential concept
    "username":     ("user",),
    "login":        ("user",),
    "pass":         ("password",),
    "passwd":       ("password",),
    "pwd":          ("password",),
    "credentials":  ("cookie", "password", "user"),
    "token":        ("api_token",),
    # Request body concept.  ``content`` means the body before it means a
    # content-type hint, so ``data`` is listed first.
    "content":      ("data", "content_type"),
    "body":         ("data",),
    "post_data":    ("data",),
    "json_body":    ("data",),
    "json":         ("data",),
    "request_body": ("data",),
    "payload":      ("data",),
    # Body encoding concept
    "body_format":  ("content_type", "encode_type"),
    "encode_type":  ("body_format",),
    # Injected parameter concept
    "parameter":    ("param", "url_param", "param_name"),
    "param_name":   ("param", "url_param", "parameter"),
    # Header concept
    "header":       ("headers",),
    "cookies":      ("cookie", "headers"),
}

#: A whole-string template token (``<tenant>``, ``{{id}}``, ``${path}``) is an
#: unfilled placeholder, not a value.  Only a bare identifier-like token counts:
#: HTML/XML bodies and paths that merely start with ``<`` are real payloads.
_PLACEHOLDER_RE = re.compile(
    r"^(?:<[A-Za-z_][A-Za-z0-9_\- ]{0,40}>|\{\{[^{}]{1,60}\}\}|\$\{[^{}]{1,60}\})$"
)
#: The same token anywhere inside a value, e.g.
#: ``http://host/<function-invoke-route>``.
_TEMPLATE_TOKEN_RE = re.compile(
    r"(?:<[A-Za-z_][A-Za-z0-9_\- ]{0,40}>|\{\{[^{}]{1,60}\}\}|\$\{[^{}]{1,60}\})"
)


def is_placeholder(value: Any) -> bool:
    """True when a value carries no request intent at all.

    Deliberately narrow: an empty value, an empty container, or an unfilled
    template token.  Natural-language values such as ``default`` are kept —
    ``workspace=default`` is a real workspace name on a real target, and
    discarding it would silently rewrite the request.
    """
    if value is None:
        return True
    if isinstance(value, str):
        stripped = value.strip()
        return not stripped or bool(_PLACEHOLDER_RE.match(stripped))
    if isinstance(value, (list, tuple, set, dict)):
        return len(value) == 0
    return False


def alias_target(
    alias: str,
    declared: dict,
    aliases: dict[str, Iterable[str]] | None = None,
) -> str:
    """First canonical name for ``alias`` that the tool actually declares."""
    candidates: Iterable[str] = ()
    if aliases and alias in aliases:
        candidates = aliases[alias]
    else:
        candidates = PARAM_ALIASES.get(alias, ())
    for candidate in candidates:
        if candidate in declared:
            return candidate
    return ""


def unresolved_placeholders(args: dict) -> dict[str, str]:
    """Parameters whose value still contains an unfilled template token.

    A dependent task planned before its producer ran carries values such as
    ``http://host/<function-invoke-route>``.  Executing those sends a literal
    placeholder to the target: the benchmark logs show a task doing exactly
    that three times, each followed by a full fix round that could only
    restate "the URL contains an unresolved placeholder".
    """
    pending: dict[str, str] = {}
    for key, value in (args or {}).items():
        if isinstance(value, str) and _TEMPLATE_TOKEN_RE.search(value):
            pending[key] = value
    return pending


def project_args(
    declared: dict,
    args: dict,
    aliases: dict[str, Iterable[str]] | None = None,
) -> tuple[dict, dict[str, str], list[str], list[str]]:
    """Project ``args`` onto the parameters ``declared`` by a tool.

    Returns ``(projected, migrated, dropped, unmappable)``:

    * ``projected`` — the argument dict the tool will actually receive;
    * ``migrated`` — ``{source_key: canonical_key}`` for values that were
      redirected, so the caller knows the call carried intent through a
      different name than it planned;
    * ``dropped`` — placeholder keys (empty values, ``<tenant>`` leftovers)
      that carry no intent and are safe to discard;
    * ``unmappable`` — keys with a real value that this tool cannot express.
      Callers must not ignore these: the gateway refuses such a call and the
      producers skip the step instead of running a different request.
    """
    tool_params = declared or {}
    projected: dict[str, Any] = {}
    migrated: dict[str, str] = {}
    dropped: list[str] = []
    unmappable: list[str] = []

    for key, value in (args or {}).items():
        if key in tool_params:
            projected[key] = value
            continue
        if is_placeholder(value):
            dropped.append(key)
            continue
        target = alias_target(key, tool_params, aliases)
        if target:
            # The canonical slot is filled either way: a second name for the
            # same value is absorbed, never reported as lost intent.
            projected.setdefault(target, value)
            migrated[key] = target
            continue
        unmappable.append(key)

    return projected, migrated, sorted(dropped), sorted(unmappable)


def coerce_string_params(declared: dict, params: dict) -> tuple[dict, list[str]]:
    """Serialize container values that landed in a declared ``string`` slot.

    Alias migration can route a list/dict into a ``str`` parameter — the
    planner sent ``credentials: [...]`` and the shared table mapped it onto
    ``cookie`` — and the tool then does ``value.strip()`` on it and raises
    ``AttributeError``, which kills the whole hypothesis instead of the call.

    Slots whose registrations already accept containers (body/header shapes,
    ``send_payload.payload``, ``parallel_request.urls``) are left alone: their
    tools normalize dict/list themselves, and rewriting them would corrupt a
    body that was about to be sent as JSON.
    """
    container_tolerant = {
        "data", "body", "json", "content", "payload",
        "headers", "header", "urls",
    }
    coerced: list[str] = []
    out = dict(params or {})
    for key, value in out.items():
        if key in container_tolerant:
            continue
        meta = (declared or {}).get(key)
        if not isinstance(meta, dict) or str(meta.get("type", "")) != "string":
            continue
        if not isinstance(value, (list, tuple, set, dict)):
            continue
        if isinstance(value, dict):
            out[key] = ", ".join(f"{k}={v}" for k, v in value.items())
        else:
            out[key] = ", ".join(str(item) for item in value)
        coerced.append(key)
    return out, sorted(coerced)
