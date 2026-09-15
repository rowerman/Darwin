"""The canonical request shape for HTTP exploitation.

Verb, Content-Type, body and the injected slot used to be re-derived at every
hop: the plan wrote ``params``, the executor picked a tool by name, the repair
loop re-spelled the arguments, and the evidence module rebuilt a follow-up
from the parameter name alone. cloud-29 proved an arbitrary file read through
a JSON POST and then lost it — the follow-up kept no ``method``/``body_format``
and went out as a GET (405), while the repair loop ping-ponged between
``http_post`` and ``send_payload`` dropping ``payload``/``content_type``.

A :class:`RequestTemplate` is the single value that survives all of them. The
planner keeps emitting tool+params (no new LLM contract); ``derive()`` turns
that into a template once, and every later stage renders *its* tool call from
the template instead of guessing parameter names.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, replace
from typing import Any, Callable

WRITE_VERBS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
BODY_FORMATS = frozenset({"none", "form", "json", "raw"})


@dataclass(frozen=True)
class InjectSlot:
    """Where the payload goes: a query parameter, a body field or a header."""

    location: str  # "query" | "body" | "header"
    name: str

    def to_dict(self) -> dict:
        return {"location": self.location, "name": self.name}

    @classmethod
    def from_dict(cls, raw: dict | None) -> "InjectSlot | None":
        if not isinstance(raw, dict) or not raw.get("name"):
            return None
        return cls(location=str(raw.get("location") or "query"), name=str(raw["name"]))


@dataclass(frozen=True)
class RequestTemplate:
    """One HTTP request the framework intends to send."""

    url: str
    method: str = "GET"
    headers: dict[str, str] = field(default_factory=dict)
    cookies: str = ""
    content_type: str = ""
    body_format: str = "none"  # none | form | json | raw
    body: Any = None
    inject: InjectSlot | None = None
    payload: str = ""

    # ── construction ────────────────────────────────────────────
    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "method": self.method,
            "headers": dict(self.headers),
            "cookies": self.cookies,
            "content_type": self.content_type,
            "body_format": self.body_format,
            "body": self.body,
            "inject": self.inject.to_dict() if self.inject else None,
            "payload": self.payload,
        }

    @classmethod
    def from_dict(cls, raw: dict | None) -> "RequestTemplate | None":
        if not isinstance(raw, dict) or not str(raw.get("url") or "").strip():
            return None
        return cls(
            url=str(raw["url"]),
            method=str(raw.get("method") or "GET").upper(),
            headers=dict(raw.get("headers") or {}),
            cookies=str(raw.get("cookies") or ""),
            content_type=str(raw.get("content_type") or ""),
            body_format=str(raw.get("body_format") or "none").lower(),
            body=raw.get("body"),
            inject=InjectSlot.from_dict(raw.get("inject")),
            payload=str(raw.get("payload") or ""),
        )

    # ── derivation ──────────────────────────────────────────────
    @classmethod
    def derive(
        cls, tool: str, params: dict, *, documented_methods: set[str] | None = None,
    ) -> "RequestTemplate | None":
        """Build a template from a planned tool call plus what the route declares.

        The route's own declaration wins over the tool's default verb: a
        planner that says "test traversal" against a documented ``POST`` route
        must not end up sending a GET because that is the tool's default.
        """
        params = dict(params or {})
        url = str(params.get("url") or params.get("target_url") or "")
        if not url.startswith(("http://", "https://")):
            return None

        body_format = str(params.get("body_format") or "").lower()
        content_type = str(params.get("content_type") or "")
        body = params.get("data")
        if body is None:
            body = params.get("body") if params.get("body") is not None else None
        if not body_format and isinstance(body, (dict, list)):
            body_format = "json"
        if not body_format:
            body_format = "none" if body in (None, "") else "raw"
        if not content_type:
            if body_format == "json":
                content_type = "application/json"
            elif body_format == "form":
                content_type = "application/x-www-form-urlencoded"

        method = str(params.get("method") or "").upper()
        declared = {m.upper() for m in (documented_methods or set())} - {
            "", "HEAD", "OPTIONS",
        }
        if method not in {"GET", "POST", "PUT", "PATCH", "DELETE"}:
            method = ""
        if method and declared and method not in declared:
            method = ""
        if not method:
            method = sorted(declared & WRITE_VERBS)[0] if declared & WRITE_VERBS else (
                sorted(declared)[0] if declared else "GET"
            )

        payload = str(params.get("payload") or "")
        slot_name = str(
            params.get("param") or params.get("param_name")
            or params.get("url_param") or ""
        )
        # A write route that takes an injected parameter needs a body; the
        # structured shape is the safer default and is what an explicit
        # body_format/content_type in the plan overrides.
        if body_format == "none" and method in WRITE_VERBS and slot_name:
            body_format = "json"
            content_type = content_type or "application/json"
        inject = cls._slot_for(params, method, slot_name, body, payload)
        return cls(
            url=url,
            method=method,
            headers=_coerce_headers(params.get("headers")),
            cookies=str(params.get("cookie") or ""),
            content_type=content_type,
            body_format=body_format,
            body=body,
            inject=inject,
            payload=payload,
        )

    @staticmethod
    def _slot_for(
        params: dict, method: str, slot_name: str, body: Any, payload: str,
    ) -> InjectSlot | None:
        if not slot_name and not payload:
            return None
        if not slot_name:
            return None
        if method == "GET":
            return InjectSlot("query", slot_name)
        if isinstance(body, (dict, list)):
            return InjectSlot("body", slot_name)
        if isinstance(body, str) and body.strip().startswith(("{", "[")):
            return InjectSlot("body", slot_name)
        return InjectSlot("body", slot_name)

    # ── use ─────────────────────────────────────────────────────
    def render(self, payload: str) -> "RequestTemplate":
        """Same request with ``payload`` written into the injected slot."""
        if self.inject is None:
            return replace(self, payload=str(payload))
        if self.body_format == "json":
            body = dict(self.body) if isinstance(self.body, dict) else (
                _json_object(self.body) if isinstance(self.body, str) else {}
            )
            body[self.inject.name] = payload
            return replace(self, body=body, body_format="json", payload=payload)
        if self.body_format == "form":
            body = dict(self.body) if isinstance(self.body, dict) else {}
            body[self.inject.name] = payload
            return replace(self, body=body, body_format="form", payload=payload)
        if self.inject.location == "query":
            return replace(self, payload=payload)
        return replace(self, body=payload, body_format=self.body_format or "raw",
                       payload=payload)

    def tool_params(self, tool: str, declared: dict | None = None) -> dict | None:
        """Render this request into ``tool``'s declared parameters.

        ``None`` means the tool cannot express this request — the caller must
        pick another one instead of silently sending a different shape (a
        form body where the plan said JSON, a GET where the route is POST).
        """
        renderer = REQUEST_RENDERERS.get(tool)
        if renderer is None:
            return None
        if not tool_can_express(tool, self):
            return None
        params = renderer(self)
        if declared:
            params = {k: v for k, v in params.items() if k in declared}
        return params

    def fingerprint(self) -> str:
        import hashlib
        blob = json.dumps(self.to_dict(), sort_keys=True, default=str)
        return hashlib.sha1(blob.encode()).hexdigest()[:12]


def _json_object(value: str) -> dict:
    try:
        parsed = json.loads(value)
    except (TypeError, ValueError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _coerce_headers(value: Any) -> dict[str, str]:
    if isinstance(value, dict):
        return {str(k): str(v) for k, v in value.items()}
    return {}


def _query_url(template: RequestTemplate) -> str:
    if template.inject is None or template.inject.location != "query":
        return template.url
    from urllib.parse import quote
    separator = "&" if "?" in template.url else "?"
    return f"{template.url}{separator}{template.inject.name}={quote(template.payload)}"


def _json_body(template: RequestTemplate) -> str:
    if template.inject is None:
        body = template.body
    elif isinstance(template.body, dict):
        body = {**template.body, template.inject.name: template.payload}
    else:
        body = _json_object(str(template.body or ""))
        body[template.inject.name] = template.payload
    if isinstance(body, (dict, list)):
        return json.dumps(body, ensure_ascii=False)
    return str(body or "")


def _render_send_payload(template: RequestTemplate) -> dict:
    params: dict[str, Any] = {"url": template.url, "method": template.method}
    if template.headers:
        params["headers"] = template.headers
    if template.method == "GET":
        if template.inject:
            params["param"] = template.inject.name
            params["payload"] = template.payload
        return params
    if template.body_format == "json":
        params.update(body_format="json", payload=_json_body(template))
    elif template.body_format == "form":
        body = dict(template.body) if isinstance(template.body, dict) else {}
        if template.inject:
            body[template.inject.name] = template.payload
        params["body_format"] = "form"
        if body:
            params["payload"] = "&".join(f"{k}={v}" for k, v in body.items())
    elif template.body_format == "raw":
        params["payload"] = str(template.body or template.payload)
    return params


def _render_http_post(template: RequestTemplate) -> dict:
    params: dict[str, Any] = {"url": template.url, "method": template.method}
    if template.headers:
        params["headers"] = template.headers
    if template.method == "GET":
        return {**params, "method": "POST"}
    if template.body_format == "json":
        params["data"] = _json_body(template)
        params["content_type"] = template.content_type or "application/json"
    elif template.body_format == "form":
        body = dict(template.body) if isinstance(template.body, dict) else {}
        if template.inject:
            body[template.inject.name] = template.payload
        params["data"] = "&".join(f"{k}={v}" for k, v in body.items())
        params["content_type"] = (
            template.content_type or "application/x-www-form-urlencoded"
        )
    elif template.body_format == "raw":
        params["data"] = str(template.body or template.payload)
        params["content_type"] = template.content_type or "text/plain"
    return params


def _render_http_method_probe(template: RequestTemplate) -> dict:
    params: dict[str, Any] = {"url": template.url, "method": template.method}
    if template.headers:
        params["headers"] = template.headers
    if template.method in WRITE_VERBS:
        if template.body_format == "json":
            params["data"] = _json_body(template)
            params["content_type"] = template.content_type or "application/json"
        elif template.body_format in ("form", "raw"):
            params["data"] = str(template.body or template.payload)
            if template.content_type:
                params["content_type"] = template.content_type
    return params


def _render_curl_get(template: RequestTemplate) -> dict:
    params: dict[str, Any] = {"url": _query_url(template)}
    if template.headers:
        params["headers"] = template.headers
    if template.cookies:
        params["cookie"] = template.cookies
    return params


def _render_sqlmap_test(template: RequestTemplate) -> dict:
    params: dict[str, Any] = {
        "url": template.url,
        "param": template.inject.name if template.inject else "",
        "method": template.method,
    }
    if template.method in WRITE_VERBS:
        params["body_format"] = "json" if template.body_format == "json" else "form"
        params["content_type"] = template.content_type
    return params


def _render_param_tester(url_key: str, name_key: str) -> Callable[[RequestTemplate], dict]:
    """Renderer for the tools that take a URL plus the injected field name."""

    def _render(template: RequestTemplate) -> dict:
        return {
            url_key: template.url,
            name_key: template.inject.name if template.inject else "",
            "method": template.method,
        }

    return _render


def _render_ssrf_probe(template: RequestTemplate) -> dict:
    return {
        "ssrf_url": template.url,
        "url_param": template.inject.name if template.inject else "",
        "method": template.method,
    }


def _render_xxe_inject(template: RequestTemplate) -> dict:
    return {
        "target_url": template.url,
        "custom_xml": str(template.body or ""),
    }


#: tool -> renderer. A tool absent from this table keeps the legacy parameter
#: path (non-HTTP tools and the domain CLIs), and ``tool_params`` says so by
#: returning ``None`` rather than inventing a request shape.
REQUEST_RENDERERS: dict[str, Callable[[RequestTemplate], dict]] = {
    "send_payload": _render_send_payload,
    "http_post": _render_http_post,
    "http_method_probe": _render_http_method_probe,
    "curl_get": _render_curl_get,
    "sqlmap_test": _render_sqlmap_test,
    "ssti_inject": _render_param_tester("target_url", "param_name"),
    "command_injection_test": _render_param_tester("url", "param"),
    "xss_reflection_test": _render_param_tester("url", "param"),
    "ssrf_probe": _render_ssrf_probe,
    "xxe_inject": _render_xxe_inject,
}

#: tool -> (verbs it can send, body formats it can carry). Kept next to the
#: renderers so the two can never drift: a tool that cannot carry a JSON body
#: must not be selected for a JSON request.
HTTP_REQUEST_CAPABILITIES: dict[str, tuple[frozenset[str] | None, frozenset[str]]] = {
    "send_payload": (
        frozenset({"GET", "POST", "PUT", "PATCH", "DELETE"}),
        frozenset({"none", "form", "json", "raw"}),
    ),
    "http_post": (
        frozenset({"POST", "PUT", "PATCH", "DELETE"}),
        frozenset({"none", "form", "json", "raw"}),
    ),
    "http_method_probe": (None, frozenset({"none", "form", "json", "raw"})),
    "curl_get": (frozenset({"GET"}), frozenset({"none", "form"})),
    "sqlmap_test": (
        frozenset({"GET", "POST"}), frozenset({"none", "form", "json"})
    ),
    "ssti_inject": (frozenset({"GET", "POST"}), frozenset({"none", "form"})),
    "command_injection_test": (
        frozenset({"GET", "POST"}), frozenset({"none", "form"})
    ),
    "xss_reflection_test": (
        frozenset({"GET", "POST"}), frozenset({"none", "form"})
    ),
    "ssrf_probe": (frozenset({"GET", "POST"}), frozenset({"none", "form"})),
    "xxe_inject": (frozenset({"POST"}), frozenset({"raw"})),
}

_READ_FAMILY_ORDER = (
    "curl_get", "http_method_probe", "send_payload", "http_post",
)
_WRITE_FAMILY_ORDER = (
    "http_post", "http_method_probe", "send_payload", "curl_get",
)

#: The generic HTTP request senders. The purpose-built payload testers
#: (sqlmap, SSTI, ...) also render templates, but they belong to their own
#: capability families — a repair must never swap a fetch for a scanner.
HTTP_SENDER_TOOLS = frozenset({
    "curl_get", "http_post", "http_method_probe", "send_payload",
})


def body_format_of(params: dict | None, body_keys: tuple[str, ...] = ("data", "payload", "body", "json")) -> str:
    """Body shape a legacy params dict carries: none | raw | json | form."""
    for key in body_keys:
        value = (params or {}).get(key)
        if value in (None, "", {}, []):
            continue
        if isinstance(value, (dict, list)):
            return "json"
        text = str(value).strip()
        if text.startswith(("{", "[")):
            try:
                json.loads(text)
                return "json"
            except ValueError:
                return "raw"
        return "raw"
    return "none"


def tool_can_express(
    name: str, template: RequestTemplate,
) -> bool:
    """Whether ``name`` can send this request's verb *and* body shape."""
    capability = HTTP_REQUEST_CAPABILITIES.get(name)
    if capability is None:
        return False
    allowed_methods, body_formats = capability
    if template.body_format not in body_formats:
        return False
    if allowed_methods is None:
        return True
    return template.method.upper() in allowed_methods


def tools_for_request(
    methods: Any, available: Any = None, body_format: str = "none",
) -> list[str]:
    """HTTP tools that can express *methods* with *body_format*, best first."""
    wanted = {str(m).upper() for m in (methods or []) if m}
    order = list(
        _WRITE_FAMILY_ORDER if wanted & WRITE_VERBS else _READ_FAMILY_ORDER
    )
    registered = None if available is None else {str(n) for n in available}
    if registered is not None:
        order = [n for n in order if n in registered]
        order += sorted(
            n for n in registered
            if n not in order and n in HTTP_REQUEST_CAPABILITIES
        )
    out: list[str] = []
    for name in order:
        capability = HTTP_REQUEST_CAPABILITIES.get(name)
        if capability is None:
            continue
        allowed_methods, body_formats = capability
        if body_format not in body_formats:
            continue
        if wanted and allowed_methods is not None and not (wanted & allowed_methods):
            continue
        out.append(name)
    return out
