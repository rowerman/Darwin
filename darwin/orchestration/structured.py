"""Shared helpers for structured LLM outputs.

Replaces the registry-lookup convergence loop: artifact stages (analyze,
plan, plan_review, research findings) now receive a compact tool contract
card in the prompt and a plain single-shot generation that is validated
against the Pydantic schema, with a bounded schema-repair retry.  The only
tolerant, explicitly logged normalization lives here as a last resort.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Callable

from darwin.core.schemas import (
    AnalyzeOutputV1,
    AnalyzeVulnV1,
    extract_json_value,
)

log = logging.getLogger(__name__)


def render_tool_contract_card(tool_defs: list[dict], max_tools: int = 90) -> str:
    """Render compact per-tool contracts (name, params, one-line description).

    OpenAI-style tool definitions are the single source used by both the
    registry tools and the execution gateways, so the card always matches the
    tool names the executor accepts.  Required parameters are marked with '*'.
    """
    lines: list[str] = []
    for td in tool_defs or []:
        fn = (td or {}).get("function", {}) or {}
        name = str(fn.get("name", "") or "")
        if not name:
            continue
        params = (fn.get("parameters", {}) or {}).get("properties", {}) or {}
        required = set((fn.get("parameters", {}) or {}).get("required", []) or [])
        param_str = ", ".join(
            p + ("*" if p in required else "") for p in params
        )
        desc = str(fn.get("description", "") or "")[:100].replace("\n", " ")
        lines.append(f"- {name}({param_str}) — {desc}")
        if len(lines) >= max_tools:
            break
    if not lines:
        return "(no tool contracts available)"
    return "\n".join(lines)


# Keyword -> canonical vuln_type inference for report-style LLM output.
_VULN_TYPE_KEYWORDS: list[tuple[str, str]] = [
    ("sql injection", "SQLi"),
    ("sqli", "SQLi"),
    ("injection", "CMDi"),
    ("command", "CMDi"),
    ("rce", "CMDi"),
    ("xss", "XSS"),
    ("ssti", "SSTI"),
    ("lfi", "LFI"),
    ("path traversal", "LFI"),
    ("file disclosure", "LFI"),
    ("ssrf", "SSRF"),
    ("xxe", "XXE"),
    ("idor", "IDOR"),
    ("bola", "IDOR"),
    ("object level authorization", "IDOR"),
    ("authorization", "IDOR"),
    ("broken access", "IDOR"),
    ("cross-tenant", "IDOR"),
    ("tenant", "IDOR"),
    ("jwt", "AUTH"),
    ("signature bypass", "AUTH"),
    ("authentication", "AUTH"),
    ("auth bypass", "AUTH"),
    ("unauthenticated", "AUTH"),
    ("weak auth", "WeakAuth"),
    ("weak credentials", "WeakAuth"),
    ("default credential", "WeakAuth"),
    ("csrf", "CSRF"),
    ("file upload", "FileUpload"),
    ("deserialization", "Deserialization"),
    ("pickle", "Deserialization"),
    ("open bucket", "PlatformDiscovery"),
    ("metadata", "PlatformDiscovery"),
    ("disclosure", "InformationDisclosure"),
    ("information", "InformationDisclosure"),
]


def _infer_vuln_type(text: str) -> str:
    t = (text or "").lower()
    for keyword, vt in _VULN_TYPE_KEYWORDS:
        if keyword in t:
            return vt
    return "generic"


def _absolute_endpoint(endpoint: str, base_url: str) -> str:
    """Join a report-style endpoint (path or '/path (METHOD)') with base_url."""
    ep = (endpoint or "").strip()
    if not ep:
        return ""
    if ep.startswith(("http://", "https://")):
        return ep.split()[0]
    # Strip a leading HTTP verb, e.g. "GET /api/users?tenant=<tenant>".
    verb_match = re.match(r"^(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(.+)$",
                          ep, re.IGNORECASE)
    if verb_match:
        ep = verb_match.group(1).strip()
    # Strip trailing method annotation and query string, e.g.
    # "/wsman (POST)" or "/api/users?tenant=<tenant>".
    path = ep.split("?", 1)[0]
    m = re.match(r"^(/\S*)", path)
    path = m.group(1) if m else path
    if not path.startswith("/"):
        return ep
    base = (base_url or "").rstrip("/")
    return base + path if base else path


def _endpoint_param(item: dict) -> str:
    raw = item.get("param") or item.get("parameter") or ""
    if isinstance(raw, str) and raw.strip():
        # "tenant=<tenant>" -> "tenant"
        return raw.split("=")[0].strip()
    # Fall back to a query parameter on the reported endpoint.
    ep = str(item.get("endpoint") or item.get("affected_endpoint") or "")
    if "?" in ep:
        q = ep.split("?", 1)[1]
        if "=" in q:
            return q.split("=")[0].strip()
    return ""


def normalize_analyze_output_lenient(
    content: str, base_url: str = ""
) -> tuple[AnalyzeOutputV1 | None, str]:
    """Best-effort normalization of report-style analyze JSON.

    Handles the drift shapes observed in cloud runs: top-level
    ``vulnerabilities`` with name/affected_endpoint/why/remediation keys,
    per-endpoint ``vulnerability_hypotheses``/``exploitation_assessment``
    blocks and ``unverified_hypotheses``.  Runs only after the strict schema
    repair loop failed, and always logs what it recovered.
    """
    raw = extract_json_value(content)
    if raw is None:
        return None, "no JSON found in LLM output"
    if isinstance(raw, list):
        return None, "expected dict but got list"
    if not isinstance(raw, dict):
        return None, "expected dict"
    strict: AnalyzeOutputV1 | None = None
    try:
        strict = AnalyzeOutputV1.model_validate(raw)
    except Exception:
        strict = None
    if strict is not None and strict.vulnerabilities:
        # Fully conformant output: nothing to normalize.
        return strict, ""

    candidates: list[dict] = []
    if strict is None or not strict.vulnerabilities:
        vuln_lists = raw.get("vulnerabilities") or raw.get("vulns") or []
        if isinstance(vuln_lists, list):
            candidates.extend(v for v in vuln_lists if isinstance(v, dict))
    unverified = raw.get("unverified_hypotheses") or []
    if isinstance(unverified, list):
        candidates.extend(v for v in unverified if isinstance(v, dict))
    for key in ("endpoints", "endpoints_analyzed", "endpoints_reviewed", "endpoint_assessment"):
        for ep in raw.get(key, []) or []:
            if not isinstance(ep, dict):
                continue
            for nested_key in ("vulnerability_hypotheses", "vulnerabilities", "issues"):
                nested = ep.get(nested_key)
                if isinstance(nested, list):
                    candidates.extend(v for v in nested if isinstance(v, dict))
            assessment = ep.get("exploitation_assessment")
            if isinstance(assessment, str) and assessment.strip():
                candidates.append({"endpoint": ep.get("endpoint") or ep.get("url") or "",
                                   "method": ep.get("method", ""),
                                   "path": ep.get("path", ""),
                                   "why": assessment})

    # Unverified entries from cloud-22 also carry endpoint / status fields.
    for i, cand in enumerate(candidates):
        if cand.get("status") == "unverified" and cand.get("reason"):
            updated = dict(cand)
            updated["why"] = cand.get("why") or f"{cand['reason']} (unverified — probe anyway)"
            updated["confidence"] = 0.3
            candidates[i] = updated

    normalized: list[AnalyzeVulnV1] = []
    dropped = 0
    for item in candidates:
        endpoint = (
            item.get("endpoint")
            or item.get("affected_endpoint")
            or item.get("url")
            or ""
        )
        if not endpoint:
            method = item.get("method") or ""
            path = item.get("path") or ""
            if path:
                endpoint = path
        ep_abs = _absolute_endpoint(str(endpoint), base_url)
        if not ep_abs:
            dropped += 1
            continue
        name_blob = " ".join(
            str(item.get(k, "") or "")
            for k in ("name", "title", "vulnerability", "vuln_type")
        )
        evidence = (
            item.get("evidence")
            or item.get("why")
            or item.get("reason")
            or item.get("exploitation_assessment")
            or ""
        )
        conf_raw = item.get("confidence")
        try:
            confidence = float(conf_raw) if conf_raw is not None else 0.5
        except (TypeError, ValueError):
            confidence = 0.5
        confidence = max(0.0, min(1.0, confidence))
        normalized.append(
            AnalyzeVulnV1(
                vuln_type=str(item.get("vuln_type", "") or "") or _infer_vuln_type(name_blob),
                endpoint=ep_abs,
                param=_endpoint_param(item),
                confidence=confidence,
                evidence=str(evidence)[:500],
                suggested_tool=str(item.get("suggested_tool", "") or ""),
                tool_args=item.get("tool_args")
                if isinstance(item.get("tool_args"), dict)
                else {},
            )
        )
    if not normalized:
        return None, "no usable vulnerability entries found after normalization"
    log.warning(
        "ANALYZE: schema repair failed; lenient normalization recovered %d "
        "hypothesis(es) (%d dropped for missing endpoint)",
        len(normalized), dropped,
    )
    understanding = raw.get("application_understanding") or raw.get("outcome") or ""
    return (
        AnalyzeOutputV1(
            application_understanding=str(understanding)[:500],
            vulnerabilities=normalized,
        ),
        "",
    )


# Validator protocol used by generate_structured: (content) -> (parsed, err).
Validator = Callable[[str], tuple[Any, str]]
