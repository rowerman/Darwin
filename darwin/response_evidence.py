"""Turn a tool response into world-model evidence.

The rule is generic: a value the request never supplied, but which appears in
the response, is information the target chose to disclose. Two disclosures are
worth promoting into hypotheses:

* an absolute server path (``/app/workspaces/default/test``) — the response is
  a *path oracle*: the server resolved the caller's input into a filesystem
  location, which is exactly what path traversal needs;
* another subject's identifier (a tenant/workspace/user token different from
  the caller's own) — the response crossed an authorization boundary.

Both are observed, not guessed, so they enter the plan as grounded evidence
instead of waiting in the guess queue.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

#: Absolute POSIX/Windows paths.  Requires a known root so ordinary slash-laden
#: text (URLs, MIME types) is not mistaken for a filesystem disclosure.
_SERVER_PATH_RE = re.compile(
    r"(?:/(?:app|srv|opt|etc|var|home|usr|root|tmp|data|workspace|var/task)"
    r"(?:/[A-Za-z0-9._\-]+){1,8}"
    r"|[A-Za-z]:\\\\(?:[A-Za-z0-9._\- ]+\\\\){1,6}[A-Za-z0-9._\- ]+)"
)

#: Subject/tenant identifiers such as ``tenant-a``, ``workspace=acme``.
#: A separator is required so path segments ("workspaces") never match.
_SUBJECT_RE = re.compile(
    r"\b(tenant|workspace|account|org|project|namespace|user)([-_=:\"' ]{1,2})"
    r"([A-Za-z0-9][A-Za-z0-9._\-]{0,40})",
    re.IGNORECASE,
)


@dataclass
class ResponseAnomaly:
    """One observed disclosure and the hypothesis it justifies."""

    kind: str
    detail: str
    evidence: str
    vuln_type: str = ""
    endpoint: str = ""
    param: str = ""
    confidence: float = 0.4
    signals: dict[str, list[str]] = field(default_factory=dict)
    suggested_tool: str = ""
    tool_args: dict = field(default_factory=dict)


def disclosed_paths(response_text: str, request_blob: str = "") -> list[str]:
    """Absolute server paths present in the response but not in the request."""
    request_text = str(request_blob or "")
    found: list[str] = []
    for match in _SERVER_PATH_RE.finditer(str(response_text or "")):
        path = match.group(0)
        if path in request_text or path in found:
            continue
        found.append(path)
    return found


def disclosed_subjects(response_text: str, request_blob: str = "") -> list[str]:
    """``key=value`` subject identifiers echoed back that the request lacked."""
    request_text = str(request_blob or "")
    found: list[str] = []
    for key, sep, value in _SUBJECT_RE.findall(str(response_text or "")):
        token = f"{key.lower()}{sep}{value}"
        if token in request_text.lower() or token in found:
            continue
        found.append(token)
    return found


def detect_response_anomalies(
    *,
    tool: str,
    params: dict,
    response_text: str,
    endpoint: str = "",
    param: str = "",
) -> list[ResponseAnomaly]:
    """Observed disclosures in one tool result, as promotable hypotheses."""
    request_blob = " ".join(str(v) for v in dict(params or {}).values())
    anomalies: list[ResponseAnomaly] = []

    paths = disclosed_paths(response_text, request_blob)
    if paths:
        anomalies.append(ResponseAnomaly(
            kind="path_oracle",
            detail=(
                "the target resolved the request into a server-side path and "
                "returned it in the response"
            ),
            evidence=(
                "Response disclosed server path(s) "
                + ", ".join(paths[:3])
                + " not present in the request"
            ),
            vuln_type="LFI",
            endpoint=endpoint,
            param=param,
            confidence=0.55,
            signals={"disclosed_paths": paths[:5]},
            suggested_tool="",
            tool_args={},
        ))

    subjects = disclosed_subjects(response_text, request_blob)
    if subjects:
        anomalies.append(ResponseAnomaly(
            kind="cross_subject_echo",
            detail="the response carried another subject's identifier",
            evidence=(
                "Response referenced subject(s) "
                + ", ".join(subjects[:3])
                + " that the request did not supply"
            ),
            vuln_type="IDOR",
            endpoint=endpoint,
            param=param,
            confidence=0.5,
            signals={"disclosed_subjects": subjects[:5]},
        ))

    return anomalies


def traversal_hypotheses(anomaly: ResponseAnomaly, *, limit: int = 3) -> list[dict]:
    """Concrete follow-up hypotheses for a path-oracle disclosure.

    The disclosed path is the server's own resolution of the caller's input, so
    the payload family is derived from that value instead of a generic wordlist.
    """
    if anomaly.kind != "path_oracle":
        return []
    paths = list(anomaly.signals.get("disclosed_paths") or [])
    if not paths:
        return []
    target = paths[0]
    parent = target.rsplit("/", 1)[0] if "/" in target else target
    payloads = [f"{target}/../flag", f"{parent}/../flag", "../../../../flag"]
    endpoint = str(anomaly.endpoint or "")
    if not endpoint:
        return []
    out: list[dict] = []
    for payload in payloads[:limit]:
        out.append({
            "vuln_type": "LFI",
            "endpoint": anomaly.endpoint,
            "param": anomaly.param,
            "confidence": 0.5,
            "evidence": (
                f"Path oracle: the response disclosed {target!r}; the same "
                f"parameter can be driven to {payload!r}"
            ),
            "suggested_tool": anomaly.suggested_tool or "send_payload",
            "tool_args": {
                "url": endpoint,
                "param": anomaly.param,
                "payload": payload,
            },
            "source": "response_evidence",
        })
    return out
