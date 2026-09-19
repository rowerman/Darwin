"""TLS helpers shared by the HTTP tools.

Lab, benchmark and Kubernetes targets serve self-signed certificates as a
matter of course. A verification failure means the request never reached the
application at all, so every HTTP tool retries once with verification disabled
instead of reporting an empty response as a probe result.
"""

from __future__ import annotations

import ssl

#: Markers of a client-side certificate verification failure (Python and curl).
_CERT_ERROR_MARKERS = (
    "certificate_verify_failed",
    "sslcertverificationerror",
    "unable to get local issuer certificate",
    "self signed certificate",
    "self-signed certificate",
    "certificate verify failed",
)


def unverified_context() -> ssl.SSLContext:
    """TLS context that accepts self-signed / untrusted certificates."""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def is_cert_verify_error(text: str) -> bool:
    """Whether ``text`` reports a certificate verification failure."""
    lowered = str(text or "").lower()
    return any(marker in lowered for marker in _CERT_ERROR_MARKERS)
