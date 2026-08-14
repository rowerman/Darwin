"""Shared base and helpers for the Tool Adapter layer (P15 G5)."""

from __future__ import annotations


class ToolAdapter:
    """Maps one capability's normalized context to gateway call params.

    ``env`` is the normalized task context (endpoint/parameter/credential/
    port/command/username) computed by the ContextResolver; ``params`` is
    the raw task action params for pass-through fields. Pure mapping —
    adapters never touch gateways, DKG or the LLM.
    """

    capability_name: str = ""

    def resolve(self, env: dict, params: dict) -> dict[str, dict]:
        """Return {tool_name: gateway-call-params} for this capability."""
        raise NotImplementedError


def passthrough(params: dict, keys) -> dict:
    """Copy declared pass-through fields from raw params (non-empty only)."""
    return {k: params[k] for k in keys if params.get(k)}


def http_post_params(endpoint: str, params: dict) -> dict:
    """Shared http_post parameter mapping (fetch + SQLi fallback)."""
    return {
        "url": endpoint,
        **passthrough(params, ("data", "headers", "cookie")),
    }
