"""Host-side reachability of endpoints derived from cluster topology.

Endpoints synthesized from in-cluster objects (ClusterIP Services, AWS
exposure rules) only resolve inside the cluster network.  The host running
darwin has no route to the Kubernetes service CIDR, so every probe against
them costs a full timeout and returns nothing — which is how a KIND target
used to burn its whole recon budget before the exploit phase started.

``relation_analyzer`` marks those nodes with ``virtual: True``; this module is
the single place that turns that marker into a probing decision.
"""

from __future__ import annotations

from typing import Any, Mapping

#: ``discovered_by`` prefixes whose endpoints exist only inside the cluster.
VIRTUAL_SOURCE_PREFIXES = ("relation_analyzer",)


def is_host_reachable(ep: Mapping[str, Any]) -> bool:
    """Whether an Endpoint node can be probed from the darwin host."""
    if not isinstance(ep, Mapping):
        return False
    if ep.get("virtual"):
        return False
    source = str(ep.get("discovered_by", "") or "")
    return not source.startswith(VIRTUAL_SOURCE_PREFIXES)
