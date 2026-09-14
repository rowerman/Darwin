"""The world model must not list the same route or hypothesis twice."""

from __future__ import annotations

import tempfile
from pathlib import Path

from darwin.dkg import DKG


def _dkg() -> DKG:
    return DKG(storage_path=str(Path(tempfile.mkdtemp()) / "dkg.json"))


def test_same_route_added_twice_keeps_one_endpoint_node():
    dkg = _dkg()

    first = dkg.add_node("Endpoint", "ep-a", {
        "url": "http://t/workflows", "method": "POST", "params": "workspace",
    })
    second = dkg.add_node("Endpoint", "ep-b", {
        "url": "http://t/workflows/", "method": "post", "params": "workspace,dataset_ref",
    })

    assert first == "ep-a"
    assert second == "ep-a", "the same route must reuse its node"
    assert len(dkg.query_nodes("Endpoint")) == 1


def test_different_method_or_path_stays_a_separate_route():
    dkg = _dkg()

    dkg.add_node("Endpoint", "ep-a", {"url": "http://t/workflows", "method": "POST"})
    dkg.add_node("Endpoint", "ep-b", {"url": "http://t/workflows", "method": "GET"})
    dkg.add_node("Endpoint", "ep-c", {"url": "http://t/workflows/1", "method": "POST"})

    assert len(dkg.query_nodes("Endpoint")) == 3
