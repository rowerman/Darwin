"""Regressions for the tool defects the benchmark logs exposed."""

from __future__ import annotations

from darwin.tools.attack_server import (
    normalize_parallel_urls,
    resolve_fuzz_wordlist,
)
from darwin.tools.recon_server import create_recon_gateway


def test_parallel_request_accepts_a_json_array_of_urls():
    """An array used to crash on ``urls.split`` before any request was sent."""
    assert normalize_parallel_urls(["http://t/a", "http://t/b"]) == [
        "http://t/a", "http://t/b",
    ]


def test_parallel_request_accepts_a_comma_separated_string():
    assert normalize_parallel_urls("http://t/a, http://t/b") == [
        "http://t/a", "http://t/b",
    ]


def test_parallel_request_tolerates_empty_input():
    assert normalize_parallel_urls("") == []
    assert normalize_parallel_urls([]) == []


def test_idor_header_test_sweep_is_never_a_noop():
    """The documented default ID set used to arrive as an empty parameter."""
    declared = create_recon_gateway()._registry["idor_header_test"].parameters

    assert declared["user_ids"]["default"]
    assert "10032" in declared["user_ids"]["default"]


def test_ffuf_wordlist_falls_back_to_a_bundled_list(caplog):
    requested = "seclists/Discovery/Web-Content/api/api-endpoints.txt"

    resolved = resolve_fuzz_wordlist(requested)

    assert resolved.endswith("common.txt")
    assert resolved != requested
    assert any(requested in record.getMessage() for record in caplog.records)


def test_ffuf_wordlist_keeps_a_resolvable_name():
    assert resolve_fuzz_wordlist("common.txt").endswith("common.txt")
