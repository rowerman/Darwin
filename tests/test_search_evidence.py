"""Tests for the unified RAG/web research-evidence format."""

from __future__ import annotations

import json

from darwin.search_evidence import (
    SCHEMA,
    empty_evidence,
    format_rag_evidence,
    format_web_evidence,
)


def _load(text: str) -> dict:
    return json.loads(text)


def test_rag_and_web_share_one_schema():
    rag = _load(format_rag_evidence(
        "redis unauthorized access",
        [{
            "id": "scenario-redis",
            "title": "Redis unauthorized access",
            "description": "Connect with redis-cli and check for NOPASS",
            "category": "network",
            "subcategory": "database",
            "techniques": ["redis_cmd"],
            "score": 0.82,
            "path": ["network", "database"],
            "guid": "DB-02",
            "confidence": 0.7,
        }],
    ))
    web = _load(format_web_evidence(
        "redis unauthorized access",
        [{
            "title": "Redis security",
            "url": "https://example.com/redis",
            "snippet": "Bind to localhost and requirepass",
        }],
    ))
    assert rag["schema"] == SCHEMA == web["schema"]
    assert {k: type(v).__name__ for k, v in rag.items()} == \
        {k: type(v).__name__ for k, v in web.items()}
    assert set(rag["results"][0]) == set(web["results"][0])


def test_rag_evidence_fields():
    env = _load(format_rag_evidence("q", [{
        "id": "x",
        "title": "T",
        "description": "D",
        "category": "web",
        "subcategory": "ssti",
        "techniques": ["step1"],
        "score": 0.5,
        "source": "../benchmark/guide.md",
        "path": ["web", "ssti"],
        "guid": "WEB-1",
        "confidence": 0.6,
        "mitre_attack": "T1190",
    }]))
    r = env["results"][0]
    assert r["rank"] == 1
    assert r["title"] == "T"
    assert r["url"] == "../benchmark/guide.md"
    assert r["snippet"] == "D"
    assert r["relevance"] == 0.5
    assert r["techniques"] == ["step1"]
    assert r["metadata"]["guid"] == "WEB-1"
    assert r["metadata"]["path"] == ["web", "ssti"]


def test_web_evidence_fields_and_null_relevance():
    env = _load(format_web_evidence("q", [{
        "title": "Page",
        "href": "https://example.com",
        "body": "Some snippet",
    }]))
    r = env["results"][0]
    assert r["title"] == "Page"
    assert r["url"] == "https://example.com"
    assert r["snippet"] == "Some snippet"
    assert r["relevance"] is None
    assert r["techniques"] == []


def test_empty_evidence():
    env = _load(empty_evidence("web", "q"))
    assert env["total"] == 0
    assert env["results"] == []
    assert env["source"] == "web"


def test_load_mcp_config_expands_env(monkeypatch, tmp_path):
    from darwin.tools.mcp_client import load_mcp_config

    cfg = tmp_path / "mcp.yaml"
    cfg.write_text(
        "servers:\n"
        "  example-server:\n"
        "    command: npx\n"
        "    args: ['-y', 'example-package']\n"
        "    env:\n"
        "      EXAMPLE_API_KEY: ${EXAMPLE_API_KEY}\n"
        "      EXAMPLE_MODEL: some-model\n"
        "    enabled: true\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("EXAMPLE_API_KEY", "test-key-123")
    servers = load_mcp_config(str(cfg))
    assert servers[0].env["EXAMPLE_API_KEY"] == "test-key-123"
    assert servers[0].env["EXAMPLE_MODEL"] == "some-model"


def test_load_mcp_config_missing_file(tmp_path):
    from darwin.tools.mcp_client import load_mcp_config

    assert load_mcp_config(str(tmp_path / "nope.yaml")) == []
