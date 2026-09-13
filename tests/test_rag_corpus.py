"""Unified RAG corpus: conversion, sanitization, lint and artifact sync."""

from __future__ import annotations

import json
from pathlib import Path

from darwin.rag_corpus import (
    SCHEMA_VERSION,
    build_corpus,
    lint_entry,
    load_corpus,
    write_corpus,
)


def _write(path: Path, data) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(data, ensure_ascii=False) if not isinstance(data, str) else data,
        encoding="utf-8",
    )
    return path


def _fixture(tmp_path: Path) -> Path:
    root = tmp_path / "knowledge"
    # Legacy "standard" shape
    _write(root / "cloud" / "aws.json", [{
        "id": "aws-dynamo",
        "title": "AWS DynamoDB Injection",
        "category": "EXPLOIT",
        "subcategory": "nosql",
        "description": "Injection into DynamoDB scans indicates weak filters.",
        "techniques": ["aws dynamodb scan --table-name TARGET_TABLE", "flag{leaked}"],
        "indicators": ["dynamodb:Scan permission present"],
        "tags": ["cloud", "nosql"],
        "tools": ["aws_cli", "not_a_real_tool"],
        "confidence": 0.6,
        "prerequisites": ["AWS credentials with DynamoDB permissions"],
    }])
    # Nuclei-style dump: raw request lines must not survive conversion
    _write(root / "nuclei_cve_templates.json", [{
        "id": "nuclei-CVE-2020-0001",
        "title": "Acme Panel v1.2 - Unauthenticated File Upload",
        "category": "CVE",
        "subcategory": "General",
        "description": "Acme Panel before 1.2.1 allows uploading files via POST /upload.php.",
        "techniques": [
            "POST /upload.php HTTP/1.1",
            "Content-Disposition: form-data; name=\"file\"",
            "------WebKitFormBoundary1234",
        ],
        "confidence": 0.9,
        "references": ["https://example.com/CVE-2020-0001"],
    }])
    # OSCP-style scan dump with target-specific values
    _write(root / "web_oscp.json", [{
        "id": "general-1",
        "title": "Nmap 7.91 scan initiated for 192.168.10.5",
        "category": "GENERAL",
        "description": "Nmap scan report for 192.168.10.5\n22/tcp open ssh OpenSSH 8.2p1",
        "techniques": ["22/tcp open ssh OpenSSH 8.2p1", "flag{scan}"],
        "tags": ["general"],
        "confidence": 0.5,
    }])
    # Markdown remediation note (k8s hardening -> failure boundary)
    _write(root / "cloud" / "remediation-templates" / "rem-x.md", (
        "# 修复方案: 禁止特权容器\n\n"
        "**风险类型**: Privileged Container\n\n"
        "## 风险描述\n\n特权容器可逃逸到宿主机。\n\n"
        "## 修复步骤\n\n- 配置 Pod Security Standards\n"
    ))
    # Benchmark GUIDE dump -> excluded from the runtime corpus
    _write(root / "scenarios" / "cloud" / "benchmark_guides.json", [{
        "id": "scenario-shared-nat",
        "title": "CLOUD-28 Shared NAT",
        "description": "Route through the shared NAT",
        "techniques": ["Send the request through the NAT"],
        "flag": "flag{cloud-28}",
    }])
    # Curated capability entry
    _write(root / "capabilities" / "cloud.json", [{
        "id": "cap-cloud-cross-tenant",
        "title": "可预测资源 ID + 属主校验缺失",
        "capability": "cloud_cross_tenant_object_access",
        "domains": ["cloud"],
        "requires_environment": ["public_cloud", "hybrid"],
        "applies_when": ["资源 ID 可预测", "服务端不比对资源属主"],
        "signals": ["替换 ID 后返回他人数据"],
        "technique_class": ["ID 枚举与替换"],
        "verification": "交叉请求两个租户的 ID 比较响应",
        "failure_boundary": ["服务端按租户强校验属主"],
        "tools": ["curl_get"],
        "aliases": {"zh": ["跨租户越权"], "en": ["cross-tenant object access"]},
        "confidence": 0.7,
        "derived_from": "benchmark scenarios: attachme-volume",
    }])
    return root


def test_corpus_conversion_and_exclusion(tmp_path):
    root = _fixture(tmp_path)
    build = build_corpus(root)
    kinds = {e["id"]: e["provenance"]["source_kind"] for e in build.entries}
    assert kinds["cap-cloud-cross-tenant"] == "curated"
    assert kinds["nuclei-CVE-2020-0001"] == "nuclei_template"
    assert not any(str(e["id"]).startswith("scenario-") for e in build.entries)
    assert build.excluded and build.excluded[0]["reason"] == "answer_leak"
    assert build.excluded[0]["entries"] == 1
    assert all(e["provenance"]["kind"] == "curated" for e in build.entries
               if e["provenance"]["source_kind"] == "curated")


def test_conversion_sanitizes_target_values_and_request_bodies(tmp_path):
    root = _fixture(tmp_path)
    entries = {e["id"]: e for e in build_corpus(root).entries}

    scan = entries["general-1"]
    blob = json.dumps(scan, ensure_ascii=False)
    assert "192.168.10.5" not in blob
    assert "<host>" in blob
    assert scan["capability"] == "recon-scan"
    assert any("22/tcp" in s for s in scan["signals"])

    nuclei = entries["nuclei-CVE-2020-0001"]
    blob = json.dumps(nuclei, ensure_ascii=False)
    assert "WebKitFormBoundary" not in blob
    assert "Content-Disposition" not in blob
    assert nuclei["cve_ids"] == ["CVE-2020-0001"]
    assert nuclei["capability"] == "file-upload"
    assert any("Acme Panel" in cond for cond in nuclei["applies_when"])

    aws = entries["aws-dynamo"]
    assert "not_a_real_tool" not in aws["tools"]
    assert "flag{leaked}" not in json.dumps(aws, ensure_ascii=False)


def test_remediation_becomes_failure_boundary(tmp_path):
    root = _fixture(tmp_path)
    entry = next(e for e in build_corpus(root).entries
                 if e["provenance"]["source_kind"] == "remediation_md")
    assert entry["capability"] == "misconfig-assessment"
    assert entry["requires_environment"] == ["private_cloud", "hybrid"]
    assert entry["failure_boundary"]
    assert "禁止特权容器" in entry["failure_boundary"][0]


def test_lint_flags_target_values_and_missing_fields():
    entry = {
        "id": "x", "title": "localhost:8080 token bypass", "capability": "c",
        "domains": ["web"], "requires_environment": [], "applies_when": [],
        "signals": [], "technique_class": ["ok"], "verification": "",
        "failure_boundary": [], "provenance": {"kind": "curated"},
        "search_text_dense": "d", "search_text_sparse": "s",
    }
    problems = lint_entry(entry)
    assert "empty_applies_when" in problems
    assert "empty_verification" in problems
    assert "target_specific_value" in problems


def test_corpus_artifact_round_trip_and_check(tmp_path):
    root = _fixture(tmp_path)
    build = build_corpus(root)
    manifest = write_corpus(build.entries, root, build)
    assert manifest["schema_version"] == SCHEMA_VERSION
    assert manifest["counts"]["total"] == len(build.entries)
    assert manifest["counts"]["curated"] == 1

    loaded, loaded_manifest = load_corpus(root)
    assert {e["id"] for e in loaded} == {e["id"] for e in build.entries}
    assert loaded_manifest["counts"] == manifest["counts"]

    from tools.build_rag_corpus import main

    assert main(["--knowledge-dir", str(root), "--check"]) == 0
    # A source change must invalidate the committed artifact.
    _write(root / "capabilities" / "web.json", [{
        "id": "cap-web-new", "title": "新条目", "capability": "web_x",
        "domains": ["web"], "requires_environment": [],
        "applies_when": ["条件"], "signals": [], "technique_class": ["类"],
        "verification": "验证", "failure_boundary": [],
    }])
    assert main(["--knowledge-dir", str(root), "--check"]) == 1


def test_conversion_is_deterministic(tmp_path):
    root = _fixture(tmp_path)
    first = build_corpus(root).entries
    second = build_corpus(root).entries
    assert [e["search_text_dense"] for e in first] == \
        [e["search_text_dense"] for e in second]
