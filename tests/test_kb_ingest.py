"""Regression tests for knowledge-base guide ingestion (cloud-21/22 data)."""

import importlib.util
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location(
    "ingest_benchmark_guides",
    _ROOT / "tools" / "ingest_benchmark_guides.py",
)
_INGEST = importlib.util.module_from_spec(_SPEC)
assert _SPEC and _SPEC.loader
_SPEC.loader.exec_module(_INGEST)

check_entries = _INGEST.check_entries
parse_guide = _INGEST.parse_guide


GUIDE = """# CLOUD-21 Entra Actor Token：身份 actor 校验缺陷

| 字段 | 值 |
|---|---|
| 技术/CVE | N/A (actor/tenant validation bug) |
| 交付方式 | Docker Compose |
| 核心漏洞与利用 | Present a Tenant-A actor token to a Tenant-B operation |

## 利用步骤
1. 从身份服务为 `tenant-a` 获取签名 token。
2. 直接 POST `/token` 换取 token。
3. 携带该 token 请求 `GET /api/users?tenant=tenant-b`。

## Flag
`flag{cloud-21-tenant-b-admin}`
"""


def _write_guide(tmp_path: Path, text: str = GUIDE) -> Path:
    d = tmp_path / "cloud" / "actor-token"
    d.mkdir(parents=True)
    p = d / "GUIDE.md"
    p.write_text(text, encoding="utf-8")
    return p


def test_parse_guide_flag_and_continuation(tmp_path):
    guide = _write_guide(tmp_path)
    entry = parse_guide(guide)
    assert entry["title"].startswith("CLOUD-21")
    assert entry["flag"] == "flag{cloud-21-tenant-b-admin}"
    assert entry["id"] == "scenario-actor-token"
    assert "POST `/token`" in entry["description"]
    # "Docker Compose" metadata must not leak into client tools.
    assert "docker_registry" not in entry["tools"]
    assert "container_escape_docker_sock" not in entry["tools"]
    assert {"curl_get", "http_post", "send_payload"} <= set(entry["tools"])


def test_parse_guide_keeps_inline_command_continuation(tmp_path):
    text = GUIDE.replace(
        "2. 直接 POST `/token` 换取 token。",
        "2. 直接 POST `/wsman/exec`（无需任何凭据）执行\n   `cat /root/flag.txt`。",
    )
    guide = _write_guide(tmp_path, text)
    entry = parse_guide(guide)
    assert any("cat /root/flag.txt" in s for s in entry["techniques"])


def test_parse_guide_truncated_flag_regex(tmp_path):
    text = GUIDE.replace("flag{cloud-21-tenant-b-admin}", "flag{cloud-21-tenant-b-admin")
    guide = _write_guide(tmp_path, text)
    entry = parse_guide(guide)
    assert entry["flag"] == ""


def test_check_entries_detects_title_registry_mismatch(tmp_path):
    guide = _write_guide(tmp_path)
    entry = parse_guide(guide)
    ok = check_entries([entry], [guide], {"actor-token": "cloud-21"})
    assert ok == []

    bad = dict(entry)
    bad["title"] = "CLOUD-32 Entra Actor Token：身份 actor 校验缺陷"
    errs = check_entries([bad], [guide], {"actor-token": "cloud-21"})
    assert any("CLOUD-21" in e for e in errs)

    bad_flag = dict(entry)
    bad_flag["flag"] = "flag{cloud-21-tenant-b-admin"
    errs = check_entries([bad_flag], [guide], {"actor-token": "cloud-21"})
    assert any("truncated" in e for e in errs)
