"""Every literal ``_call_tool`` call site must speak the tool's declared names.

The gateway can only refuse a call whose keys the tool does not declare; it
cannot know that the framework's own recon code meant ``data`` when it wrote
``content``.  That drift silently killed the bootstrap response parsing of two
benchmark runs, so the call sites are checked statically instead.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]
_MANIFEST = _ROOT / "tools_manifest.json"


def _declared_params() -> dict[str, set[str]]:
    manifest = json.loads(_MANIFEST.read_text())
    return {
        tool["name"]: set((tool.get("parameters") or {}).keys())
        for tool in manifest["tools"]
    }


def _literal_call_sites() -> tuple[list[tuple[str, int, str, list[str]]], int]:
    """Literal ``_call_tool("<name>", {<literal keys>})`` sites + skip count."""
    sites: list[tuple[str, int, str, list[str]]] = []
    skipped = 0
    for path in sorted((_ROOT / "darwin").rglob("*.py")):
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if not (isinstance(func, ast.Attribute) and func.attr == "_call_tool"):
                continue
            if len(node.args) < 2:
                continue
            name_arg, params_arg = node.args[0], node.args[1]
            if not (
                isinstance(name_arg, ast.Constant)
                and isinstance(name_arg.value, str)
            ):
                skipped += 1
                continue
            if not isinstance(params_arg, ast.Dict):
                skipped += 1
                continue
            keys = [
                key.value for key in params_arg.keys
                if isinstance(key, ast.Constant) and isinstance(key.value, str)
            ]
            if len(keys) != len(params_arg.keys):
                skipped += 1
                continue
            sites.append((str(path.relative_to(_ROOT)), node.lineno, name_arg.value, keys))
    return sites, skipped


def test_literal_call_site_keys_are_declared():
    declared = _declared_params()
    sites, skipped = _literal_call_sites()

    assert len(sites) >= 10, "the static scan lost its targets"
    assert skipped < len(sites), "too many dynamic call sites to be useful"

    violations: list[str] = []
    for path, lineno, tool, keys in sites:
        if tool not in declared:
            violations.append(f"{path}:{lineno}: unregistered tool '{tool}'")
            continue
        extra = [key for key in keys if key not in declared[tool]]
        if extra:
            violations.append(
                f"{path}:{lineno}: {tool} does not declare {extra} "
                f"(declared: {sorted(declared[tool])})"
            )
    assert not violations, "\n".join(violations)


@pytest.mark.parametrize(
    "tool,key",
    [
        ("response_parse", "data"),
        ("http_post", "data"),
    ],
)
def test_known_contract_slots_exist(tool, key):
    """Guard the two slots whose drift caused the benchmark failures."""
    assert key in _declared_params()[tool]
