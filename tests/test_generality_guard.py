"""Guards against scenario-specific patching inside ``darwin/``.

Every fix must come from a rule that holds for the whole class of targets,
never from a constant copied out of one benchmark scenario. These checks fail
as soon as a scenario id, a concrete flag value, or a write hypothesis mapped
to a read-only tool appears in the production tree.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

from darwin.orchestration.execution import (
    _FALLBACK_HTTP_TOOLS,
    _systematic_vuln_tool_map,
)
from darwin.orchestration.planning import PlanCoordinator
from darwin.tools.attack_server import create_attack_gateway
from darwin.tools.recon_server import create_recon_gateway


_DARWIN = Path(__file__).resolve().parents[1] / "darwin"
_SCENARIO_ID_RE = re.compile(r"^(cloud|k8s|web|db|ad|lnx)-\d{1,3}$", re.I)
_FLAG_VALUE_RE = re.compile(r"flag\{([^}\s]{3,})\}")
_WRITE_KEYWORDS = ("dependency", "supply", "poison", "squat", "publish", "package")
#: Placeholders the prompts legitimately discuss; a concrete value additionally
#: carries a digit (scenario flags are "<theme>-<nn>-<name>").
_GENERIC_FLAG_PREFIXES = ("test", "example", "honeypot", "...")


def _is_concrete_flag(value: str) -> bool:
    match = _FLAG_VALUE_RE.search(value)
    if not match:
        return False
    body = match.group(1)
    if body.lower().startswith(_GENERIC_FLAG_PREFIXES):
        return False
    return any(char.isdigit() for char in body)


def _string_constants() -> list[tuple[Path, int, str]]:
    out: list[tuple[Path, int, str]] = []
    for path in sorted(_DARWIN.rglob("*.py")):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (SyntaxError, UnicodeDecodeError):
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                out.append((path, getattr(node, "lineno", 0), node.value))
    return out


def test_no_scenario_identity_is_branched_on():
    offenders = [
        (path, line, value)
        for path, line, value in _string_constants()
        if _SCENARIO_ID_RE.match(value.strip())
    ]
    assert offenders == [], f"scenario id used as a value: {offenders}"


def test_no_concrete_flag_value_is_embedded():
    offenders = [
        (path, line, value)
        for path, line, value in _string_constants()
        if _is_concrete_flag(value)
    ]
    assert offenders == [], f"flag literal embedded in source: {offenders}"


def _method_capable_tools() -> set[str]:
    tools: set[str] = set()
    for gateway in (create_attack_gateway(), create_recon_gateway()):
        for name, spec in gateway.get_tool_specs().items():
            if "method" in (spec.parameters or {}):
                tools.add(name)
    return tools


def test_write_class_vulns_map_to_a_tool_that_can_express_a_write():
    capable = _method_capable_tools()
    mapping = _systematic_vuln_tool_map()
    write_keys = [
        key for key in mapping
        if any(keyword in key for keyword in _WRITE_KEYWORDS)
    ]
    assert write_keys, "write-class vulnerability mapping disappeared"
    for key in write_keys:
        first = mapping[key][0]
        assert first in capable, (
            f"write-class vuln '{key}' maps to '{first}', "
            "which cannot express PUT/PATCH/DELETE"
        )


def test_unknown_vuln_types_get_a_method_capable_fallback():
    capable = _method_capable_tools()
    assert _FALLBACK_HTTP_TOOLS[0] in capable


def test_vulnerability_type_guessing_splits_read_and_write():
    coord = PlanCoordinator.__new__(PlanCoordinator)
    assert coord._guess_tool("dependency_confusion") in _method_capable_tools()
    assert coord._guess_tool("SQLi") == "sqlmap_test"
    assert coord._guess_tool("IDOR") == "curl_get"
