"""Tool manifest generation and verification (Phase 1: tool contract).

The manifest is the machine-readable snapshot of every registered tool's
ToolSpec. It is the single artifact the LLM prompt builder, evaluators,
coverage audit and CI can rely on — a refactor is only "released" when
``python -m darwin.tools.manifest --check`` passes against the committed
manifest.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from darwin.tools.spec import CONTRACT_VERSION, ToolSpec

MANIFEST_FILENAME = "tools_manifest.json"


def build_manifest(
    specs: dict[str, ToolSpec],
    source: str = "",
) -> dict[str, Any]:
    """Build a manifest dict from a name → ToolSpec mapping."""
    tools = sorted(
        (spec.to_dict() for spec in specs.values()),
        key=lambda t: t["name"],
    )
    return {
        "schema_version": CONTRACT_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "source": source,
        "tool_count": len(tools),
        "tools": tools,
    }


def write_manifest(manifest: dict[str, Any], path: str | Path) -> None:
    """Write the manifest as pretty JSON."""
    target = Path(path)
    target.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def load_manifest(path: str | Path) -> dict[str, Any]:
    """Load a manifest file."""
    return json.loads(Path(path).read_text(encoding="utf-8"))


def verify_manifest(
    manifest: dict[str, Any],
    specs: dict[str, ToolSpec],
) -> list[str]:
    """Return differences between a manifest and the live registry specs.

    An empty list means the manifest is in sync with the registry.
    The generated_at/source/tool_count fields are not compared (they are
    metadata, not contract).
    """
    issues: list[str] = []
    live = {name: spec.to_dict() for name, spec in specs.items()}
    recorded = {
        str(item.get("name")): item
        for item in manifest.get("tools", [])
        if isinstance(item, dict)
    }

    for name in sorted(set(live) | set(recorded)):
        if name not in recorded:
            issues.append(f"manifest missing tool: {name}")
            continue
        if name not in live:
            issues.append(f"manifest has stale tool: {name}")
            continue
        live_item = {k: v for k, v in live[name].items() if k != "auto"}
        recorded_item = {k: v for k, v in recorded[name].items() if k != "auto"}
        if live_item != recorded_item:
            for key in sorted(set(live_item) | set(recorded_item)):
                if live_item.get(key) != recorded_item.get(key):
                    issues.append(
                        f"tool '{name}' field '{key}' changed: "
                        f"manifest={recorded_item.get(key)!r} "
                        f"registry={live_item.get(key)!r}"
                    )
    return issues


def _collect_specs_from_gateways() -> dict[str, ToolSpec]:
    """Build both gateways and collect every registered tool spec."""
    from darwin.tools.attack_server import create_attack_gateway
    from darwin.tools.recon_server import create_recon_gateway

    attack = create_attack_gateway()
    recon = create_recon_gateway()
    specs: dict[str, ToolSpec] = {}
    specs.update(attack.get_tool_specs())
    specs.update(recon.get_tool_specs())
    return specs


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m darwin.tools.manifest",
        description="Generate or verify the Darwin tool manifest.",
    )
    parser.add_argument(
        "--out", default=MANIFEST_FILENAME,
        help="manifest output path (default: tools_manifest.json)",
    )
    parser.add_argument(
        "--check", action="store_true",
        help="verify the manifest at --out against the live registry",
    )
    parser.add_argument(
        "--strict", action="store_true",
        help="fail on any ToolSpec validation issue",
    )
    args = parser.parse_args(argv)

    from darwin.tools.spec import check_all_specs

    specs = _collect_specs_from_gateways()
    issues = check_all_specs(specs, strict=args.strict)
    for issue in issues:
        print(issue, file=sys.stderr)
    if args.strict and issues:
        return 1

    if args.check:
        try:
            recorded = load_manifest(args.out)
        except FileNotFoundError:
            print(f"manifest not found: {args.out}", file=sys.stderr)
            return 1
        diffs = verify_manifest(recorded, specs)
        if diffs:
            for diff in diffs:
                print(f"DIFF: {diff}", file=sys.stderr)
            return 1
        print(
            f"OK: manifest {args.out} in sync with "
            f"{len(specs)} live tools"
        )
        return 0

    manifest = build_manifest(specs, source="darwin.tools.manifest")
    write_manifest(manifest, args.out)
    print(
        f"wrote {args.out}: {manifest['tool_count']} tools "
        f"(schema v{manifest['schema_version']})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
