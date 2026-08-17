"""Phase 3 linkage tests: manifest lock + taxonomy reference integrity."""

from pathlib import Path

from darwin.tools.attack_server import create_attack_gateway
from darwin.tools.manifest import build_manifest, load_manifest, verify_manifest
from darwin.tools.recon_server import create_recon_gateway

ROOT = Path(__file__).resolve().parent.parent


def _live_specs():
    return {
        **create_attack_gateway().get_tool_specs(),
        **create_recon_gateway().get_tool_specs(),
    }


def test_committed_manifest_is_in_sync():
    """The committed tools_manifest.json is the lock: regenerating it from
    the live registry must produce an identical contract."""
    manifest_path = ROOT / "tools_manifest.json"
    assert manifest_path.exists()
    recorded = load_manifest(manifest_path)
    live = build_manifest(_live_specs(), source="test")
    # Compare contracts only (ignore generated_at/source metadata).
    recorded["generated_at"] = ""
    live["generated_at"] = ""
    recorded["source"] = ""
    live["source"] = ""
    assert recorded == live
    assert verify_manifest(recorded, _live_specs()) == []


def test_taxonomy_leaves_reference_valid_tools_capabilities_and_knowledge():
    """Every taxonomy leaf must resolve to registered tools, an existing
    capability, and an ingested knowledge entry (audit passes cleanly)."""
    from tools.audit_coverage import audit

    result = audit()
    assert result["summary"]["total"] == 89
    assert result["summary"]["with_problems"] == 0
