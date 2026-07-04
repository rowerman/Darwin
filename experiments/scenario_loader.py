"""Dynamic scenario loader — reads scenarios.yaml and resolves target URLs.

Replaces the hardcoded CVE_BENCHMARK_CHALLENGES in runner.py with a
dynamic loader that reads from the authoritative scenarios.yaml registry.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import os
import yaml

ROOT_DIR = Path(__file__).resolve().parent.parent

# Benchmark infrastructure moved to /home/kianabin/benchmark_design/benchmarks/
# Prefer env var BENCHMARK_DIR, fallback to known absolute path
_BENCHMARK_BASE = os.environ.get(
    "BENCHMARK_DIR",
    str(Path.home() / "benchmark_design" / "benchmarks")
)
SCENARIOS_YAML = Path(_BENCHMARK_BASE) / "cve_challenges" / "scripts" / "scenarios.yaml"
CVE_CHALLENGES_DIR = Path(_BENCHMARK_BASE) / "cve_challenges"


# ── K8s target URL mapping ───────────────────────────────────────────
# Most K8s scenarios expose the standard K8s API (6443).
# A few expose alternative services (kubelet, etcd) on specific hostPorts.

K8S_TARGET_MAP: dict[str, str] = {
    "K8S-01": "localhost:6443",   # runC WORKDIR escape
    "K8S-02": "localhost:6443",   # runC /dev/null symlink
    "K8S-03": "localhost:6443",   # runC LSM bypass
    "K8S-05": "localhost:6443",   # gitRepo volume
    "K8S-06": "localhost:6443",   # RBAC secrets
    "K8S-07": "localhost:10250",  # Kubelet API
    "K8S-08": "localhost:11379",  # etcd (hostPort from kind-config)
    "K8S-09": "localhost:6443",   # Registry poisoning
    "K8S-10": "localhost:6443",   # Helm Tiller
    "K8S-11": "localhost:6443",   # Privileged breakout
    "K8S-12": "localhost:6443",   # hostPath escape
    "K8S-13": "localhost:6443",   # SA cross-namespace
    "K8S-14": "localhost:6443",   # CAP_SYS_ADMIN cgroup
    "K8S-15": "localhost:6443",   # Mutable image tag
}

# K8s scenarios (by ID) that need to be skipped because the
# scenario infrastructure is not deployable on this host.
K8S_BLOCKED: dict[str, str] = {
    # Add known-broken K8s scenarios here as discovered.
    # "K8S-04": "NVIDIA Container Toolkit requires GPU hardware",
}


@dataclass
class ScenarioDef:
    """A single benchmark scenario definition."""

    id: str                       # e.g. "WEB-01"
    name: str                     # Human-readable name
    scenario_type: str            # "docker" | "k8s"
    category: str                 # "web" | "db" | "linux" | "k8s" | "defense"
    difficulty: str               # "L1" | "L2" | "L3"
    cve: str                      # CVE id or technique name
    target_url: str               # URL for orchestrator.run()
    target_host: str              # hostname portion
    target_port: int              # port number (0 if N/A)
    port_range: str | None        # e.g. "10101-10101" for nmap scoping
    path: str                     # relative path from cve_challenges/
    is_available: bool = True     # can this scenario be run?
    block_reason: str | None = None
    defense_present: bool = False
    waf_present: bool = False
    base_scenario: str | None = None  # for WAF variants
    description: str = ""         # task description for orchestrator
    extra: dict[str, Any] = field(default_factory=dict)


# ── Category helpers ──────────────────────────────────────────────────

def _classify_category(scenario_id: str, scenario_type: str) -> str:
    """Classify a scenario into a category based on its ID prefix."""
    prefix = scenario_id.split("-")[0].upper()
    if prefix in ("WEB",):
        return "web"
    if prefix in ("DB",):
        return "db"
    if prefix in ("LNX",):
        return "linux"
    if prefix in ("K8S",):
        return "k8s"
    if prefix in ("AD",):
        return "ad"
    return "other"


def _build_description(scenario: dict[str, Any]) -> str:
    """Build a task description for the orchestrator."""
    sid = scenario.get("id", "")
    name = scenario.get("name", "")
    cve = scenario.get("cve", "")
    diff = scenario.get("difficulty", "")

    base = f"Exploit {name}"
    if cve and "N/A" not in str(cve):
        base += f" ({cve})"
    base += f". Difficulty: {diff}."
    base += " Find and capture the flag."

    if scenario.get("defense") == "waf":
        base += " The target is protected by a WAF — you must bypass it."

    return base


# ── Main loading function ─────────────────────────────────────────────

def load_scenarios(include_ad: bool = False) -> list[ScenarioDef]:
    """Load all Docker and K8s scenarios from scenarios.yaml.

    Args:
        include_ad: If True, also include samba-ad scenarios.

    Returns:
        List of ScenarioDef objects, with blocked scenarios marked
        as is_available=False.
    """
    if not SCENARIOS_YAML.exists():
        raise FileNotFoundError(f"scenarios.yaml not found at {SCENARIOS_YAML}")

    with open(SCENARIOS_YAML, encoding="utf-8") as fh:
        data = yaml.safe_load(fh)

    scenarios: list[ScenarioDef] = []

    for key, raw in data.get("scenarios", {}).items():
        stype = raw.get("type", "")

        # Filter: only docker and k8s (optionally samba-ad)
        if stype not in ("docker", "k8s", "samba-ad"):
            continue
        if stype == "samba-ad" and not include_ad:
            continue

        sid = raw.get("id", key.upper())
        category = _classify_category(sid, stype)
        description = _build_description(raw)

        # ── Determine availability ────────────────────────────────
        is_available = True
        block_reason = None

        if raw.get("platform") == "windows-only":
            is_available = False
            block_reason = "Windows-only scenario"
        elif stype == "vagrant":
            is_available = False
            block_reason = "Requires Vagrant/VirtualBox/QEMU (VT-x)"
        elif stype == "k8s" and sid in K8S_BLOCKED:
            is_available = False
            block_reason = K8S_BLOCKED[sid]

        # ── Resolve target URL and port ───────────────────────────
        target_url, target_host, target_port, port_range = _resolve_target(
            sid, stype, raw
        )

        scenarios.append(ScenarioDef(
            id=sid,
            name=raw.get("name", key),
            scenario_type=stype,
            category=category,
            difficulty=raw.get("difficulty", "L1"),
            cve=str(raw.get("cve", "")),
            target_url=target_url,
            target_host=target_host,
            target_port=target_port,
            port_range=port_range,
            path=raw.get("path", ""),
            is_available=is_available,
            block_reason=block_reason,
            defense_present=raw.get("defense") is not None,
            waf_present=raw.get("defense") == "waf",
            base_scenario=raw.get("base_scenario"),
            description=description,
            extra={
                "ssh_user": raw.get("ssh_user"),
                "ssh_password": raw.get("ssh_password"),
                "ssh_port": raw.get("ssh_port"),
                "dc_ip": raw.get("dc_ip"),
            },
        ))

    return scenarios


def _resolve_target(
    sid: str, stype: str, raw: dict[str, Any]
) -> tuple[str, str, int, str | None]:
    """Resolve target_url, target_host, target_port, and port_range.

    Returns:
        (target_url, target_host, target_port, port_range)
    """
    if stype == "docker":
        port = raw.get("port", 0)
        port = int(port) if port else 0

        if not port:
            ssh_port = int(raw.get("ssh_port", 22))
            return (
                f"http://localhost:{ssh_port}",
                "localhost",
                ssh_port,
                f"{ssh_port}-{ssh_port}",
            )

        # HTTP services: use http:// prefix
        # DB services (postgres, mysql, oracle, mssql, redis): raw localhost:port
        prefix = "http://"
        web_ports = {10101, 10102, 10103, 10104, 10105, 10106, 10107, 10108, 9080, 9081}

        # Always use http:// prefix — bare host:port breaks urlparse in
        # orchestrator._bootstrap_scan(). The orchestrator handles non-HTTP
        # services (DB, SSH) correctly via nmap service detection regardless.
        target_url = f"http://localhost:{port}"

        return (target_url, "localhost", port, f"{port}-{port}")

    elif stype == "k8s":
        target_url = K8S_TARGET_MAP.get(sid, "localhost:6443")
        host = target_url.split(":")[0]
        port_str = target_url.split(":")[1] if ":" in target_url else "6443"
        port = int(port_str)

        # For K8s, we don't use port_range since each scenario has its own
        # KIND cluster. The target port is the only reachable service.
        return (target_url, host, port, f"{port}-{port}")

    elif stype == "samba-ad":
        dc_ip = raw.get("dc_ip", "192.168.100.10")
        return (dc_ip, dc_ip, 0, None)

    return (f"localhost:{raw.get('port', 8080)}", "localhost", int(raw.get("port", 8080)), None)


# ── Grouping helpers ──────────────────────────────────────────────────

def group_scenarios(
    scenarios: list[ScenarioDef],
) -> dict[str, list[ScenarioDef]]:
    """Group scenarios by infrastructure type.

    Returns:
        dict with keys "docker" and "k8s" (and optionally "ad").
    """
    groups: dict[str, list[ScenarioDef]] = {"docker": [], "k8s": [], "ad": []}

    for s in scenarios:
        if not s.is_available:
            continue
        if s.scenario_type == "docker":
            groups["docker"].append(s)
        elif s.scenario_type == "k8s":
            groups["k8s"].append(s)
        elif s.scenario_type == "samba-ad":
            groups["ad"].append(s)

    # Remove empty groups
    return {k: v for k, v in groups.items() if v}


def get_blocked_scenarios(
    scenarios: list[ScenarioDef],
) -> list[dict[str, str]]:
    """Return list of blocked scenarios with reasons."""
    return [
        {"id": s.id, "name": s.name, "reason": s.block_reason or "Unknown"}
        for s in scenarios
        if not s.is_available
    ]
