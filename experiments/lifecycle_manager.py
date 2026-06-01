"""Scenario lifecycle manager — start / wait / stop for Docker and K8s.

Handles the full lifecycle of each benchmark scenario:
  START  → wait for readiness → (DARWIN runs) → STOP
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
from pathlib import Path

from experiments.scenario_loader import ScenarioDef, ROOT_DIR

logger = logging.getLogger(__name__)

# ── Timeouts ──────────────────────────────────────────────────────────
DOCKER_START_TIMEOUT = 180    # seconds to wait for Docker scenario to be ready
DOCKER_STOP_TIMEOUT = 60      # seconds to wait for Docker scenario to stop
K8S_START_TIMEOUT = 300       # seconds for KIND cluster to be ready
K8S_STOP_TIMEOUT = 120        # seconds for KIND cluster teardown
PORT_POLL_INTERVAL = 2        # seconds between port checks
HTTP_POLL_INTERVAL = 2        # seconds between HTTP checks


# ── Public API ────────────────────────────────────────────────────────

async def start_scenario(scenario: ScenarioDef) -> dict:
    """Start a scenario's infrastructure. Returns metadata dict.

    The returned dict always contains:
        flag: the generated flag string (may be "unknown" if not extractable)

    Raises RuntimeError on startup failure.
    """
    if scenario.scenario_type == "docker":
        return await _start_docker(scenario)
    elif scenario.scenario_type == "k8s":
        return await _start_k8s(scenario)
    else:
        raise ValueError(f"Unknown scenario type: {scenario.scenario_type}")


async def stop_scenario(scenario: ScenarioDef) -> None:
    """Stop a scenario's infrastructure. Never raises (errors are logged)."""
    try:
        if scenario.scenario_type == "docker":
            await _stop_docker(scenario)
        elif scenario.scenario_type == "k8s":
            await _stop_k8s(scenario)
    except Exception as exc:
        logger.warning(f"Teardown error for {scenario.id}: {exc}")


# ── Docker lifecycle ──────────────────────────────────────────────────

async def _start_docker(scenario: ScenarioDef) -> dict:
    """Start a Docker scenario via start-scenario.sh."""
    script = str(ROOT_DIR / "benchmarks" / "cve_challenges" / "scripts" / "start-scenario.sh")
    scenario_key = scenario.id.lower()

    logger.info(f"[{scenario.id}] Starting Docker scenario (port {scenario.target_port})...")

    proc = await asyncio.create_subprocess_exec(
        "bash", script, scenario_key,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=str(ROOT_DIR),
    )
    stdout, stderr = await asyncio.wait_for(
        proc.communicate(), timeout=DOCKER_START_TIMEOUT + 60,
    )

    out_text = stdout.decode(errors="replace")
    err_text = stderr.decode(errors="replace")

    if proc.returncode != 0:
        raise RuntimeError(
            f"start-scenario.sh failed (exit={proc.returncode}): "
            f"{err_text[:500]}"
        )

    # Extract flag from script output: "[+] Flag: flag{...}"
    flag = _extract_flag(out_text)

    # Wait for port to be reachable
    if scenario.target_port > 0:
        ready = await _wait_for_port(
            scenario.target_host, scenario.target_port, DOCKER_START_TIMEOUT,
        )
        if not ready:
            raise RuntimeError(
                f"Port {scenario.target_host}:{scenario.target_port} "
                f"not reachable after {DOCKER_START_TIMEOUT}s"
            )

    # For web scenarios, also wait for HTTP 200
    if scenario.target_url.startswith("http"):
        await _wait_for_http(scenario.target_url, DOCKER_START_TIMEOUT)

    logger.info(f"[{scenario.id}] Docker scenario ready (flag={flag[:40]}...)")
    return {"flag": flag, "output": out_text[:2000]}


async def _stop_docker(scenario: ScenarioDef) -> None:
    """Stop a Docker scenario via stop-scenario.sh."""
    script = str(ROOT_DIR / "benchmarks" / "cve_challenges" / "scripts" / "stop-scenario.sh")
    scenario_key = scenario.id.lower()

    logger.info(f"[{scenario.id}] Stopping Docker scenario...")

    proc = await asyncio.create_subprocess_exec(
        "bash", script, scenario_key,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=str(ROOT_DIR),
    )
    try:
        await asyncio.wait_for(proc.communicate(), timeout=DOCKER_STOP_TIMEOUT)
    except asyncio.TimeoutError:
        logger.warning(f"[{scenario.id}] Docker stop timed out, killing process")
        proc.kill()
        await proc.wait()

    logger.info(f"[{scenario.id}] Docker scenario stopped")


# ── K8s lifecycle ─────────────────────────────────────────────────────

async def _start_k8s(scenario: ScenarioDef) -> dict:
    """Start a K8s scenario via its deploy.sh."""
    scenario_dir = ROOT_DIR / "benchmarks" / "cve_challenges" / scenario.path
    deploy_script = scenario_dir / "deploy.sh"

    if not deploy_script.exists():
        raise RuntimeError(f"deploy.sh not found: {deploy_script}")

    logger.info(f"[{scenario.id}] Starting K8s scenario ({deploy_script})...")

    # Pass CVE_FLAG via environment
    env = {}
    flag = _generate_default_flag(scenario.id)
    env["CVE_FLAG"] = flag

    proc = await asyncio.create_subprocess_exec(
        "bash", str(deploy_script),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=str(scenario_dir),
        env={**__import__("os").environ, **env},
    )

    try:
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(), timeout=K8S_START_TIMEOUT,
        )
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        raise RuntimeError(f"K8s deploy timed out after {K8S_START_TIMEOUT}s")

    out_text = stdout.decode(errors="replace")
    err_text = stderr.decode(errors="replace")

    if proc.returncode != 0:
        raise RuntimeError(
            f"K8s deploy.sh failed (exit={proc.returncode}): {err_text[:500]}"
        )

    # Extract flag from output
    extracted = _extract_flag(out_text)
    if extracted != "unknown":
        flag = extracted

    # Wait for K8s target to be reachable
    if scenario.target_port > 0:
        ready = await _wait_for_port(
            scenario.target_host, scenario.target_port, 60,
        )
        if not ready:
            logger.warning(
                f"[{scenario.id}] K8s target port {scenario.target_port} "
                f"not reachable — continuing anyway (may need in-cluster access)"
            )

    logger.info(f"[{scenario.id}] K8s scenario ready")
    return {"flag": flag, "output": out_text[:2000]}


async def _stop_k8s(scenario: ScenarioDef) -> None:
    """Stop a K8s scenario via teardown.sh or stop-scenario.sh."""
    scenario_dir = ROOT_DIR / "benchmarks" / "cve_challenges" / scenario.path
    teardown_script = scenario_dir / "teardown.sh"

    if teardown_script.exists():
        logger.info(f"[{scenario.id}] Tearing down K8s scenario...")
        proc = await asyncio.create_subprocess_exec(
            "bash", str(teardown_script),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=str(scenario_dir),
        )
        try:
            await asyncio.wait_for(proc.communicate(), timeout=K8S_STOP_TIMEOUT)
        except asyncio.TimeoutError:
            logger.warning(f"[{scenario.id}] K8s teardown timed out")
            proc.kill()
            await proc.wait()
    else:
        # Fallback: use stop-scenario.sh
        script = str(ROOT_DIR / "benchmarks" / "cve_challenges" / "scripts" / "stop-scenario.sh")
        scenario_key = scenario.id.lower()
        proc = await asyncio.create_subprocess_exec(
            "bash", script, scenario_key,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=str(ROOT_DIR),
        )
        try:
            await asyncio.wait_for(proc.communicate(), timeout=K8S_STOP_TIMEOUT)
        except asyncio.TimeoutError:
            logger.warning(f"[{scenario.id}] K8s stop timed out")
            proc.kill()
            await proc.wait()

    logger.info(f"[{scenario.id}] K8s scenario stopped")


# ── Health check utilities ────────────────────────────────────────────

async def _wait_for_port(host: str, port: int, timeout: int) -> bool:
    """Poll until a TCP port is accepting connections."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=5,
            )
            writer.close()
            await writer.wait_closed()
            return True
        except (ConnectionRefusedError, OSError, asyncio.TimeoutError):
            await asyncio.sleep(PORT_POLL_INTERVAL)
    return False


async def _wait_for_http(url: str, timeout: int) -> bool:
    """Poll until an HTTP endpoint returns a response (any status)."""
    import aiohttp

    deadline = time.monotonic() + timeout
    async with aiohttp.ClientSession() as session:
        while time.monotonic() < deadline:
            try:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                    # Any response means the service is up
                    return True
            except Exception:
                await asyncio.sleep(HTTP_POLL_INTERVAL)
    return False


# ── Helpers ───────────────────────────────────────────────────────────

def _extract_flag(text: str) -> str:
    """Extract a flag string from text output. Returns 'unknown' if not found."""
    # Match patterns like: "Flag: flag{...}" or "flag{...}"
    match = re.search(r"flag\{[a-zA-Z0-9_\-!@#$%^&*()+=]+\}", text)
    if match:
        return match.group(0)
    return "unknown"


def _generate_default_flag(scenario_id: str) -> str:
    """Generate a placeholder flag when the real one can't be extracted."""
    import hashlib
    suffix = hashlib.md5(scenario_id.encode()).hexdigest()[:8]
    return f"flag{{{scenario_id}-{suffix}}}"
