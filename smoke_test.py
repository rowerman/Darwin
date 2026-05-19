"""Quick smoke test — run DARWIN against a local target."""
import asyncio
import sys
import logging
from darwin.orchestrator import Orchestrator
from darwin.utils.llm import LLMSession
from darwin.tools.mcp_client import load_mcp_config

# Enable info-level logging so recon progress is visible
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    datefmt="%H:%M:%S",
)


async def main():
    target = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8080"

    print(f"Target: {target}")
    print("Loading LLM config from config/llm.yaml ...")

    llm = LLMSession.from_config(profile="default", config_path="config/llm.yaml")
    print(f"Provider: {llm.provider}, Model: {llm.model}")

    # Check MCP servers
    mcp_configs = load_mcp_config("config/mcp_servers.yaml")
    enabled = [c.name for c in mcp_configs if c.enabled]
    if enabled:
        print(f"MCP servers:    {', '.join(enabled)}")
    else:
        print("MCP servers:    (none enabled in config/mcp_servers.yaml)")

    orch = Orchestrator(llm_session=llm, time_budget=600, token_budget=200000)
    print("Starting penetration test ...\n")

    result = await orch.run(
        task_description="Find and capture the flag from the target web application.",
        target_url=target,
    )

    # ── Recon summary from DKG ────────────────────────────────────
    hosts = orch.dkg.query_nodes("Host")
    services = orch.dkg.query_nodes("Service")
    endpoints = orch.dkg.query_nodes("Endpoint")
    vulns = orch.dkg.query_nodes("Vulnerability")
    flags = orch.dkg.query_nodes("Flag")

    if hosts:
        print(f"\nHosts discovered:    {len(hosts)}")
    if services:
        print(f"Services discovered:  {len(services)}")
        for svc in services[:10]:
            port = svc.get("port", "?")
            version = svc.get("version", "") or svc.get("banner", "") or ""
            proto = svc.get("protocol", "")
            if port and port != 0:
                print(f"  - port {port}/{proto} {version}".strip())
    if endpoints:
        print(f"Endpoints discovered: {len(endpoints)}")
        for ep in endpoints[:10]:
            print(f"  - {ep.get('url', ep.get('id', '?'))}")
        if len(endpoints) > 10:
            print(f"  ... and {len(endpoints) - 10} more")
    if vulns:
        print(f"Vulnerabilities found: {len(vulns)}")
    if flags:
        print(f"Flags found:          {len(flags)}")

    # Show MCP tools discovered
    mcp_tools = orch.mcp_pool.get_tool_names()
    if mcp_tools:
        print(f"\nMCP tools available: {len(mcp_tools)}")

    print(f"\n{'='*50}")
    print(f"Success:        {result.success}")
    print(f"Flag:           {result.flag or '(none)'}")
    print(f"Steps:          {result.steps}")
    print(f"Tokens used:    {result.tokens_used}")
    print(f"Time elapsed:   {result.time_elapsed:.1f}s")
    print(f"Defense found:  {result.defense_detected}")
    print(f"WAF bypassed:   {result.waf_bypassed}")
    if result.error:
        print(f"Error:          {result.error}")
    print(f"{'='*50}")


if __name__ == "__main__":
    asyncio.run(main())
