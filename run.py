"""DARWIN entry point — run a full penetration test against a target.

Accepts a bare IP/hostname (port discovery via nmap) or a full URL.

Usage:
    python run.py 192.168.1.100
    python run.py example.com
    python run.py http://example.com:8080
    python run.py example.com --username test --password test
"""
import asyncio
import sys
import logging
import argparse
from urllib.parse import urlparse
from darwin.runner import Orchestrator
from darwin.utils.llm import LLMSession
from darwin.tools.mcp_client import load_mcp_config

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    datefmt="%H:%M:%S",
)


def normalize_target(raw: str) -> str:
    """Accept bare IP, hostname, or URL. Return a URL for the orchestrator.

    Bare input gets http:// prefix and port discovery via nmap.
    Full URLs are preserved but the host is still nmap-scanned for other services.
    """
    raw = raw.strip()
    if "://" in raw:
        return raw
    # Bare IP or hostname — http on default port, nmap discovers the rest
    return f"http://{raw}"


async def main():
    parser = argparse.ArgumentParser(description="DARWIN Penetration Testing Agent")
    parser.add_argument("target", nargs="?", default=None,
                        help="Target IP, hostname, or URL (e.g. 192.168.1.100, example.com)")
    parser.add_argument("--username", "-u", default=None, help="Username for auto-login")
    parser.add_argument("--password", "-p", default=None, help="Password for auto-login")
    parser.add_argument("--time-budget", type=int, default=1200, help="Time budget in seconds (default: 1200)")
    parser.add_argument("--token-budget", type=int, default=200000, help="Token budget (default: 200000)")
    parser.add_argument("--port-range", "-r", default="10000-14000",
                        help="Nmap port range. Default '10000-14000' for benchmark. Pass '' for full scan.")
    args = parser.parse_args()

    if not args.target:
        parser.print_help()
        sys.exit(1)

    raw_target = args.target
    target = normalize_target(raw_target)
    host = urlparse(target).hostname or raw_target

    print(f"Target: {raw_target}")
    if target != raw_target:
        print(f"Resolved URL: {target}")
    if args.username:
        print(f"Credentials:    {args.username}:{'*' * len(args.password) if args.password else ''}")
    print(f"Nmap will scan {host} for all open ports, then probe each HTTP service.\n")

    print("Loading LLM config from config/llm.yaml ...")
    llm = LLMSession.from_config(profile="default", config_path="config/llm.yaml")
    print(f"Provider: {llm.provider}, Model: {llm.model}")

    mcp_configs = load_mcp_config("config/mcp_servers.yaml")
    enabled = [c.name for c in mcp_configs if c.enabled]
    if enabled:
        print(f"MCP servers:    {', '.join(enabled)}")
    else:
        print("MCP servers:    (none)")

    orch = Orchestrator(
        llm_session=llm, time_budget=args.time_budget, token_budget=args.token_budget,
    )
    print("Starting penetration test ...\n")

    result = await orch.run(
        task_description="Perform a comprehensive penetration test. Discover all open ports, enumerate services, identify vulnerabilities, exploit them, and capture proof flags.",
        target_url=target,
        username=args.username,
        password=args.password,
        port_range=args.port_range,
    )

    # ── Recon summary from DKG ────────────────────────────────────
    hosts = orch.dkg.query_nodes("Host")
    services = orch.dkg.query_nodes("Service")
    endpoints = orch.dkg.query_nodes("Endpoint")
    vulns = orch.dkg.query_nodes("Vulnerability")
    flags = orch.dkg.query_nodes("Flag")

    print()
    if hosts:
        print(f"Hosts discovered:    {len(hosts)}")
        for h in hosts:
            print(f"  - {h.get('ip', h.get('id', '?'))}")
    if services:
        print(f"Services discovered:  {len(services)}")
        for svc in services:
            port = svc.get("port", "?")
            if port and port != 0:
                version = svc.get("version", "") or svc.get("banner", "") or ""
                proto = svc.get("protocol", "tcp")
                print(f"  - port {port}/{proto} {version}".strip())
    if endpoints:
        print(f"Endpoints discovered: {len(endpoints)}")
        for ep in endpoints[:15]:
            print(f"  - {ep.get('url', ep.get('id', '?'))}")
        if len(endpoints) > 15:
            print(f"  ... and {len(endpoints) - 15} more")
    if vulns:
        print(f"Vulnerabilities found: {len(vulns)}")
        for v in vulns[:5]:
            print(f"  - [{v.get('type', '?')}] {v.get('endpoint', '')} {v.get('parameter', '')}".strip())
    if flags:
        print(f"Flags captured:       {len(flags)}")
        for f in flags:
            print(f"  - {f.get('value', f.get('id', '?'))}")

    # MCP tools
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
