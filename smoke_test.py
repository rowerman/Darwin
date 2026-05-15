"""Quick smoke test — run DARWIN against a local target."""
import asyncio
import sys
from darwin.orchestrator import Orchestrator
from darwin.utils.llm import LLMSession
from darwin.tools.mcp_client import load_mcp_config, MCPClientPool


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

    orch = Orchestrator(llm_session=llm, time_budget=300, token_budget=100000)
    print("Starting penetration test ...\n")

    result = await orch.run(
        task_description="Find and capture the flag from the target web application.",
        target_url=target,
    )

    # Show MCP tools discovered
    mcp_tools = orch.mcp_pool.get_tool_names()
    if mcp_tools:
        print(f"MCP tools found: {len(mcp_tools)} ({', '.join(sorted(mcp_tools)[:10])})")

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
