# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

DARWIN is an LLM-driven adaptive penetration testing agent framework. Two core innovations:

- **Defense Perception (DPM)**: Detects WAF/Cloak/Honey/Trap and triggers bypass strategies. All SOTA frameworks score 0% on PACEBench D-CVE (WAF scenarios).
- **Dynamic Scaling (B dimension)**: B = 0.30×N_norm + 0.15×M_domain + 0.20×L_move + 0.20×V_diversity + 0.15×D_present. Simple single-host vulns use Solo Mode (0 sub-agents); complex multi-host/WAF scenarios auto-spawn ReconAgent/ExploitAgent/PivotAgent via persistent pool.
- **DKG communication**: Sub-agents communicate only via structured Dynamic Knowledge Graph with asyncio.Event notifications, never natural language.
- **CTEG cross-task learning**: Abstract bypass/exploit patterns accumulated across challenges, with time-based decay.
- **LangGraph integration**: Optional ReAct loop (observe→plan→act→evaluate) via LangGraph StateGraph with checkpointing.

## Commands

```bash
# Activate virtual environment (prerequisite for all commands below)
source venv/bin/activate

# Install (run from repo root)
pip install -e ".[dev]"

# Browser verification layer (DAVE L2)
playwright install chromium

# Run against a target (main entry point)
python run.py <target>                    # IP, hostname, or URL
python run.py example.com --username admin --password pass123

# Quick smoke test against a local target
python smoke_test.py [target_url]         # defaults to http://localhost:8080

# Run all tests
pytest tests/ -v

# Run a single test file
pytest tests/test_dkg.py -v

# Run tests with coverage
pytest tests/ -v --cov=darwin --cov=experiments --cov-report=term

# Run pilot experiment (single PACEBench D-CVE challenge)
python experiments/runner.py

# Start PACEBench adapter server (port 8000)
python benchmarks/pacebench_adapter.py

# Start XBOW adapter server
python benchmarks/xbow_adapter.py
```

**External tool dependencies**: The reconnaissance and attack tools wrap CLI commands. These must be installed on the host for the corresponding tools to work:
- `nmap`, `dirb`, `whatweb`, `curl` (recon)
- `sqlmap`, `ffuf`, `sshpass` (attack/pivot)

The orchestrator checks for these at startup and warns if any are missing.

## Architecture

### Core data flow

```
Orchestrator.run() → recon → analyze → exploit → bypass → verify
                         ↓        ↓          ↓         ↓
                        DKG      LLM     DPM+DAVE   DAVE(L1-L4)
```

The `run()` method (orchestrator.py:180) follows this linear phase pipeline for Solo mode. For Coordinated/Distributed modes, it dispatches to `_run_coordinated_cycle()` or `_run_distributed_cycle()` based on the B dimension threshold from `dynamic_scaling.py`.

### Module roles

| Module | Role |
|--------|------|
| `orchestrator.py` | Main loop: Solo mode directly executes tools. Also contains `_run_coordinated_cycle` and `_run_distributed_cycle` methods, dispatched from `run()` based on B threshold. |
| `dkg.py` | Dynamic Knowledge Graph (NetworkX MultiDiGraph). Thread-safe. 8 node types, 9 edge types. All agent communication flows through DKG nodes. v2: asyncio.Event notification per node type for real-time coordination. |
| `dpm.py` | Defense Perception Module. 3-layer detection: rule-based filter analysis → WAF signature matching → LLM classifier (only when confidence < 0.8). Outputs a `DefenseStateVector`. |
| `dynamic_scaling.py` | TDI'' formula (`0.20*H + 0.20*(1-E) + 0.10*C + 0.10*(1-S) + 0.15*D + 0.25*B`). B dimension determines Solo/Coordinated/Distributed via hysteresis voting. |
| `dave.py` | 4-layer verification: L1 HTTP response, L2 Playwright browser, L3 defense integrity (payload modification), L4 impact confirmation (flag extraction + honeypot detection). |
| `cteg.py` | Cross-Task Experience Graph. Stores abstract `BypassPattern` and `ExploitPattern` nodes with half-life decay. Called from orchestrator via `commit_task()` (after each task) and `get_suggestions()` (during analyze phase). |
| `sub_agents/base.py` | `BaseSubAgent` with Plan→Act→Observe loop. `SubAgentPool` manages concurrent agents. 10 lifecycle states. |
| `sub_agents/recon_agent.py` | Whatweb→dirb→curl workflow. Writes discovered Endpoints/Services to DKG. |
| `sub_agents/exploit_agent.py` | SQLi/XSS/CMDi exploitation with integrated defense bypass. Uses DAVE for verification. |
| `sub_agents/pivot_agent.py` | Credential reuse, SSH key testing, internal host discovery. |
| `tools/mcp_gateway.py` | Tool registry with OpenAI function-calling format export. Supports both Python functions and shell command templates. |
| `tools/mcp_client.py` | MCP client for connecting to external MCP servers (configured in `config/mcp_servers.yaml`). |
| `tools/recon_server.py` | nmap, dirb, curl, whatweb tool registrations with output parsers. |
| `tools/attack_server.py` | sqlmap, ffuf, send_payload, xss_reflection_test, command_injection_test. |
| `knowledge/` | JSON knowledge base files (`web_vulnerabilities.json`, `advanced_exploitation.json`) with exploit patterns for common vulnerability types. |
| `utils/llm.py` | LiteLLM wrapper with conversation history, token counting, context compression (`compress()` method), and `LLMFunctionMapping` for auto-converting Python functions to tool definitions. |
| `utils/http_client.py` | Async HTTP client (aiohttp) with A-E WAF probe classes and baseline comparison. `ProbeClient` extends `HTTPClient`. |

### Three operating modes

| Mode | B threshold | Sub-agents | Use case |
|------|------------|------------|----------|
| Solo | B < 0.3 | 0 | Single-host web vulns (XBOW simple) |
| Coordinated | 0.3 ≤ B < 0.6 | 1-2 | Multi-service exploit chains |
| Distributed | B ≥ 0.6 | 3+ | Multi-host lateral movement |

### B dimension formula

`B = 0.4 * N_norm + 0.3 * M_domain + 0.3 * L_move`

Where N_norm = min(n_hosts/5, 1.0), M_domain = 1 if >1 domain, L_move = 1 if lateral movement needed.

**Note**: `compute_task_breadth()` is duplicated in both `dkg.py:196` and `dynamic_scaling.py:117`. They are identical; `dynamic_scaling.py`'s version is the canonical one (the DKG method delegates to the same logic).

## Key design decisions

1. **Single vs Multi-Agent**: Not fixed. B dimension drives dynamic scaling. Simple = Solo (zero overhead), complex = spawn sub-agents.
2. **Agent communication**: 100% through structured DKG (nodes + edges). Never natural language chat between agents.
3. **Defense detection**: Three-layer cascade (rule → signature → LLM), LLM only called for low-confidence cases to save cost.
4. **Only generic baselines kept**: AWE/Cochise/VulnBot could only adapt to partial benchmarks — removed. Only Claude Code and PentestAgent remain as baselines.
5. **Web benchmarks only**: CyberGym (binary) and GOADv3 (AD) removed — PentestAgent can't handle them, so unfair comparison.
6. **ADAgent/PersistAgent removed**: No corresponding benchmark = no evaluation scenario.
7. **Context compression, not hard reset**: When conversation history approaches the token limit (default: 40% of 180K), `LLMSession.compress()` summarizes older messages via a dedicated LLM call. This preserves key facts/actions/state while reducing token usage, enabling the agent to continue operating rather than silently failing. SubAgents compress independently (dedicated LLM sessions). The DKG carries structured state across phase boundaries; LLM conversation compression handles within-phase tool call chains.

## What is wired vs planned

**Wired and functional:**
- Solo Mode orchestrator loop (recon → analyze → exploit → bypass → verify)
- Coordinated and Distributed modes dispatched from `run()` based on dynamic scaling B threshold
- Persistent multi-agent system (`_run_multi_agent_cycle`) with incremental agent spawning + DKG monitor
- DKG notification mechanism (asyncio.Event per node type) for real-time agent coordination
- LangGraph ReAct sub-agent loop (`run_with_langgraph`) with observe→plan→act→evaluate StateGraph
- CTEG commit_task() and get_suggestions() integrated into orchestrator
- DKG with all node/edge types and persistence (checkpoints saved to `checkpoints/` directory)
- DPM 3-layer detection pipeline
- DAVE 4-layer verification
- All 5 system prompt templates (in `darwin/orchestrator.py` and `darwin/prompts/`)
- All recon and attack tools registered
- PACEBench adapter (FastAPI server) at `benchmarks/pacebench_adapter.py`
- XBOW adapter at `benchmarks/xbow_adapter.py`
- Custom Defense benchmark runner at `benchmarks/custom_defense/runner.py` with 20 local challenges (no Docker needed)
- Local WAF server at `benchmarks/local_waf/waf_server.py`
- Experiment runner with metrics computation
- Statistical analysis (McNemar, paired t-test, Friedman, bootstrap, Cohen's κ)
- PentestAgent baseline adapter in `experiments/baselines/pentest_agent.py`
- CTEG state persistence to `cteg_state.json`
- Knowledge base: `knowledge/web_vulnerabilities.json` and `knowledge/advanced_exploitation.json`
- Context compression: `LLMSession.compress()` summarizes older conversation history via a dedicated LLM call when `context_load` exceeds `compression_threshold` (default 0.4). Orchestrator calls `_maybe_compress()` before each LLM interaction and in the exploit loop; SubAgents call it before plan generation and replanning. Falls back to keyword-based truncation if the compression LLM call fails.
- Design docs: `docs/context-compression.md`, `plan/DARWIN_framework.md`, `plan/DARWIN_implementation_plan.md`, `BENCHMARK_IMAGES.md`

**Not yet integrated:**
- `experiments/comparative_runner.py` (planned in `darwin-experiment-automation.md`) not yet created
- No external baseline runner adapters beyond PentestAgent (no ClaudeCode adapter)
- `experiments/failure_analysis.py` not yet created
- `paper_analysis/` directory referenced by README doesn't exist yet

## Configuration

**Important**: The `config/` directory is in `.gitignore` (it contains API keys). On a fresh checkout, you must create these files manually or obtain them from a secure source.

- `config/darwin.yaml`: Time/token budgets, solo mode limits, defense probe settings, browser config. Also defines `max_context_tokens` (180000) and `context_compression_threshold` (0.4) for the compression trigger.
- `config/llm.yaml`: Three LLM profiles — `default`, `reasoning`, `classifier`. API key can be set in the file or via `${PROVIDER}_API_KEY` env var (e.g., `OPENAI_API_KEY`, `DEEPSEEK_API_KEY`). Set `api_key: ""` to use the env var instead of a hardcoded key.
- `config/waf_fingerprints.yaml`: ModSecurity, Cloudflare, Naxsi, Coraza signatures with detection rules and bypass hints
- `config/mcp_servers.yaml`: MCP server configurations for optional external tool servers

## Flag format

`flag{...}` — matched by regex `flag\{[a-zA-Z0-9_\-!@#$%^&*()+=]+\}` across orchestrator, DAVE, base sub-agent, and exploit agent modules. Honeypot flags like `flag{test}`, `flag{example}`, `flag{honeypot}` etc. are rejected by DAVE L4.
