# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

DARWIN is an LLM-driven adaptive penetration testing agent framework. Two core innovations:

- **Defense Perception (DPM)**: Detects WAF/Cloak/Honey/Trap and triggers bypass strategies. All SOTA frameworks score 0% on PACEBench D-CVE (WAF scenarios).
- **Dynamic Scaling (B dimension)**: Simple single-host vulns use Solo Mode (0 sub-agents); complex multi-host scenarios auto-spawn ReconAgent/ExploitAgent/PivotAgent.
- **DKG communication**: Sub-agents communicate only via structured Dynamic Knowledge Graph, never natural language.
- **CTEG cross-task learning**: Abstract bypass/exploit patterns accumulated across challenges, with time-based decay.

## Commands

```bash
# Install (run from repo root)
pip install -e ".[dev]"

# Browser verification layer (DAVE L2)
playwright install chromium

# Run pilot experiment (single PACEBench D-CVE challenge)
python experiments/runner.py

# Start PACEBench adapter server (port 8000)
python benchmarks/pacebench_adapter.py

# Run tests (when added)
pytest
```

**External tool dependencies**: The reconnaissance and attack tools wrap CLI commands. These must be installed on the host for the corresponding tools to work:
- `nmap`, `dirb`, `whatweb`, `curl` (recon)
- `sqlmap`, `ffuf`, `sshpass` (attack/pivot)

## Architecture

### Core data flow

```
Orchestrator.run() → recon → analyze → exploit → bypass → verify
                         ↓        ↓          ↓         ↓
                        DKG      LLM     DPM+DAVE   DAVE(L1-L4)
```

### Module roles

| Module | Role |
|--------|------|
| `orchestrator.py` | Main loop: Solo mode directly executes tools. Also contains `_run_coordinated_cycle` and `_run_distributed_cycle` methods (not yet wired into the main `run()` flow). |
| `dkg.py` | Dynamic Knowledge Graph (NetworkX MultiDiGraph). Thread-safe. 8 node types, 9 edge types. All agent communication flows through DKG nodes. |
| `dpm.py` | Defense Perception Module. 3-layer detection: rule-based filter analysis → WAF signature matching → LLM classifier (only when confidence < 0.8). Outputs a `DefenseStateVector`. |
| `dynamic_scaling.py` | TDI'' formula (`0.20*H + 0.20*(1-E) + 0.10*C + 0.10*(1-S) + 0.15*D + 0.25*B`). B dimension determines Solo/Coordinated/Distributed via hysteresis voting. |
| `dave.py` | 4-layer verification: L1 HTTP response, L2 Playwright browser, L3 defense integrity (payload modification), L4 impact confirmation (flag extraction + honeypot detection). |
| `cteg.py` | Cross-Task Experience Graph. Stores abstract `BypassPattern` and `ExploitPattern` nodes with half-life decay. `commit_task()` extracts patterns from completed `TaskRecord`. |
| `sub_agents/base.py` | `BaseSubAgent` with Plan→Act→Observe loop. `SubAgentPool` manages concurrent agents. 10 lifecycle states. |
| `sub_agents/recon_agent.py` | Whatweb→dirb→curl workflow. Writes discovered Endpoints/Services to DKG. |
| `sub_agents/exploit_agent.py` | SQLi/XSS/CMDi exploitation with integrated defense bypass. Uses DAVE for verification. |
| `sub_agents/pivot_agent.py` | Credential reuse, SSH key testing, internal host discovery. |
| `tools/mcp_gateway.py` | Tool registry with OpenAI function-calling format export. Supports both Python functions and shell command templates. |
| `tools/recon_server.py` | nmap, dirb, curl, whatweb tool registrations with output parsers. |
| `tools/attack_server.py` | sqlmap, ffuf, send_payload, xss_reflection_test, command_injection_test. |
| `utils/llm.py` | LiteLLM wrapper with conversation history, token counting, and `LLMFunctionMapping` for auto-converting Python functions to tool definitions. |
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

## What is wired vs planned

**Wired and functional:**
- Solo Mode orchestrator loop (recon → analyze → exploit → bypass → verify)
- DKG with all node/edge types and persistence
- DPM 3-layer detection pipeline
- DAVE 4-layer verification
- All 5 system prompt templates
- All recon and attack tools registered
- PACEBench adapter (FastAPI server)
- Experiment runner with metrics computation
- Statistical analysis (McNemar, paired t-test, Friedman, bootstrap, Cohen's κ)
- CTEG pattern storage and retrieval

**Not yet integrated:**
- Coordinated/Distributed modes exist as methods on Orchestrator but are not called from the main `run()` flow — currently always runs Solo
- CTEG is not called from the Orchestrator during task execution (no `commit_task()` or `get_suggestions()` calls)
- No actual test files exist (pytest is in dev dependencies but unused)
- Custom Defense benchmark (20 Docker challenges) not yet built
- No external baseline runner adapters (PentestAgent/ClaudeCode)
- `experiments/failure_analysis.py` not yet created
- `experiments/baselines/` directory empty

## Configuration

- `config/darwin.yaml`: Time/token budgets, solo mode limits, defense probe settings, browser config
- `config/llm.yaml`: Three LLM profiles — `default` (gpt-4o), `reasoning` (claude-sonnet-4), `classifier` (gpt-5-nano). API key via `${LLM_API_KEY}` env var.
- `config/waf_fingerprints.yaml`: ModSecurity, Cloudflare, Naxsi, Coraza signatures with detection rules and bypass hints

## Flag format

`flag{...}` — matched by regex `flag\{[a-zA-Z0-9_\-!@#$%^&*()+=]+\}` across orchestrator, DAVE, base sub-agent, and exploit agent modules. Honeypot flags like `flag{test}`, `flag{example}`, `flag{honeypot}` etc. are rejected by DAVE L4.
