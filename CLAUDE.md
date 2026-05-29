# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

**When debugging experiment failures or modifying DARWIN core modules, load the darwin-experiment-driven-dev skill first.**

DARWIN is an LLM-driven adaptive penetration testing agent framework. Two core innovations:

- **Defense Perception (DPM)**: Detects WAF/Cloak/Honey/Trap and triggers bypass strategies. All SOTA frameworks score 0% on PACEBench D-CVE (WAF scenarios).
- **Dynamic Scaling (B dimension)**: Simple single-host vulns use Solo Mode (0 sub-agents); complex multi-host/WAF scenarios auto-spawn ReconAgent/ExploitAgent/PivotAgent. See B dimension formula section below.
- **DKG communication**: Sub-agents communicate only via structured Dynamic Knowledge Graph with asyncio.Event notifications, never natural language.
- **CTEG cross-task learning**: Dynamic bypass/exploit patterns accumulated across challenges, with time-based decay (static knowledge is handled separately by DarwinRAG).
- **DarwinRAG static knowledge**: 108 curated entries across 4 domain collections (web, windows_ad, cloud, network). SentenceTransformer `all-MiniLM-L6-v2` (384-dim) + Faiss IndexFlatIP with TfidfVectorizer fallback.
- **LangGraph integration**: ReAct loop (observe→plan→act→evaluate) via LangGraph StateGraph with checkpointing. SubAgentPool defaults to LangGraph.
- **Prompt architecture (Layer 0)**: All system prompts live in `darwin/prompts/` as templated Python strings with `.format()` substitution, separated from agent logic.

## Commands

Requires Python >=3.10. Dependencies are in `pyproject.toml`.

```bash
# Activate virtual environment (prerequisite for all commands below)
source venv/bin/activate

# Install
pip install -e ".[dev]"

# Browser verification layer (DAVE L2)
playwright install chromium

# Run against a target (main entry point)
python run.py <target>                    # IP, hostname, or URL
python run.py example.com --username admin --password pass123

# Quick smoke test against a local target
python smoke_test.py [target_url]         # defaults to http://localhost:8080

# Run all tests (pytest-asyncio with asyncio_mode=auto — no @pytest.mark.asyncio needed)
pytest tests/ -v

# Run a single test file
pytest tests/test_dkg.py -v

# Run a single test function
pytest tests/test_dkg.py::test_function_name -v

# Run tests with coverage
pytest tests/ -v --cov=darwin --cov=experiments --cov-report=term

# Run pilot experiment (single PACEBench D-CVE challenge)
python experiments/runner.py

# Start PACEBench adapter server (port 8000)
python benchmarks/pacebench_adapter.py

# Start XBOW adapter server
python benchmarks/xbow_adapter.py

# Knowledge ingestion (import .json or .md files into DarwinRAG)
python tools/ingest_knowledge.py --file <path>                  # single file
python tools/ingest_knowledge.py --dir <path>                   # directory recursively
python tools/ingest_knowledge.py --file <path> --collection <c> # explicit collection
python tools/ingest_knowledge.py --stats                        # show collection sizes
python tools/ingest_knowledge.py --rebuild                      # rebuild all indices
python tools/ingest_knowledge.py --model-dir <path>             # custom model path

# Convert external knowledge sources to DARWIN format
python tools/convert_knowledge.py --source <path> --output <path> --category <c>
```

**API keys**: Set via env var (preferred) or in `config/llm.yaml` with `api_key: ""`. Env vars by provider:

| Provider   | Env Var              |
|-----------|----------------------|
| openai    | `OPENAI_API_KEY`     |
| anthropic | `ANTHROPIC_API_KEY`  |
| deepseek  | `DEEPSEEK_API_KEY`   |
| gemini    | `GEMINI_API_KEY`     |

**External tool dependencies**: The reconnaissance and attack tools wrap CLI commands. These must be installed on the host:
- `nmap`, `dirb`, `whatweb`, `curl` (recon)
- `sqlmap`, `ffuf`, `sshpass` (attack/pivot)
- `netexec`, `impacket-secretsdump`, `impacket-psexec`, `impacket-wmiexec`, `ldapsearch` (AD agent)
- `kubectl`, `capsh` (cloud/K8s agent)

Additional Python dependencies for RAG: `sentence-transformers`, `faiss-cpu` (or `faiss-gpu`).

The orchestrator checks for required CLI tools at startup and warns if any are missing.

## Architecture

### Core data flow

```
Orchestrator.run() → recon → analyze → exploit → bypass → verify
                         ↓        ↓          ↓         ↓
                        DKG      LLM     DPM+DAVE   DAVE(L1-L4)
```

The `run()` method (orchestrator.py:181) follows this linear phase pipeline for Solo mode. For Coordinated/Distributed modes, it dispatches to `_run_multi_agent_cycle()` (orchestrator.py:5129) based on the B dimension threshold from `dynamic_scaling.py`.

### Module roles

| Module | Role |
|--------|------|
| `orchestrator.py` | Main loop: Solo mode directly executes tools. `_run_multi_agent_cycle()` handles Coordinated and Distributed modes. |
| `dkg.py` | Dynamic Knowledge Graph (NetworkX MultiDiGraph). Thread-safe. 8 node types, 9 edge types. All agent communication flows through DKG. v2: asyncio.Event per node type for real-time coordination. |
| `dpm.py` | Defense Perception Module. 3-layer detection: rule-based filter analysis → WAF signature matching → LLM classifier (only when confidence < 0.8). Outputs `DefenseStateVector`. |
| `dynamic_scaling.py` | `TaskDifficultyAssessor` tracks TDI'' difficulty with per-component smoothing; `ScalingStateMachine` maps B to Solo/Coordinated/Distributed via hysteresis voting (2 votes to switch). |
| `dave.py` | 4-layer verification: L1 HTTP response, L2 Playwright browser, L3 defense integrity (payload modification), L4 impact confirmation (flag extraction + honeypot detection). |
| `cteg.py` | Cross-Task Experience Graph — **dynamic patterns only**. Stores `BypassPattern` and `ExploitPattern` nodes with half-life decay. Static knowledge uses DarwinRAG. |
| `rag.py` | DarwinRAG — **static knowledge RAG**. Multi-collection Faiss + SentenceTransformer with TfidfVectorizer fallback. 108 entries across 4 domain collections. Singleton via `get_rag()`. |
| `knowledge_base.py` | **Deprecated**. Inverted-index keyword search. Superseded by DarwinRAG. |
| `sub_agents/base.py` | `BaseSubAgent` with Plan→Act→Observe loop. `SubAgentPool` manages concurrent agents with 10 lifecycle states. |
| `sub_agents/recon_agent.py` | Whatweb→dirb→curl workflow. Writes discovered Endpoints/Services to DKG. |
| `sub_agents/exploit_agent.py` | SQLi/XSS/CMDi exploitation with integrated defense bypass and DAVE verification. |
| `sub_agents/pivot_agent.py` | Credential reuse, SSH key testing, internal host discovery. |
| `sub_agents/ad_agent.py` | Active Directory pentesting: domain enumeration, Kerberoasting, Pass-the-Hash, DCSync, Golden/Silver Ticket. |
| `sub_agents/cloud_agent.py` | Cloud/K8s pentesting: pod enumeration, RBAC abuse, container escape, cloud metadata (IMDS) access. |
| `data_model.py` | Typed dataclasses (`EndpointInfo`, `ServiceInfo`, `VulnerabilityInfo`, `HostInfo`, `CredentialInfo`) for normalizing data exchange between phases. `normalize_dkg_state()` / `to_prompt_context()`. |
| `darwin/tools/mcp_gateway.py` | Tool registry with OpenAI function-calling format export. Supports Python functions and shell command templates. |
| `darwin/tools/mcp_client.py` | MCP client for external MCP servers (configured in `config/mcp_servers.yaml`). |
| `darwin/tools/recon_server.py` | 10 recon tools: nmap, masscan, whatweb, dirb, gobuster, nikto, curl GET/POST, form_extract, try_login, idor_header_test. |
| `darwin/tools/attack_server.py` | 16 attack tools: sqlmap, ffuf, send_payload, xss_reflection_test, command_injection_test, hydra, searchsploit, smbmap, cve_lookup, metasploit_search, knowledge_search, etc. |
| `darwin/prompts/` | System prompt templates for Orchestrator (all 5 phases), ReconAgent, ExploitAgent, PivotAgent, ADAgent, CloudAgent, and DPM classifier. `.format()` substitution. |
| `knowledge/` | 108 curated knowledge entries: `web/` (17), `windows_ad/` (11), `cloud/` (74), `network/` (6). Loaded by DarwinRAG at startup. |
| `utils/llm.py` | LiteLLM wrapper with conversation history, token counting, context compression (`compress()` method), and `LLMFunctionMapping`. |
| `utils/http_client.py` | Async HTTP client (aiohttp) with A-E WAF probe classes and baseline comparison. `ProbeClient` extends `HTTPClient`. |
| `experiments/` | `runner.py` (single PACEBench D-CVE challenge), `metrics.py` (TSR, Pass@k, token efficiency), `analysis.py` (McNemar, Friedman, bootstrap, Cohen's κ), `chain_runner.py` (multi-step chain from chain.yaml). |
| `benchmarks/` | PACEBench adapter, XBOW adapter, custom_defense runner (20 local challenges, no Docker), local WAF server. |

### Three operating modes

| Mode | B threshold | Sub-agents | Use case |
|------|------------|------------|----------|
| Solo | B < 0.3 | 0 | Single-host web vulns (XBOW simple) |
| Coordinated | 0.3 ≤ B < 0.6 | 1-2 | Multi-service exploit chains |
| Distributed | B ≥ 0.6 | 3+ | Multi-host lateral movement |

### B dimension formula

`B = 0.28 * N_norm + 0.12 * M_domain + 0.18 * L_move + 0.18 * V_diversity + 0.14 * D_present + 0.18 * env_complexity`

Where:
- `N_norm = min(n_services / 6.0, 1.0)` — number of distinct services (ports)
- `M_domain = 1.0 if multi-domain else 0.0`
- `L_move = 1.0 if lateral movement needed else 0.0`
- `V_diversity = min(len(vuln_types) / 5.0, 1.0)` — vulnerability type variety
- `D_present = 1.0 if defense_complexity > 0.1 else 0.0` — active defenses (WAF/Honey/Trap)
- `env_complexity = 1.0` for AD (SMB+LDAP), `0.8` for cloud (K8s API), `0.0` otherwise

Canonical implementation: `compute_task_breadth()` at `dynamic_scaling.py:118`.

## Key design decisions

1. **Dynamic scaling, not fixed single/multi-agent**: Simple targets use Solo mode (zero overhead); complex targets spawn sub-agents. Driven by B dimension with hysteresis voting.
2. **Agent communication**: 100% through structured DKG (nodes + edges). Never natural language chat between agents.
3. **Defense detection**: Three-layer cascade (rule → signature → LLM), LLM only for low-confidence cases to save cost.
4. **Context compression, not hard reset**: When history approaches token limit (default 40% of 180K), `LLMSession.compress()` summarizes older messages via LLM. SubAgents compress independently. DKG carries structured state across phase boundaries.
5. **RAG separation (CTEG vs DarwinRAG)**: CTEG = dynamic cross-task experience (patterns learned from actual runs). DarwinRAG = static reference knowledge (attack techniques, MITRE ATT&CK, CIS benchmarks). Orchestrator queries both independently and merges in the LLM prompt.
6. **DarwinRAG uses SentenceTransformer + Faiss**: Model at `/home/kianabin/utils/all-MiniLM-L6-v2` (384-dim). TfidfVectorizer fallback when model unavailable.
7. **Sub-agents use LLM-driven replanning**: After task failure, agents replan via LLM rather than just marking-and-skipping.
8. **ADAgent and CloudAgent**: Auto-spawned when domain/K8s infrastructure detected during recon. Not yet benchmarked separately.
9. **Baselines**: Only Claude Code and PentestAgent remain. AWE/Cochise/VulnBot removed (partial benchmark adaptation only). Non-web benchmarks (CyberGym, GOADv3) removed (PentestAgent incompatible).

## What is not yet integrated

- `experiments/comparative_runner.py` — not yet created
- No external baseline adapters beyond PentestAgent (no ClaudeCode adapter)
- `experiments/failure_analysis.py` — not yet created
- `paper_analysis/` directory — not yet created

## Configuration

**Important**: The `config/` directory is in `.gitignore` (contains API keys). On a fresh checkout, create these files manually or obtain from a secure source.

- `config/darwin.yaml`: Time/token budgets, solo mode limits, defense probe settings, browser config. `max_context_tokens` (180000) and `context_compression_threshold` (0.4).
- `config/llm.yaml`: Three LLM profiles — `default`, `reasoning`, `classifier`. Set `api_key: ""` to use env var instead of hardcoded key.
- `config/waf_fingerprints.yaml`: ModSecurity, Cloudflare, Naxsi, Coraza signatures with detection rules and bypass hints.
- `config/mcp_servers.yaml`: Optional MCP server configurations for external tool servers.

**Model path**: DarwinRAG loads SentenceTransformer from `/home/kianabin/utils/all-MiniLM-L6-v2` by default. Override via `DarwinRAG(model_dir=...)` or `--model-dir`.

## Flag format

`flag{...}` — matched by regex `flag\{[a-zA-Z0-9_\-!@#$%^&*()+=]+\}` across orchestrator, DAVE, base sub-agent, and exploit agent modules. Honeypot flags (`flag{test}`, `flag{example}`, `flag{honeypot}`, etc.) are rejected by DAVE L4.
