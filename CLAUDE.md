# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

DARWIN is an LLM-driven adaptive penetration testing agent framework. Two core innovations:

- **Defense Perception (DPM)**: Detects WAF/Cloak/Honey/Trap and triggers bypass strategies. All SOTA frameworks score 0% on PACEBench D-CVE (WAF scenarios).
- **Dynamic Scaling (B dimension)**: B = 0.30×N_norm + 0.15×M_domain + 0.20×L_move + 0.20×V_diversity + 0.15×D_present. Simple single-host vulns use Solo Mode (0 sub-agents); complex multi-host/WAF scenarios auto-spawn ReconAgent/ExploitAgent/PivotAgent via persistent pool. Mode selection uses hysteresis voting (2 consecutive votes to switch).
- **DKG communication**: Sub-agents communicate only via structured Dynamic Knowledge Graph with asyncio.Event notifications, never natural language.
- **CTEG cross-task learning**: Abstract bypass/exploit patterns accumulated across challenges, with time-based decay. Pure dynamic experience — static knowledge is handled by DarwinRAG.
- **DarwinRAG static knowledge**: 108 curated entries across 4 domain collections (web, windows_ad, cloud, network). SentenceTransformer `all-MiniLM-L6-v2` (384-dim) + Faiss IndexFlatIP for semantic search, TfidfVectorizer fallback. Multi-collection ETL pipeline matching container-pentester-agent's architecture. Three LLM integration paths: automatic context enrichment, on-demand `knowledge_search` tool, and plan generation injection.
- **LangGraph integration**: ReAct loop (observe→plan→act→evaluate) via LangGraph StateGraph with checkpointing. SubAgentPool defaults to LangGraph (`run_all(use_langgraph=True)`).
- **Prompt architecture (Layer 0)**: All system prompts live in `darwin/prompts/` as templated Python strings with `.format()` substitution. This separates prompt engineering from agent logic — `darwin/prompts/orchestrator.py`, `exploit_agent.py`, `recon_agent.py`, `pivot_agent.py`, `ad_agent.py`, `cloud_agent.py`, `dpm_classifier.py`.

## Commands

Requires Python >=3.10. Dependencies are in `pyproject.toml` (litellm, networkx, pydantic, aiohttp, fastapi, playwright, langgraph, etc.).

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
```

**External tool dependencies**: The reconnaissance and attack tools wrap CLI commands. These must be installed on the host for the corresponding tools to work:
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

The `run()` method (orchestrator.py:180) follows this linear phase pipeline for Solo mode. For Coordinated/Distributed modes, it dispatches to `_run_coordinated_cycle()` or `_run_distributed_cycle()` based on the B dimension threshold from `dynamic_scaling.py`.

### Module roles

| Module | Role |
|--------|------|
| `orchestrator.py` | Main loop: Solo mode directly executes tools. Also contains `_run_coordinated_cycle` and `_run_distributed_cycle` methods, dispatched from `run()` based on B threshold. |
| `dkg.py` | Dynamic Knowledge Graph (NetworkX MultiDiGraph). Thread-safe. 8 node types, 9 edge types. All agent communication flows through DKG nodes. v2: asyncio.Event notification per node type for real-time coordination. |
| `dpm.py` | Defense Perception Module. 3-layer detection: rule-based filter analysis → WAF signature matching → LLM classifier (only when confidence < 0.8). Outputs a `DefenseStateVector`. |
| `dynamic_scaling.py` | Two responsibilities: (1) `TaskDifficultyAssessor` tracks TDI'' difficulty (`0.20*H + 0.20*(1-E) + 0.10*C + 0.10*(1-S) + 0.15*D + 0.25*B`) with per-component smoothing; (2) `ScalingStateMachine` maps B to Solo/Coordinated/Distributed via hysteresis voting (2 votes to switch). |
| `dave.py` | 4-layer verification: L1 HTTP response, L2 Playwright browser, L3 defense integrity (payload modification), L4 impact confirmation (flag extraction + honeypot detection). |
| `cteg.py` | Cross-Task Experience Graph — **dynamic patterns only**. Stores `BypassPattern` and `ExploitPattern` nodes with half-life decay. Methods: `commit_task()`, `get_suggestions()`, `commit_attempt()`, `query_bypass_patterns()`, `query_exploit_patterns()`. Static knowledge methods removed — use DarwinRAG for that. |
| `rag.py` | DarwinRAG — **static knowledge RAG**. Multi-collection Faiss + SentenceTransformer (384-dim) with TfidfVectorizer fallback. 108 entries: web(17), windows_ad(11), cloud(74), network(6). Supports JSON + Markdown ingestion. Methods: `load()`, `search()`, `summarize()`, `add_documents()`, `ingest_file()`, `ingest_directory()`, `rebuild_indices()`. Singleton via `get_rag()`. Model at `/home/kianabin/utils/all-MiniLM-L6-v2`. |
| `knowledge_base.py` | **Deprecated**. Inverted-index keyword search. Only used as fallback in `knowledge_search` tool. Superseded by `DarwinRAG`. |
| `sub_agents/base.py` | `BaseSubAgent` with Plan→Act→Observe loop. `SubAgentPool` manages concurrent agents. 10 lifecycle states. |
| `sub_agents/recon_agent.py` | Whatweb→dirb→curl workflow. Writes discovered Endpoints/Services to DKG. |
| `sub_agents/exploit_agent.py` | SQLi/XSS/CMDi exploitation with integrated defense bypass. Uses DAVE for verification. |
| `sub_agents/pivot_agent.py` | Credential reuse, SSH key testing, internal host discovery. |
| `sub_agents/ad_agent.py` | Active Directory pentesting: domain enumeration, Kerberoasting, Pass-the-Hash, DCSync, Golden/Silver Ticket. Spawned by orchestrator when domain infrastructure detected. |
| `sub_agents/cloud_agent.py` | Cloud/K8s pentesting: pod enumeration, RBAC abuse, container escape, cloud metadata (IMDS) access. Spawned by orchestrator when K8s/cloud environments detected. |
| `tools/mcp_gateway.py` | Tool registry with OpenAI function-calling format export. Supports both Python functions and shell command templates. |
| `tools/mcp_client.py` | MCP client for connecting to external MCP servers (configured in `config/mcp_servers.yaml`). |
| `tools/recon_server.py` | nmap (standard + full + vulners), masscan, whatweb, dirb, gobuster, nikto, curl GET/POST, form_extract, try_login, idor_header_test tool registrations with output parsers. |
| `tools/attack_server.py` | sqlmap (with JSON body support), ffuf, send_payload, xss_reflection_test, command_injection_test, hydra (HTTP + SSH), searchsploit, smbmap, cve_lookup, metasploit_search. Also registers `knowledge_search` tool backed by DarwinRAG. |
| `tools/ingest_knowledge.py` | CLI tool for importing knowledge files (.json/.md) into DarwinRAG. Mirrors container-pentester-agent's `cmd/ingest`. Supports `--file`, `--dir`, `--collection`, `--stats`, `--rebuild`. |
| `darwin/prompts/` | System prompt templates for Orchestrator (all 5 phases), ReconAgent, ExploitAgent, PivotAgent, ADAgent, CloudAgent, and DPM classifier. Templates use `.format()` substitution for dynamic context injection. Prompts are in separate files per agent: `orchestrator.py`, `exploit_agent.py`, `recon_agent.py`, `pivot_agent.py`, `ad_agent.py`, `cloud_agent.py`, `dpm_classifier.py`. `__init__.py` is archived reference only. |
| `knowledge/` | 108 curated knowledge entries across 4 domain collections: `web/` (17 JSON), `windows_ad/` (11 JSON), `cloud/` (7 JSON + 70 .md from container-pentester-agent), `network/` (6 JSON). All loaded by DarwinRAG at startup. |
| `utils/llm.py` | LiteLLM wrapper with conversation history, token counting, context compression (`compress()` method), and `LLMFunctionMapping` for auto-converting Python functions to tool definitions. |
| `utils/http_client.py` | Async HTTP client (aiohttp) with A-E WAF probe classes and baseline comparison. `ProbeClient` extends `HTTPClient`. |

### Three operating modes

| Mode | B threshold | Sub-agents | Use case |
|------|------------|------------|----------|
| Solo | B < 0.3 | 0 | Single-host web vulns (XBOW simple) |
| Coordinated | 0.3 ≤ B < 0.6 | 1-2 | Multi-service exploit chains |
| Distributed | B ≥ 0.6 | 3+ | Multi-host lateral movement |

### B dimension formula

`B = 0.30 * N_norm + 0.15 * M_domain + 0.20 * L_move + 0.20 * V_diversity + 0.15 * D_present`

Where:
- `N_norm = min(n_targets / 5.0, 1.0)` — number of target hosts/services
- `M_domain = 1.0 if multi-domain else 0.0`
- `L_move = 1.0 if lateral movement needed else 0.0`
- `V_diversity = min(len(vuln_types) / 5.0, 1.0)` — vulnerability type variety
- `D_present = 1.0 if defense_complexity > 0.1 else 0.0` — active defenses (WAF/Honey/Trap)

`compute_task_breadth()` is in `dynamic_scaling.py:118` and is the single canonical implementation. Orchestrator imports it from there.

## Key design decisions

1. **Single vs Multi-Agent**: Not fixed. B dimension drives dynamic scaling. Simple = Solo (zero overhead), complex = spawn sub-agents.
2. **Agent communication**: 100% through structured DKG (nodes + edges). Never natural language chat between agents.
3. **Defense detection**: Three-layer cascade (rule → signature → LLM), LLM only called for low-confidence cases to save cost.
4. **Only generic baselines kept**: AWE/Cochise/VulnBot could only adapt to partial benchmarks — removed. Only Claude Code and PentestAgent remain as baselines.
5. **Web benchmarks only**: CyberGym (binary) and GOADv3 (AD) removed — PentestAgent can't handle them, so unfair comparison.
6. **ADAgent and CloudAgent added back**: Domain and K8s pentesting agents wired for multi-agent cycle detection. Currently used when domain/K8s infrastructure is detected during recon; not yet benchmarked separately.
7. **Context compression, not hard reset**: When conversation history approaches the token limit (default: 40% of 180K), `LLMSession.compress()` summarizes older messages via a dedicated LLM call. This preserves key facts/actions/state while reducing token usage, enabling the agent to continue operating rather than silently failing. SubAgents compress independently (dedicated LLM sessions). The DKG carries structured state across phase boundaries; LLM conversation compression handles within-phase tool call chains.
8. **RAG separation (CTEG vs DarwinRAG)**: CTEG handles only dynamic cross-task experience (BypassPattern, ExploitPattern learned from actual runs). DarwinRAG handles only static reference knowledge (attack techniques, MITRE ATT&CK, CIS benchmarks). No mixing — orchestrator queries both independently and merges in the LLM prompt. This matches container-pentester-agent's architecture where RAG and execution history are separate stores.
9. **DarwinRAG uses SentenceTransformer + Faiss**: Model at `/home/kianabin/utils/all-MiniLM-L6-v2` (384-dim). Falls back to TfidfVectorizer when model unavailable. Collections per domain: web, windows_ad, cloud, network. Knowledge format: JSON (DARWIN native) + Markdown (container-pentester-agent compatible, with `**元数据**:` metadata footer).

## What is wired vs planned

**Wired and functional:**
- Solo Mode orchestrator loop (recon → analyze → exploit → bypass → verify)
- Coordinated and Distributed modes dispatched from `run()` based on dynamic scaling B threshold
- Persistent multi-agent system (`_run_multi_agent_cycle`) with incremental agent spawning + DKG monitor
- AD agent auto-spawning when domain infrastructure detected (Domain Controller, LDAP, Kerberos)
- Cloud agent auto-spawning when K8s/container environments detected
- DKG notification mechanism (asyncio.Event per node type) for real-time agent coordination
- LangGraph ReAct sub-agent loop (`run_with_langgraph`) with observe→plan→act→evaluate StateGraph
- CTEG dynamic pattern learning: `commit_task()` for task completion, `get_suggestions()` for pre-execution hints, `commit_attempt()` for per-attempt feedback (wired in exploit_agent.py)
- DarwinRAG static knowledge: SentenceTransformer + Faiss multi-collection search, 108 entries across 4 domains, three LLM integration paths (auto-enrich, knowledge_search tool, plan injection), Markdown + JSON ingestion, `tools/ingest_knowledge.py` CLI
- CTEG/DarwinRAG separation: CTEG → dynamic only (BypassPattern/ExploitPattern), DarwinRAG → static only (knowledge files). No mixing.
- DKG with all node/edge types and persistence (checkpoints saved to `checkpoints/` directory)
- DPM 3-layer detection pipeline
- DAVE 4-layer verification
- All system prompt templates in `darwin/prompts/` for Orchestrator (5 phases), ReconAgent, ExploitAgent, PivotAgent, ADAgent, CloudAgent, and DPM classifier
- Sub-agent prompts with evaluate and replan variants for all agent types
- All recon and attack tools registered (26 tools in attack_server, 10 in recon_server)
- PACEBench adapter (FastAPI server) at `benchmarks/pacebench_adapter.py`
- XBOW adapter at `benchmarks/xbow_adapter.py`
- Custom Defense benchmark runner at `benchmarks/custom_defense/runner.py` with 20 local challenges (no Docker needed)
- Local WAF server at `benchmarks/local_waf/waf_server.py`
- Experiment runner with metrics computation
- Statistical analysis (McNemar, paired t-test, Friedman, bootstrap, Cohen's κ)
- PentestAgent baseline adapter in `experiments/baselines/pentest_agent.py`
- CTEG state persistence to `cteg_state.json`
- Context compression: `LLMSession.compress()` summarizes older conversation history via a dedicated LLM call when `context_load` exceeds `compression_threshold` (default 0.4). Orchestrator calls `_maybe_compress()` before each LLM interaction and in the exploit loop; SubAgents call it before plan generation and replanning. Falls back to keyword-based truncation if the compression LLM call fails.
- `LLMSession.add_context_message()` for injecting diagnostic/filter-debug reports into conversation history
- `ExploitAgent` accepts pre-fetched `cteg_hints` from orchestrator for plan generation
- Sub-agents use LLM-driven replanning after task failure (not just mark-and-skip)
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

**Model path**: DarwinRAG loads SentenceTransformer from `/home/kianabin/utils/all-MiniLM-L6-v2` by default. Override via `DarwinRAG(model_dir=...)` or `--model-dir` flag on `tools/ingest_knowledge.py`.

## Flag format

`flag{...}` — matched by regex `flag\{[a-zA-Z0-9_\-!@#$%^&*()+=]+\}` across orchestrator, DAVE, base sub-agent, and exploit agent modules. Honeypot flags like `flag{test}`, `flag{example}`, `flag{honeypot}` etc. are rejected by DAVE L4.
