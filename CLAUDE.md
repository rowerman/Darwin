# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

**When debugging experiment failures or modifying DARWIN core modules, load the darwin-experiment-driven-dev skill first.**

DARWIN is an LLM-driven adaptive penetration testing agent framework. Two core innovations:

- **Defense Perception (DPM)**: Detects WAF/Cloak/Honey/Trap and triggers bypass strategies. All SOTA frameworks score 0% on PACEBench D-CVE (WAF scenarios).
- **Dynamic Scaling (B dimension)**: Simple single-host vulns use Solo Mode (0 sub-agents); complex multi-host/WAF scenarios auto-spawn ReconAgent/ExploitAgent/PivotAgent. See B dimension formula section below.
- **DKG communication**: Sub-agents communicate only via structured Dynamic Knowledge Graph with asyncio.Event notifications, never natural language.
- **CTEG cross-task learning**: Dynamic bypass/exploit patterns accumulated across challenges, with time-based decay (static knowledge is handled separately by DarwinRAG).
- **DarwinRAG static knowledge**: 94 curated entries across 4 domain collections (web=7, windows_ad=7, cloud=72, network=5, plus 3 root-level misc files). SentenceTransformer `all-MiniLM-L6-v2` (384-dim) + Faiss IndexFlatIP with TfidfVectorizer fallback.
- **LangGraph integration**: ReAct loop (observe→plan→act→evaluate) via LangGraph StateGraph with checkpointing. SubAgentPool defaults to LangGraph.
- **Prompt architecture (Layer 0)**: System prompts live in `darwin/prompts/` as per-agent Python files with templated string constants. The `__init__.py` is archived — canonical prompts are in the individual agent files (`orchestrator.py`, `recon_agent.py`, `exploit_agent.py`, `pivot_agent.py`, `ad_agent.py`, `cloud_agent.py`, `dpm_classifier.py`).

## Commands

Requires Python >=3.10. Dependencies are in `pyproject.toml`.

```bash
# Create and activate virtual environment (prerequisite for all commands below)
python3 -m venv venv
source venv/bin/activate

# Install
pip install -e ".[dev]"

# Browser verification layer (DAVE L2)
playwright install chromium

# Run against a target (main entry point)
python run.py <target>                    # IP, hostname, or URL
python run.py example.com --username admin --password pass123
python run.py example.com --time-budget 1200 --token-budget 200000
python run.py example.com --port-range "1-65535"  # full scan; default "10000-10400" for benchmarks

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

# Run parallel benchmark experiment (Docker/K8s scenarios with configurable parallelism)
python experiments/parallel_runner.py --dry-run        # list scenarios without executing
python experiments/parallel_runner.py --parallel 4     # run with 4 concurrent scenarios

# Start PACEBench adapter server (port 8000)
python benchmarks/pacebench_adapter.py

# Start XBOW adapter server
python benchmarks/xbow_adapter.py

# Run custom defense benchmark (20 local challenges, no Docker)
python benchmarks/custom_defense/runner.py

# Knowledge ingestion (import .json or .md files into DarwinRAG)
python tools/ingest_knowledge.py --file <path>                  # single file
python tools/ingest_knowledge.py --dir <path>                   # directory recursively
python tools/ingest_knowledge.py --file <path> --collection <c> # explicit collection
python tools/ingest_knowledge.py --stats                        # show collection sizes
python tools/ingest_knowledge.py --rebuild                      # rebuild all indices
python tools/ingest_knowledge.py --model-dir <path>             # custom model path

# Convert external knowledge sources to DARWIN format
python tools/convert_knowledge.py --source <path> --output <path> --category <c>

# Convert nuclei-templates CVE YAML to DARWIN knowledge JSON
python tools/convert_nuclei.py --source <path> --output <path>

# Pull Docker images for benchmark challenges
bash scripts/pull_benchmark_images.sh
```

**API keys**: Set via env var or directly in `config/llm.yaml`. Env vars by provider:

| Provider   | Env Var              |
|-----------|----------------------|
| openai    | `OPENAI_API_KEY`     |
| anthropic | `ANTHROPIC_API_KEY`  |
| deepseek  | `DEEPSEEK_API_KEY`   |
| gemini    | `GEMINI_API_KEY`     |

Additional env vars (not in the LLM provider table):
| Env Var | Used By |
|---------|---------|
| `WPSCAN_API_TOKEN` | `wpscan_enum` tool (WPScan API token for WordPress vulnerability detection) |
| `BRAVE_API_KEY` | Brave Search MCP server |
| `GITHUB_PERSONAL_ACCESS_TOKEN` | GitHub MCP server |

**External tool dependencies**: The reconnaissance and attack tools wrap CLI commands. These must be installed on the host:
- `nmap`, `dirb`, `whatweb`, `curl` (recon)
- `sqlmap`, `ffuf`, `sshpass`, `wpscan` (attack/pivot)
- `netexec`, `impacket-secretsdump`, `impacket-psexec`, `impacket-wmiexec`, `ldapsearch` (AD agent)
- `kubectl`, `capsh` (cloud/K8s agent)

Additional Python dependencies for RAG: `sentence-transformers`, `faiss-cpu` (or `faiss-gpu`). **These are NOT in `pyproject.toml`** — install them manually if DarwinRAG is needed.

The orchestrator checks for required CLI tools at startup and warns if any are missing.

## Architecture

### Core data flow

```
Orchestrator.run() → recon → analyze → exploit → bypass → verify
                         ↓        ↓          ↓         ↓
                        DKG      LLM     DPM+DAVE   DAVE(L1-L4)
```

The `run()` method (`orchestrator.py:200`) follows this linear phase pipeline for Solo mode. For Coordinated/Distributed modes, it dispatches to `_run_multi_agent_cycle()` (`orchestrator.py:5727`) based on the B dimension threshold from `dynamic_scaling.py`.

Key `Orchestrator` method locations (~6700-line file; line numbers approximate):
- `run()` (~line 200) — entry point, main loop with mode dispatch, termination conditions
- `_unified_llm_loop()` (~line 1484) — Solo mode LLM-driven ReAct loop
- `_analyze_phase()` (~line 2613) — vulnerability hypothesis generation
- `_sanitize_plan_tools()` (~line 3748) — filters/rewrites plan tasks (blacklist, fallback, credential placeholder resolution, file:// detection)
- `_generate_exploitation_plan()` (~line 3805) — LLM exploitation strategy
- `_exploit_phase()` (~line 5022) — tool execution and verification
- `_run_multi_agent_cycle()` (~line 5727) — Coordinated/Distributed dispatch

### Module roles

| Module | Role |
|--------|------|
| `orchestrator.py` | Main loop with 7 termination conditions. Solo mode: `_sanitize_plan_tools()` filters tasks, `_analyze_and_fix_task()` retries fixable failures, deterministic tools execute directly (non-LLM). `_run_multi_agent_cycle()` handles Coordinated/Distributed modes. Tracks `_absent_services` (unreachable), `_BLACKLISTED_TOOLS` (broken), `_TOOL_FALLBACK` (alternatives). |
| `dkg.py` | Dynamic Knowledge Graph (NetworkX MultiDiGraph). Thread-safe. 8 node types, 9 edge types. All agent communication flows through DKG. v2: asyncio.Event per node type for real-time coordination. |
| `dpm.py` | Defense Perception Module. 3-layer detection: rule-based filter analysis → WAF signature matching → LLM classifier (only when confidence < 0.8). Outputs `DefenseStateVector`. |
| `dynamic_scaling.py` | `DynamicScalingEngine` with `TDAState` dataclass tracking TDI'' difficulty. `decide()` maps B to Solo/Coordinated/Distributed via hysteresis voting (2 votes to switch). Also includes `scan_collaboration_opportunities()` for cross-agent coordination detection. |
| `dave.py` | 4-layer verification: L1 HTTP response, L2 Playwright browser, L3 defense integrity (payload modification), L4 impact confirmation (flag extraction + honeypot detection). |
| `cteg.py` | Cross-Task Experience Graph — **dynamic patterns only**. Stores `BypassPattern` and `ExploitPattern` nodes with half-life decay. State persisted to `cteg_state.json`. Static knowledge uses DarwinRAG. |
| `rag.py` | DarwinRAG — **static knowledge RAG**. Multi-collection Faiss + SentenceTransformer with TfidfVectorizer fallback. Singleton via `get_rag()`. |
| `knowledge_base.py` | **Deprecated**. Inverted-index keyword search. Superseded by DarwinRAG. Still present on disk but should not be used. |
| `sub_agents/base.py` | `BaseSubAgent` with Plan→Act→Observe loop. `SubAgentPool` manages concurrent agents with 10 lifecycle states. |
| `sub_agents/recon_agent.py` | Whatweb→dirb→curl workflow. Writes discovered Endpoints/Services to DKG. |
| `sub_agents/exploit_agent.py` | SQLi/XSS/CMDi exploitation with integrated defense bypass and DAVE verification. |
| `sub_agents/pivot_agent.py` | Credential reuse, SSH key testing, internal host discovery. |
| `sub_agents/ad_agent.py` | Active Directory pentesting: domain enumeration, Kerberoasting, Pass-the-Hash, DCSync, Golden/Silver Ticket. |
| `sub_agents/cloud_agent.py` | Cloud/K8s pentesting: pod enumeration, RBAC abuse, container escape, cloud metadata (IMDS) access. |
| `data_model.py` | Typed dataclasses (`EndpointInfo`, `ServiceInfo`, `VulnerabilityInfo`, `HostInfo`, `CredentialInfo`) for normalizing data exchange between phases. `normalize_dkg_state()` / `to_prompt_context()`. |
| `darwin/tools/mcp_gateway.py` | Tool registry with OpenAI function-calling format export. Supports Python functions and shell command templates. |
| `darwin/tools/mcp_client.py` | MCP client pool (`MCPClientPool`) with per-server connection management. `MCPServerConfig` and `MCPToolDef` dataclasses. `load_mcp_config()` reads `config/mcp_servers.yaml`. Tool calls time out gracefully (return error dict, never raise). |
| `darwin/tools/recon_server.py` | 15 recon tools: nmap_scan, nmap_full_scan, nmap_port_range, nmap_vulners_scan, masscan_scan, whatweb_scan, dirb_scan, gobuster_dir, nikto_scan, curl_get, http_post, form_extract, try_login, idor_header_test, response_parse. |
| `darwin/tools/attack_server.py` | 59 attack tools across categories: SQL injection (sqlmap_test), fuzzing (ffuf_fuzz, send_payload, command_injection_test, xss_reflection_test), brute force (hydra_http_brute, hydra_ssh_brute, wp_xmlrpc_brute), DB clients (mysql_query, psql_query, redis_cmd, mssql_query, mssqlclient_query, oracle_query), AD/Windows (netexec_enum, netexec_ldap_enum, impacket_secretsdump, impacket_psexec, impacket_wmiexec, ldapsearch_ad, impacket_GetUserSPNs, impacket_GetNPUsers, impacket_secretsdump_dcsync, impacket_pth, impacket_ticketer, impacket_silver_ticket, impacket_ntlmrelayx), K8s/cloud (kubectl_auth_check, kubectl_get_secrets, kubectl_get_pods, kubectl_run, kubectl_get_clusterrolebindings, kubectl_exec, check_capabilities, check_mounts, check_cloud_metadata, sa_token_read, etcdctl_get, kubelet_probe, docker_registry, helm), post-exploit (ssh_exec, shell_exec, ssh_key_exec, linux_priv_check, file_upload, php_filter_chain), knowledge (knowledge_search, cve_lookup, metasploit_search, go_exploitdb_search, searchsploit_search, searchsploit_copy), and specialized exploits (tomcat_exploit, oracle_tns_poison, wpscan_enum, jwt_forge, test_credential, smbmap_enum). |
| `darwin/prompts/` | System prompt templates per agent: `orchestrator.py`, `recon_agent.py`, `exploit_agent.py`, `pivot_agent.py`, `ad_agent.py`, `cloud_agent.py`, `dpm_classifier.py`. The `__init__.py` is archived (not imported). |
| `darwin/utils/llm.py` | LiteLLM wrapper with conversation history, token counting, context compression (`compress()` method), and `LLMFunctionMapping`. |
| `darwin/utils/http_client.py` | Async HTTP client (aiohttp) with A-E WAF probe classes and baseline comparison. `ProbeClient` extends `HTTPClient`. |
| `experiments/runner.py` | Pilot experiment runner: single PACEBench D-CVE challenge. |
| `experiments/parallel_runner.py` | Parallel experiment runner for Docker and K8s benchmark scenarios. Groups by infrastructure type with configurable parallelism. |
| `experiments/lifecycle_manager.py` | Scenario lifecycle manager: START → wait-for-readiness → (DARWIN runs) → STOP for Docker and K8s. |
| `experiments/result_aggregator.py` | Collects, classifies, and reports experiment results across parallel runs. |
| `experiments/scenario_loader.py` | Dynamic scenario loader: reads `scenarios.yaml` registry to resolve target URLs (replaces hardcoded challenge lists). |
| `experiments/metrics.py` | TSR, Pass@k, token efficiency, defense detection rate, WAF bypass rate. |
| `experiments/analysis.py` | Statistical tests: McNemar, Friedman, bootstrap CI, Cohen's κ, paired t-test, EMA. |
| `experiments/chain_runner.py` | Multi-step attack chain runner (reads chain.yaml from `benchmarks/cve_challenges/chains/<name>/`). |
| `experiments/baselines/pentest_agent.py` | PentestAgent (AsiaCCS 2025) baseline adapter. Wraps PentestAgent as a comparative baseline with `BaselineResult` dataclass. |

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

Canonical implementation: `compute_task_breadth()` at `dynamic_scaling.py:118`. Note: README.md shows a simplified 3-factor version (`B = 0.4*N + 0.3*M + 0.3*L`); the 6-factor formula here is authoritative.

## Key design decisions

1. **Dynamic scaling, not fixed single/multi-agent**: Simple targets use Solo mode (zero overhead); complex targets spawn sub-agents. Driven by B dimension with hysteresis voting.
2. **Agent communication**: 100% through structured DKG (nodes + edges). Never natural language chat between agents.
3. **Defense detection**: Three-layer cascade (rule → signature → LLM), LLM only for low-confidence cases to save cost.
4. **Context compression, not hard reset**: When history approaches token limit (default 40% of 180K), `LLMSession.compress()` summarizes older messages via LLM. SubAgents compress independently. DKG carries structured state across phase boundaries.
5. **RAG separation (CTEG vs DarwinRAG)**: CTEG = dynamic cross-task experience (patterns learned from actual runs, persisted to `cteg_state.json`). DarwinRAG = static reference knowledge (attack techniques, MITRE ATT&CK, CIS benchmarks). Orchestrator queries both independently and merges in the LLM prompt.
6. **DarwinRAG uses SentenceTransformer + Faiss**: Model at `/home/kianabin/utils/all-MiniLM-L6-v2` (384-dim). TfidfVectorizer fallback when model unavailable.
7. **Sub-agents use LLM-driven replanning**: After task failure, agents replan via LLM rather than just marking-and-skipping.
8. **ADAgent and CloudAgent**: Auto-spawned when domain/K8s infrastructure detected during recon. Not yet benchmarked separately.
9. **Baselines**: Only PentestAgent baseline adapter exists (`experiments/baselines/pentest_agent.py`). No Claude Code adapter has been created yet.
10. **Plan sanitization**: `_sanitize_plan_tools()` filters/rewrites tasks across all three generation paths (initial plan, plan review, thin_warning). Handles tool blacklisting, automatic tool fallback (`_TOOL_FALLBACK`), credential placeholder resolution (`$credentials.*`), port-range gating (>5000 ports → skip), and `file://` URL blocking.
11. **Runtime tool blacklisting + fallback**: `_BLACKLISTED_TOOLS` prevents known-broken tools from appearing in plans. Tools returning `exit=127` are auto-blacklisted at runtime. `_TOOL_FALLBACK` maps unavailable tools to alternatives (e.g., `mssql_query` → `mssqlclient_query` when `sqlcmd` is not installed).
12. **Task failure analysis and retry**: `_analyze_and_fix_task()` uses LLM to classify failures as fixable (parameter errors) vs permanent. Fixable tasks are retried up to 2 times with corrected parameters. Partial successes (e.g., auth succeeds but sub-command fails) extract partial value (credentials) before marking done.
13. **Termination conditions**: 7 conditions including solo exhaustion stall (3 rounds of solo exhaustion without multi-agent entry), no-progress detection (2 consecutive loops with 0 discoveries), and absent-services tracking (prevents re-probing unreachable hosts).

## Benchmark infrastructure

### PACEBench and XBOW adapters
- `benchmarks/pacebench_adapter.py` — PACEBench adapter server (port 8000)
- `benchmarks/xbow_adapter.py` — XBOW adapter server

### CVE challenges (`benchmarks/cve_challenges/`)
Docker-based challenge infrastructure for comprehensive evaluation:

- **18 attack chains** in `chains/<name>/` — each with `chain.yaml` + deploy/teardown scripts. Chains span web→DA, container→cluster, Redis→K8s, WordPress→K8s, and more.
- **Docker scenarios** in `docker/`:
  - `db/` — 5 database targets (mssql-linked-server, mysql-udf-direct, oracle-tns, postgres-weak-auth, redis-unauth)
  - `web/` — 9 web targets (mssql-xp-cmdshell, mysql-udf, postgres-sqli, tomcat-deserialization, tomcat-race-condition, plus 4 WordPress vulns)
  - `linux/` — 5 Linux kernel CVE challenges (QEMU/Vagrant)
  - `_defense/` — 4 defense compose fragments (waf, cloak, honey, trap) + trap-proxy
- **K8s scenarios** in `k8s/` — 14 deployable scenarios with kind-config, deploy.sh, teardown.sh (K8S-04 is defined in scenarios.yaml but blocked — requires NVIDIA GPU hardware)
- **AD scenarios** in `ad/scenarios/` — 12 AD scenarios (ad-01 through ad-12) with config.yaml
- **Management scripts** in `benchmarks/cve_challenges/scripts/` — `flag_manager.py`, `generate_defense_variants.py`, `start-scenario.sh`, `stop-scenario.sh`, `validate-all.sh`, `verify-flag.sh`, `scenarios.yaml` (note: the top-level `scripts/` directory only contains `pull_benchmark_images.sh`)

### Custom defense benchmark (`benchmarks/custom_defense/`)
- `challenges.py` — 20 local challenge definitions + HTTP challenge server
- `runner.py` — runs DARWIN against all 20 challenges without Docker

### Local WAF (`benchmarks/local_waf/`)
- `waf_server.py` — local ModSecurity-style WAF for testing defense bypass

## Testing

### Current state
Only 3 of ~25+ modules have tests, covering pure data-structure code:
- `tests/test_dkg.py` — DKG node/edge CRUD, query, filter, serialization, save/load, reset. 8 test classes covering all node/edge types.
- `tests/test_metrics.py` — ExperimentMetrics properties (TSR, token efficiency, avg steps, etc.) and Pass@k calculation.
- `tests/test_analysis.py` — Statistical functions: McNemar, Cohen's g, paired t-test, bootstrap CI, Friedman, Cohen's κ, EMA.

Core orchestrator, all agents, tools, RAG, DPM, CTEG, DAVE, and LLM utilities are **untested**.

### Testing conventions
- Class-based test grouping (descriptive class names), no unittest.TestCase
- Edge-case coverage pattern: every test class includes `test_empty`/`test_missing` variants
- `@pytest.mark.parametrize` for exhaustive constant iteration
- `pytest.approx` for float comparisons, `pytest.raises` for expected exceptions
- `tmp_path` fixture for file I/O tests
- `asyncio_mode = "auto"` configured but no async tests exist yet
- No conftest.py, no shared fixtures, no mocking infrastructure yet

### Integration testing
- `smoke_test.py` at project root runs a full DARWIN penetration test against a target URL (manual, not pytest)

## Configuration

**Important**: The `config/` directory is in `.gitignore` (contains API keys). On a fresh checkout, create these files manually or obtain from a secure source.

- `config/darwin.yaml`: Time/token budgets, solo mode limits, defense probe settings, browser config. `max_context_tokens` (180000) and `context_compression_threshold` (0.4).
- `config/llm.yaml`: Three LLM profiles — `default`, `reasoning`, `classifier`. API key can be set directly in this file or via the corresponding env var (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `DEEPSEEK_API_KEY`, `GEMINI_API_KEY`).
- `config/waf_fingerprints.yaml`: ModSecurity, Cloudflare, Naxsi, Coraza signatures with detection rules and bypass hints.
- `config/mcp_servers.yaml`: MCP server configurations for external tool servers. 8 servers defined: `filesystem` (disabled), `brave-search` (disabled), `puppeteer` (enabled), `github` (enabled), `memory` (enabled), `sequential-thinking` (enabled), `ddg-search` (disabled — deprecated, replaced by `ddg_web_search` Python tool in attack_server.py), `nvd` (enabled).

**Model path**: DarwinRAG loads SentenceTransformer from `/home/kianabin/utils/all-MiniLM-L6-v2` by default. Override via `DarwinRAG(model_dir=...)` or `--model-dir`.

## Documentation and planning

- `docs/` — Design and research docs: benchmark research, context compression design, CVE benchmark guide, experiment procedure. `docs/phase-plans/` contains 8 phase implementation plans (phase1–phase8).
- `plan/` — Framework design (`DARWIN_framework.md`), implementation plan, progress tracker (`DARWIN_todo.md`), and `KNOWN_ISSUES.md` (note: many critical items from the May 2026 audit have been resolved — CTEG is integrated, multi-agent dispatch is active, tests exist, duplicate `compute_task_breadth` removed).

## Runtime state

- **`checkpoints/`** — LangGraph checkpoint JSON files (bootstrap + per-loop snapshots). DKG state is persisted at the end of each loop iteration. Critical for debugging failed runs. **Note**: despite the `.gitignore` `checkpoint/` pattern (singular), `checkpoints/` (plural) is tracked by git — local run artifacts may appear in `git status`.
- **`cteg_state.json`** — Persisted CTEG graph (bypass/exploit patterns with half-life decay). Accumulates across runs. Also tracked by git.
- **DKG persistence**: `dkg.save()` is called each loop iteration via `_checkpoint_path()`. On crash, the last checkpoint preserves all reconnaissance/exploitation state.

## Flag format

`flag{...}` — matched by regex `flag\{[a-zA-Z0-9_\-]+\}` (config, `config/darwin.yaml:27` flag_pattern). Note: DAVE L4, orchestrator, and exploit agent modules use a more permissive variant (`flag\{[a-zA-Z0-9_\-!@#$%^&*()+=]+\}`) that also matches special characters. Honeypot flags (`flag{test}`, `flag{example}`, `flag{honeypot}`, etc.) are rejected by DAVE L4.

## What is not yet integrated

- `experiments/comparative_runner.py` — not yet created
- No Claude Code baseline adapter (only PentestAgent exists)
- `experiments/failure_analysis.py` — not yet created
- `paper_analysis/` directory — not yet created
- Majority of modules lack test coverage (see Testing section)
