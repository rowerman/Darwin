# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

**When debugging experiment failures or modifying DARWIN core modules, load the darwin-experiment-driven-dev skill first.**
**Benchmark infrastructure has moved to `/home/kianabin/benchmark_design/benchmarks/`. The old `benchmarks/cve_challenges/` path is deprecated.**

DARWIN is an LLM-driven adaptive penetration testing agent framework. Two core innovations:

- **Defense Perception (DPM)**: Detects WAF/Cloak/Honey/Trap and triggers bypass strategies. All SOTA frameworks score 0% on PACEBench D-CVE (WAF scenarios).
- **Dynamic Scaling (B dimension)**: Simple single-host vulns use Solo Mode (0 sub-agents); complex multi-host/WAF scenarios auto-spawn ReconAgent/ExploitAgent/PivotAgent. See B dimension formula section below.
- **DKG communication**: Sub-agents communicate only via structured Dynamic Knowledge Graph with asyncio.Event notifications, never natural language.
- **CTEG cross-task learning**: Dynamic bypass/exploit patterns accumulated across challenges, with time-based decay (static knowledge is handled separately by DarwinRAG).
- **DarwinRAG static knowledge**: 8106+ curated entries across 4 domain collections (web, windows_ad, cloud, network), continuously expanded via `tools/ingest_knowledge.py`. SentenceTransformer `all-MiniLM-L6-v2` (384-dim) + Faiss IndexFlatIP with TfidfVectorizer fallback.
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

# Run all tests (pytest-asyncio with asyncio_mode=auto — no @pytest.mark.asyncio needed)
pytest tests/ -v

# Run a single test file
pytest tests/test_dkg.py -v

# Run a single test function
pytest tests/test_dkg.py::test_function_name -v

# Run DARWIN against a target (CLI entry point)
python run.py <target>                      # IP, hostname, or URL
python run.py example.com --username admin --password pass123
python run.py example.com --time-budget 1200 --token-budget 200000

# Run tests with coverage
pytest tests/ -v --cov=darwin --cov=experiments --cov-report=term

# Run DARWIN via the experiment runner (benchmark mode)
python experiments/runner.py                    # pilot mode
python experiments/runner.py cve [scenario_id]  # CVE benchmark mode

# Parallel experiment runner
python experiments/parallel_runner.py --dry-run
python experiments/parallel_runner.py --parallelism 4
python experiments/parallel_runner.py --scenario WEB-01

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

**Cloud/K8s container escape tools** (`tools/tools_open/`): External Go/Python tools used by `cloud_agent.py` for container breakout and K8s penetration testing:
- `botb` — Break Out The Box (container breakout detection via capabilities, mounts, sockets)
- `ccat` — Cloud Container Attack Tool (metadata extraction, credential discovery)
- `CDK` — Container Defense Kit (K8s RBAC abuse, node escape, lateral movement)
- `peirates` — K8s penetration testing (pod enumeration, secret theft, service account abuse)
- `veinmind-tools` — Container security scanning (image inspection, malware detection)

Additional Python dependencies for RAG: `sentence-transformers`, `faiss-cpu` (or `faiss-gpu`). **These are NOT in `pyproject.toml`** — install them manually if DarwinRAG is needed.

The orchestrator checks for required CLI tools at startup and warns if any are missing.

## Architecture

### Core data flow

```
Orchestrator.run() → recon → analyze → exploit → bypass → verify
                         ↓        ↓          ↓         ↓
                        DKG      LLM     DPM+DAVE   DAVE(L1-L4)
```

The `run()` method (`orchestrator.py:212`) follows this linear phase pipeline for Solo mode. For Coordinated/Distributed modes, it dispatches to `_run_multi_agent_cycle()` (`orchestrator.py:6437`) based on the B dimension threshold from `dynamic_scaling.py`.

Key `Orchestrator` method locations (~9537-line file; line numbers approximate):
- `run()` (line 212) — entry point, main loop with mode dispatch, termination conditions
- `_unified_llm_loop()` (line 2243) — Solo mode LLM-driven ReAct loop
- `_analyze_phase()` (line 3560) — vulnerability hypothesis generation
- `_sanitize_plan_tools()` (line 4914) — filters/rewrites plan tasks (blacklist, fallback, credential placeholder resolution, file:// detection)
- `_generate_exploitation_plan()` (line 5370) — LLM exploitation strategy
- `_analyze_and_fix_task()` (line 6186) — LLM-based task failure classification and retry (up to 2 attempts)
- `_review_and_update_plan()` (line 6402) — dedup merged plans (tool+endpoint matching + >75% word overlap), remap stale task ID references in dependencies
- `_exploit_phase()` (line 6983) — tool execution and verification
- `_run_multi_agent_cycle()` (line 7738) — Coordinated/Distributed dispatch
- `_execute_privesc()` (~line 9100) — auto-detects and exploits Linux privesc vectors (SUID, writable /etc/passwd, Docker socket, capabilities, cron, LD_PRELOAD) from `linux_priv_check` output
- `_try_db_default_credentials()` (~line 9200) — auto-trials known default credentials against discovered DB services (MySQL/PostgreSQL/Redis/MSSQL/Oracle/MongoDB)
- `_extract_recent_artifacts()` (~line 9250) — extracts recently discovered credentials/sessions/endpoints for cross-step context injection
- `_build_truncation_context()` (~line 9300) — builds structured DKG summary (flags/creds/sessions/services/vulns) for context compression fallback

### Module roles

| Module | Role |
|--------|------|
| `orchestrator.py` | Main loop with 7 termination conditions. Solo mode: `_sanitize_plan_tools()` filters tasks, `_analyze_and_fix_task()` retries fixable failures, `_review_and_update_plan()` deduplicates merged plans and remaps stale dependency references, deterministic tools execute directly (non-LLM). `_run_multi_agent_cycle()` handles Coordinated/Distributed modes. Tracks `_absent_services` (unreachable), `_BLACKLISTED_TOOLS` (broken), `_TOOL_FALLBACK` (alternatives). Auto-exploits Linux privesc vectors (`_execute_privesc()`), trials DB default credentials (`_try_db_default_credentials()`), and injects intermediate artifacts for multi-step exploit continuity (`_extract_recent_artifacts()`). |
| `dkg.py` | Dynamic Knowledge Graph (NetworkX MultiDiGraph). Thread-safe. 17 node types (8 base + 9 cloud-native: K8sCluster, K8sNode, K8sNamespace, K8sPod, K8sSA, CloudAccount, IAMRole, IAMPolicy, TrustRelationship), 22 edge types. All agent communication flows through DKG. v2: asyncio.Event per node type for real-time coordination. |
| `dpm.py` | Defense Perception Module. 3-layer detection: rule-based filter analysis → WAF signature matching → LLM classifier (only when confidence < 0.8). Outputs `DefenseStateVector`. CDF (Cloud Defense Fingerprinting): `detect_cloud_defenses()` probes IMDSv2 enforcement, K8s NetworkPolicy/Admission Controller, IAM Permission Boundary, SCP limits, CloudTrail/GuardDuty monitoring, and generates cloud-native bypass strategies. |
| `dynamic_scaling.py` | `DynamicScalingEngine` with `TDAState` dataclass tracking TDI'' difficulty. `decide()` maps B to Solo/Coordinated/Distributed via hysteresis voting (2 votes to switch). Also includes `scan_collaboration_opportunities()` for cross-agent coordination detection. `env_complexity` is continuous when CTAGE topology data is available (based on cluster size, namespace diversity, IAM role count, cross-account trusts, multi-cluster presence), with floor 0.5 for cloud environments. |
| `dave.py` | 4-layer verification: L1 HTTP response, L2 Playwright browser, L3 defense integrity (payload modification), L4 impact confirmation (flag extraction + honeypot detection). |
| `cteg.py` | Cross-Task Experience Graph — **dynamic patterns only**. Stores `BypassPattern` and `ExploitPattern` nodes with half-life decay. State persisted to `cteg_state.json`. Static knowledge uses DarwinRAG. |
| `rag.py` | DarwinRAG — **static knowledge RAG**. Multi-collection Faiss + SentenceTransformer with TfidfVectorizer fallback. Singleton via `get_rag()`. |
| `knowledge_base.py` | **Deprecated**. Inverted-index keyword search. Superseded by DarwinRAG. Still present on disk but should not be used. |
| `sub_agents/base.py` | `BaseSubAgent` with Plan→Act→Observe loop. `SubAgentPool` manages concurrent agents with 10 lifecycle states. |
| `sub_agents/recon_agent.py` | Whatweb→dirb→curl workflow. Writes discovered Endpoints/Services to DKG. |
| `sub_agents/exploit_agent.py` | SQLi/XSS/CMDi exploitation with integrated defense bypass and DAVE verification. |
| `sub_agents/pivot_agent.py` | Credential reuse, SSH key testing, internal host discovery. |
| `sub_agents/ad_agent.py` | Active Directory pentesting: domain enumeration, Kerberoasting, Pass-the-Hash, DCSync, Golden/Silver Ticket. |
| `sub_agents/cloud_agent.py` | Cloud/K8s pentesting: pod enumeration, RBAC abuse, container escape, cloud metadata (IMDS) access. Integrates CTAGE context via `_build_ctage_context()` for topology-aware plan generation. |
| `cloud_topology.py` | CTAGE (Cloud Topology & Attack Graph Engine): auto-discovers K8s cluster topology (nodes/pods/namespaces/SAs/RBAC bindings), analyzes Pod security contexts (privileged/capabilities/hostPID/mounts) and matches escape vectors, enumerates IAM roles and cross-account trust relationships. Outputs structured DKG nodes+edges. |
| `cloud_attack_path.py` | AttackPathReasoner: four BFS path discoverers — IAM privilege escalation (role_can_assume chains), container escape (security config→tool matching), lateral movement (cross-namespace RBAC), cross-account (TrustRelationship traversal). Ranked by difficulty and confidence, outputs LLM-ready prompt injection. |
| `data_model.py` | Typed dataclasses (`EndpointInfo`, `ServiceInfo`, `VulnerabilityInfo`, `HostInfo`, `CredentialInfo`) for normalizing data exchange between phases. `normalize_dkg_state()` / `to_prompt_context()`. |
| `darwin/tools/mcp_gateway.py` | Tool registry with OpenAI function-calling format export. Supports Python functions and shell command templates. Includes parameter aliasing (`host`→`target` with port auto-construction, `anonymous`→empty creds, `url`→`target_url`) to bridge LLM parameter names to tool template expectations. |
| `darwin/tools/mcp_client.py` | MCP client pool (`MCPClientPool`) with per-server connection management. `MCPServerConfig` and `MCPToolDef` dataclasses. `load_mcp_config()` reads `config/mcp_servers.yaml`. Tool calls time out gracefully (return error dict, never raise). |
| `darwin/tools/recon_server.py` | 15 recon tools: nmap_scan, nmap_full_scan, nmap_port_range, nmap_vulners_scan, masscan_scan, whatweb_scan, dirb_scan, gobuster_dir, nikto_scan, curl_get, http_post, form_extract, try_login, idor_header_test, response_parse. |
| `darwin/tools/attack_server.py` | 82 unique tools across categories (filtered from 112 via `_apply_domain_filter()` based on `config/darwin.yaml` `tools.enabled_domains`): SQL injection (sqlmap_test), fuzzing (ffuf_fuzz, send_payload, command_injection_test, xss_reflection_test, ssti_inject), brute force (hydra_http_brute, hydra_ssh_brute, wp_xmlrpc_brute), DB/NoSQL clients (mysql_query, mysql_file_write, psql_query, redis_cmd, mssql_query, mssqlclient_query, oracle_query, mongodb_query, elasticsearch_query, couchdb_query), AD/Windows (netexec_enum, netexec_ldap_enum, impacket_secretsdump, impacket_psexec, impacket_wmiexec, ldapsearch_ad, impacket_GetUserSPNs, impacket_GetNPUsers, impacket_secretsdump_dcsync, impacket_pth, impacket_ticketer, impacket_silver_ticket, impacket_ntlmrelayx, impacket_getST, smb_client, gpp_decrypt, hash_crack), K8s/cloud (kubectl_auth_check, kubectl_get_secrets, kubectl_get_pods, kubectl_run, kubectl_get_clusterrolebindings, kubectl_exec, check_capabilities, check_mounts, check_cloud_metadata, sa_token_read, etcdctl_get, kubelet_probe, docker_registry, helm, aws_cli), post-exploit (ssh_exec, shell_exec, ssh_key_exec, linux_priv_check, file_upload, php_filter_chain), knowledge (knowledge_search, cve_lookup, metasploit_search, go_exploitdb_search, searchsploit_search, searchsploit_copy, ddg_web_search), specialized exploits (tomcat_exploit, oracle_tns_poison, wpscan_enum, jwt_forge, test_credential, smbmap_enum, ssrf_probe, xxe_inject, graphql_introspect), and Linux privesc (SUID, capabilities, cron, LD_PRELOAD). |
| `darwin/prompts/` | System prompt templates per agent: `orchestrator.py`, `recon_agent.py`, `exploit_agent.py`, `pivot_agent.py`, `ad_agent.py`, `cloud_agent.py`, `dpm_classifier.py`. The `__init__.py` is archived (not imported). |
| `darwin/utils/llm.py` | LiteLLM wrapper with conversation history, token counting, context compression (`compress()` method), and `LLMFunctionMapping`. |
| `darwin/utils/http_client.py` | Async HTTP client (aiohttp) with A-E WAF probe classes and baseline comparison. `ProbeClient` extends `HTTPClient`. |
| `darwin/utils/phase_logger.py` | Structured per-phase file logging. Creates `log/<phase>/<run_id>_<phase>.log` files at phase boundaries (scan/recon/research/plan/exploit/replan/summary). Phase timing, metadata, and summary generation. Configurable via `config/darwin.yaml` (`log_dir`, `log_level`). Zero new dependencies (stdlib only). |
| `run.py` | CLI entry point. Bootstraps the `Orchestrator` from command-line args (`--username`, `--password`, `--time-budget`, `--token-budget`). Handles MCP server startup, LLM config loading, and graceful shutdown. |
| `experiments/runner.py` | Experiment runner supporting both pilot (single PACEBench D-CVE challenge) and CVE benchmark modes. Run `python experiments/runner.py` for pilot or `python experiments/runner.py cve [scenario_id...]` for benchmarks against a hardcoded 21-challenge list. Also supports attack chains via `run_chains()`. |
| `experiments/parallel_runner.py` | Parallel experiment runner for Docker and K8s benchmark scenarios. Groups by infrastructure type with configurable parallelism. |
| `experiments/lifecycle_manager.py` | Scenario lifecycle manager: START → wait-for-readiness → (DARWIN runs) → STOP for Docker and K8s. |
| `experiments/result_aggregator.py` | Collects, classifies, and reports experiment results across parallel runs. |
| `experiments/scenario_loader.py` | Dynamic scenario loader: reads `scenarios.yaml` registry to resolve target URLs (replaces hardcoded challenge lists). |
| `experiments/metrics.py` | TSR, Pass@k, token efficiency, defense detection rate, WAF bypass rate. |
| `experiments/analysis.py` | Statistical tests: McNemar, Friedman, bootstrap CI, Cohen's κ, paired t-test, EMA. |
| `experiments/chain_runner.py` | Multi-step attack chain runner. |
| `experiments/baselines/pentest_agent.py` | PentestAgent (AsiaCCS 2025) baseline adapter. Wraps PentestAgent as a comparative baseline with `BaselineResult` dataclass. |

### Knowledge collections (`knowledge/`)

DarwinRAG's 4 domain collections in subdirectories, plus flat JSON files at the root:

| Path | Contents |
|------|----------|
| `web/` | Web exploitation (SQLi, XSS, CMDi, file inclusion, SSRF, SSTI, XXE, PHP deserialization, GraphQL, WordPress) |
| `network/` | Network services exploitation, default credentials, lateral movement, protocol attacks, Linux privesc, NoSQL exploitation, defense evasion |
| `windows_ad/` | AD enumeration, exploitation, privilege escalation, persistence, Kerberos attacks, RBCD, Shadow Credentials, WriteOwner, ForceChangePassword |
| `cloud/` | K8s escape, container breakout, cloud metadata (IMDS) access, K8s networking attacks, AWS exploitation, CI/CD attacks, CIS benchmark docs |
| `nuclei_cve_templates.json` | Nuclei CVE templates (6.3 MB) |
| `web_vulnerabilities.json` | Web vulnerability signatures |
| `unauth_services.json` | Unauthenticated service fingerprints |
| `advanced_exploitation.json` | Advanced exploitation techniques |
| `db_exploitation.json` | Database exploitation techniques |
| `web_converted-1..4.json` | Converted web knowledge (4-part split) |
| `web_oscp.json` | OSCP web techniques |
| `web_pat.json` | PAT web techniques |

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
- `env_complexity = 1.0` for AD (SMB+LDAP), continuous for cloud (0.5–1.0 based on cluster size, namespace diversity, IAM role count, cross-account trusts from CTAGE topology), `0.0` otherwise

Canonical implementation: `compute_task_breadth()` at `dynamic_scaling.py:118`. Note: README.md shows a simplified 3-factor version (`B = 0.4*N + 0.3*M + 0.3*L`); the 6-factor formula here is authoritative. Also note: the module docstring at `dynamic_scaling.py:5` incorrectly states `0.10*env_complexity` — the code at line 184 uses `0.18`, which is correct.

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
14. **MCP gateway parameter aliasing**: `register_shell_tool()` has explicit parameter aliases (`host`→`target` with auto `host:port` construction, `anonymous: True`→empty credentials, `url`→`target_url`) that bridge LLM-preferred parameter names to tool template expectations. Prevents Template format errors from parameter name mismatches without requiring the LLM to know tool-internal parameter names.
15. **CTAGE/CDF/CADS cloud-native triad**: Cloud Topology & Attack Graph Engine auto-discovers K8s cluster topology and IAM trust relationships into DKG, AttackPathReasoner enumerates BFS-ranked attack paths for LLM prompt injection, and Cloud Defense Fingerprinting probes cloud-native defenses (IMDSv2, NetworkPolicy, SCP, CloudTrail) for bypass strategy generation. Cloud-Aware Dynamic Scaling uses topology data for continuous `env_complexity` scoring.
16. **Multi-step exploit continuity**: `_extract_recent_artifacts()` injects intermediate credentials/sessions/endpoints between exploit steps so the LLM maintains awareness across multi-step attack chains without re-scanning. Context compression fallback (`_build_truncation_context()`) injects structured DKG summary when compression is exhausted.
17. **Chain checkpoint & resume**: `experiments/chain_runner.py` saves `chain_state.json` + DKG snapshot after each chain step. `run_chain(resume=True)` auto-loads the latest checkpoint and skips completed steps. Supports crash recovery for long attack chains.
18. **Tool domain filtering**: `_apply_domain_filter()` in `attack_server.py` removes tools for disabled domains per `config/darwin.yaml` `tools.enabled_domains`. Domain categories: `_AD_TOOLS` (27), `_LNX_TOOLS` (1), `_CLOUD_EXTRA_TOOLS` (2). Default: no filtering (all 112 tools available, 82 after AD/LNX/CLOUD classification).

## Benchmark infrastructure

**Benchmark infrastructure has moved to `/home/kianabin/benchmark_design/benchmarks/`.** The old `benchmarks/` path in this repo is removed. The experiment runners (`experiments/runner.py`, `experiments/parallel_runner.py`) and scenario loader (`experiments/scenario_loader.py`) remain in this repo and discover scenarios dynamically.

**Note**: README.md still references `benchmarks/pacebench_adapter.py` — this path no longer exists. Use `experiments/runner.py` for benchmark evaluation instead.

### Root-level benchmark documentation
- `BENCHMARK_SUMMARY.md` — Comprehensive ~7900-line exploitation guide covering deployable scenarios and attack chains.
- `BENCHMARK_SCENARIOS_OVERVIEW.md` — Concise overview table of 57 single-point scenarios and 24 attack chains.

## Testing

### Current state
Only 6 of ~25+ modules have tests (183 total test methods), covering pure data-structure code:
- `tests/test_dkg.py` — DKG node/edge CRUD, query, filter, serialization, save/load, reset. 8 test classes covering all node/edge types.
- `tests/test_metrics.py` — ExperimentMetrics properties (TSR, token efficiency, avg steps, etc.) and Pass@k calculation.
- `tests/test_analysis.py` — Statistical functions: McNemar, Cohen's g, paired t-test, bootstrap CI, Friedman, Cohen's κ, EMA.
- `tests/test_dynamic_scaling.py` — B dimension formula (`compute_task_breadth()`), complexity hint detection, hysteresis voting.
- `tests/test_mcp_gateway.py` — MCP gateway parameter aliasing (`host`→`target`, `url`→`target_url`, etc.), credential placeholder resolution, fuzzy matching.
- `tests/test_phase_logger.py` — PhaseLogger file-based phase logging, directory mapping, timing, summary generation, metadata handling.

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
- DARWIN is run via `experiments/runner.py` which orchestrates end-to-end penetration tests against target scenarios.

## Configuration

**Important**: The `config/` directory is in `.gitignore` (contains API keys). On a fresh checkout, create these files manually or obtain from a secure source.

- `config/darwin.yaml`: Time/token budgets, solo mode limits, defense probe settings, browser config. `max_context_tokens` (180000) and `context_compression_threshold` (0.4). Also: `chain_mode: auto` (multi-flag attack chain mode), `chain_max_flags: 10` (safety cap for intermediate flags), and `wpscan.api_token` (WPScan API token for WordPress scanning — falls back to unauthenticated if empty).
- `config/llm.yaml`: Three LLM profiles — `default`, `reasoning`, `classifier`. API key can be set directly in this file or via the corresponding env var (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `DEEPSEEK_API_KEY`, `GEMINI_API_KEY`).
- `config/waf_fingerprints.yaml`: ModSecurity, Cloudflare, Naxsi, Coraza signatures with detection rules and bypass hints.
- `config/mcp_servers.yaml`: MCP server configurations for external tool servers. 8 servers defined: `filesystem` (disabled), `brave-search` (disabled), `puppeteer` (enabled), `github` (enabled), `memory` (enabled), `sequential-thinking` (enabled), `ddg-search` (disabled — deprecated, replaced by `ddg_web_search` Python tool in attack_server.py), `nvd` (enabled).

**Model path**: DarwinRAG loads SentenceTransformer from `/home/kianabin/utils/all-MiniLM-L6-v2` by default. Override via `DarwinRAG(model_dir=...)` or `--model-dir`.

## Documentation and planning

- `plan/` — Framework design (`DARWIN_framework.md`), implementation plan, progress tracker (`DARWIN_todo.md`), and `KNOWN_ISSUES.md`. **Note**: `KNOWN_ISSUES.md` is dated 2026-05-14 and several items listed there have since been resolved (CTEG is integrated, multi-agent dispatch is active, tests exist, duplicate `compute_task_breadth` removed). Consult `CHANGES.md` for the authoritative resolution status of each item.
- `darwin-experiment-automation.md` — Plan for automated DARWIN vs PentestAgent comparative experiments across Custom Defense, PACEBench, and XBOW benchmarks. Phase A (Custom Defense, 20 challenges) is immediately runnable.
- `CHANGES.md` — Chronological change log of all framework modifications since May 2026. Consult this when investigating why a feature works a certain way or when a recent change may have introduced a regression.
- `research/` — Research notes (e.g., `container_escape_cve_research.md`).
- `tools/` (top-level) — Knowledge ingestion/conversion scripts: `ingest_knowledge.py`, `convert_knowledge.py`, `convert_nuclei.py`.

### Root-level documentation
- `BENCHMARK_SUMMARY.md` — Comprehensive ~7900-line exploitation guide covering all deployable scenarios and attack chains with step-by-step commands. The single most detailed benchmark reference.
- `BENCHMARK_SCENARIOS_OVERVIEW.md` — Concise overview table of 57 single-point scenarios and 24 attack chains.
- `TOOLS.md` — Security tools installation checklist.
- `install.sh` — Full system installation script (35KB). Automates dependency setup including external CLI tools.

### Claude Code integration (`.claude/`)
- `settings.local.json` — Fine-grained Bash permission allowlist for Claude Code operations in this project (e.g., pytest, git, docker, kubectl, nmap, gobuster). 200+ allowed patterns covering the full development workflow.
- `skills/darwin-experiment-driven-dev/SKILL.md` — 745-line experiment-driven development skill with diagnostic decision tree, module dependency maps, and verification checklist. **Load this skill first** when debugging experiment failures or modifying DARWIN core modules (orchestrator, DKG, CTEG, RAG, DPM, prompts, sub-agents, tools). Invoke via `/darwin-experiment-driven-dev` or the Skill tool.

### Wordlists (`wordlists/`)
Dictionary files used by fuzzing tools (ffuf, dirb, gobuster):
- `raft-large-directories.txt`, `raft-medium-words.txt`, `combined_directories.txt`
- `cms/` subdirectory with CMS-specific wordlists

## Runtime state

- **`checkpoints/`** — LangGraph checkpoint JSON files (bootstrap + per-loop snapshots). DKG state is persisted at the end of each loop iteration. Critical for debugging failed runs. **Note**: despite the `.gitignore` `checkpoint/` pattern (singular), `checkpoints/` (plural) is tracked by git — local run artifacts may appear in `git status`.
- **`cteg_state.json`** — Persisted CTEG graph (bypass/exploit patterns with half-life decay). Accumulates across runs. Also tracked by git.
- **`log/`** — PhaseLogger output directory (when enabled). Contains per-phase subdirectories (`scan/`, `recon/`, `research/`, `plan/`, `exploit/`, `replan/`, `summary/`) each holding timestamped `<run_id>_<phase>.log` files. Created at runtime; in `.gitignore` but may appear in `git status` during development.
- **`checkpoints/chains/`** — Chain checkpoint files (`chain_state.json` + DKG snapshots) saved after each attack chain step. Enables resume from intermediate steps after crash/interruption via `chain_runner.run_chain(resume=True)`.
- **DKG persistence**: `dkg.save()` is called each loop iteration via `_checkpoint_path()`. On crash, the last checkpoint preserves all reconnaissance/exploitation state.

## Flag format

`flag{...}` — matched by regex `flag\{[a-zA-Z0-9_\-]+\}` (config, `config/darwin.yaml:34` flag_pattern). Note: DAVE L4, orchestrator, and exploit agent modules use a more permissive variant (`flag\{[a-zA-Z0-9_\-!@#$%^&*()+=]+\}`) that also matches special characters. Honeypot flags (`flag{test}`, `flag{example}`, `flag{honeypot}`, etc.) are rejected by DAVE L4.

## What is not yet integrated

- `experiments/comparative_runner.py` — not yet created
- No Claude Code baseline adapter (only PentestAgent exists at `experiments/baselines/pentest_agent.py`)
- `experiments/failure_analysis.py` — not yet created
- `paper_analysis/` directory — not yet created
- Core orchestrator, all agents, tools, RAG, DPM, CTEG, DAVE, and LLM utilities are untested (only 6 modules — DKG, metrics, analysis, dynamic_scaling, MCP gateway, phase_logger — have test coverage via 183 tests)
