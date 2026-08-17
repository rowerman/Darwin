# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

DARWIN is an LLM-driven adaptive penetration testing agent framework. Core innovations:

- **Defense Perception (DPM)**: Detects WAF/Cloak/Honey/Trap and triggers bypass strategies.
- **Solo control plane (v2)**: Single-agent LLM-driven loop — the LLM plans structured Tasks, the system executes them through the Task/Capability/Executor layers. Multi-agent dispatch (Coordinated/Distributed) was removed in the v2 refactor (M0).
- **DKG world state**: DKG is the structured world model with provenance (who discovered what and why); planner/replan read it via typed state snapshots.
- **CTEG cross-task learning**: Dynamic bypass/exploit patterns accumulated across challenges with time-based decay.
- **DarwinRAG static knowledge**: 8125+ curated entries across 4 domain collections (web, windows_ad, cloud, network). SentenceTransformer `all-MiniLM-L6-v2` (384-dim) + Faiss IndexFlatIP with TfidfVectorizer fallback.
- **LangGraph integration**: ReAct loop (observe→plan→act→evaluate) via LangGraph StateGraph with checkpointing.

## Commands

Requires Python >=3.10.

```bash
python3 -m venv venv && source venv/bin/activate
pip install -e ".[dev]"
playwright install chromium                            # DAVE L2 browser verification

# Run tests
pytest tests/ -v                                       # all tests
pytest tests/test_dkg.py::test_function_name -v        # single test

# Run DARWIN
python run.py <target>                                  # IP, hostname, or URL
python run.py example.com --username admin --password pass123
python run.py example.com --time-budget 1200 --token-budget 200000

# Experiment runner
python experiments/runner.py                            # pilot mode
python experiments/runner.py cve [scenario_id]          # CVE benchmark mode
python experiments/parallel_runner.py --parallelism 4
python experiments/parallel_runner.py --scenario WEB-01

# Knowledge ingestion
python tools/ingest_knowledge.py --file <path>
python tools/ingest_knowledge.py --dir <path>
python tools/ingest_knowledge.py --stats
```

**API keys**: Set via env var or `config/llm.yaml`. Env vars: `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `DEEPSEEK_API_KEY`, `GEMINI_API_KEY`. Additional: `WPSCAN_API_TOKEN`, `BRAVE_API_KEY`, `GITHUB_PERSONAL_ACCESS_TOKEN`.

**External tool dependencies**: `nmap`, `dirb`, `whatweb`, `curl`, `sqlmap`, `ffuf`, `sshpass`, `wpscan`, `netexec`, `impacket-*`, `ldapsearch`, `kubectl`, `capsh`. Orchestrator checks for required tools at startup and warns if missing.

**RAG dependencies**: `sentence-transformers`, `faiss-cpu` (NOT in `pyproject.toml` — install manually if DarwinRAG is needed).

## Architecture

### Core data flow

```
Orchestrator.run() → recon → analyze → exploit → bypass → verify
                        ↓        ↓          ↓         ↓
                       DKG      LLM     DPM+DAVE   DAVE(L1-L4)
```

The main loop (`_unified_llm_loop`) is plan → execute → evaluate → replan:
the LLM produces an exploitation plan, each task is consumed as a
structured `Task` and executed by the Task-based Executor, failures are
classified by the rule-based Evaluator, and local repairs are applied by
the Replanner before the LLM review fallback. All execution goes through
`darwin/core/executor.py` — the orchestrator never calls tools directly.

### Module roles

| Module | Role |
|--------|------|
| `darwin/orchestrator.py` (~9600 lines) | Solo main loop (`_unified_llm_loop`): plan sanitization, Task-based execution, failure analysis+retry, local replan, defense probes, credential extraction, flag verification. Multi-agent dispatch was removed (M0). |
| `darwin/core/` | v2 control plane: Task model, TaskGraph, Executor, Evaluator/FailureAnalyzer, Replanner, Capabilities, schema-driven Parameter validation, Memory (plan/execution + compression grading), Metrics. |
| `darwin/dkg.py` | Dynamic Knowledge Graph (NetworkX MultiDiGraph). Thread-safe. World state with provenance (source/evidence/timestamp); no inter-agent messaging exists in Solo mode. |
| `darwin/dpm.py` | Defense Perception Module. 3-layer detection: rule-based → WAF signature → LLM classifier. CDF (Cloud Defense Fingerprinting) for cloud-native defenses. |
| `darwin/dave.py` | 4-layer verification: L1 HTTP response, L2 Playwright browser, L3 defense integrity, L4 impact confirmation (flag extraction + honeypot detection). |
| `darwin/cteg.py` | Cross-Task Experience Graph — dynamic patterns only. Persisted to `cteg_state.json` with half-life decay. |
| `darwin/rag.py` | DarwinRAG — static knowledge. Multi-collection Faiss + SentenceTransformer; `search_hierarchical()` routes through `knowledge/taxonomy.json` (domain → class → scenario leaf) before ranking inside the subtree. Singleton via `get_rag()`. |
| `darwin/cloud_topology.py` | CTAGE: auto-discovers K8s cluster topology and IAM trust relationships into DKG nodes+edges. |
| `darwin/cloud_attack_path.py` | AttackPathReasoner: BFS path discoverers for IAM escalation, container escape, lateral movement, cross-account. |
| `darwin/data_model.py` | Typed dataclasses: `EndpointInfo`, `ServiceInfo`, `VulnerabilityInfo`, `HostInfo`, `CredentialInfo`. |
| `darwin/tools/attack_server.py` (~277K, 113 tools) | SQL injection, web fuzzing, brute force, DB clients, AD/Windows, K8s/cloud, container escape, post-exploit, knowledge search, specialized exploits. Domain filtering via `config/darwin.yaml`. |
| `darwin/tools/recon_server.py` | 15 recon tools: nmap, whatweb, dirb, gobuster, curl, form extraction, login testing. |
| `darwin/tools/mcp_gateway.py` | Tool registry with OpenAI function-calling format. Parameter aliasing (`host`→`target`, etc.). |
| `darwin/tools/mcp_client.py` | MCP client pool with per-server connection management. |
| `darwin/tools/spec.py` | Tool contract (ToolSpec): name/version/domains/capability/parameters/executor/dependencies. Every registered tool carries one (auto-derived for legacy registrations). |
| `darwin/tools/manifest.py` | `python -m darwin.tools.manifest --out tools_manifest.json [--check]` — machine-readable tool manifest + lock verification. |
| `darwin/utils/llm.py` | LiteLLM wrapper with conversation history, token counting, context compression. |
| `darwin/utils/http_client.py` | Async HTTP client with WAF probe classes and baseline comparison. |
| `darwin/utils/phase_logger.py` | Structured per-phase file logging to `log/<phase>/`. |
| `darwin/prompts/` | Role prompts: `orchestrator.py` (unified), `planner.py`, `evaluator.py`, `memory.py`, `research.py`, `dpm_classifier.py`. Planner/evaluator/memory are wired; research is a prepared asset. |
| `run.py` | CLI entry point. Bootstraps orchestrator from args. |
| `experiments/runner.py` | Experiment runner for pilot (single challenge) and CVE benchmark modes. |
| `experiments/parallel_runner.py` | Parallel runner for Docker/K8s scenarios with configurable parallelism. |
| `experiments/scenario_loader.py` | Dynamic scenario discovery from `scenarios.yaml` at `/home/kianabin/benchmark_design/benchmarks/`. |

### Operating mode

| Mode | Description |
|------|-------------|
| Solo | Single-agent LLM-driven loop — the only mode. Multi-agent dispatch (Coordinated/Distributed) and `dynamic_scaling.py` were removed in the v2 refactor (M0). |

### Knowledge collections (`knowledge/`)

4 domain subdirectories: `web/`, `windows_ad/`, `cloud/`, `network/`. Plus flat JSON files at root: `nuclei_cve_templates.json`, `web_vulnerabilities.json`, `unauth_services.json`, `advanced_exploitation.json`, `db_exploitation.json`, and converted web knowledge files.

## Key Design Decisions

1. **Solo control plane over sub-agents**: v2 removed multi-agent dispatch; discipline comes from structured Task → Executor → Evaluator → Replanner, not from spawning more agents.
2. **DKG as world state**: structured nodes/edges with provenance; the single agent reads/writes it directly — no inter-agent messaging.
3. **Defense detection cascade**: Rule → signature → LLM, LLM only for low-confidence cases.
4. **Context compression, not hard reset**: When history approaches 40% of 180K tokens, `LLMSession.compress()` summarizes older messages via LLM. DKG carries structured state across phase boundaries.
5. **RAG separation**: CTEG = dynamic cross-task experience (patterns from actual runs). DarwinRAG = static reference knowledge (attack techniques, MITRE ATT&CK). Both queried independently and merged in LLM prompt.
6. **Plan sanitization**: `_sanitize_plan_tools()` filters/rewrites tasks — tool blacklisting, automatic fallback (`_TOOL_FALLBACK`), credential placeholder resolution, port-range gating, `file://` blocking.
7. **Task failure analysis + retry**: `_analyze_and_fix_task()` classifies failures (fixable vs permanent), retries up to 2 times. Partial successes extract partial value before marking done.
8. **7 termination conditions**: Including solo exhaustion stall, no-progress detection, absent-services tracking.
9. **CTAGE/CDF cloud triad**: Cloud Topology auto-discovery → Attack Path BFS reasoning → Cloud Defense Fingerprinting.
10. **Multi-step exploit continuity**: `_extract_recent_artifacts()` injects intermediate credentials/sessions/endpoints. Context compression fallback injects structured DKG summary.
11. **Exploit task prioritization**: Container escape, K8s, cloud, post-exploit tasks run before low-confidence web probing (XSS, SQLI, IDOR).
12. **Chain mode**: `_detect_chain_topology()` auto-identifies multi-flag attack chains. Chain runner supports checkpoint & resume via `chain_state.json`.

## Testing

334 tests: DKG (incl. provenance), core v2 modules (Task, TaskGraph, Executor, Evaluator, Replanner, Capabilities, Parameters, Memory, Metrics), MCP gateway, phase logger, orchestrator main-loop smoke tests (mock LLM), and acceptance-marked failure samples (`pytest -m acceptance`).

Conventions: class-based grouping (no unittest.TestCase), edge-case coverage (`test_empty`/`test_missing`), `@pytest.mark.parametrize`, `pytest.approx` for floats, `tmp_path` for file I/O. `asyncio_mode = "auto"` configured.

## Configuration

- `config/darwin.yaml`: Time/token budgets, solo mode limits, defense probe settings, browser config, chain mode, flag pattern.
- `config/llm.yaml`: Three LLM profiles — `default`, `reasoning`, `classifier`. API keys via env var or inline.
- `config/waf_fingerprints.yaml`: ModSecurity, Cloudflare, Naxsi, Coraza signatures with bypass hints.
- `config/mcp_servers.yaml`: MCP server configurations (filesystem, brave-search, puppeteer, github, memory, sequential-thinking, ddg-search, nvd).

**Note**: `config/` is in `.gitignore` (contains API keys).

## Benchmark Infrastructure

Benchmarks have moved to `/home/kianabin/benchmark_design/benchmarks/`. The experiment runners discover scenarios dynamically from `scenarios.yaml` there (115+ scenarios + 43 attack chains across 10 domains).

```bash
python experiments/runner.py cve K8S-06 CLOUD-10          # specific scenarios
python experiments/parallel_runner.py --group k8s --parallelism 2
bash scripts/pull_benchmark_images.sh                      # pre-pull Docker images
```

Key documentation: `/home/kianabin/benchmark_design/benchmarks/BENCHMARK_SUMMARY.md`, `/home/kianabin/Darwin/BENCHMARK_SUMMARY_CLOUD_K8S.md`.

## Flag Format

`flag{...}` — matched by regex `flag\{[a-zA-Z0-9_\-]+\}`. Honeypot flags (`flag{test}`, `flag{example}`, `flag{honeypot}`) are rejected by DAVE L4.
