# Known Issues

This document catalogs issues identified during codebase review (2026-05-14) that prevent DARWIN from reliably completing penetration testing tasks, even with a correctly configured LLM API.

## Critical

### 1. API Key environment variable mismatch

**Files**: `config/llm.yaml:15` vs `darwin/utils/llm.py:38`

`config/llm.yaml` references `${LLM_API_KEY}`, but `LLMSession.__init__()` writes the key to `OPENAI_API_KEY`:

```python
# utils/llm.py:38
os.environ["OPENAI_API_KEY"] = api_key
```

If the user sets `LLM_API_KEY` in their environment (as the config suggests), LiteLLM never sees it. All LLM calls fail authentication. Since `_analyze_phase()` depends on LLM output to generate vulnerability hypotheses, this halts the entire pipeline after recon.

**Fix**: Either change the config to reference `${OPENAI_API_KEY}`, or change `llm.py` to set both `OPENAI_API_KEY` and `ANTHROPIC_API_KEY`, or read the env var name from config.

### 2. No external tool existence checks

**Files**: `darwin/tools/recon_server.py`, `darwin/tools/attack_server.py`, `darwin/sub_agents/pivot_agent.py`

Recon and attack tools wrap CLI commands via `asyncio.create_subprocess_shell()`:
- `nmap`, `dirb`, `whatweb`, `curl` (recon)
- `sqlmap`, `ffuf` (attack)
- `sshpass`, `ssh` (pivot)

None of these tools are checked for existence at startup. If any are missing, subprocess calls silently return empty results. The orchestrator then operates on empty reconnaissance data — `_analyze_phase()` receives a DKG with no endpoints or services, and the LLM cannot meaningfully identify vulnerabilities from nothing.

**Fix**: Add a startup dependency check that verifies each required binary exists on `$PATH`, and report which are missing before beginning a task.

## High

### 3. Silent exception swallowing in critical paths

**Files**: `darwin/orchestrator.py:273`, `darwin/dpm.py:174`, `darwin/dave.py:87-88`

Multiple critical paths use bare `except: pass`:

- **`orchestrator.py:273`** — If the LLM returns malformed JSON during `_analyze_phase()`, the parsing error is silently swallowed. `self.vulnerabilities` remains empty, and the exploit phase has nothing to target.
- **`dpm.py:174`** — If `yaml` import fails while loading WAF fingerprints, the entire signature database is silently skipped. WAF detection degrades to rule-only without any indication.
- **`dave.py:87-88`** — If Playwright import fails during browser verification, the error is silently converted to `UNKNOWN` status.

**Fix**: At minimum, log warnings at each site. Ideally, surface these errors to the caller so the orchestrator can adapt (e.g., skip LLM-dependent analysis if the model is unavailable).

### 4. CTEG never called from the Orchestrator

**Files**: `darwin/cteg.py`, `darwin/orchestrator.py`

`CTEG.commit_task()` and `CTEG.get_suggestions()` are fully implemented but have zero call sites in `orchestrator.py`. The cross-task learning system — one of DARWIN's four core innovations — is completely inert during actual task execution.

**Fix**: Call `cteg.get_suggestions()` during `_analyze_phase()` to retrieve relevant bypass/exploit patterns from prior tasks, and call `cteg.commit_task()` after `run()` completes (success or failure) to extract patterns from the completed `TaskRecord`.

### 5. Coordinated and Distributed modes never activated

**Files**: `darwin/orchestrator.py:158`, `darwin/dynamic_scaling.py`

`Orchestrator.run()` only executes the Solo Mode path. The `_run_coordinated_cycle()` and `_run_distributed_cycle()` methods exist but are never called from `run()`. The `DynamicScalingEngine` and its hysteresis-based mode switching are implemented but unused. Every task runs as Solo regardless of complexity.

**Fix**: Integrate `DynamicScalingEngine.decide()` into the main loop so that when B ≥ 0.3, the orchestrator transitions to Coordinated or Distributed mode.

### 6. Zero tests

**Files**: `pyproject.toml:20-23`

`pytest`, `pytest-asyncio`, and `pytest-cov` are declared as dev dependencies, but the repository contains no test files. No module has any automated verification of correctness.

**Fix**: Write tests starting with the most isolated, deterministic modules: `dkg.py` (graph operations), `experiments/analysis.py` (statistical functions), `experiments/metrics.py` (metric computations).

## Medium

### 7. Duplicated `compute_task_breadth()` function

**Files**: `darwin/dkg.py:176-195`, `darwin/dynamic_scaling.py:117-139`

The B dimension computation exists identically in both files. Changes to the formula must be made in two places.

**Fix**: Remove the DKG method and have all callers use `dynamic_scaling.compute_task_breadth(dkg)`.

### 8. Hardcoded default target URLs

**Files**: Multiple locations

Several places fall back to `http://localhost:8080` or `http://localhost` when no target is specified (e.g., `benchmarks/pacebench_adapter.py:185`, `experiments/runner.py:150`). This silently papers over missing or unparseable target URLs.

### 9. In-memory-only state with no checkpointing

**Files**: `darwin/dkg.py`, `darwin/cteg.py`

Both DKG and CTEG support JSON persistence, but the orchestrator never calls `dkg.save()` during execution. A crash mid-task loses all accumulated reconnaissance and exploitation state.

### 10. No timeout or error handling for hung subprocess calls

**Files**: `darwin/tools/mcp_gateway.py:78`

The MCP gateway has a 60-second timeout for shell commands, but `tools/attack_server.py` uses `_run_shell()` with a 120-second timeout. When tools hang (network unreachable, service stuck), the orchestrator blocks until the timeout fires, with no progressive backoff or circuit breaking.

---

*Generated from codebase review of commit state at 2026-05-14.*
