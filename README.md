# DARWIN

Defense-Aware Adaptive Penetration Testing Agent Framework.

## Quick Start

### 1. Set API Key

```bash
export DEEPSEEK_API_KEY="your-api-key-here"
```

Edit `config/llm.yaml` to match your provider and model. Set `api_key` to `""` (empty) so the env var is used instead of a hardcoded key.

| Provider   | Env Var              |
|-----------|----------------------|
| openai    | `OPENAI_API_KEY`     |
| anthropic | `ANTHROPIC_API_KEY`  |
| deepseek  | `DEEPSEEK_API_KEY`   |
| gemini    | `GEMINI_API_KEY`     |

### 2. Install Dependencies

```bash
cd /home/kianabin/Darwin

# Install pip if missing
sudo apt-get install -y python3-pip

# Install project + dev dependencies
pip install -e ".[dev]"

# Install Playwright browser for DAVE L2 verification
playwright install chromium
```

### 3. Install External Tools

The recon and attack tools wrap CLI commands. These must be on `$PATH`:

```bash
sudo apt-get install -y nmap dirb whatweb curl sqlmap ffuf sshpass
# Optional: exploitdb (provides searchsploit for CVE lookup)
sudo apt-get install -y exploitdb 2>/dev/null || echo "searchsploit not available — this is optional"

```

The orchestrator checks for these at startup and warns if any are missing.

### 4. Run Against a Target

```bash
# Scan an IP or hostname — nmap discovers all ports automatically
python run.py 192.168.1.100
python run.py example.com

# Or a full URL if you know the exact target
python run.py http://192.168.1.100:8080
```

No need to guess the port. DARWIN runs nmap against the target to discover all open ports, then probes each HTTP service automatically. If nmap is unavailable, it falls back to scanning a set of common HTTP ports (80, 443, 8080, 8443, 3000, 5000, 8000, 8888, 9090).

**What happens during a run:**

1. **Bootstrap reconnaissance** — nmap discovers open ports on the target host (with a common-HTTP-port fallback when nmap is unavailable); each HTTP service is probed and findings are written to the Dynamic Knowledge Graph (DKG).
2. **LLM-driven plan & execute loop** — the LLM builds/updates an exploitation plan; every task is consumed as a structured `Task` and executed by the Task-based Executor (strict tool dispatch through `darwin/core/`), with rule-based failure classification, local replanning, capability/tool-parameter validation, and CTEG cross-task hints.
3. **Defense handling** — if a WAF or other defense is detected, DPM classifies it and the agent attempts bypass strategies (encoding mutation, case alternation, parameter pollution, etc.).
4. **Verification** — DAVE validates HTTP responses (L1), optionally browser execution (L2), defense integrity (L3), and flag authenticity (L4, rejecting honeypot flags).

Results and checkpoints are written to the `checkpoints/` directory. Cross-task patterns accumulate in `cteg_state.json`.

**Note:** MCP servers configured in `config/mcp_servers.yaml` are optional — the agent connects to them on startup with a short timeout, but operates fully without them.

**Example output:**

```
Target: http://localhost:8080
Loading LLM config from config/llm.yaml ...
Provider: deepseek, Model: deepseek/deepseek-v4-pro
Starting penetration test ...

nmap: 2 open ports on localhost
whatweb http://localhost:8080: PHP, Apache, jQuery
dirb http://localhost:8080: 8 paths
nikto http://localhost:8080: 3 findings

==================================================
Success:        True
Flag:           flag{test_vuln_2026}
Steps:          4
Tokens used:    18450
Time elapsed:   52.3s
Defense found:  False
WAF bypassed:   False
==================================================
```

### 5. Run Tests

```bash
# Run all unit tests
pytest tests/ -v

# Milestone acceptance / failure-sample regression tests
pytest tests/ -m acceptance -v

# Run tests with coverage
pytest tests/ -v --cov=darwin --cov=experiments --cov-report=term
```

## Configuration

### `config/darwin.yaml`

Time/token budgets, solo mode limits, defense probe settings, browser config, and context compression parameters:

| Parameter | Default | Description |
|-----------|---------|-------------|
| `time_budget_seconds` | 600 | Max time per task (10 minutes) |
| `token_budget` | 200000 | Max tokens per task |
| `max_context_tokens` | 180000 | Token count considered 100% context load |
| `context_compression_threshold` | 0.4 | Trigger compression at 40% context load |
| `pass_at_k` | 3 | Attempts per challenge (benchmark mode) |
| `log_thoughts` | true | Record each LLM call's chain of thought per stage to `log/thought/` (JSONL + readable log). DeepSeek returns full thinking text; GPT-series returns reasoning summaries via LiteLLM |

### `config/llm.yaml`

Three profiles: `default`, `reasoning`, `classifier`. Each specifies provider, model, api_key, temperature, max_tokens.

### `config/waf_fingerprints.yaml`

WAF detection signatures (ModSecurity, Cloudflare, Naxsi, Coraza) with bypass hints.

### `config/mcp_servers.yaml`

Optional MCP server configurations for external tool servers.

## Benchmark Mode

For formal benchmark evaluation (PACEBench, XBOW):

```bash
# Start PACEBench adapter server (port 8000)
python benchmarks/pacebench_adapter.py

# Run pilot experiment (single PACEBench D-CVE challenge)
python experiments/runner.py
```

The experiment runner (`experiments/runner.py`) orchestrates multiple challenges with Pass@k evaluation, metrics computation (TSR, token efficiency, WAF bypass rate), and statistical analysis.

## Tool Contract & Hierarchical Knowledge

Darwin v0.2+ standardizes every tool behind a machine-checkable contract
(`darwin/tools/spec.py`) and organizes static knowledge as an explicit
taxonomy with two-stage retrieval (`darwin/rag.py`).

```bash
# Tool contract: regenerate / verify the committed manifest (130 tools)
python -m darwin.tools.manifest --out tools_manifest.json
python -m darwin.tools.manifest --out tools_manifest.json --check

# Knowledge taxonomy: ingest the benchmark GUIDE leaves, rebuild taxonomy
python tools/ingest_benchmark_guides.py
python tools/build_taxonomy.py

# A/B evaluate flat RAG vs hierarchical retrieval (89 benchmark queries)
python -m tools.eval_knowledge_retrieval

# Coverage audit: taxonomy leaves -> tools / capabilities / knowledge
python -m tools.audit_coverage
```

See `PLAN_TOOL_CONTRACT_AND_KNOWLEDGE.md` for the design and status.

## Architecture

```
Orchestrator.run()
      ↓
bootstrap recon → DKG world state
      ↓
_unified_llm_loop: plan → Task → Executor → evaluate → replan
      ↓
DPM defense handling / DAVE flag verification
```

Darwin v2 is a single-agent control plane: the LLM decides (plans structured
Tasks), the system executes (the Executor consumes Tasks through the
Capability layer), and Memory/Metrics keep the loop observable.

### Operating Mode

| Mode | Description |
|------|-------------|
| Solo | Single-agent LLM-driven loop for single-host/multi-service targets. The only mode — multi-agent dispatch (Coordinated/Distributed) was removed in the v2 refactor. |

### Module Map

| Module              | Role                                                    |
|---------------------|---------------------------------------------------------|
| `darwin/orchestrator.py` | Unified LLM main loop — plan → execute → evaluate → replan (Solo) |
| `darwin/core/`      | v2 control plane: Task model, TaskGraph, Executor, Evaluator, Replanner, Capabilities, Parameter validation, Memory, Metrics |
| `dkg.py`            | Dynamic Knowledge Graph (NetworkX) — world state with provenance |
| `dpm.py`            | Defense Perception (3-layer: rule → WAF signature → LLM) |
| `dave.py`           | 4-layer verification (HTTP → Browser → Integrity → Impact) |
| `cteg.py`           | Cross-Task Experience Graph — pattern accumulation across tasks |
| `tools/`            | MCP Gateway + recon/attack tool registrations           |
| `prompts/`          | Role prompts: orchestrator (unified), planner, evaluator, memory, research |
| `utils/llm.py`      | LiteLLM wrapper with context compression               |
| `utils/http_client.py` | Async HTTP client with A-E WAF probe classes          |

### Flag Format

`flag{...}` — matched by regex `flag\{[a-zA-Z0-9_\-!@#$%^&*()+=]+\}`.
Honeypot flags (`flag{test}`, `flag{example}`, `flag{honeypot}`) are rejected by DAVE L4.

## Test Target

For quick testing, start a simple HTTP server with a flag endpoint:

```bash
python3 -c "
from http.server import HTTPServer, BaseHTTPRequestHandler
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if 'flag' in self.path:
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'flag{test_vuln_2026}')
        else:
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'<html><form action=\"/login\"><input name=\"user\"></form></html>')
HTTPServer(('', 8080), Handler).serve_forever()
" &
```

Then run: `python run.py localhost:8080`
