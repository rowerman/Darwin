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

1. **Network Reconnaissance** — nmap port scan discovers all open ports on the target host. If nmap is unavailable, falls back to probing the URL's port directly.
2. **HTTP Reconnaissance** — for each discovered HTTP service: whatweb technology fingerprinting, dirb directory enumeration, nikto vulnerability scan, HTML link/endpoint extraction, and form parameter discovery. All findings are written to the Dynamic Knowledge Graph (DKG).
3. **Analyze** — DKG summary fed to LLM to identify potential vulnerabilities (SQLi, XSS, CMDi, SSTI, LFI, etc.), enriched with CTEG cross-task patterns from prior runs.
4. **Exploit** — each hypothesized vulnerability is tested (sqlmap, XSS reflection, command injection), results verified through DAVE's 4-layer verification engine.
5. **Defense Bypass** — if a WAF or other defense is detected, DPM classifies it and the agent attempts bypass strategies (encoding mutation, case alternation, parameter pollution, etc.).
6. **Verify** — DAVE validates HTTP responses (L1), optionally browser execution (L2), defense integrity (L3), and flag authenticity (L4, rejecting honeypot flags).

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

## Architecture

```
Orchestrator.run() → recon → analyze → exploit → bypass → verify
                         ↓        ↓          ↓         ↓
                        DKG      LLM     DPM+DAVE   DAVE(L1-L4)
```

### Operating Modes

| Mode         | B threshold | Sub-agents | Use case                          |
|-------------|------------|------------|-----------------------------------|
| Solo        | B < 0.3    | 0          | Single-host web vulns             |
| Coordinated | 0.3 ≤ B < 0.6 | 1-2    | Multi-service exploit chains      |
| Distributed | B ≥ 0.6    | 3+         | Multi-host lateral movement       |

B = 0.4 × N_norm + 0.3 × M_domain + 0.3 × L_move

### Module Map

| Module              | Role                                                    |
|---------------------|---------------------------------------------------------|
| `orchestrator.py`   | Main loop with dynamic Solo/Coordinated/Distributed dispatch |
| `dkg.py`            | Dynamic Knowledge Graph (NetworkX) — all agent communication |
| `dpm.py`            | Defense Perception (3-layer: rule → WAF signature → LLM) |
| `dave.py`           | 4-layer verification (HTTP → Browser → Integrity → Impact) |
| `cteg.py`           | Cross-Task Experience Graph — pattern accumulation across tasks |
| `dynamic_scaling.py`| B dimension + TDI'' hysteresis for mode switching     |
| `sub_agents/`       | ReconAgent / ExploitAgent / PivotAgent                  |
| `tools/`            | MCP Gateway + recon/attack tool registrations           |
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
