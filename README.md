# DARWIN

Defense-Aware Adaptive Penetration Testing Agent Framework.

## Quick Start

### 1. Set API Key

```bash
export DEEPSEEK_API_KEY="your-api-key-here"
```

Edit `config/llm.yaml` to match your provider and model. Set `api_key` to `""` (empty) so the env var is used instead of a hardcoded key.

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
```

The orchestrator checks for these at startup and warns if any are missing.

### 4. Start a Test Target

The experiment runner expects a vulnerable web application at a target URL. For quick testing:

```bash
# Start a simple HTTP server with a flag endpoint
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

For real benchmarks (PACEBench, XBOW), deploy the Docker containers from `paper_analysis/`.

### 5. Run

```bash
# Run unit tests
pytest tests/ -v

# Run pilot experiment (single PACEBench D-CVE challenge)
python3 experiments/runner.py

# Start PACEBench adapter server for benchmark integration
python3 benchmarks/pacebench_adapter.py  # port 8000
```

## Configuration

### `config/llm.yaml`

Three profiles: `default`, `reasoning`, `classifier`. Each specifies provider, model, api_key, temperature, max_tokens. Set `api_key` to `""` and use environment variables instead:

| Provider   | Env Var              |
|-----------|----------------------|
| openai    | `OPENAI_API_KEY`     |
| anthropic | `ANTHROPIC_API_KEY`  |
| deepseek  | `DEEPSEEK_API_KEY`   |
| gemini    | `GEMINI_API_KEY`     |

### `config/darwin.yaml`

Time/token budgets, solo mode limits, defense probe settings, browser config.

### `config/waf_fingerprints.yaml`

WAF detection signatures (ModSecurity, Cloudflare, Naxsi, Coraza) with bypass hints.

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
| `utils/llm.py`      | LiteLLM wrapper with per-provider API key support       |
| `utils/http_client.py` | Async HTTP client with A-E WAF probe classes          |

### Flag Format

`flag{...}` — matched by regex `flag\{[a-zA-Z0-9_\-!@#$%^&*()+=]+\}`.
Honeypot flags (`flag{test}`, `flag{example}`, `flag{honeypot}`) are rejected by DAVE L4.

## Development

```bash
# Run tests with coverage
pytest tests/ -v --cov=darwin --cov=experiments --cov-report=term

# Syntax check all modules
python3 -c "
import py_compile, os
for root, dirs, files in os.walk('darwin'):
    for f in files:
        if f.endswith('.py'):
            py_compile.compile(os.path.join(root, f), doraise=True)
print('All OK')
"
```
