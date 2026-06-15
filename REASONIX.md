# REASONIX.md — DARWIN

## Stack

- **Language:** Python 3.10+
- **Agent orchestration:** LangGraph StateGraph with asyncio
- **LLM dispatch:** LiteLLM (multi-provider: OpenAI, Anthropic, DeepSeek, Gemini)
- **Key deps:** litellm, networkx (MultiDiGraph — agent comms via DKG), pydantic, aiohttp, playwright (browser verification)
- **RAG:** sentence-transformers (`all-MiniLM-L6-v2`) + Faiss IndexFlatIP — **NOT in pyproject.toml** (install manually)

## Layout

| Path | What lives there |
|------|------------------|
| `darwin/` | Core modules — orchestrator, DKG, DPM, DAVE, CTEG, sub-agents, tools, utils |
| `experiments/` | Benchmark runner, parallel runner, metrics, scenario loader, lifecycle manager |
| `tests/` | Unit tests (pytest-asyncio, `asyncio_mode = auto`) |
| `knowledge/` | Static knowledge collections for DarwinRAG (web, network, windows_ad, cloud) |
| `tools/` | Knowledge ingestion / conversion scripts (`ingest_knowledge.py`, `convert_nuclei.py`) |
| `config/` | YAML configs — **gitignored**, contains API keys |
| `checkpoints/` | Runtime results — **gitignored** |
| `plans/` | Design docs / implementation plans (not source code) |
| `scripts/` | Utility shell scripts (`pull_benchmark_images.sh`) |
| `wordlists/` | CMS / directory fuzzing wordlists |

## Commands

```
pip install -e ".[dev]"          # install + dev deps
pytest tests/ -v                  # run tests (no @pytest.mark.asyncio needed)
pytest tests/ -v --cov=darwin --cov=experiments --cov-report=term  # with coverage
python run.py <target>            # CLI entry — IP, hostname, or URL
python experiments/runner.py      # benchmark mode (pilot or CVE)
python experiments/parallel_runner.py  # parallel benchmark runner
python tools/ingest_knowledge.py  # ingest .json/.md into DarwinRAG
python tools/convert_nuclei.py    # convert nuclei-templates YAML → knowledge JSON
```

## Conventions

- **Tests:** `tests/` directory, class-based test groups with docstrings, `asyncio_mode = auto` in pyproject.toml (no `@pytest.mark.asyncio` decorator needed).
- **Imports:** Standard lib first, then third-party, then local (`darwin.*`) — visible in `run.py`.
- **Naming:** `snake_case` for functions/vars, `PascalCase` for classes, `SCREAMING_SNAKE_CASE` for constants (NODE_TYPES, EDGE_TYPES in dkg).
- **Flag format:** `flag{...}` matched by regex `flag\{[a-zA-Z0-9_\-!@#$%^&*()+=]+\}`. Honeypot flags (`flag{test}`, `flag{example}`, `flag{honeypot}`) rejected by DAVE L4.
- **LLM config:** Three profiles in `config/llm.yaml` — `default`, `reasoning`, `classifier` — each with provider/model/temperature.
- **orch linecount:** `orchestrator.py` is ~7258 lines — largest file. `_unified_llm_loop()` (Solo mode) / `_run_multi_agent_cycle()` (Coordinated/Distributed) are the main dispatch paths.

## Watch out for

- **RAG deps missing from pyproject.toml** — `sentence-transformers` and `faiss-cpu` must be installed manually if DarwinRAG is needed.
- **External CLI tools on $PATH** — nmap, dirb, whatweb, curl, sqlmap, ffuf, sshpass, wpscan, netexec, impacket-*, kubectl. Orchestrator warns at startup if missing.
- **`tools/tools_open/`** — gitignored external Go/Python cloud-escape binaries (botb, ccat, CDK, peirates, veinmind-tools). Must be built/downloaded separately.
- **`config/` is gitignored** — API keys and `llm.yaml` live here. New clones need `config/llm.yaml` created before running.
- **`multi_edit` won't accept edits to files not `read_file`'d this session** — Always read before editing. SEARCH text must match on-disk bytes exactly.
