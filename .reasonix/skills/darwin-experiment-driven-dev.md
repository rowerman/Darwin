---
name: darwin-experiment-driven-dev
description: DARWIN experiment-driven dev cycle — debug failures, modify orchestrator/DKG/CTEG/RAG/DPM/prompt/sub-agent code, follow Karpathy discipline, record changes to CHANGES.md
runAs: subagent
---
# DARWIN Experiment-Driven Development

You are helping debug and develop the DARWIN penetration testing framework. Follow these rules.

## Three Core Principles

### Principle 1: Generality First
Code changes must make the framework stronger generally, NOT to pass a specific target. FORBIDDEN:
- Hardcoded ports, paths, filenames (e.g. `/flag.txt`, `:10103`)
- Special-case branches for specific CVEs (e.g. `if "wpbookit" in url: ...`)
- Target info leaked into prompts
- Special parsing for one target's output format

Verify every change with 2+ different target types.

### Principle 2: Tools Before Orchestration
When the LLM can't capture a flag, investigate in this order:
1. **Tool layer** — Does the agent have the right tools? Is the tool registered in recon_server/attack_server? Is output parsing complete?
2. **Knowledge layer** — Did RAG hit relevant knowledge? Did CTEG provide useful history?
3. **Orchestration layer** — Is the Solo/Coordinated/Distributed mode choice correct? Is the Plan-Act-Observe loop correct?
4. **Prompt layer** — Last resort. Prompt adjustments are the least reliable fix.

### Principle 3: Karpathy Discipline
1. Think Before Coding — find root cause, don't guess.
2. Simplicity First — 50 lines over 200. No abstractions for single-use code.
3. Surgical Changes — only touch what must change. No adjacent refactoring.
4. Goal-Driven — every change needs verifiable success criteria.

### Principle 4: Record Every Change
After ALL code modifications, append a summary to CHANGES.md at project root:
```markdown
## YYYY-MM-DD
- **file**: description. reason/effect
```
One line per change, grouped by module. Brief is fine.

## Workflow
```
START → [1. Select target & start] → [2. Run experiment] 
         → success → [6. Next target, record generalization]
         → failure → [3. Collect evidence] → [4. Diagnose] → [5. Modify code] → [6. Verify & next]
```

## Module Dependency Map

Key locations:
- `orchestrator.py` — Central dispatch (~7258 lines). `run()` → Solo/Coordinated/Distributed. `_bootstrap_scan` is the common entry point for all 3 modes.
- `dkg.py` — Dynamic Knowledge Graph (NetworkX MultiDiGraph). 8 node types, 9 edge types. asyncio.Event notifications.
- `dpm.py` — Defense Perception (3-layer: rule → WAF signature → LLM). Max 6 GET probes.
- `dave.py` — 4-layer verification (L1 HTTP → L2 Browser → L3 Integrity → L4 Impact). L3 doesn't short-circuit L4.
- `cteg.py` — Cross-Task Experience Graph. pattern accumulation with time-based decay.
- `dynamic_scaling.py` — B dimension calculation + TDI'' hysteresis (2 votes for mode switch).
- `rag.py` — SentenceTransformer + Faiss. Preloaded via `asyncio.create_task(asyncio.to_thread(get_rag))` at startup (~45s parallel with bootstrap).
- `utils/llm.py` — LiteLLM wrapper. Context compression max 3 times, then truncation.

### Solo prompt architecture (Layer 0):
- `darwin/prompts/orchestrator.py` — `SYSTEM_PROMPT_ORCHESTRATOR_UNIFIED` is the ONLY active orchestrator prompt (legacy `SYSTEM_PROMPT_ORCHESTRATOR` is deprecated). All 6 code paths use UNIFIED.
- Individual agent prompts in `darwin/prompts/*.py`.

### Tool layer:
- `tools/recon_server.py` → `register_recon_tools()` — 12 recon tools
- `tools/attack_server.py` → `register_attack_tools()` — 35 attack tools
- `tools/mcp_gateway.py` — auto-fills parameter defaults

### Investigation priority when LLM uses wrong tool names:
1. Is it registered in the server? (recon_server or attack_server)
2. Is it listed in the prompt template?
3. Framework has `get_close_matches()` validation — near-misses auto-correct, unknown names trigger re-prompt

## Diagnosis Decision Tree

Key symptoms and where to look (refer to the full tree in the original SKILL.md for details):

| Symptom | First check |
|---------|-------------|
| nmap no results / missing ports | port_range config, Docker network, _NON_HTTP_PORTS filtering in _bootstrap_scan |
| LLM calls nonexistent tool | tool registration + prompt template |
| Tool succeeds but LLM ignores output | output parser truncation, context compression hits, tool_calls handler |
| Solo works, Multi-agent broken (or vice versa) | mode dispatch in orchestrator, agent spawn conditions |
| Multi-agent sub-agent timeout | SubAgentPool lifecycle, asyncio.Event in DKG |
| Flag verification fails (L4) | DAVE flag regex, honeypot detection |
| Defect detection wrong (DPM) | probe endpoints, waf_fingerprints.yaml, classifier prompt |
| CTEG/RAG not helpful | query format, collection selection, knowledge_search tool |

## Verification Checklist
After every fix:
- [ ] Original failing target now passes?
- [ ] At least 1 different type of target runs cleanly (no regression)?
- [ ] If Solo mode fix → Multi-agent also OK?
- [ ] If Multi-agent fix → Solo also OK?
- [ ] After 3 same-type targets pass → move to more complex scenario types
- [ ] Record verification results in commit message: "verified: web-03 + db-05 both pass"

## Project Context
- Working directory: `/home/kianabin/Darwin`
- Benchmark infrastructure: `/home/kianabin/benchmark_design/benchmarks/`
- CVE challenges: `/home/kianabin/benchmark_design/benchmarks/cve_challenges/`
- Test targets start via: `cd /home/kianabin/benchmark_design/benchmarks/cve_challenges && ./scripts/start-scenario.sh <scenario-id>`
- Run experiments via: `cd /home/kianabin/Darwin && source venv/bin/activate && python run.py http://127.0.0.1:<port>`
- All code modifications must be recorded in CHANGES.md at project root.
