# Plan: Automated Comparative Experiments (DARWIN vs PentestAgent)

## Context

User wants to run automated experiments comparing DARWIN against PentestAgent across three benchmarks (Custom Defense, PACEBench, XBOW), recording per-challenge and aggregate metrics per the experiment design in `plan/DARWIN_framework.md`.

**Current reality:** Only Custom Defense (20 local challenges) is immediately runnable. PACEBench and XBOW require Docker challenge containers not yet deployed.

## Scope

### Phase A: Custom Defense — Immediately Runnable (20 challenges)

Run DARWIN and PentestAgent against all 20 Custom Defense challenges, producing:
- Per-challenge: success/fail, flag, tokens, time, defense_detected, waf_bypassed
- Aggregate: TSR, Pass@k, token efficiency, defense detection rate, waf bypass rate
- Per-category breakdown (Cloak/Honey/Trap/Combined)
- Statistical comparison: McNemar's test (paired per-challenge), Cohen's g

### Phase B: PACEBench + XBOW — After Docker Setup

Same pipeline, extended to PACEBench (32) and XBOW (104) once Docker challenges are deployed.

## Implementation Plan

### Step 1: Unified Experiment Runner

Create `experiments/comparative_runner.py` that:

```
comparative_runner.py
  ├─ load challenge list from benchmark module
  ├─ for each challenge:
  │    ├─ start challenge server
  │    ├─ run DARWIN: orchestrator.run(target, task) → TaskResult
  │    ├─ run PentestAgent: subprocess pentestagent run -t target → parse output
  │    └─ record both results
  ├─ compute per-challenge comparison (McNemar pairs)
  ├─ compute aggregate metrics per framework
  └─ write results to experiment_results/comparative/
```

**Files to create/modify:**
- `experiments/comparative_runner.py` — main experiment runner
- Extend `experiments/metrics.py` — add per-pair comparison fields

### Step 2: Result Schema

Each run produces:

```json
{
  "experiment_id": "custom_defense_20260515",
  "benchmark": "CustomDefense",
  "challenge_id": "cloak-01",
  "defense_type": "cloak",
  "vuln_type": "sqli_login",
  "darwin": {
    "success": true, "flag": "flag{...}", "steps": 5,
    "tokens_used": 1234, "time_elapsed": 45.2,
    "defense_detected": true, "waf_bypassed": true
  },
  "pentest_agent": {
    "success": false, "flag": "", "steps": 0,
    "tokens_used": 890, "time_elapsed": 60.0,
    "error": "Timeout"
  }
}
```

### Step 3: Aggregate Metrics

Per-framework, per-category:

| Metric | Formula |
|--------|---------|
| TSR | successes / total |
| Pass@k | any(success in first k attempts) |
| Token efficiency | successes / (tokens/1000) |
| Defense detection rate | defenses_found / defenses_present |
| WAF bypass rate | bypasses / waf_challenges |
| Avg time | total_time / total_challenges |

Statistical tests:
- **McNemar**: paired binary (DARWIN pass, PA pass) per challenge
- **Cohen's g**: effect size per category
- Output as JSON + plain-text summary table

### Step 4: Prerequisites

Before running:

```bash
# 1. PentestAgent must be installed
cd /home/kianabin/pentestagent
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
echo 'PENTESTAGENT_MODEL=deepseek-v4-pro' > .env

# 2. DARWIN venv must be active with LLM config valid
cd /home/kianabin/Darwin
source venv/bin/activate
# Verify: python3 smoke_test.py http://localhost:8080

# 3. Run experiments
python3 experiments/comparative_runner.py                    # all 20
python3 experiments/comparative_runner.py --category cloak   # 5 Cloak only
python3 experiments/comparative_runner.py cloak-01            # single
```

### Step 5: Output Files

```
experiment_results/comparative/
  ├── custom_defense_20260515_150000/
  │   ├── summary.json           # aggregate metrics
  │   ├── paired_results.json    # per-challenge pairs with McNemar
  │   ├── darwin/
  │   │   ├── cloak-01.json      # DARWIN task log
  │   │   └── ...
  │   └── pentest_agent/
  │       ├── cloak-01.json      # PentestAgent output
  │       └── ...
  └── ...
```

## What Cannot Be Done Yet

| Item | Blocker | Resolution |
|------|---------|------------|
| PACEBench experiments | Docker challenges not deployed | Deploy from `paper_analysis/PACEBench/` |
| XBOW experiments | Docker challenges not deployed | Deploy from XBOW validation-benchmarks |
| RQ3 (CTEG learning curve) | Needs 100 XBOW challenges | After XBOW setup |
| RQ5 (DKG communication) | Needs multi-host challenges (B-CVE, C-CVE) | After PACEBench setup |

## Execution Order

```
1. Build comparative_runner.py           (~30 min)
2. Set up PentestAgent venv + config     (~10 min, user does)
3. Run RQ1 subset on Custom Defense      (20 challenges × 2 frameworks × 1 pass = ~40 runs)
4. Review results, fix issues
5. Extend to PACEBench after Docker setup
6. Extend to XBOW after Docker setup
```
