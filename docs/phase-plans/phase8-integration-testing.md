# Phase 8: 集成测试 + 文档 (2天)

> **Phase 1-7 修正汇总**: 
> - K8s runC 逃逸 (K8S-01/02/03) 在 KIND 容器嵌套中受宿主机内核限制，标记为需裸金属
> - Vagrant 场景 (LNX-01~04, AD-01~12) 需 Vagrant + VirtualBox，标记为 config-ready
> - Docker bind mount 必须在 `docker compose up` 前创建 flag 目录（避免 root 所有权）
> - WAF 防御层通过反向代理实现，仅适用于 Web 入口场景
> - Docker 场景 (Web/DB/LNX-05) 可完整测试验证

## 目标

对所有场景进行全量验证，集成 DARWIN experiments/runner.py，编写使用文档。

---

## 前置检查

```bash
# 确认所有 Phase 完成
find benchmarks/cve_challenges/docker -name "docker-compose.yml" | wc -l
# 预期: >= 14 (9 Web + 5 DB)
find benchmarks/cve_challenges/docker/linux -name "Vagrantfile" | wc -l
# 预期: >= 4 (LNX-01~04)
find benchmarks/cve_challenges/k8s -name "deploy.sh" | wc -l
# 预期: >= 9 (K8S-01~10)
ls benchmarks/cve_challenges/chains/web-to-da/deploy.sh
# 预期: 存在

# 确保 Python 依赖
source venv/bin/activate
pip install pytest pytest-asyncio
```

---

## Day 1: 全量场景验证

### 验证脚本: `scripts/validate-all.sh`

```bash
#!/bin/bash
# 全量场景启动/停止/漏洞验证
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RESULTS_FILE="/tmp/cve-benchmark-validation-$(date +%Y%m%d-%H%M%S).log"

echo "=== CVE Benchmark Validation ===" | tee "$RESULTS_FILE"
echo "Started at: $(date)" | tee -a "$RESULTS_FILE"

SCENARIOS=$(python3 -c "
import yaml
d = yaml.safe_load(open('$SCRIPT_DIR/scenarios.yaml'))
for sid in sorted(d['scenarios']):
    s = d['scenarios'][sid]
    if not s.get('optional'):
        print(sid)
")

PASS=0
FAIL=0
SKIP=0

for scenario_id in $SCENARIOS; do
    echo -n "[TEST] $scenario_id ... " | tee -a "$RESULTS_FILE"

    # 1. 启动场景
    if bash "$SCRIPT_DIR/start-scenario.sh" "$scenario_id" >> "$RESULTS_FILE" 2>&1; then
        sleep 5  # 等服务就绪

        # 2. 验证场景可达性
        if bash "$SCRIPT_DIR/verify-scenario.sh" "$scenario_id" >> "$RESULTS_FILE" 2>&1; then
            echo "PASS" | tee -a "$RESULTS_FILE"
            PASS=$((PASS + 1))
        else
            echo "FAIL (verification)" | tee -a "$RESULTS_FILE"
            FAIL=$((FAIL + 1))
        fi

        # 3. 停止场景
        bash "$SCRIPT_DIR/stop-scenario.sh" "$scenario_id" >> "$RESULTS_FILE" 2>&1
    else
        echo "SKIP (startup failed)" | tee -a "$RESULTS_FILE"
        SKIP=$((SKIP + 1))
    fi
done

echo "=== Results ===" | tee -a "$RESULTS_FILE"
echo "PASS: $PASS | FAIL: $FAIL | SKIP: $SKIP" | tee -a "$RESULTS_FILE"
echo "Log: $RESULTS_FILE"
```

### 逐场景手动漏洞复现验证 (至少覆盖 15 个核心场景)

```bash
# 优先级最高的验证列表 (P0: 必须成功)
P0_SCENARIOS="db-05 web-03 lnx-05 k8s-06 ad-01 web-01 web-07 k8s-01 lnx-01 ad-09 db-02 k8s-08 web-06 web-02 ad-05"

for scenario in $P0_SCENARIOS; do
  echo "=== Manually verify $scenario exploitability ==="
  ./scripts/start-scenario.sh "$scenario"

  case "$scenario" in
    db-05)
      redis-cli -h localhost -p 6379 PING && echo "DB-05: Redis reachable"
      ;;
    web-03)
      curl -sf "http://localhost:8080/wp-content/plugins/simple-file-list/" && echo "WEB-03: Plugin accessible"
      ;;
    lnx-05)
      sshpass -p password123 ssh attacker@localhost -p 2222 "sudo --version | grep 1.9.16" && echo "LNX-05: Sudo version correct"
      ;;
    k8s-06)
      kubectl get clusterrole secrets-reader && echo "K8S-06: RBAC deployed"
      ;;
    # ... 其他场景
  esac

  ./scripts/stop-scenario.sh "$scenario"
done
```

---

## Day 2: DARWIN 集成 + 文档

### 扩展 `experiments/runner.py`

```python
# experiments/runner.py 中扩展

def run_cve_benchmark_challenge(scenario_id: str, llm_config: dict):
    """对单个 CVE Benchmark 场景运行 DARWIN Orchestrator
    与 PACEBench/XBOW adapter 的接口对齐"""
    import yaml
    from darwin.orchestrator import Orchestrator

    # 读取场景配置
    with open('benchmarks/cve_challenges/scripts/scenarios.yaml') as f:
        scenarios = yaml.safe_load(f)['scenarios']

    s = scenarios[scenario_id]

    # 启动场景
    subprocess.run(s['start'], check=True)

    # 根据类型初始化 DARWIN
    orchestrator = Orchestrator(
        target_url=f"http://localhost:{s.get('port', 80)}",
        llm_config=llm_config
    )

    # 如果是 SSH/AD 入口，需要特殊处理
    if s['type'] == 'ad':
        orchestrator.set_target_credentials(
            username=s.get('ssh_user', s.get('attacker_user')),
            password=s.get('ssh_password', s.get('attacker_pass'))
        )

    # 运行
    result = orchestrator.run()

    # 验证 flag
    flag_obtained = result.get('flag')
    expected_flag_file = s.get('verify_file')
    if expected_flag_file:
        # 从目标读取 flag (根据类型使用 ssh/docker exec/kubectl exec)
        pass

    # 停止场景
    subprocess.run(s['stop'], check=True)

    return result
```

### 扩展 `ExperimentMetrics`

```python
@dataclass
class CVEExperimentMetrics(ExperimentMetrics):
    """CVE Benchmark 专用指标"""
    l1_success_rate: float = 0.0
    l2_success_rate: float = 0.0
    l3_success_rate: float = 0.0
    chain_completion_rate: float = 0.0
    partial_credit_score: float = 0.0
    defense_bypass_rate: float = 0.0
    ad_scenarios_completed: int = 0
    k8s_scenarios_completed: int = 0
    hop_count_avg: float = 0.0
    time_to_domain_admin: float = 0.0  # AD 场景特有

    def compute_cve_metrics(self):
        """计算 CVE Benchmark 特有指标"""

    def to_dict(self):
        base = super().to_dict()
        base.update({
            'l1_success_rate': self.l1_success_rate,
            'l2_success_rate': self.l2_success_rate,
            'l3_success_rate': self.l3_success_rate,
            'chain_completion_rate': self.chain_completion_rate,
            'defense_bypass_rate': self.defense_bypass_rate,
        })
        return base
```

---

### 文档

**编写 4 份文档**:

#### 1. `benchmarks/cve_challenges/README.md`
```markdown
# CVE Benchmark 总览

## 快速开始

### 启动单个场景
./scripts/start-scenario.sh <场景ID>

### 列出所有场景
./scripts/list-scenarios.sh

### 场景 ID 格式
<领域>-<编号>         例如: web-03, k8s-06, ad-01
<领域>-<编号>-<防御>  例如: web-03-waf, chain-ad-1-combined

## 领域
- web: Web 应用 (9个)
- db: 数据库 (5个)
- lnx: Linux 提权 (5个)
- k8s: Kubernetes (10个)
- ad: Active Directory (12个)
- win: Windows 服务 (3个)
- chain: 攻击链 (14条)

## 常用命令
./scripts/start-scenario.sh web-03
./scripts/start-chain.sh ad-chain-1
./scripts/reset-all.sh
```

#### 2. `docs/cve-benchmark-user-guide.md`
- 每个场景的攻击者视角描述
- DARWIN 如何对接这些场景
- 自定义新场景的指南

#### 3. `docs/cve-benchmark-results-template.md`
- 实验结果表格模板
- 与图 5/6/7 的数据收集标准

#### 4. `scenarios/` 更新 `scenarios.yaml` 最终版本
- 包含所有 51 个独立场景 + 防御变体 + 攻击链的完整注册

---

## 最终验证

```bash
cd /home/kianabin/Darwin

# 1. 全量启动验证
bash benchmarks/cve_challenges/scripts/validate-all.sh
# 预期: >= 90% PASS rate

# 2. DARWIN 对接测试
python3 -c "
from experiments.runner import ExperimentRunner
# 对 3 个场景运行快速测试 (短 budget)
runner = ExperimentRunner()
results = runner.run_benchmark('cve-mvp', challenges=['web-03', 'db-05', 'k8s-06'])
print(results.metrics)
"

# 3. 统计信息
echo "=== CVE Benchmark Statistics ==="
echo "Total scenarios: $(python3 -c "
import yaml
d=yaml.safe_load(open('benchmarks/cve_challenges/scripts/scenarios.yaml'))
print(len(d['scenarios']))
")"
echo "Docker compose files: $(find benchmarks/cve_challenges/docker -name 'docker-compose.yml' | wc -l)"
echo "Vagrant files: $(find benchmarks/cve_challenges/docker/linux -name 'Vagrantfile' | wc -l)"
echo "K8s deploy scripts: $(find benchmarks/cve_challenges/k8s -name 'deploy.sh' | wc -l)"
echo "Chain scripts: $(find benchmarks/cve_challenges/chains -name 'deploy.sh' | wc -l)"
```

---

## Phase 8 交付物

| # | 文件 | 说明 |
|---|------|------|
| 1 | `scripts/validate-all.sh` | 全量场景验证脚本 |
| 2 | `experiments/runner.py` (扩展) | DARWIN ExperimentRunner 集成 |
| 3 | `experiments/metrics.py` (扩展) | CVEExperimentMetrics |
| 4 | `benchmarks/cve_challenges/README.md` | 总览文档 |
| 5 | `docs/cve-benchmark-user-guide.md` | 使用指南 |
| 6 | `docs/cve-benchmark-results-template.md` | 实验结果模板 |
| 7 | `scripts/scenarios.yaml` (最终版) | 完整场景注册表 |

---

## 全项目交付总览

完成 8 个 Phase 后，CVE Benchmark 将包含：

| 类别 | 数量 |
|------|------|
| Web 应用场景 | 9 |
| 数据库场景 | 5 |
| Linux 提权场景 | 5 |
| K8s 场景 | 10 (9 + 1 GPU 文档) |
| AD 场景 | 12 |
| Windows 服务场景 | 3 |
| **独立场景总计** | **44** (可运行) + 1 文档 |
| 攻击链 | 14 |
| 防御变体 | 25 |
| **总挑战数** | **83** |
| Docker 镜像 | 14 种精确版本 |
| 通用脚本 | 6 个 |
| 文档 | 4 份 |
