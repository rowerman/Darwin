# DARWIN 架构文档

## 一、概述

DARWIN（Defense-Aware Adaptive Penetration Testing Agent Framework）是一个 LLM 驱动的自适应渗透测试 Agent 框架。核心创新点：

- **B 维度动态伸缩**：根据目标拓扑复杂度和攻击复杂度自动在 Solo/Coordinated/Distributed 三种模式间切换
- **DPM 防御感知**：三层检测（规则→WAF 指纹→LLM 分类器），检测 WAF/Cloak/Honey/Trap 并触发绕过
- **DKG 结构化通信**：Agent 间仅通过 Dynamic Knowledge Graph（NetworkX MultiDiGraph）通信，无自然语言对话
- **CTEG 跨任务学习**：抽象绕过/利用模式跨任务累积，带时间衰减
- **DAVE 四层验证**：HTTP 响应→浏览器执行→防御完整性→影响确认（含蜜罐检测）
- **LangGraph ReAct 循环**：子 Agent 的 Observe→Plan→Act→Evaluate 状态机，带 checkpointing

---

## 二、总体架构（六层）

```
Layer 0: System Prompts (Orchestrator + 3 Sub-Agent Types)
Layer 1: Orchestration (中央调度 Agent + 动态伸缩引擎)
Layer 2: Dynamic Scaling Engine (B 维度 + TDI'' + 伸缩状态机)
Layer 3: Execution (MCP Gateway + 22 Tools + LLM 工具调用)
Layer 4: Memory & Knowledge (Shared DKG + CTEG + Knowledge Base)
Layer 5: Verification (DAVE: L1 HTTP → L2 Browser → L3 Defense Integrity → L4 Impact)
```

### 实现架构（概念到代码的映射）

```
概念层                    实现组件                      关键文件
──────────────────────────────────────────────────────────────
Orchestrator Agent  →  Orchestrator 类              darwin/orchestrator.py (2704行)
Sub-Agent Pool      →  BaseSubAgent + 3 子类         darwin/sub_agents/
DKG                 →  DKG 类 (NetworkX + JSON)      darwin/dkg.py
CTEG                →  CTEG 类 (JSON 图 + RAG)       darwin/cteg.py (804行)
DPM                 →  DefensePerceptionModule       darwin/dpm.py (509行)
DAVE                →  DAVE 类                       darwin/dave.py (375行)
MCP Gateway         →  MCPGateway + 工具注册         darwin/tools/mcp_gateway.py
Dynamic Scaling     →  DynamicScalingEngine          darwin/dynamic_scaling.py (416行)
LLM Wrapper         →  LLMSession + 上下文压缩       darwin/utils/llm.py (372行)
HTTP Client         →  HTTPClient + ProbeClient      darwin/utils/http_client.py (398行)
```

---

## 三、模块详细设计

### 3.1 Orchestrator（中央调度 Agent）

**文件**: `darwin/orchestrator.py` (2704 行)

**职责**: 渗透测试全流程编排，B 维度驱动的模式切换，工具调用路由。

**核心方法**:

| 方法 | 行号 | 功能 |
|------|------|------|
| `run()` | 232 | 主入口：Recon → Login → Analyze → Main Loop → Verify |
| `_recon_phase()` | 437 | Phase 1: nmap/whatweb/dirb/nikto 侦察，写入 DKG |
| `_try_auto_login()` | 760 | 默认凭据登录，使用 HTTPClient 持久 session |
| `_analyze_phase()` | 1031 | Phase 2: LLM 分析 DKG → 漏洞假设 JSON → DKG |
| `_augment_from_dkg()` | 1427 | LLM 批量分类 nikto 发现 + 表单参数/数字路径启发式 |
| `_run_solo_cycle()` | 642 | Solo 模式：系统化 Exploit → LLM 工具调用循环（最多 10 轮）|
| `_run_multi_agent_cycle()` | ~2029 | Coordinated/Distributed：持久化 Agent Pool + DKG 监控 |
| `_systematic_exploit_pass()` | 899 | 遍历 DKG 漏洞节点→自动选工具→DAVE 验证 flag |
| `_systematic_post_check()` | ~2213 | LLM 驱动的后检查（替换硬编码 IDOR 循环）|
| `_check_response_for_flag()` | 2302 | LLM 生成 flag 路径 + 端点扫描 |

**系统提示词（5 个）**:

| 提示词 | 用途 |
|--------|------|
| `SYSTEM_PROMPT_ORCHESTRATOR` | Solo 模式主 Agent，含模式/工具/防御/绕过指南 |
| `SYSTEM_PROMPT_ANALYZE` | 漏洞分析，输出 JSON（vuln_type + suggested_tool + tool_args）|
| `SYSTEM_PROMPT_BYPASS` | WAF 绕过策略建议 |
| `SYSTEM_PROMPT_EXPLORE` | 认证后探索（自定义 header/POST body/URL IDOR）|
| `SYSTEM_PROMPT_LOGIN` | LLM 驱动的登录策略（备用）|

### 3.2 Dynamic Scaling Engine

**文件**: `darwin/dynamic_scaling.py` (416 行)

**B 维度公式**:

```
B = 0.30 × N_norm + 0.15 × M_domain + 0.20 × L_move
  + 0.20 × V_diversity + 0.15 × D_present
```

| 因素 | 含义 | 计算 |
|------|------|------|
| N_norm | 主机数归一化 | min(n_hosts/5, 1.0) |
| M_domain | 多域标志 | 1 if >1 domain else 0 |
| L_move | 横向移动需求 | 1 if internal_hosts AND credentials |
| V_diversity | 漏洞类型多样性 | min(unique_vuln_types/5, 1.0) |
| D_present | 防御存在 | 1 if defense_complexity > 0.1 |

**三种运行模式**:

| 模式 | B 阈值 | 子 Agent 数 | 适用场景 |
|------|--------|------------|----------|
| Solo | B < 0.3 | 0 | 单主机简单 Web 漏洞 |
| Coordinated | 0.3 ≤ B < 0.6 | 1-2 | 多服务利用链 / WAF 场景 |
| Distributed | B ≥ 0.6 | 3+ | 多主机横向移动 |

**TDI'' 公式**（整体任务难度评估）:

```
TDI'' = 0.20×H + 0.20×(1-E) + 0.10×C + 0.10×(1-S) + 0.15×D + 0.25×B
```

- H: Horizon（预估剩余步数）
- E: Evidence confidence（证据置信度）
- C: Context load（上下文负载）
- S: Historical success rate（历史成功率，Laplace 平滑）
- D: Defense complexity（防御复杂度）
- B: Task breadth（任务广度）

**滞后机制**: 滑动窗口（默认 2），需要连续 2 次评估一致才切换模式，防止边界震荡。

### 3.3 DKG（Dynamic Knowledge Graph）

**文件**: `darwin/dkg.py`

**技术栈**: NetworkX MultiDiGraph + JSON 持久化 + asyncio.Event 通知

**8 种节点类型**:

| 节点 | 属性 |
|------|------|
| Host | ip, os, is_reachable, is_internal |
| Service | port, protocol, version, banner |
| Endpoint | url, method, params, auth_required |
| Vulnerability | vuln_type, endpoint, parameter, severity, suggested_tool |
| Credential | user, password, type, source_host |
| Session | host, user, access_level |
| Domain | name, functional_level |
| Flag | value, location, verified |

**9 种边类型**: host_has_service, host_has_endpoint, service_has_vuln, endpoint_has_vuln, session_on_host, credential_for, host_in_domain, domain_trusts, vuln_exploited_by

**v2 新增特性**:
- asyncio.Event 通知机制：每个节点类型一个 Event，`add_node()` 触发
- `wait_for_nodes(type, min_count, timeout)` — Agent 可异步等待
- Scoped 视图：`get_scoped_view(agent_type, target_hosts)` — Agent 角色过滤
- 乐观锁：`_version` 字段 + `update_node_if_current()` — 防写入冲突
- 端点认领：`claim_endpoint()` / `is_endpoint_claimed()` — 防重复工作

### 3.4 DPM（Defense Perception Module）

**文件**: `darwin/dpm.py` (509 行)

**三层检测架构**:

| 层 | 方法 | 成本 | 检测内容 |
|----|------|------|---------|
| L1: 规则 | `_analyze_filter_behavior()` | 0 LLM | 5 类 28 探针（字符/标签/事件/协议/编码），推导 SanitizationStrategy |
| L2: 指纹 | `_match_waf_signatures()` | 0 LLM | 4 种 WAF（ModSecurity/Cloudflare/Naxsi/Coraza），响应头/体/状态码匹配 |
| L3: LLM | `_llm_classify()` | 仅在 confidence<0.8 | LLM 综合分类，输出 DefenseStateVector |

**DefenseStateVector**: WAF 类型、置信度、杀毒策略（BLACKLIST/WHITELIST/ENCODING）、严格度、防御复杂度 D 值

### 3.5 DAVE（Defense-Aware Verification Engine）

**文件**: `darwin/dave.py` (375 行)

**四层验证**:

| 层 | 方法 | 功能 |
|----|------|------|
| L1: HTTP | `_verify_http()` | 状态码检测（403/406/429）、拦截关键词、慢响应 |
| L2: Browser | `_verify_browser()` | Playwright 浏览器执行验证（可选） |
| L3: Integrity | `_verify_defense_integrity()` | Payload 反射对比：原始匹配/HTML 编码/修改检测 |
| L4: Impact | `_verify_impact()` | Flag 提取（正则）+ 9 种蜜罐 flag 拒绝 |

### 3.6 CTEG（Cross-Task Experience Graph）

**文件**: `darwin/cteg.py` (804 行)

**核心数据结构**:
- `BypassPattern`: 抽象绕过技术（机制、防御类型、漏洞类型、前置条件、半衰期 30 天）
- `ExploitPattern`: 抽象利用技术（机制、漏洞类型、所需上下文）
- `TaskRecord`: 已完成任务记录

**关键方法**:

| 方法 | 功能 |
|------|------|
| `commit_task()` | 从 TaskRecord 提取抽象模式→合并到图→持久化 |
| `get_suggestions()` | 综合 CTEG 学习模式 + 静态知识库 RAG |
| `query_rag()` | 语义搜索（SentenceTransformer）+ TF-IDF 回退 |
| `_compute_decay()` | 半衰期衰减: `0.5^(days/half_life)` |
| `prune_stale_patterns()` | 删除 90 天未使用且强化次数 <3 的模式 |

### 3.7 Sub-Agent System

**文件**: `darwin/sub_agents/base.py`, `recon_agent.py`, `exploit_agent.py`, `pivot_agent.py`

**BaseSubAgent 生命周期**:

```
SPAWNING → INITIALIZING → RUNNING → DONE/BUDGET_EXHAUSTED/STALLED/CANCELLED
```

**ReAct 循环**（LangGraph StateGraph）:

```
observe → plan → act → evaluate
   ↑                        │
   └────── continue ────────┘
              │
           end (done)
```

**三种子 Agent**:

| Agent | 工具 | 工作流 |
|-------|------|--------|
| ReconAgent | whatweb, dirb, curl_get, form_extract | Web 指纹→目录爆破→HTTP 探测→表单提取 |
| ExploitAgent | sqlmap, xss_reflection, command_injection, send_payload, ffuf | 读 DKG 漏洞→执行工具→DPM 绕过→DAVE 验证 |
| PivotAgent | ssh_exec, ssh_key_exec, test_credential | 凭证复用→SSH 连接→内网发现 |

**SubAgentPool**: 并发执行（asyncio.gather），持久化跨循环存活，增量孵化+去重

### 3.8 Tool System（MCP Gateway）

**文件**: `darwin/tools/mcp_gateway.py`, `recon_server.py`, `attack_server.py`

**22 个注册工具**:

**Recon 工具 (12)**:

| 工具 | 类型 | 功能 |
|------|------|------|
| nmap_scan | Shell | 端口扫描 (-sV -T4 --top-ports 1000) |
| nmap_full_scan | Shell | 全端口扫描 (-p-) |
| masscan_scan | Shell | 快速端口扫描 |
| dirb_scan | Shell | 目录枚举 |
| gobuster_dir | Shell | 快速目录枚举 |
| nikto_scan | Shell | Web 服务器漏洞扫描 |
| whatweb_scan | Shell | Web 技术指纹识别 |
| curl_get | Python | HTTP GET（支持 cookie/session）|
| http_post | Python | HTTP POST（支持 cookie/session）|
| form_extract | Python | HTML 表单/输入/链接提取（结构化 JSON）|
| try_login | Python | 自动登录（表单检测/两步登录/CSRF/hidden 字段）|
| idor_header_test | Python | IDOR Header 测试（X-UserId, X-User-Id × 多种 ID）|

**Attack 工具 (10)**:

| 工具 | 类型 | 功能 |
|------|------|------|
| sqlmap_test | Shell/Python | SQL 注入测试 |
| xss_reflection_test | Python | XSS 反射测试（5 种探针）|
| command_injection_test | Python | 命令注入测试（5 种探针）|
| send_payload | Python | 自定义 payload 发送（3 种编码）|
| ffuf_fuzz | Shell | Web fuzzing |
| hydra_http_brute | Shell | HTTP 密码爆破 |
| hydra_ssh_brute | Shell | SSH 密码爆破 |
| searchsploit_search | Shell | Exploit-DB 搜索 |
| smbmap_enum | Shell | SMB 共享枚举 |
| knowledge_search | Python | CTEG RAG 知识库查询 |

---

## 四、渗透测试流程

### 4.1 完整流程图

```
                         ┌─────────────────┐
                         │   run(target)    │
                         └────────┬────────┘
                                  │
                    ┌─────────────▼─────────────┐
                    │  Phase 1: Reconnaissance   │
                    │  nmap → whatweb → dirb     │
                    │  → nikto → curl → link     │
                    │  extract → DKG nodes       │
                    └─────────────┬─────────────┘
                                  │
                    ┌─────────────▼─────────────┐
                    │  Phase 1.5: Auto-Login     │
                    │  HTTPClient.auto_login()   │
                    │  默认凭据 (test:test etc.) │
                    └─────────────┬─────────────┘
                                  │
                    ┌─────────────▼─────────────┐
                    │  Phase 2: Analyze          │
                    │  LLM 分析 DKG 摘要         │
                    │  → JSON 漏洞假设            │
                    │  → _augment_from_dkg()     │
                    │  (LLM 分类 nikto 发现)     │
                    │  → DKG Vulnerability 节点  │
                    └─────────────┬─────────────┘
                                  │
                    ┌─────────────▼─────────────┐
                    │  Early Flag Check          │
                    │  _check_response_for_flag()│
                    │  LLM 生成 flag 路径        │
                    │  + 扫描已知端点            │
                    └─────────────┬─────────────┘
                                  │
                    ┌─────────────▼─────────────┐
                    │  Main Loop (max 10 iter)   │
                    │  B 维度计算 → 模式选择     │
                    └─────────────┬─────────────┘
                                  │
              ┌───────────────────┼───────────────────┐
              │                   │                   │
    ┌─────────▼──────┐  ┌────────▼───────┐  ┌────────▼──────────┐
    │   SOLO MODE    │  │  COORDINATED   │  │   DISTRIBUTED     │
    │   B < 0.3      │  │  0.3≤B<0.6    │  │   B ≥ 0.6         │
    └─────────┬──────┘  └────────┬───────┘  └────────┬──────────┘
              │                   │                   │
    ┌─────────▼──────┐  ┌────────▼───────┐  ┌────────▼──────────┐
    │ Systematic     │  │ Spawn 1-2      │  │ Spawn 3+ agents   │
    │ Exploit Pass   │  │ agents via     │  │ ReconAgent per    │
    │ (遍历 DKG vuln │  │ persistent pool│  │ host + Exploit    │
    │  自动选工具)    │  │ + DKG monitor  │  │ Agent per vuln    │
    │                │  │ + IDOR test    │  │ + PivotAgent      │
    │ IDOR Header    │  │ + Auth crawl   │  │ + DKG monitor     │
    │ Test (system-  │  └────────┬───────┘  └────────┬──────────┘
    │ atic, fresh    │           │                   │
    │ session)       │           │                   │
    │                │           │                   │
    │ Auth Crawl     │           │                   │
    │ (带 cookie     │           │                   │
    │  访问所有端点) │           │                   │
    └─────────┬──────┘           │                   │
              │                   │                   │
    ┌─────────▼──────┐           │                   │
    │ LLM Tool Loop  │           │                   │
    │ (max 10 iter)  │           │                   │
    │ LLM 接收 DKG   │           │                   │
    │ + 22 工具定义  │           │                   │
    │ → 选择工具调用  │           │                   │
    │ → 观察结果     │           │                   │
    │ → Flag 检查    │           │                   │
    └─────────┬──────┘           │                   │
              │                   │                   │
              └───────────────────┼───────────────────┘
                                  │
                    ┌─────────────▼─────────────┐
                    │  Systematic Post-Check     │
                    │  LLM 生成针对性检查        │
                    │  + Flag 最终扫描           │
                    └─────────────┬─────────────┘
                                  │
                    ┌─────────────▼─────────────┐
                    │  CTEG commit_task()        │
                    │  经验持久化                │
                    └─────────────┬─────────────┘
                                  │
                    ┌─────────────▼─────────────┐
                    │  TaskResult                │
                    │  (success, flag, steps,    │
                    │   tokens, time, defense)   │
                    └───────────────────────────┘
```

### 4.2 Solo Mode 详细流程

```
_run_solo_cycle(target_url, cteg_hints):
  │
  ├─ 1. Re-login (刷新 session)
  │
  ├─ 2. Systematic Exploit Pass
  │     ├─ 遍历 DKG Vulnerability 节点
  │     ├─ vuln_type → tool 映射 (硬编码 + LLM-suggested + generic fallback)
  │     ├─ 每个工具执行后检查 flag (DAVE L4)
  │     ├─ IDOR Header Test (session cookie 新鲜时)
  │     └─ Auth Crawl (带 session 访问所有端点)
  │
  ├─ 3. LLM Tool Loop (max 10 iterations)
  │     ├─ 构建 initial prompt (DKG 摘要 + 端点 + CTEG hints + 知识库)
  │     ├─ LLM 接收 22 个工具定义 → 选择工具
  │     ├─ 执行工具 → 结果反馈
  │     ├─ DPM 监控响应 (检测 WAF 特征)
  │     ├─ Flag 检查 (DAVE L4 验证)
  │     └─ 循环直到: flag 找到 / 时间用尽 / token 用尽 / LLM 无更多工具
  │
  └─ 4. 返回 TaskResult 或 None
```

### 4.3 Coordinated/Distributed Mode 详细流程

```
_run_multi_agent_cycle(target_url):
  │
  ├─ 1. 创建/复用持久化 SubAgentPool
  │
  ├─ 2. _spawn_agents_from_dkg()
  │     ├─ ReconAgent per host (去重)
  │     ├─ ExploitAgent per vuln type (去重, max 3)
  │     └─ PivotAgent (如有 credentials + 多主机)
  │
  ├─ 3. 后台 Flag Watcher (asyncio.Event)
  │     └─ 监控 DKG Flag 节点 → 提前终止
  │
  ├─ 4. pool.run_all() (asyncio.gather 并发)
  │     └─ 每个 Agent 独立运行 ReAct 循环
  │
  ├─ 5. 结果检查
  │     ├─ 查询 DKG Flag 节点
  │     └─ DAVE 验证
  │
  ├─ 6. _spawn_followup_agents()
  │     ├─ 新 Credential → PivotAgent
  │     ├─ 新 Internal Host → ReconAgent
  │     └─ 新 Vuln type → ExploitAgent
  │
  └─ 7. 返回 TaskResult 或 None
```

---

## 五、Agent 通信机制

```
┌─────────────────────────────────────────────────────────┐
│                     Shared DKG                          │
│                                                         │
│  ┌──────┐ ┌─────────┐ ┌──────────┐ ┌──────┐ ┌──────┐  │
│  │ Host │ │ Service │ │ Endpoint │ │ Vuln │ │ Flag │  │
│  └──────┘ └─────────┘ └──────────┘ └──────┘ └──────┘  │
│                                                         │
│  asyncio.Event per type → real-time notifications       │
│  _version per node → optimistic locking                 │
│  claim_endpoint() → dedup                               │
└─────────────────────────────────────────────────────────┘
         ▲  ▲  ▲                    │  │  │
         │  │  │   write nodes      │  │  │  read nodes
         │  │  │                    ▼  ▼  ▼
    ┌────┴──┴──┴────┐          ┌──────────────┐
    │  ReconAgent   │          │ ExploitAgent  │
    │  (per host)   │          │ (per vuln)    │
    └───────────────┘          └──────────────┘
                                     │
                                ┌────┴───────┐
                                │ PivotAgent │
                                │(per cred)  │
                                └────────────┘

Agent 间无自然语言对话 — 100% 通过结构化 DKG 节点/边通信
```

---

## 六、LLM 集成方式

### 6.1 LLM 的角色

| 阶段 | LLM 角色 | 替代方案 |
|------|---------|---------|
| Analyze | 分析 DKG 摘要→输出漏洞假设 JSON | `_augment_from_dkg()` 启发式补充 |
| Nikto 分类 | 批量分类 nikto 发现→vuln_type | 关键词 fallback |
| Solo Exploit | 接收 22 工具定义→选择工具→观察结果→迭代 | 系统化 Exploit 自动化 |
| Login | 可选：分析登录页 HTML→制定策略 | HTTPClient.auto_login() fallback |
| 后检查 | 根据上下文生成针对性检查 | 无 |
| Flag 路径 | 根据技术栈生成路径 | 默认列表 fallback |
| Bypass payload | 根据 WAF+漏洞类型生成 | CTEG + knowledge_search + 硬编码 fallback |

### 6.2 上下文压缩

当 `context_load > 0.4`（40% of 180K tokens = 72K tokens）时触发：

```
旧消息 → LLM 摘要 (5 类信息) → 单条 system 消息 → 替换旧消息
                             ↓ 失败
                    关键词提取回退 (flag/port/service/vuln/waf 等)
```

---

## 七、配置体系

| 文件 | 内容 |
|------|------|
| `config/darwin.yaml` | 时间/token 预算、Solo 限制、防御探针设置、浏览器配置、上下文压缩参数 |
| `config/llm.yaml` | 3 个 LLM 配置（default/reasoning/classifier）|
| `config/waf_fingerprints.yaml` | 4 种 WAF 签名（ModSecurity/Cloudflare/Naxsi/Coraza）|
| `config/mcp_servers.yaml` | 可选 MCP 服务器（filesystem/puppeteer/github/memory/sequential-thinking）|

### 关键参数

| 参数 | 默认值 | 说明 |
|------|--------|------|
| time_budget_seconds | 600 | 每任务最大时间 |
| token_budget | 200000 | 每任务最大 token |
| max_context_tokens | 180000 | 上下文窗口大小 |
| context_compression_threshold | 0.4 | 压缩触发比例 |
| pass_at_k | 3 | 基准测试每挑战尝试次数 |

---

## 八、设计决策

1. **动态伸缩，非固定 Agent 数**: B 维度驱动 — 简单场景 Solo（零开销），复杂场景自动孵化 Agent
2. **DKG 为唯一通信媒介**: 无 Agent 间自然语言对话 — 消除信息传递损失
3. **LLM 做决策，工具做执行**: LLM 选择策略（分析漏洞、决定凭据、选择端点），工具处理机制（表单提取、HTTP 请求、HTML 解析）
4. **防御检测三层级联**: LLM 仅在规则置信度 <0.8 时调用 — 节省成本
5. **上下文压缩，非硬重置**: 保留关键信息 — Agent 可持续运行
6. **系统化 + LLM 双路径**: 系统化 Exploit 处理已知漏洞类型（快、零 LLM 成本），LLM 循环处理未知/复杂场景

---

## 九、技术栈

| 组件 | 技术 |
|------|------|
| LLM 抽象 | LiteLLM (provider-agnostic) |
| 知识图谱 | NetworkX MultiDiGraph |
| 异步框架 | asyncio (aiohttp, asyncio.create_subprocess_shell) |
| Agent 编排 | LangGraph StateGraph (ReAct 循环 + Checkpointing) |
| 浏览器验证 | Playwright (DAVE L2, 可选) |
| 持久化 | JSON 文件 (DKG checkpoints, CTEG state) |
| 外部工具 | nmap, dirb, whatweb, curl, sqlmap, ffuf, hydra, nikto, gobuster |
