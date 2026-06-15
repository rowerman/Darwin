---
name: darwin-experiment-driven-dev
description: Use when debugging DARWIN experiment failures, modifying orchestrator/DKG/CTEG/RAG/DPM/prompt/sub-agent code, analyzing why an LLM-driven pentest didn't capture a flag, adding tools to recon_server or attack_server, using web-search for exploitation research, changing Solo/Multi-agent mode behavior, or working with new domains (CLOUD IAM/IMDS/cross-account, CI/CD pipeline, kernel exploits/eBPF, network attacks) in the DARWIN penetration testing framework
---

# DARWIN Experiment-Driven Development

## Overview

以"启动靶机 → 运行实验 → 诊断失败 → 修改代码 → 验证修复 → 换靶机"为主循环的开发调试 skill。在每个阶段提供架构感知提醒和诊断指导，确保修改代码时保持对 DARWIN 整体架构的清晰认知。

## 三条核心原则

### 原则 1：泛用性优先

修改代码是为了让框架更强，不是为了通过某个特定靶机。以下修改是禁区：

- 硬编码特定端口、路径、文件名（如 `/flag.txt`、`:10103`）
- 为特定 CVE 添加特殊处理分支（如 `if "wpbookit" in url: ...`）
- 在 prompt 中透露靶机信息（如 "this is WordPress"）
- 针对某个靶机的输出格式做特殊解析

如果一段修改只在场景 A 下生效但在场景 B 下无意义，那就是错的。正确做法：修改后至少用 2 个不同类型的靶机验证。

### 原则 2：工具优先于编排

当 LLM 无法攻破靶机时，按以下顺序排查：

1. **工具层** — agent 有正确的工具吗？recon_server 有没有注册需要的扫描器？attack_server 有没有对应的利用工具？工具的输出解析是否完整？
2. **知识层** — RAG 有没有命中相关知识？CTEG 有没有提供有用的历史经验？
3. **编排层** — Solo/Coordinated/Distributed 模式选择对吗？agent 的 Plan-Act-Observe 循环逻辑对吗？
4. **Prompt 层** — 最后才怀疑 prompt。prompt 调整是最不可靠的修复手段。

### 原则 3：Karpathy 修改纪律

1. **Think Before Coding** — 不确定的假设先说出来。先定位根因，不猜。
2. **Simplicity First** — 能用 50 行解决的问题不写 200 行。不给单一用途的代码加抽象层。不添加未被要求的功能。
3. **Surgical Changes** — 只动必须动的代码。不改旁边的、不重构不相干的、不顺手"优化"。匹配已有代码风格。
4. **Goal-Driven Execution** — 每个修改必须有可验证的成功标准。多步骤任务先陈述计划再执行。

### 原则 4：修改必记录

**所有对代码的修改结束后，必须将修改摘要写入项目根目录 `CHANGES.md`。** 格式要求：
- 在文件顶部添加日期标题（如 `## 2026-05-30`）
- 每条修改一行：`- **文件**: 变更描述。原因/效果`
- 如果修改涉及多个文件，按模块分组
- 不要求冗长——每条 1-2 行即可，重点是让后续 session 能快速了解改动历史

---

## 核心工作流

```
START
  │
  ▼
[1. 选择靶机 & 启动]  ←── 参考：/home/kianabin/benchmark_design/benchmarks/cve_challenges/README.md
  │
  ▼
[2. 运行实验]  ←── 参考：模块依赖地图（理解 run.py → Orchestrator 的数据流）
  │
  ├── 成功 → [6. 换下一个靶机，记录泛化验证结果]
  │
  └── 失败 → [3. 收集失败证据]
                │
                ▼
             [4. 诊断决策树]  ←── 参考：模块依赖地图（定位根因模块）
                │
                ▼
             [5. 修改代码]  ←── 参考：模块依赖地图 + Karpathy 方法论
                │
                ▼
             [6. 验证修复 & 换靶机]  ←── 参考：验证检查清单
```

### 阶段 1：选择靶机 & 启动

启动命令：
```bash
cd /home/kianabin/benchmark_design/benchmarks/cve_challenges
./scripts/start-scenario.sh <scenario-id>
docker ps --format "table {{.Names}}\t{{.Ports}}" | grep <scenario-id>
```

**参考文档**：
- `/home/kianabin/benchmark_design/benchmarks/cve_challenges/README.md` — 场景总览（115+ 场景 + 43 条攻击链，覆盖 10 个领域）
- `/home/kianabin/benchmark_design/benchmarks/cve_challenges/docs/LEARNING_PATH.md` — 按难度和攻击路径的场景推荐
- `/home/kianabin/benchmark_design/benchmarks/cve_challenges/docs/scenarios/` — 逐个场景详细利用流程（K8s/AD/Web/DB/Linux/Cloud 共 70+ 文档）
- `/home/kianabin/benchmark_design/benchmarks/cve_challenges/docs/chains/` — 每条攻击链的完整利用步骤
- `/home/kianabin/benchmark_design/benchmarks/CLAUDE.md` — Benchmark 架构和操作指南
- `/home/kianabin/benchmark_design/benchmarks/BENCHMARK_SUMMARY.md` — 最详尽的利用命令参考
- `/home/kianabin/benchmark_design/benchmarks/BENCHMARK_SCENARIOS_OVERVIEW.md` — 场景一览表

选靶机顺序建议（从简单到复杂，渐进发现框架泛化问题）：
1. **L1 Web 基础**（web-03 WordPress, web-04 WPBookit）→ Solo 模式基础链路
2. **L2 Web + 新漏洞类型**（web-01 Tomcat, web-02 Tomcat Race, web-10 SSRF, web-12 SSTI）→ 多步骤利用 + SSRF/SSTI
3. **L1 DB + NoSQL**（db-05 Redis, db-06 MongoDB）→ 非 HTTP + NoSQL
4. **Defense 变体**（DEF-01~05：WAF + Process Hiding + Anti-Forensics + LOTL）→ DPM 检测和 bypass
5. **L2 DB**（db-01~04 SQL, db-07 Elasticsearch, db-08 CouchDB）→ 数据库利用多样性
6. **Linux 提权 + 内核**（LNX-05~13: SUID/Docker socket/CAP/Cron/Polkit/LD_PRELOAD; LKX-01~05: kernel UAF/eBPF/Dirty Pipe）→ 后渗透 + 内核 exploit
7. **CI/CD**（CI-01~05：Poisoned Pipeline/.git/Secrets/Webhook/Build Arg）→ 供应链攻击面
8. **NET 网络攻击**（NET-01~03：ARP spoofing/DNS exfil/Container sniffing）→ 网络层横向移动
9. **K8s 全场景**（29 个：容器逃逸 + RBAC + 网络攻击 + Node Selector/Toleration/CNI spoof）→ CloudAgent + multi-agent
10. **AD 全场景**（16 个 Samba-compatible：经典 + 高级 DACL + Cross-Forest/AdminSDHolder 持久化）→ ADAgent
11. **CLOUD 全场景**（22 个：IMDS/跨账号/联合身份/Lambda PassRole/S3 独占/Notebook 逃逸/OIDC/SCP 绕过等）→ Cloud 渗透
12. **攻击链全类型**（43 条：纯 K8s + 纯 AD + Web→DB + Web→Cloud + DB→Cloud + Cloud→Cloud 跨账号 + Cross-Forest AD）→ 跨域 + 跨账号

### 阶段 2：运行实验

```bash
cd /home/kianabin/Darwin && source venv/bin/activate
python run.py http://127.0.0.1:<port>
```

也可通过 experiments/runner.py 运行 CVE benchmark：
```bash
python experiments/runner.py cve <scenario-id>
```

默认配置：time_budget=1200s, token_budget=200000。benchmark 模式下可通过 `port_range` 参数限制扫描范围。

**运行前自问**：
- 这次实验要验证什么？（新功能？bug 修复？回归？泛化？）
- 我改了哪些模块？这些模块的数据流下游是什么？（查模块依赖地图）
- 成功的具体标准是什么？（拿到 flag？DPM 检测到 WAF？模式正确切换？）

### 阶段 3：收集失败证据

**不要猜。先收集再诊断。**

收集清单（按优先级）：
1. **终端输出** — 最后的 error/traceback 是什么？
2. **Checkpoint 文件** — `checkpoints/task_*.json`，看最后一条记录的 phase 和 error
3. **DKG 状态** — checkpoint 中的 DKG nodes/edges，是否缺了关键节点？
4. **CTEG 状态** — `cteg_state.json`，是否积累了有用经验？
5. **RAG 检索日志** — 搜索是否命中了正确的集合？
6. **模式切换** — 如果触发了 multi-agent，子代理是否被正确创建？

快速提取关键信息：
```bash
# 最新 checkpoint
ls -t checkpoints/task_*.json | head -1 | xargs python3 -c "
import json, sys
with open(sys.argv[1]) as f:
    d = json.load(f)
print('Phase:', d.get('phase'))
print('Error:', d.get('error'))
print('Defense:', d.get('defense_state'))
print('B value:', d.get('b_value'))
print('DKG nodes:', len(d.get('dkg_state', {}).get('nodes', [])))
print('Compressions:', d.get('compressed_count', 0))
"

# 最后几条非 system 消息
ls -t checkpoints/task_*.json | head -1 | xargs python3 -c "
import json, sys
with open(sys.argv[1]) as f:
    d = json.load(f)
messages = d.get('messages', [])
for m in messages[-5:]:
    if m['role'] != 'system':
        print(f\"[{m['role']}]: {m['content'][:200]}...\")
"
```

### 阶段 5：修改代码

遵循 Karpathy 纪律 + 模块依赖地图。修改前查地图判断影响面，修改后至少用 2 个不同类型的靶机验证。

**修改完成后，必须将修改摘要写入 `CHANGES.md`：**
```markdown
## YYYY-MM-DD
- **文件**: 变更描述。原因/效果
```
不要求冗长，每条 1-2 行即可——重点是让后续 session 能快速了解改动历史。

### 阶段 6：验证修复 & 换靶机

**修复验证检查**：
- [ ] 原来的失败靶机现在能通过了？
- [ ] 至少再跑 1 个不同类型的靶机（不只是原来那个），确认没有回归？
- [ ] 如果是 Solo 模式修复，Multi-agent 模式下也正常？
- [ ] 如果是 Multi-agent 修复，Solo 模式下也正常？

**换靶机时的思考**：
- 上一个靶机暴露了什么问题？修改了什么模块？
- 下一个靶机是否天然地测试了我刚改的模块？
- 如果连续 3 个同类型靶机通过，考虑跳到更复杂的场景类型。

---

## 模块依赖地图

修改任何模块前，查此地图判断影响面。

### 依赖关系总图

```
run.py / experiments/runner.py
        │
        ▼
┌──────────────────────────────────────────────────────────────┐
│                     Orchestrator (中央调度)                    │
│  orchestrator.py:180 run() → Solo / Coordinated / Distributed│
└──────┬───────┬────────┬────────┬────────┬────────┬───────────┘
       │       │        │        │        │        │
       ▼       ▼        ▼        ▼        ▼        ▼
     DKG    DPM    DynamicScaling  DAVE    CTEG    DarwinRAG
  (通信中枢) (防御检测) (模式选择)   (验证)  (动态经验) (静态知识)
       │       │        │        │        │        │
       └───────┴────────┴────────┴──────┬─┴────────┘
                                        │
                    ┌───────────────────┴───────────────────┐
                    │                                       │
                    ▼                                       ▼
          SubAgentPool                              Tool Registry
    ┌───────┼────────┬────────┐                  (mcp_gateway.py)
    │       │        │        │                        │
    ▼       ▼        ▼        ▼                  ┌─────┴─────┐
 ReconAgent Exploit  Pivot   AD/Cloud             │           │
            Agent    Agent   Agent          recon_server  attack_server
                                           (12 tools)    (35 tools)
```

### 每个模块的详细依赖

#### Orchestrator (`darwin/orchestrator.py`)
| 维度 | 详情 |
|------|------|
| **读取** | DKG (nodes/edges), DPM (DefenseStateVector), DynamicScaling (B value, mode), DAVE (verification result), CTEG (suggestions), RAG (search results), data_model (typed objects), LLM |
| **写入** | DKG (phase results), CTEG (commit_task), checkpoints/ |
| **被谁依赖** | run.py, experiments/runner.py, experiments/chain_runner.py |
| **修改影响面** | 全部。修改 run() 循环逻辑影响三个模式。修改 phase 顺序影响数据流。`_bootstrap_scan` 是三个模式的共同入口，端口遗漏是阻塞性故障。 |
| **关键参数** | time_budget=1200, token_budget=200000, port_range (benchmark 模式) |
| **Prompt 架构** | `SYSTEM_PROMPT_ORCHESTRATOR_UNIFIED` 是唯一的 orchestrator prompt（legacy `SYSTEM_PROMPT_ORCHESTRATOR` 已废弃）。所有 6 处引用（exploit plan 生成、plan review、replan、multi-agent 等）统一使用 UNIFIED。Analyze prompt 新增 Phase 3 "Synthesize Attack Paths" 输出 `attack_paths` 字段（多步攻击链推理）。 |
| **知识合成** | `_generate_exploitation_plan()` 在 RAG context 与 Task format 之间插入 "Synthesizing Knowledge into Attack Tasks" 知识合成桥梁——指导 LLM 将 RAG pattern + 漏洞假设 + 服务版本 结合为一个 task。RAG/CTEG 无数据时输出明确 fallback 消息（非空白段落）。 |
| **模式耗尽** | `_solo_exhausted` 和 `_multi_exhausted` 独立标志，替代旧的共享 `_surface_exhausted`。Solo 3 次迭代或成功后标记耗尽；Multi-agent 同理。`_should_terminate()` 只在两者均耗尽时才终止。 |
| **非 HTTP 过滤** | `_bootstrap_scan` 使用 `_NON_HTTP_PORTS`（端口号）和 `_NON_HTTP_SVC_NAMES`（服务名称，如 ssh/redis/mysql/ldap/smb）双重过滤，防止为非 HTTP 服务创建 HTTP 端点。同时为新 Service 节点填充 `service_name` 字段（来自 nmap），用于 CTEG 凭据匹配。 |
| **RAG 预加载** | `run()` 中通过 `asyncio.create_task(asyncio.to_thread(get_rag))` 后台加载 RAG，与 bootstrap 扫描并行，节省 ~45s 启动时间。 |
| **CTEG 凭据过滤** | `_current_svc_names` 构建时过滤空 service_name（`if s.get("service_name")`），防止 `"" in "mssql"` 永远为 True 导致历史凭据泄漏到当前靶机。 |

#### DKG (`darwin/dkg.py`)
| 维度 | 详情 |
|------|------|
| **读取** | data_model (node/edge type definitions) |
| **写入** | 8 种 node type + 9 种 edge type |
| **被谁依赖** | Orchestrator（写入 phase 结果），所有 SubAgent（读写发现），DynamicScaling（读取 service count 和 host count） |
| **修改影响面** | 改了数据结构，所有读者都得跟着改。改了通知机制（asyncio.Event），子代理的实时协调会受影响。 |
| **常见故障** | 数据写到 DKG 但下游没读到；asyncio.Event 通知没触发；checkpoint 反序列化失败 |

#### DPM (`darwin/dpm.py`)
| 维度 | 详情 |
|------|------|
| **读取** | http_client (probe), waf_fingerprints.yaml, prompts/dpm_classifier.py (LLM 分类) |
| **写入** | DefenseStateVector |
| **被谁依赖** | Orchestrator (defense bypass 策略), DynamicScaling (D_present 标志) |
| **修改影响面** | DefenseStateVector 字段变更影响 orchestrator 和 dynamic_scaling。检测逻辑改动影响 bypass 策略选择。 |
| **当前行为** | 最多 probe 6 个 GET 端点（优先带参数的）。exploit 被 BLOCKED 时会重新评估。 |

#### Dynamic Scaling (`darwin/dynamic_scaling.py`)
| 维度 | 详情 |
|------|------|
| **读取** | DKG (_dkg.query_nodes), DPM (D_present), 环境检测 |
| **写入** | B value, mode (Solo/Coordinated/Distributed), TDI'' |
| **被谁依赖** | Orchestrator (mode dispatch) |
| **修改影响面** | B 公式系数调整直接影响 sub-agent spawn 数量。阈值调整影响 Solo↔Multi 切换时机。hysteresis voting (2 票) 影响切换灵敏度。`_get_host_count()` 现在从 DKG 读取而非硬编码 1。 |

#### DAVE (`darwin/dave.py`)
| 维度 | 详情 |
|------|------|
| **读取** | http_client (L1), Playwright (L2), payload 历史 (L3) |
| **写入** | 4 层验证结果, flag 提取, honeypot 检测 |
| **被谁依赖** | Orchestrator (最终验证), ExploitAgent (攻击结果验证) |
| **修改影响面** | flag regex 改动影响所有验证层。honeypot 检测影响误报率。 |
| **当前行为** | L3 即使检测到 payload 被修改，L4 仍然继续执行 flag 提取（不短路）。 |

#### CTEG (`darwin/cteg.py`)
| 维度 | 详情 |
|------|------|
| **读取** | data_model (BypassPattern/ExploitPattern) |
| **写入** | cteg_state.json (持久化), BypassPattern/ExploitPattern nodes |
| **被谁依赖** | Orchestrator (get_suggestions, commit_task), ExploitAgent (commit_attempt) |
| **修改影响面** | 衰减函数改动影响经验权重。pattern 结构改动影响 get_suggestions 匹配质量。 |

#### DarwinRAG (`darwin/rag.py`)
| 维度 | 详情 |
|------|------|
| **读取** | SentenceTransformer 模型 (`/home/kianabin/utils/all-MiniLM-L6-v2`), knowledge/ 目录 |
| **写入** | Faiss 索引, TF-IDF 索引 |
| **被谁依赖** | Orchestrator (plan injection), attack_server (knowledge_search tool) |
| **修改影响面** | embedding 模型路径改动影响索引加载。collection 增删影响 search 路由。 |
| **集成路径** | 仅两种：`knowledge_search` tool（LLM 主动调用）+ plan injection（plan 生成时注入）。auto-enrich 已从 orchestrator 中移除。RAG 在 `run()` 启动时通过 `asyncio.create_task(asyncio.to_thread(get_rag))` 后台预加载（~45s），与 bootstrap 扫描并行。 |
| **最佳实践** | `knowledge_search` 查询应使用空 category（`category=""`），让语义搜索自行过滤。先尝试 knowledge_search，无结果时用 web-search 补充。prompt 中已更新为非 CVE-only 表述，包含 unauth service 和 exploitation technique 条目。 |

#### SubAgentPool & SubAgents (`darwin/sub_agents/`)
| 维度 | 详情 |
|------|------|
| **读取** | DKG (上下文), LLM (planning), MCP Gateway (工具注册), prompts/ (模板) |
| **写入** | DKG (发现结果), LLM session |
| **被谁依赖** | Orchestrator (spawn, manage, collect) |
| **修改影响面** | BaseSubAgent 的 Plan-Act-Observe 循环改动影响所有 5 种子代理。单个 agent 的工具集改动只影响该 agent。 |
| **PivotAgent 新增** | 支持 Windows 横向移动：impacket_pth/psexec/wmiexec + netexec_enum。凭据类型感知路由（NTLM hash → impacket_pth, SSH → ssh_exec）。 |
| **Agent spawn 条件** | `_spawn_followup_agents` 重评估 AD/cloud 环境。CloudAgent 需要 populated cloud_context。etcd 端口 2379 触发 cloud 环境检测。 |

#### Tool Registry & Servers (`darwin/tools/`)
| 维度 | 详情 |
|------|------|
| **读取** | 外部 CLI 工具 (nmap, sqlmap, ffuf, netexec, kubectl, impacket 等) |
| **写入** | 工具输出解析 → 传给调用者 (orchestrator 或 sub_agent) |
| **被谁依赖** | Orchestrator (Solo 直接调用), 所有 SubAgent (通过 MCP Gateway) |
| **修改影响面** | 新增工具：需要同时在 server 注册 + prompt 模板中告知 LLM。修改输出解析：影响下游所有依赖该工具输出的逻辑。 |
| **近期新增** | impacket_silver_ticket, tomcat_exploit, wpscan_enum, wp_xmlrpc_brute, oracle_tns_poison, nmap_port_range, searchsploit_copy, php_filter_chain, impacket_ntlmrelayx, web-search |
| **近期改进** | oracle_query: heredoc→printf（单引号修复）；jwt_forge: claims→claims_b64（base64 编码防单引号破坏）；wp_xmlrpc_brute: 用户列表字符串分割；oracle_tns_poison: PORT 模板变量 + 包长度含 header；gobuster_dir: 自定义 wordlist；ssh_key_exec: BatchMode；mcp_gateway: 自动填充参数默认值 |
| **Benchmark Phase 10-13** | 场景 ~57→115+，新增 4 个领域：**CLOUD** (22: IMDS/跨账号/OIDC/PassRole/S3/SCP bypass)、**CI/CD** (5: Poisoned Pipeline/.git/Secrets/Webhook/Build Arg)、**NET** (3: ARP spoofing/DNS exfil/Container sniffing)、**LKX** (5: kernel UAF/eBPF/Dirty Pipe)。Web 12→22、AD 14→16 (Cross-Forest/AdminSDHolder)、K8s 26→29 (Node Selector/Toleration/CNI spoof)、DEF 2→5。攻击链 34→43，Cloud 链从旧版完全替换为跨账号/SCP/OIDC/Federation 主题。DARWIN CloudAgent 需确认覆盖：**Cloud 工具**（AWS CLI — STS AssumeRole/IMDS metadata/S3/Lambda/IAM/Organizations SCP）、**CI/CD 工具**（.git 提取/Pipeline YAML 解析/Webhook 利用）、**内核 exploit 工具**（eBPF 程序加载/kernel module 编译/Dirty Pipe）、**网络攻击工具**（ARP spoofing/DNS tunneling/packet capture） |

#### LLM Session (`darwin/utils/llm.py`)
| 维度 | 详情 |
|------|------|
| **读取** | config/llm.yaml, conversation_history |
| **写入** | conversation_history, _pending_compressed_context |
| **被谁依赖** | 所有 LLM 调用点 (Orchestrator + 5 SubAgents) |
| **修改影响面** | 压缩机制、system prompt 替换、tool call 解析——影响所有 LLM 交互。 |
| **当前压缩机制** | `_pending_compressed_context` 存储在实例变量中，在下一次 `_build_messages` 调用时一次性注入为 user prompt 前缀。`replace_system_prompt` 保护 `[COMPRESSED CONTEXT` 开头的消息不被覆盖。最多压缩 3 次（`_max_compressions`），超过后截断旧消息。 |

### 模块修改影响速查表

| 修改模块 | 必查影响方 |
|----------|-----------|
| orchestrator.py | run.py, DKG 写入格式, CTEG commit, 所有 sub_agent 调用方式, DPM bypass 策略 |
| dkg.py | orchestrator, 所有 sub_agent, dynamic_scaling, dave, checkpoint 格式 |
| dpm.py | orchestrator (defense bypass), dynamic_scaling (D_present) |
| dynamic_scaling.py | orchestrator (mode dispatch), sub_agent spawn 数量 |
| dave.py | orchestrator (验证流程), exploit_agent (攻击验证), flag regex |
| cteg.py | orchestrator (get_suggestions, commit_task), exploit_agent (commit_attempt), cteg_state.json |
| rag.py | orchestrator (search, enrich), attack_server (knowledge_search tool), knowledge/ 文件格式 |
| prompts/*.py | 对应 agent 的 plan/act/evaluate 行为 |
| sub_agents/base.py | 所有 5 种子代理, SubAgentPool 生命周期 |
| sub_agents/*_agent.py | 对应 agent 的工具使用, DKG 读写, LLM 交互 |
| tools/recon_server.py | orchestrator Solo recon phase, ReconAgent 工具集 |
| tools/attack_server.py | orchestrator Solo exploit phase, ExploitAgent/PivotAgent/ADAgent 工具集 |
| utils/llm.py | 所有 LLM 调用点, context compression, tool call 解析, system prompt 替换 |

---

## 诊断决策树

核心原则：**工具缺失 → 流程编排 → Prompt，按此顺序排查。**

### 症状索引

| 症状 | 跳转 |
|------|------|
| nmap 扫描无结果 / 端口遗漏 | → D1 |
| LLM 调用不存在的工具 / 工具名错误 | → D2 |
| 工具执行成功但 LLM 没读取输出 | → D3 |
| 漏洞已确认但利用不成功 | → D4 |
| Solo 模式正常，Multi-agent 模式异常（或反之） | → D5 |
| Multi-agent 模式下子代理无响应 / 超时 | → D6 |
| Flag 验证失败（L4 未通过） | → D7 |
| DKG 状态不一致 / 节点丢失 | → D8 |
| 上下文压缩后 LLM 行为退化 | → D9 |
| 防御检测不准确（DPM 误报/漏报） | → D10 |
| CTEG/RAG 没有提供有用经验 | → D11 |

---

### D1：nmap 扫描无结果 / 端口遗漏

```
nmap 结果为空或缺少关键端口
    │
    ├── benchmark 模式用了 port_range？
    │   └── 是 → 检查 scenarios.yaml 中该 scenario 的 port_range 配置
    │
    ├── Docker 网络隔离？
    │   └── 用 localhost 而非容器 IP，确认 docker ps 端口映射正确
    │
    ├── recon_server 注册了正确的 nmap 工具吗？
    │   ├── nmap_full_scan — 全端口扫描 (65535 ports, timeout 150s)
    │   └── nmap_port_range — 范围扫描 (benchmark 必备, timeout 60s)
    │
    └── _bootstrap_scan 中的非 HTTP 过滤是否错误排除了目标端口？
        ├── 端口号过滤：_NON_HTTP_PORTS = {22, 445, 389, 636, 3268, 3269,
        │   3306, 5432, 6379, 1433, 1521, 27017}
        └── 服务名称过滤：_NON_HTTP_SVC_NAMES = {ssh, redis, mysql, mariadb,
            postgresql, mssql, oracle, mongodb, memcached, ldap, kerberos,
            smb, rdp, vnc} — 即使非标准端口，服务名匹配也会跳过 HTTP probe
```

**架构提示**：`_bootstrap_scan` 是 Solo/Coordinated/Distributed 三个模式的共同入口。端口遗漏是阻塞性故障——这里出错，后续所有阶段都没有数据可操作。

### D2：LLM 调用不存在的工具 / 工具名错误

```
LLM 输出包含不存在的工具名
    │
    ├── 工具在 server 中注册了吗？
    │   ├── recon_server.py → register_recon_tools()
    │   └── attack_server.py → register_attack_tools()
    │
    ├── 工具名在 prompt 模板中告诉 LLM 了吗？
    │   ├── Solo 模式 → darwin/prompts/orchestrator.py（唯一活跃 prompt：UNIFIED）
    │   │   └── Legacy SYSTEM_PROMPT_ORCHESTRATOR 已废弃，所有代码路径使用 UNIFIED
    │   ├── ReconAgent → darwin/prompts/recon_agent.py
    │   ├── ExploitAgent → darwin/prompts/exploit_agent.py
    │   ├── PivotAgent → darwin/prompts/pivot_agent.py
    │   ├── ADAgent → darwin/prompts/ad_agent.py
    │   └── CloudAgent → darwin/prompts/cloud_agent.py
    │
    └── 框架已有 get_close_matches() 校验（plan 生成阶段）
        └── LLM 给了接近但不完全匹配的名字 → 自动修正
        └── LLM 给了完全不在 registry 中的名字 → 提示 LLM 重新选择
```

**修复优先级**：
1. 如果工具已经在 server 注册但 prompt 没提 → 更新 prompt 模板
2. 如果工具不存在 → 在 server 中注册新工具
3. 如果工具存在但 LLM 总是不选它 → prompt 中对工具的 description 不够清晰

### D3：工具执行成功但 LLM 没读取输出

```
工具返回 success=True 但 LLM 下一步行为好像没看到输出
    │
    ├── 检查工具的输出解析器（parser）
    │   └── recon_server / attack_server 中的 _parse_* 函数
    │   └── 输出是否被截断？结构化信息是否被正确提取？
    │
    ├── 检查上下文是否太长导致输出被压缩
    │   └── 查看 checkpoint 中 compressed_count 字段
    │   └── 如果 ≥ 3 → 达到 _max_compressions 上限，旧消息被直接截断
    │
    └── 检查 LLM 的 tool_calls 响应处理
        └── llm.py _build_messages 是否正确匹配了 tool_call_id？
        └── 是否存在未 resolved 的 tool_calls 被错误 strip？
```

### D4：漏洞已确认但利用不成功

```
_analyze_phase 正确识别了漏洞，但 exploit 阶段失败
    │
    ├── 第一步：检查工具是否充分（最常见原因）
    │   ├── 这个漏洞类型需要什么利用工具？当前 attack_server 有吗？
    │   ├── 不需要一次性补全，但至少要有 1 个可达路径的工具
    │   ├── 按漏洞类型对照：
    │   │   ├── SQLi → sqlmap_test, mysql_query, psql_query, mssql_query
    │   │   ├── RCE/shell → shell_exec, ssh_exec, php_filter_chain, tomcat_exploit
    │   │   ├── SSRF → curl_get (internal), cloud metadata probe (169.254.169.254)
    │   │   ├── SSTI → send_payload (Jinja2/Twig ${7*7} / {{7*7}} 检测)
    │   │   ├── NoSQLi → MongoDB $regex injection, Elasticsearch script query
    │   │   ├── Linux 提权 → SUID binary, Docker socket, capsh, cron, Polkit exploit
    │   │   ├── K8s 网络 → kubectl (Ingress), ExternalIP, Webhook, Toleration, CNI
    │   │   ├── Cloud IAM → AWS STS AssumeRole, IMDS metadata (169.254.169.254),
    │   │   │   Lambda PassRole, S3 bucket policy, SCP evaluation, OIDC federation
    │   │   ├── CI/CD → .git extraction, Pipeline YAML parsing, Webhook forgery,
    │   │   │   Dockerfile Build Arg injection
    │   │   ├── 内核 exploit → kernel module 编译, eBPF 程序加载, Dirty Pipe
    │   │   ├── NET 网络 → ARP spoofing, DNS tunneling, packet capture (tcpdump)
    │   │   ├── 非 HTTP 服务 → VULN_TOOL_MAP: authbypass/weakauth → redis_cmd 等
    │   │   └── AD 高级 → impacket (RBCD/KeyCredentialLink/DACL/Cross-Forest Trust)
    │   └── ExploitAgent 能识别 15 种漏洞类型——如果 LLM 无法评估工具输出，
    │       检查 exploit_agent prompt 的 Key indicators 是否覆盖了当前漏洞类型
    │
    ├── 第二步：检查 exploit agent 是否能访问必要参数
    │   ├── DKG 中有目标的端口/服务/版本信息吗？
    │   ├── DKG 中有漏洞对应的 CVE 编号吗？（_analyze_phase 结果是否持久化到 DKG Analysis 节点？）
    │   └── 凭据是否存储为 Credential 节点？（DB 凭据现在也会自动存储）
    │
    ├── 第三步：检查 plan 生成逻辑
    │   ├── _systematic_exploit_pass 是否为每个漏洞生成了尝试？
    │   ├── plan 中的 tool name 是否通过 get_close_matches 校验？
    │   ├── _replan_after_failure 是否正确去重了 task ID？
    │   ├── _topological_sort 是否警告了未解决的依赖引用？
    │   ├── 攻击链合成是否合理？analyze 阶段是否输出了 attack_paths？
    │   │   └── attack_paths 为 exploitation plan 提供步骤顺序——如果 analyze 没给 attack_paths，
    │   │       LLM 需要自行推断依赖关系（更易出错）
    │   └── Plan review 是否有 "Target Consistency" 约束？
    │       └── 防止 LLM 为未发现的端口/服务创建虚构任务
    │
    └── 第四步：检查验证层
        └── DAVE L4 flag 提取 — 即使 L3 检测到 payload 被修改，L4 也会继续执行
        └── 确认 flag regex 匹配了正确的格式：flag\{[a-zA-Z0-9_\-!@#$%^&*()+=]+\}
```

### D5：Solo ↔ Multi-agent 模式差异

```
Solo 模式能成功但 Multi-agent 失败（或反之）
    │
    ├── 检查 DynamicScaling 的 B 值计算
    │   ├── dynamic_scaling.py compute_task_breadth()
    │   ├── B < 0.3 → Solo, 0.3≤B<0.6 → Coordinated, B≥0.6 → Distributed
    │   └── 模式选择是否符合预期？hysteresis voting (2 票) 是否导致切换滞后？
    │
    ├── 检查模式耗尽逻辑
    │   ├── _solo_exhausted / _multi_exhausted 独立标志（非共享 _surface_exhausted）
    │   ├── Solo 3 次迭代或成功后耗尽；Multi-agent 同理
    │   ├── _should_terminate() 仅在两者均耗尽时才终止
    │   └── Solo 耗尽后空转会被 continue 跳过（防止 7 次无效循环）
    │
    ├── 检查子代理的 spawn 条件
    │   ├── _spawn_followup_agents 是否正确重评估了 AD/cloud 环境？
    │   ├── AD 端口 (389, 445, 88) 被检测到了吗？
    │   ├── K8s 端口 (6443, 10250, 2379) 被检测到了吗？
    │   └── CloudAgent 的 cloud_context 是否被正确填充？
    │
    ├── Multi-agent 模式下 DKG 通信
    │   ├── asyncio.Event 通知是否按 node type 正确触发？
    │   └── 子代理写入 DKG 后，orchestrator 是否收到了通知？
    │
    └── Solo 模式下 LLM 记忆
        └── 检查 _solo_cycle_context_injected 标志和 Unified LLM Loop 的初始上下文注入
```

### D6：Multi-agent 子代理无响应 / 超时

```
子代理被 spawn 后没有产生结果
    │
    ├── SubAgentPool 的 lifecycle 状态
    │   ├── 子代理卡在哪个 state？（base.py 中 10 种 lifecycle state）
    │   └── iteration==0 且无任务执行 → STALLED（防止环形依赖导致假 DONE）
    │
    ├── 子代理的 LLM session 是否独立？
    │   └── 每个子代理有自己的 LLMSession 实例
    │
    ├── 子代理的任务失败后被正确标记了吗？
    │   ├── _replan_after_failure 现在标记 status: "failed"（不是 done）
    │   └── 失败的 task 写入 DKG Task 节点供后续查询
    │
    ├── 子代理的工具调用是否超时？
    │   └── 某些工具（nmap_full_scan 150s, sqlmap 120s）需要更长时间
    │
    └── Multi-agent summary 是否包含了必要信息？
        ├── summary 现在包含 flags, credentials, vulnerabilities
        └── asyncio.gather() 返回值通过 pool._results 收集，防止结果丢弃
```

### D7：Flag 验证失败（L4 未通过）

```
DAVE 报告 flag 验证失败
    │
    ├── flag 确实没拿到
    │   └── 回到 D4 —— 利用不充分，不是 DAVE 的问题
    │
    ├── flag 拿到了但 DAVE 没识别
    │   ├── 检查 flag regex: flag\{[a-zA-Z0-9_\-!@#$%^&*()+=]+\}
    │   ├── 检查 DAVE L4 _verify_impact 的 flag 提取逻辑
    │   └── flag 是否被误判为 honeypot？
    │       └── honeypot 黑名单：flag{test}, flag{example}, flag{honeypot}
    │
    └── L3 检测到 payload modification 但 L4 仍然执行
        └── 正确行为——即使 WAF 修改了 payload，flag 仍可能在响应中
        └── 如果 L3 modification 检测是误报，检查 dpm.py 规则
```

### D8：DKG 状态不一致 / 节点丢失

```
checkpoint 中 DKG 节点/边不完整
    │
    ├── 写入侧
    │   ├── 哪个模块负责写入缺失的节点类型？
    │   ├── orchestrator → Host, Service, Vulnerability, Endpoint
    │   ├── sub_agents → Credential, Session, Flag, Analysis
    │   └── 是否在正确的时间点调用了 dkg.save()？
    │
    ├── 读取侧
    │   ├── 哪个模块读取时没找到需要的节点？
    │   ├── _get_state() → data_model.normalize_dkg_state()
    │   ├── PipelineState 现在包含：endpoints, services, vulnerabilities, credentials,
    │   │   flags, analysis_notes, hosts, sessions, domains（共 9 种类型）
    │   └── 如果 Host/Session/Domain 节点在 DKG 中存在但未出现在 prompt context 中，
    │       检查 normalize_dkg_state 是否有对应的提取逻辑
    │
    └── 持久化
        └── checkpoint JSON 是否正确序列化了 MultiDiGraph？
        └── 反序列化时是否有节点/边丢失？
```

### D9：上下文压缩后 LLM 行为退化

```
压缩后 LLM 丢失了关键信息
    │
    ├── 检查压缩触发条件
    │   ├── context_load ≥ compression_threshold (默认 0.4 of 180K)
    │   └── 阈值是否太激进？提高 compression_threshold 可减少压缩频率
    │
    ├── 检查压缩次数
    │   ├── _compressed_count ≥ 3 → 达到 _max_compressions 上限
    │   └── 此时旧消息被直接截断，注入 `[CONTEXT TRUNCATED]` 通知消息
    │       └── 通知 LLM "earlier actions and discoveries may no longer be visible,
    │           current DKG state has the structured facts"
    │
    ├── 检查压缩后的上下文注入
    │   ├── _pending_compressed_context 是否被 _build_messages 正确消费？
    │   ├── 多次压缩时上下文是否被合并（merge）而非覆盖？
    │   │   └── 修复前：第二次压缩覆盖第一次；修复后：prev + new_text 合并
    │   ├── compressed system message 是否被 replace_system_prompt 保护？
    │   └── 压缩摘要是否保留了 5 类关键信息？
    │       └── 已执行的命令、已获取的信息、当前状态、活跃凭据、待完成任务
    │
    └── 压缩质量差 → 调整 llm.py 中的 SYSTEM_PROMPT_COMPRESS 模板
```

### D10：防御检测不准确（DPM 误报/漏报）

```
DPM 报告有 WAF 但实际上没有（或反之）
    │
    ├── 检查规则层
    │   └── config/waf_fingerprints.yaml 的签名是否正确？
    │
    ├── 检查 probe 层
    │   ├── _detect_defenses 是否 probe 了足够的端点？
    │   └── 现在默认 probe 最多 6 个 GET 端点（优先带参数的）
    │
    ├── 检查 LLM 分类层
    │   └── 只在 confidence < 0.8 时才调用
    │   └── prompts/dpm_classifier.py 模板是否合适？
    │
    └── DPM 在 exploit 被 BLOCKED 时会重新评估
```

### D11：CTEG/RAG 没有提供有用经验

```
CTEG get_suggestions() 返回空或无关结果
    │
    ├── CTEG
    │   ├── cteg_state.json 中是否有积累的经验？
    │   ├── BypassPattern/ExploitPattern 的衰减函数是否过快淘汰了经验？
    │   ├── commit_task / commit_attempt 是否在正确的时机被调用？
    │   └── CTEG 凭据是否泄漏到当前靶机？（跨靶机污染）
    │       └── 检查 `_current_svc_names` 是否包含空字符串 `""`
    │       └── 如果 Service 节点缺少 `service_name` 字段，`"" in any_string` 永远为 True
    │           → 所有历史凭据的 service match filter 失效 → LLM 看到不属于当前靶机的凭据
    │
    └── RAG (knowledge_search tool)
        ├── knowledge/ 中对应 collection 是否有相关内容？
        ├── SentenceTransformer 模型加载成功？（/home/kianabin/utils/all-MiniLM-L6-v2）
        ├── Faiss 索引是否过期需要 rebuild？
        │   └── python tools/ingest_knowledge.py --rebuild
        ├── LLM 调用 knowledge_search 时是否用了 category="" ？
        │   └── 非空 category 过滤会导致假阴性
        ├── 对非 HTTP 服务：先尝试 knowledge_search（RAG 已包含 unauth 服务和利用技术条目）
        │   └── 无结果时用 web-search 补充
        └── RAG 是否已后台预加载完成？（bootstrap 阶段 asyncio.create_task 并行加载）
```

**架构变更**：RAG 的 auto-enrich 路径已从 orchestrator 中移除（`_solo_llm_loop`、`_unified_llm_loop`、`_service_research`、`_run_multi_agent_cycle`）。现在 RAG 只通过 `knowledge_search` tool（LLM 主动调用）和 plan injection 两种路径生效。这意味着 LLM 必须**主动**调用 knowledge_search——如果它不知道某服务有利用方法，它不会去搜索。监控 checkpoint 中 knowledge_search 的调用频率是判断 RAG 是否有效的关键指标。
```

### 诊断快速参考卡

最常见的 3 种失败模式：

| 排名 | 症状 | 最可能的原因 | 入口 |
|------|------|-------------|------|
| 1 | 漏洞确认但利用失败 | 缺工具 | D4 第一步 |
| 2 | nmap 没扫到端口 | 端口范围不对或 Docker 网络 | D1 |
| 3 | LLM 行为混乱 | 上下文压缩丢失信息 | D9 |
| 4 | LLM 为不存在的服务创建任务 | CTEG 凭据跨靶机泄漏 | D11 CTEG 分支 |
| 5 | 攻击链任务缺少依赖关系 | analyze 未输出 attack_paths | D4 第三步 |

---

## Karpathy 修改方法论

来自 Andrej Karpathy 的 LLM 编码指导原则，适配到 DARWIN 开发场景。

### 1. Think Before Coding

**不要假设。不要隐藏困惑。暴露权衡。**

修改前：
- 明确陈述你的假设。如果不确定——问。
- 如果存在多种解释，列出它们——不要沉默地选择一种。
- 如果存在更简单的方案，说出来。
- 如果不清楚，停下来。说出困惑的地方。

DARWIN 特化：
- 先通过 checkpoint 和日志确认根因，不靠直觉猜。
- "LLM 没拿到 flag"不是根因——是症状。根因是"attack_server 没有为这个 CVE 注册利用工具"或"DKG 中的 CVE 信息被 _analyze_phase reset 丢失了"。

### 2. Simplicity First

**解决问题的最少代码。没有投机性功能。**

- 不添加未要求的功能。
- 不为单一用途的代码添加抽象层。
- 不为不可能发生的场景添加错误处理。
- 如果写了 200 行而 50 行就够了，重写。

DARWIN 特化：
- 加一个新工具通常只需要 15 行：server 注册 + prompt 模板添加一行。不要"顺便重构工具注册系统"。
- 不要为某个靶机创建特殊处理——想清楚这个修改如何让所有靶机受益。

### 3. Surgical Changes

**只动必须动的。只清理自己的烂摊子。**

编辑已有代码时：
- 不要"改进"旁边的代码、注释、格式。
- 不要重构没有坏的东西。
- 匹配已有代码风格，即使你觉得有更好的写法。
- 如果注意到无关的死代码，提出来——不要直接删除。

当你的修改产生孤儿代码时：
- 移除因你的修改而不再使用的 imports/变量/函数。
- 不要删除预先存在的死代码，除非被要求。

自测：每个被改动行都能追溯到你的目标。

### 4. Goal-Driven Execution

**定义成功标准。循环直到验证通过。**

将任务转化为可验证目标：
- "添加工具" → "新工具出现在 MCP gateway 的函数列表中，LLM 能在下一个实验中成功调用它"
- "修复 bug" → "写一个能复现的场景，修完后再跑确认不再出现"
- "重构 X" → "重构前后所有已有测试通过"

强成功标准让你能独立循环。弱标准（"让它能工作"）需要不断确认。

DARWIN 特化：
- 成功标准必须有靶机验证："改完后，web-03 和 db-05 都能在 time_budget 内拿到 flag"
- 单靶机通过不算通过——至少 2 个不同类型。

---

## 验证检查清单

每次修改代码后必须验证：

### 基础验证
- [ ] 原失败的靶机现在能通过了？
- [ ] 至少再跑 1 个不同类型的靶机确认无回归？
- [ ] 相关测试通过：`pytest tests/ -v`？
- [ ] `python -c "from darwin.orchestrator import Orchestrator; print('OK')"` 无 import 错误？
- [ ] 修改摘要已写入 `CHANGES.md`？

### 跨模式验证
- [ ] Solo 模式修复 → 也跑一个 Multi-agent 场景确认正常？
- [ ] Multi-agent 修复 → 也跑一个 Solo 场景确认正常？

### 靶机交叉验证（按修改模块）
| 修改模块 | 至少验证的靶机类型 |
|----------|-------------------|
| orchestrator.py | 1 Web + 1 DB |
| dkg.py | 1 Solo + 1 Multi-agent (K8s 或攻击链) |
| dpm.py | 1 Defense (def-waf) + 1 无防御 Web |
| dynamic_scaling.py | 1 单端口 (Web) + 1 多端口 (DB+K8s) |
| tools/recon_server.py | 1 HTTP + 1 非 HTTP (DB) |
| tools/attack_server.py | 使用新工具的靶机 + 1 个使用其他工具的靶机 |
| sub_agents/*.py | 触发该 agent 的场景 + 1 个不触发的场景 |
| utils/llm.py | 1 长时间运行场景（触发压缩）+ 1 短场景 |

### 验证后
- [ ] 如果连续 3 个同类型靶机通过 → 跳到更复杂的场景类型测试泛化
- [ ] 记录验证结果到 commit message 中："验证: web-03 + db-05 均通过"
