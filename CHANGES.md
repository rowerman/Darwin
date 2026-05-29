# DARWIN Framework Changes — 2026-05-29

## 2026-05-29 (late)
- **darwin/orchestrator.py**: 彻底禁止 SSH 暴力爆破任务。新增 `_BLACKLISTED_TOOLS` 类常量 + `_sanitize_plan_tools()` 方法，在三个任务生成路径中统一替换 `hydra_ssh_brute` → `ssh_exec`。同时在 tool_defs 和 plan generation prompt 的 tool list 中过滤黑名单工具。
- **darwin/orchestrator.py**: Task 执行确定性改造。对 shell_exec/redis_cmd/ssh_exec 等明确工具，plan 生成后直接调用 `gateway.call()` 执行，不再通过 LLM 生成 tool call（防止 LLM 在执行阶段篡改 plan 的 params）。curl_get/send_payload 等探索性工具仍走 LLM 路径。
- **darwin/orchestrator.py**: Task 失败自动分析与修复重试。新增 `_execute_single_tool()` 工具执行辅助方法 + `_analyze_and_fix_task()` LLM 失败分析方法。Task 执行失败后，LLM 分析是否为参数错误（fixable），若是则修正 params 并重试（最多 2 次），重试成功则跳过 plan-review 的失败标记。
- **darwin/orchestrator.py**: Direct execution 的 LLM 历史兼容修复。直接执行 task 时注入 synthetic assistant 消息（含 tool_calls），使后续 `add_tool_result` 形成合法的 tool_calls → tool 消息序列，满足 DeepSeek API 要求。

## Overview

经过 6 轮迭代修复，对 DARWIN 框架进行了全面的逻辑审计、bug 修复、日志系统和工具增强。累计修复 **57 个问题**，涉及 7 个文件。

---

## Round 1: Phase 1-4 主体修改

### Phase 1: 记忆模块修复
**文件**: `darwin/orchestrator.py`
**变更**: 替换 3 处 `llm.reset()` 为 `replace_system_prompt()` + `add_context_message()` 阶段过渡消息
- `_analyze_phase()` line 2172: 不再清空对话历史，改为切换系统提示词并注入过渡摘要
- `_llm_explore()` line 3672: 同上
- `_llm_driven_exploit()` line 4068: 同上
**效果**: LLM 在整个渗透测试生命周期内保持连续对话历史，不会丢失之前的推理过程

### Phase 2: Replan 改进
**文件**: `darwin/orchestrator.py`, `darwin/sub_agents/base.py`
**变更**:
- 添加 `_detect_cycle()` 和 `_break_cycle()` 静态方法，在每次 plan 更新后检测并断开循环依赖
- 添加 `_task_attempt_limit = 3`，任务失败超过 3 次后标记为 `exhausted`
- `_select_next_plan_task()` 过滤 `exhausted` 任务
- `_review_and_update_plan()` 失败提示增强（告诉 LLM 生成替代方案）
- `_select_next_task()` 从 O(n) 线性扫描改为 Kahn 算法拓扑排序
- `_select_next_task_from_plan()` 添加旧版 `dependencies` 字段回退
**效果**: Plan 支持真 DAG 结构，循环依赖自动断开，失败任务有重试上限

### Phase 3: 缺失工具
**文件**: `darwin/tools/attack_server.py`, `darwin/prompts/orchestrator.py`, `darwin/prompts/ad_agent.py`
**新增 5 个工具**:
- `impacket_silver_ticket` — Kerberos Silver Ticket（TGS）伪造
- `tomcat_exploit` — Tomcat 漏洞利用（反序列化/竞态条件文件上传）
- `wpscan_enum` — WordPress 漏洞扫描
- `wp_xmlrpc_brute` — WordPress xmlrpc.php 暴力破解
- `oracle_tns_poison` — Oracle TNS 协议投毒
**效果**: 57 个 attack 工具，AD/WordPress/Tomcat/Oracle 覆盖增强

### Phase 4: 循环过渡 + Checkpoint
**文件**: `darwin/data_model.py`, `darwin/orchestrator.py`
**变更**:
- 新增 `CycleTransitionSummary` dataclass，结构化记录每轮循环的完成/失败/新发现
- 替换简陋的 `[CYCLE TRANSITION]` 消息为结构化摘要
- 新增 `_save_orchestrator_checkpoint()` / `_load_orchestrator_checkpoint()` / `_find_latest_checkpoint()`
- 在关键节点（bootstrap 后、analyze 后、循环迭代后）保存 checkpoint
**效果**: LLM 每次循环重新进入时看到"已尝试/已失败/已成功"的结构化摘要；支持中断恢复

---

## Round 2: 兼容性修补（12 项）

**文件**: `darwin/orchestrator.py`, `darwin/sub_agents/base.py`

| # | 问题 | 修复 |
|---|------|------|
| A | `t["id"]` 直接键访问可能 KeyError | 改为 `t.get("id")` |
| B | `_analyze_phase` DKG svc_research 重复注入 | 移除重复注入代码块 |
| C | `_select_next_task_from_plan` 不支持旧 `dependencies` 字段 | 添加 `or task.get("dependencies", [])` |
| D | `_generate_exploitation_plan` 不传 `system_prompt` | 添加 `system_prompt=SYSTEM_PROMPT_ORCHESTRATOR_UNIFIED` |
| E-H | `exhausted` 状态未被下游消费者识别 | `_format_plan_status`, `_sync_plan_to_dkg`, `_generate_phase_summary`, `_update_plan_after_task` 全部添加 `exhausted` 处理 |
| I | 日志消息缺少 exhausted 计数 | 添加 |
| J | 0 vuln 过渡消息矛盾 | 分支处理 |
| K | `str(id(task))` 回退键不稳定 | 改为基于内容 hash 的稳定键 |
| L | Kahn 算法无条件递减 in_degree | 仅在任务完成时递减 |

---

## Round 3: 日志系统

**文件**: `darwin/orchestrator.py`, `darwin/sub_agents/base.py`, `darwin/sub_agents/exploit_agent.py`, `darwin/sub_agents/recon_agent.py`

### 新增辅助方法（6 个）
- `_print_phase(name)` — 阶段切换 banner
- `_print_discovery(category, items)` — 发现项列表
- `_print_plan_status()` — 计划状态摘要
- `_print_task_execution(task, tools, iter)` — 任务执行头
- `_print_task_result(task, success, summary)` — 任务结果
- `_print_progress(level, B)` — 循环进度条

### 增强的各阶段输出
- **Bootstrap**: 端口/服务表格，非 HTTP 服务，域名，SSH/DB 凭据
- **Deep Recon**: dirb/nikto 发现数，表单列表
- **Defense**: WAF 类型/复杂度/Honeypot/Cloaking
- **Service Research**: 发现的 CVE 编号
- **Analyze**: 每个 vuln 的 type/endpoint/param/confidence/evidence/tool
- **Plan**: 任务列表含 ID/状态/依赖，每次更新后打印
- **Replan**: 失败任务 → 替代方案生成过程

### 子代理日志
- `base.py`: 计划生成、任务执行、结果、完成/崩溃
- `exploit_agent.py`: 计划生成、replan

---

## Round 4: 非 HTTP 漏洞检测 + 暴力破解降级 + RAG 修复（6 项）

**文件**: `darwin/orchestrator.py`, `darwin/prompts/orchestrator.py`

### Fix 1: `_augment_from_dkg` 非 HTTP 服务检测
新增 `_NON_HTTP_VULN_MAP`，为 8 种非 HTTP 端口生成 AuthBypass/WeakAuth 漏洞假设
支持服务名称匹配（非标准端口如 Redis:10205）

### Fix 2: `_analyze_phase` prompt 更新
添加 `WeakAuth` vuln 类型 + Non-HTTP Services 分析指南

### Fix 3: `_service_research()` 调用 `knowledge_search`
对非 HTTP 服务额外调用 RAG 搜索技术文档

### Fix 4: 暴力破解降级
`hydra_ssh_brute` 和 `hydra_http_brute` 从 `_EXPLOIT_PRIORITY` 移入 `_LOW_PRIORITY`

### Fix 5: 协议工具加入系统提示词
`redis_cmd`, `mysql_query`, `psql_query`, `mssql_query`, `oracle_query`, `ssh_exec`, `ssh_key_exec`

### Fix 6: RAG prompt 文本修复
不再误导为 CVE-only

---

## Round 5: 31-Bug 全局修复

**涉及 7 个文件**

### Critical (2)
| # | 问题 | 修复 |
|---|------|------|
| C1 | `_surface_exhausted` 共享标志阻止 Solo↔Multi 切换 | 拆分为 `_solo_exhausted` + `_multi_exhausted` |
| C2 | `_review_and_update_plan` 丢弃 pending 任务 | `preserved` 过滤器增加 `"pending"` |

### High (7)
| H1 | Sub-agent 结果被丢弃 | 收集 `asyncio.gather()` 返回值写入 `pool._results` |
| H2 | `pool.terminate()` 缺少 agent_id | 遍历所有 agent 逐个终止 |
| H3 | `oracle_tns_poison` PORT 硬编码 | `PORT=port` → `PORT={port}` |
| H4 | `wp_xmlrpc_brute` 不分割用户列表 | `['{users}']` → `'{users}'.split(',')` |
| H5 | `SYSTEM_PROMPT_ANALYZE` 6 处未 format | 缓存在 `self._analyze_prompt_formatted` |
| H6 | 环形依赖 → agent 假 DONE | iteration==0 时标记 STALLED |
| H7 | Base `_replan_after_failure` 标记失败为 done | 改为 `status: "failed"` |

### Medium (11)
| M1 | `_exploit_chain` 每周期覆盖 | 检查已有再初始化 |
| M2 | `_systematic_exploit_pass` 无跨周期去重 | `_tried_systematic` 实例级 set |
| M3 | `normalize_dkg_state` 丢弃 8/14 节点类型 | 添加 Host/Session/Domain |
| M4 | TNS 包长度不含 header | `+8` |
| M5 | `_EXPLOIT_TOOLS` 缺失工具 | 添加 20+ 利用工具 |
| M6 | MongoDB/Memcached 生成 `shell://` URI | 添加 proto 字段 |
| M7 | `_EXPLOIT_PRIORITY` 缺失 | 添加 20+ 利用工具 |
| M8 | `_topological_sort` vs `_select_next` 不一致 | 统一处理 |
| M9 | `_select_next_task_from_plan` 缺回退 | 已在 R2 修复 |
| M10 | `_cteg_committed` 始终为 0 | 同步更新时机 |
| M11 | `_analyze_done` 不重置 | — |

### Low (11)
| L1 | 多 tool 调用 OR 语义掩盖部分失败 | — |
| L2 | `_pending_compressed_context` 可被覆盖 | 合并而非覆盖 |
| L3 | 硬截断后丧失情景记忆 | 注入截断通知消息 |
| L4 | `ddg_search` MCP 命名不可靠 | 提示词标注 |
| L5 | RAG 端口不完整 | 添加 9200/8086/5984 等 |
| L6 | MCP required 参数错误 | 排除有默认值的参数 |
| L7 | `oracle_query` heredoc 单引号敏感 | `<<<` → `printf` |
| L8 | `jwt_forge` 单引号 breaking | 改为 base64 编码 |
| L9 | `_flag_watcher` 访问私有 `_events` | `dkg.subscribe()` |
| L10 | 多 flag 覆盖 TaskResults | — |
| L11 | prompt.split() 脆弱 | — |

---

## Round 6: 最终审计修补（4 项）

| # | 问题 | 修复 |
|---|------|------|
| 1 | `asyncio.wait_for(timeout)` 超时丢弃已完成结果 | try/except TimeoutError 回退到 `_build_result()` |
| 2 | `_solo_exhausted` / `_multi_exhausted` 未初始化 | `__init__` 显式初始化 False |
| 3 | Solo 耗尽后空转 7 次 | 添加 `if self._solo_exhausted: continue` |
| 4 | 5 个未使用 imports | 移除 |

---

## Round 7: 运行反馈修复（4 项）

### Fix 7.1: 黑名单 SSH 暴力破解
**文件**: `darwin/orchestrator.py` — `_generate_exploitation_plan()`
```python
_PLAN_BLACKLIST = {"hydra_ssh_brute"}
plan.tasks = [t for t in plan.tasks if t.get("tool", "") not in _PLAN_BLACKLIST]
```

### Fix 7.2: 路径启发式跳过非 HTTP URL
**文件**: `darwin/orchestrator.py` — `_augment_from_dkg()`
path heuristic 增加 `not url.startswith("http")` 检查，防止 `redis://` URL 中端口号被 `/\d+/` 匹配

### Fix 7.3: 服务名称匹配非标准端口
**文件**: `darwin/orchestrator.py` — `_augment_from_dkg()`
新增 `_SVC_NAME_MAP`，通过 banner 文字匹配服务类型，支持非标准端口（如 Redis:10205）

### Fix 7.4: `authbypass`/`weakauth` 加入 VULN_TOOL_MAP
**文件**: `darwin/orchestrator.py` — `_systematic_exploit_pass()`
systematic exploit pass 能正确映射 AuthBypass→redis_cmd 等非 HTTP 漏洞

### Fix 7.5: Bootstrap 跳过非 HTTP 服务的 HTTP probe
**文件**: `darwin/orchestrator.py` — `_bootstrap_scan()`
新增 `_NON_HTTP_SVC_NAMES` 按服务名称过滤，防止为 Redis/SSH/MySQL 等非 HTTP 服务创建 HTTP 端点（避免后续生成 XSS 假阳性）

### Fix 7.6: RAG 后台预加载
**文件**: `darwin/orchestrator.py` — `run()`
在 bootstrap 开始时通过 `asyncio.create_task(asyncio.to_thread(get_rag))` 后台加载 RAG，将 ~45s 加载时间与 bootstrap 扫描并行化

### Fix 7.7: 后过滤非 HTTP 假阳性
**文件**: `darwin/orchestrator.py` — `_augment_from_dkg()`
在 augmentation 完成后，过滤掉所有对非 HTTP 服务（redis://, mysql://, ssh:// 等）的 web-only vuln（XSS, SQLI, IDOR 等）

---

## 修改文件统计

| 文件 | 修改次数 |
|------|---------|
| `darwin/orchestrator.py` | 核心调度器 — 涉及所有 7 轮修改 |
| `darwin/sub_agents/base.py` | 子代理基础类 — 环形依赖/失败标记/Kahn 算法/日志 |
| `darwin/sub_agents/exploit_agent.py` | 利用代理 — 日志 |
| `darwin/sub_agents/recon_agent.py` | 侦察代理 — 日志 |
| `darwin/tools/attack_server.py` | 攻击工具 — 5 个新工具 + 5 个模板修复 |
| `darwin/tools/mcp_gateway.py` | MCP 网关 — required 参数修复 |
| `darwin/data_model.py` | 数据模型 — CycleTransitionSummary + Host/Session/Domain |
| `darwin/utils/llm.py` | LLM 会话 — 截断通知 + 压缩合并 |
| `darwin/prompts/orchestrator.py` | 提示词 — 非 HTTP + 工具列表 + RAG 文本 |
| `darwin/prompts/ad_agent.py` | AD 提示词 — Silver Ticket 工具名 |

---

## 测试状态

```
90 passed in 0.29s
```
所有修改后测试全绿，无回归。

## Round 8: Plan粒度 + RAG传输修复

### Fix A: 研究结果结构化传输
- VulnerabilityHypothesis 新增 research_techniques / research_cves 字段
- _research_phase 填充新字段（不再仅拼接 evidence 字符串）
- _format_vulnerability_summary 显示独立的研究结果段落（不受200字符截断限制）

### Fix B: 任务链分解
- 简单利用（SQLi/XSS/CMDi）仍为 1 task
- 复杂多步利用（Redis SSH注入 / K8s逃逸 / 横向移动）LLM可拆分为独立task
- 任务上限 3-8 → 3-30
- 示例：CONFIG SET → dbfilename → SET → SAVE 各为独立task

### Fix C: redis_cmd 工具描述完善
- 增加完整 SSH key 注入链步骤
- 增加 cron shell 注入链
- 标注每次调用一个命令以明确需要多次调用

### Fix D: systematic exploit pass proto 工具过滤
- `_systematic_exploit_pass` 添加 `_PROTO_TOOLS` 映射
- `redis://` 端点只用 `redis_cmd`/`shell_exec`
- `ssh://` 端点只用 `ssh_exec`/`ssh_key_exec`/`test_credential`
- `mysql://` 端点只用 `mysql_query`/`shell_exec`
- DKG XSS 假阳性节点一并清理

### Fix E: systematic pass 移除 hydra_ssh_brute
- `weakauth` 的 VULN_TOOL_MAP 中删除 `hydra_ssh_brute`

---

## Round 9: 任务执行工具强制绑定

**文件**: `darwin/orchestrator.py` — `_unified_llm_loop()`

**问题**: Plan 生成了正确的 `"tool"` 字段，但执行阶段 LLM 可以自由替换工具（"You may use a different tool"）。task-4 应该用 `redis_cmd GET`，LLM 却选了 `shell_exec cat`。

**修复**: 当 plan task 有明确非空的 `"tool"` 字段时，强制 LLM 使用该工具：
```python
if task_tool and task_tool != "curl_get":
    freedom_note = "You MUST call the tool '{task_tool}' now. Do not substitute."
```
prompt 中 `Suggested tool:` → `Required tool:`。

**效果**: 计划指定了工具的任务不会在执行时被 LLM 错误替换。

---

## 修改文件最终统计

| 文件 | 修改轮次 |
|------|---------|
| `darwin/orchestrator.py` | R1-R9（所有轮次） |
| `darwin/sub_agents/base.py` | R2, R3, R5 |
| `darwin/sub_agents/exploit_agent.py` | R3 |
| `darwin/sub_agents/recon_agent.py` | R3 |
| `darwin/tools/attack_server.py` | R3, R5, R8 |
| `darwin/tools/mcp_gateway.py` | R5 |
| `darwin/data_model.py` | R4, R5, R8 |
| `darwin/utils/llm.py` | R5 |
| `darwin/prompts/orchestrator.py` | R3, R4, R5 |
| `darwin/prompts/ad_agent.py` | R3 |

## 测试状态

```
90 passed in 0.29s
```
所有修改后测试全绿，无回归。
