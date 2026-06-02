# DARWIN Framework Changes — 2026-05-29

## 2026-06-02 (tools + knowledge: benchmark capability gap fill)

**背景**: 对照 `benchmarks/cve_challenges/docs/` 中 50 个场景 + 22 条攻击链，识别 DARWIN 缺失的工具和知识条目。

**新增工具 (4)**:
- **darwin/tools/attack_server.py — `mysql_file_write`**: MySQL SELECT INTO DUMPFILE 二进制文件写入。用 hex-encoded content 通过 `mysql -e` 写入 MySQL 服务器文件系统。填补 MySQL UDF 提权的关键工具缺口（WEB-08, DB-02, 2 条链）。
- **darwin/tools/attack_server.py — `impacket_getST`**: S4U2Self/S4U2Proxy 约束委派攻击。填补 AD-16 (Constrained Delegation) 和 kerb-to-deleg 链的工具缺口。
- **darwin/tools/attack_server.py — `smb_client`**: SMB/CIFS 文件读写。填补 GPP/cpassword 提取（AD-13）和 SMB 文件访问的缺口。
- **darwin/tools/attack_server.py — `etcdctl_get` 增强**: 新增 `key` 和 `output_opts` 参数。支持读取具体 Secret 的完整值（-o json），不再只做 keys-only。影响所有 12 条以 etcd 为终点的 K8s 链。

**VULN_TOOL_MAP 扩增**:
- **darwin/orchestrator.py**: 新增 11 个漏洞类型映射（deserialization, ssrf, xxe, jwt, race condition, informationdisclosure, privilege_escalation, container_escape, mysql_file_write, mysql_udf, postgres_rce）。FUZZY_MAP 新增 6 个关键词。

**新增知识条目 (11)**:
- **knowledge/db_exploitation.json** (新文件): MySQL UDF 提权, PostgreSQL COPY PROGRAM RCE, MSSQL xp_cmdshell 启用, MSSQL Linked Server 横向移动
- **knowledge/cloud/k8s_escape_techniques.json** (新文件): cgroup release_agent 逃逸, Kubelet 匿名 API, etcd 导航, CRI socket 逃逸, Docker socket 逃逸, hostPath symlink 逃逸, SA token 跨命名空间横向移动

**RAG**: 8073 total entries (rebuild 后)

**验证**: Pytest 90 passed (0.31s), import test 通过, RAG rebuild 成功

## 2026-06-02 (fix: CTEG credential leak → LLM drift)

**根因**: `_current_svc_names` set 包含空字符串 (`{""}`)，因为 bootstrap Service 节点没有 `service_name` 字段。`"" in "mssql"` 在 Python 中永远为 True → CTEG 凭据的 service match filter 完全失效 → 所有历史凭据（包括 `sa:Password123! → localhost:10119`）泄漏到当前靶机的 LLM context → LLM 在 plan review 阶段创造虚构目标的任务（nmap_full_scan, MSSQL 探测 port 10119, K8s）。

**修复**:
- **darwin/orchestrator.py — Fix 1 (根因)**: `_current_svc_names` 构建时过滤掉空的 service_name：`if s.get("service_name")`。修复后空 set → `_svc_match` = False → 凭据只能通过 port 精确匹配进入。
- **darwin/orchestrator.py — Fix 3 (数据完整性)**: Bootstrap `_bootstrap_scan()` 创建 Service 节点时新增 `service_name` 字段（来自 nmap 输出）。2 处 Service 节点创建均添加。
- **darwin/orchestrator.py — Fix 4 (防御层)**: Plan review prompt 新增 "Target Consistency" 提醒：LLM 只能为 reconnaissance 已确认的服务创建 task，未发现的端口/服务上的凭据不可用于当前靶机。

**验证**: Pytest 90 passed (0.32s)。空字符串匹配逻辑确认：修复前 `{""}` → `"" in "mssql"` = True (bug)；修复后空 set → `_svc_match` = False。

## 2026-06-02 (prompt: attack path reasoning)

**核心问题**: LLM 拥有 Recon + Research 知识但无法合成攻击链、设计带依赖关系的攻击 task。根因：prompt 引导 LLM 识别独立漏洞，但无攻击链合成指引。

**修改**:
- **darwin/prompts/orchestrator.py — SYSTEM_PROMPT_ANALYZE**: 新增 Phase 3 "Synthesize Attack Paths"（5 步推理框架）+ attack_paths JSON 输出字段。Phase 2 扩展版本对照子步骤。
- **darwin/prompts/orchestrator.py — SYSTEM_PROMPT_ORCHESTRATOR_UNIFIED**: 将 1 句话的 Exploit 步骤(step 9)替换为 4 段策略块（入口选择→多步分解→失败自适应→后利用集成）。step 11 "Re-prioritize" 改为 "Recognize exhaustion"（含停止条件）。
- **darwin/orchestrator.py — _generate_exploitation_plan()**: 在 RAG context 与 Task format 之间插入"Synthesizing Knowledge into Attack Tasks"知识合成桥梁。
- **darwin/prompts/exploit_agent.py — SYSTEM_PROMPT_EXPLOIT_EVALUATE**: Key indicators 从 5 种扩展到 15 种漏洞类型（SSTI/LFI/XXE/IDOR/SSRF/反序列化/JWT/FileUpload 等）。
- **darwin/data_model.py — to_prompt_context()**: 漏洞假设/凭据段落无数据时输出显式空状态文本。
- **darwin/orchestrator.py**: 统一双 Prompt — 6 处 legacy SYSTEM_PROMPT_ORCHESTRATOR 引用替换为 UNIFIED。
- **darwin/orchestrator.py**: CTEG/RAG 无数据时输出明确 fallback 消息。

**泛用性**: 所有攻击链示例为抽象模式，无硬编码路径/端口/CVE，适用于 Web/DB/K8s/AD 场景。向后兼容。

**验证**: import test 通过、pytest 90 passed (0.33s)、模板 .format() 无 KeyError。

## 2026-06-01 (dependency + file:// fixes)
- **darwin/orchestrator.py**: `_select_next_plan_task` 新增全部依赖失败检测。当任务的所有依赖都是 FAILED 时，任务标记为 skipped（如"如果任何凭据成功，枚举数据库"的 7 个凭据全部失败时，后续利用任务不应执行）。修复前 FAILED 被当作"依赖满足"解锁下游任务。
- **darwin/orchestrator.py**: `_sanitize_plan_tools` 新增 `file://` URL 检测。Plan 任务中 `curl_get`/`http_post` 使用 `file://` 协议时直接标记为 skipped。同时在工具执行时（line ~1860）拦截 `file://` URL 调用并返回 BLOCKED 错误。
- 修复背景：MSSQL 凭据全部失败后 LLM 漂移到搜索本地文件系统（`curl_get file:///root/.bash_history`），在 /root/.bash_history 中发现 `flag{test_vuln_2026}` 残留 flag。

## 2026-06-01 (plan generation + thin-warning fixes)
- **darwin/orchestrator.py**: thin_warning 触发条件放宽：从 `n_endpoints >= 3` 改为 `n_endpoints >= 3 or n_services >= 1`。修复前非 HTTP 靶机（0 endpoint）永远不会触发 thin_warning，LLM 不会生成额外任务。同时强化提示词：要求 WeakAuth 至少尝试 5-10 组凭据。
- **darwin/orchestrator.py**: `_generate_exploitation_plan` prompt 新增 WeakAuth 专项指导：列出常见 MSSQL 账户/密码组合，要求生成多个凭据测试任务 + 数据库枚举 + xp_cmdshell + linked server 发现任务。修复前 LLM 对单个 WeakAuth 漏洞只生成 1 个任务。

## 2026-06-01 (credential placeholder resolution)
- **darwin/orchestrator.py**: `_sanitize_plan_tools` 新增 `$credentials.*` 占位符解析。从 DKG 查询 Credential 节点，如果有有效凭据则替换占位符为实际值；如果没有凭据则标记任务为 skipped（避免用空值执行导致无意义的 "OK, 0 rows" 结果并错误地解除下游阻塞）。

## 2026-06-01 (preventive blacklist + auth detection)
- **darwin/orchestrator.py**: `_BLACKLISTED_TOOLS` 初始值新增 `mssql_query → mssqlclient_query`（sqlcmd 未安装，直接路由到 impacket）和 `nmap_port_range → skip`（bootstrap 已完成扫描）。修复前这些工具在 plan 生成时就会出现，导致 7 个任务连续 `exit=127` 失败后才被响应式黑名单拦截。
- **darwin/tools/attack_server.py**: `mssqlclient_query` 新增认证失败检测。impacket 的 `mssqlclient.py` 即使 "Login failed" 也返回 exit=0，导致空凭据连接被标记为 DONE，解除后续 10 个依赖任务的阻塞。现在解析输出中的 "Login failed" 并设置 success=False。

## 2026-06-01 (remove explore phases)
- **darwin/orchestrator.py**: 移除 Solo 模式 free-form exploration 阶段（~155 行）。Plan exhausted 后直接进入 outer loop 下一轮生成新 plan，不再有 6 轮无结构的 `[solo:explore:N]` 自由探索。同时删除 `_EXPLORE_BLOCKED_TOOLS` 和 `_summarize_plan_learnings()` 方法。
- **darwin/orchestrator.py**: 移除 Multi-agent `_llm_explore` 方法（~225 行）。认证后探索直接走 `_post_auth_explore`（确定性启发式爬虫），不再先尝试 LLM 自由发挥。删除 `SYSTEM_PROMPT_EXPLORE` import。
- 原因：explore 阶段从未产生有效 flag，只产生 false flag（本地文件搜索）、浪费 token（每轮 ~3-4k）、重复 nmap/curl 等无效操作。Plan exhausted 后的 `_review_and_update_plan` + thin_warning 已提供结构化重试机制。

## 2026-06-01 (tool fallback & plan sanitization)
- **darwin/orchestrator.py**: `mssql_query` 失败时自动回退到 `mssqlclient_query`。新增 `_TOOL_FALLBACK` 映射：当工具因 `exit=127`（二进制未安装）失败时，自动用 fallback 工具重试同一组参数。`_BLACKLISTED_TOOLS` 的 replacement 设为 fallback 工具名（非空），后续 plan 任务自动替换。修复前 `sqlcmd` 未安装导致 5+ 个 MSSQL 任务全部失败，LLM 开始怀疑端口 10119 不是 MSSQL 而漂移。
- **darwin/orchestrator.py**: `_BLACKLISTED_TOOLS` 新增 `nmap_full_scan` 和 `masscan_scan`（空 replacement = 跳过）。Bootstrap 已完成全端口扫描，plan 中的全扫描任务一律标记为 skipped。
- **darwin/orchestrator.py**: `_sanitize_plan_tools` 新增 `nmap_port_range` 范围检测：端口范围 >5000 时标记为 skipped。防止 plan 阶段重复全端口扫描。

## 2026-06-01 (explore & systematic fixes)
- **darwin/orchestrator.py**: Free-form explore 阶段阻止冗余 recon 工具。新增 `_EXPLORE_BLOCKED_TOOLS` 集合（nmap_*, masscan_scan），explore 阶段 LLM 调用这些工具时返回 BLOCKED 消息而不执行。explore prompt 新增 "Do NOT run port scanners" 提示。修复前 plan 耗尽后 LLM 重复运行 nmap/masscan（bootstrap 已扫描完毕）。
- **darwin/orchestrator.py**: `_systematic_exploit_pass` 协议检测修复。新增 `_detect_proto_from_service()` 函数：当 endpoint 无 URI scheme（如 `localhost:10119`）时，从 DKG Service 节点通过端口号反查协议（service_name + port-based fallback）。修复前 scheme-less endpoint 回退到 `_ALL_PROTOCOL_TOOLS`，导致 ssh_exec/mysql_query/psql_query 全部尝试 MSSQL 端口，全部报 Template format error。
- **darwin/orchestrator.py**: `_review_and_update_plan` 新增 `focus_reminder`。当 plan 中存在 FAILED 利用任务（非 probe/whatweb 类探测任务）时，强制提醒 LLM 优先用修正后的工具/参数重试这些主目标任务，禁止在主要利用任务完成前为偶然发现的 HTTP 端口添加探测任务。修复前 nmap_full_scan 发现 20+ 端口后，LLM 立即为每个端口创建 whatweb/curl 任务，抛弃失败的 MSSQL 利用任务。
- **darwin/orchestrator.py**: thin-plan warning 增加 target focus 提醒。当 plan 耗尽需要补充任务时，提示 LLM 优先穷尽分析阶段识别的原始漏洞类型（如 WeakAuth），再探索无关 HTTP 端点。
- **darwin/orchestrator.py**: `_summarize_plan_learnings()` 新增非 HTTP 服务列表输出。explore 阶段 LLM 现在可以看到 DKG 中已发现的服务（协议+端口+banner），无需 nmap 就能知道目标。
- **darwin/orchestrator.py**: `_summarize_plan_learnings()` 新增非 HTTP 服务列表输出。explore 阶段 LLM 现在可以看到 DKG 中已发现的服务（协议+端口+banner），无需 nmap 就能知道目标。
- **darwin/orchestrator.py**: thin-plan warning 增加 target focus 提醒。当 plan 耗尽需要补充任务时，提示 LLM 优先穷尽分析阶段识别的原始漏洞类型（如 WeakAuth），再探索无关 HTTP 端点。防止 plan 漂移到 K8s/Plannotator 等无关目标。

## 2026-06-01 (later)
- **darwin/tools/attack_server.py**: 新增 `mssqlclient_query` 工具，使用 impacket 的 `mssqlclient.py`（已预装）替代 `sqlcmd`（未安装）。与 `mssql_query` 并存，LLM 可择优使用。修复前 `sqlcmd` 缺失导致所有 MSSQL 凭据测试因 `exit=127` 失败，LLM 飘逸到 nmap/curl/SSH/kubectl。
- **darwin/tools/attack_server.py**: `netexec_enum` 模板重构：二进制名 `nxc`→`netexec`，支持 `{protocol}` 参数化（smb/mssql/winrm/ssh/ldap），支持 `{user}` `{password}` `{extra_flags}` 传参。
- **darwin/orchestrator.py**: Solo 耗尽后提前终止。新增 `_solo_exhausted_stall` 计数器：solo 耗尽后若 3 轮仍无 multi-agent 进入（B < 0.3 不变），立即终止。修复前需等到 MAX_LOOPS=100 才停止（95 轮空转）。
- **darwin/orchestrator.py**: 无进展检测。新增 `_no_progress_loops` 计数器：连续 2 轮外部循环产生 0 新端点/凭据/漏洞 → 提前终止。修复前任务全部失败但探测类任务 "done" 制造假进展，框架感知不到。
- **darwin/orchestrator.py**: `_should_terminate` 终止条件从 5 项扩展为 7 项（新增 solo-stall + no-progress）。
- **darwin/orchestrator.py**: 运行时工具黑名单（Fix B）。工具返回 `exit=127` + stderr 含 `not found` 时，自动将工具名加入 `_BLACKLISTED_TOOLS`（空替代值 → 标记 skipped），并调用 `_sanitize_plan_tools` 即时清除 plan 中的待执行任务。修复前 `netexec` 未安装导致 12 个相同 `netexec: not found` 失败。
- **darwin/orchestrator.py**: DB 认证部分成功检测（Fix A）。扩展 `_analyze_and_fix_task` 增加 `partial_success` 分类：当 LLM 判定"认证成功但子命令失败"时（如 MSSQL sa/sa 登录成功但 xp_cmdshell 'findstr' 在 Linux 上返回 127），提取凭据存入 DKG，任务标记为 done 而非 failed。下游任务可复用已验证的凭据。
- **darwin/orchestrator.py**: Plan review 负向知识注入（Fix C）。新增 `_absent_services` 集合追踪被探测但不可达的目标（connection refused / can't connect / DB 工具失败），在 plan review prompt 中注入一行 `## Unreachable (do NOT probe again)` 避免 LLM 重复生成 check-redis/check-mysql 等低质量探测任务。
- **darwin/tools/mcp_gateway.py**: 参数名双向自动纠正。在原有的 `_tv in k`（模板变量是 kwargs key 的子串）基础上增加 `k in _tv` 方向（kwargs key 是模板变量的子串），解决 `target`→`target_url` 不匹配（如 whatweb_scan 模板用 `{target_url}` 但 LLM 传 `target`）。同时要求 ≥3 chars 且 ≥50% 长度避免误匹配。

## 2026-06-01 (early)
- **darwin/tools/mcp_gateway.py**: `register_shell_tool` 参数名自动纠正。当 LLM 生成的参数名与 shell 模板变量名不匹配时（如 LLM 传 `username` 但模板用 `{user}`），自动检测 substring 包含关系并映射。修复前 `mssql_query` 因 `username`→`{user}` 不匹配报 "Template format error" 导致所有 MSSQL 凭据测试任务失败。
- **darwin/orchestrator.py**: `_select_next_plan_task` 依赖解除逻辑修复。将 `dep_task.get("status") != "done"` 改为 `not in ("done", "failed", "exhausted", "skipped")`。修复前上游任务因参数错误 FAILED 后，所有依赖任务被永久阻塞（deadlock），导致 Solo 模式在 3 次迭代后 plan exhausted 但无任何进展。

## 2026-05-30
- **darwin/orchestrator.py**: `_systematic_exploit_pass` HTTP 协议过滤。当 endpoint 是 http/https 时，过滤掉 `ssh_exec`, `mysql_query`, `psql_query`, `mssql_query`, `oracle_query`, `redis_cmd`, `shell_exec` 等仅适用于非 HTTP 协议的工具。修复前 `weakauth` 对 WordPress 登录页会依次尝试 7 个工具（其中 6 个是 DB/SSH 工具全部空转），修复后只保留 HTTP 兼容工具。
- **darwin/orchestrator.py**: 将 `wpscan` 加入 `REQUIRED_TOOLS` 列表。wpscan_enum 工具依赖 wpscan CLI（Ruby gem），之前未在启动时检查可用性，导致 WordPress 用户枚举静默失败（仅返回 45 bytes 输出）。
- **darwin/tools/attack_server.py**: 重写 `wpscan_enum` 从 shell template 改为 Python 函数。API token 为空时自动省略 `--api-token` 参数并将 `vp`→`p`, `vt`→`t` 降级（漏洞检测需要 token，但插件/用户枚举不需要）。添加 `--no-banner` 和增大输出限制 head -500。修复前返回 45 bytes，修复后返回 3504 bytes（77x 提升），含 XML-RPC、WP 版本、主题等信息。
- **darwin/tools/attack_server.py**: `_wpscan_enum` API 额度耗尽自动降级。检测 8 种 API limit 错误模式 + 无漏洞数据返回（缺少 CVE/[critical]），自动重试不带 token。token 来源优先级：LLM 传参 → WPSCAN_API_TOKEN 环境变量 → config/darwin.yaml。
- **darwin/tools/attack_server.py**: `_wpscan_enum` enum_mode 自动升级。LLM 不知道 token 已配置，传入降级模式 `p,t,u` 时自动升级为 `vp,vt,u` 利用 token 做漏洞检测。
- **darwin/orchestrator.py**: `_format_tool_feedback` 信息收集工具输出截断上限从 1500→5000 字符。wpscan/nmap/nikto/dirb/knowledge_search 等 11 个工具的 stdout 不再在格式化阶段被截断。
- **darwin/orchestrator.py**: `add_tool_result` 截断上限从 2500→7000（信息工具）/ 3000（其他工具）。配合格式化阶段改动，确保 LLM 能看到 wpscan 插件列表等长输出。
- **darwin/utils/llm.py**: `compress()` 修复 tool_calls/tool 对拆散问题。压缩边界（keep_recent=6）可能将 assistant tool_calls 放入被压缩的老消息，而对应的 tool result 保留在最近消息中，导致 DeepSeek 拒绝请求（"Messages with role 'tool' must be a response to a preceding message with 'tool_calls'"）。修复后扫描边界，检测到第一个保留消息是 tool 角色时向前扩展边界以包含其配对的 tool_calls。
- **darwin/orchestrator.py**: Plan 任务数限制。初始 plan 生成限 8 个任务（prompt 中明确要求），plan review 限总任务数不超过 15（超过时要求先删除低质量 pending 再添加新任务）。修复前单次 plan 生成可达 33 个任务。
- **darwin/tools/mcp_client.py**: `MCPClientPool.call_tool` 不再向上抛出 `asyncio.TimeoutError`。MCP 工具超时（web-search/nvd_search_cves 等）后 return error dict 而非 re-raise 异常，防止 `_research_phase` → `_unified_llm_loop` → `run()` 整条调用链被一次 MCP 超时杀死。
- **darwin/orchestrator.py**: `_research_phase` 工具执行增加 45s MCP 超时保护 + 逐工具 try/except。单个 MCP 工具超时或失败不会中断整个研究阶段，其他工具继续执行。修复前 LLM 调用 web-search/nvd_search_cves → MCP 120s 超时 → TimeoutError 穿透到 run() → 任务返回 "Internal timeout at 209s"。
- **config/darwin.yaml**: 新增 `wpscan.api_token` 配置项。

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
