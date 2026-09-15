# `darwin/orchestration/planning.py`

## 模块定位

`PlanCoordinator`：计划域方法分片，继承 `CoordinatorContext`。

## 关键入口

- `_generate_exploitation_plan()`：基于 DKG/CTEG/注册表生成利用计划。
  RAG「Attack Pattern Knowledge」按 techniques 优先渲染并注入 prompt；
  该块异常会记 warning（历史上被静默吞掉，导致所有计划都拿不到 RAG 步骤）。
  计划任务必须带 `success_condition`（见 core/schemas.md），计划评审同样透传。
- `_generate_with_registry_lookup()`：注册表查询 + LLM 生成（经门面转发，
  保证测试/调用方对门面的 patch 生效）；查询轮次耗尽且内容无效时执行一次
  无工具 JSON-only 收敛重试；DSML 工具调用会先被 `LLMSession` 归一化，最终
  JSON 校验结果与调用格式（dsml/openai）记录到日志。
- `_sanitize_plan_tools()`：黑名单清洗（`_BLACKLISTED_TOOLS`）。
- `_review_and_update_plan()`：计划评审与更新。
- `_analyze_and_fix_task()` / `_extract_credentials_from_task()`：失败分析与
  凭据提取。
- `normalize_success_condition()`：只保留运行时可验证的条件类型
  （`KNOWN_CONDITION_TYPES`），未知类型显式丢弃并告警。
- `_guess_tool(vuln_type, endpoint="", method="")`：按请求形状选工具——目标把
  路由声明为写动词时，读类默认工具不再适用。
- `_http_alternative_block()`：把能表达非 GET 请求的工具及其参数契约渲染进
  fix 提示，使"换工具"成为可执行的修复选项。
- 空漏洞兜底：Analyze 无假设但 DKG 存在 API/POST/JSON 端点时，
  `_collect_api_verification_endpoints()` + `_build_api_verification_tasks()`
  生成有上限的路由验证任务（仅端点确认与响应结构获取，不宣称漏洞；无参数
  schema 时用 `{}` 通用 JSON 探测）。两者皆空时保留空 PLAN 并明确记录原因。

## 相关模块

## 修复分析去重与修枝保护

- `_analyze_and_fix_task()` 按 `(task, tool, params)` 签名只分析一次：同样的失败
  再次出现时直接判为不可修复（`None`），不再付一次 60–180s 的 LLM 轮次。
  真实修复会改变签名，因此仍有分析机会。
- `_cap_pending_tasks()` 修剪低质量任务时保护"某端点的唯一、尚未执行过的任务"，
  避免剪掉 `ssrf_probe` / `command_injection_test` / `sqlmap_test` 后又被 plan
  review 重建同一攻击面。

`core/task.py`、`core/task_graph.py`、`core/schemas.py`、`cteg.py`、
`ports.py`。

注册表查询结束后使用无工具的结构化收敛请求；工具替换需依据已注册
`ToolSpec` 的参数和域信息，无法唯一匹配时不猜测替换。

## 工具可见性、可用性与纠错（通用规则）

- 工具契约卡渲染**全部**已注册工具（不再按条数截断）。此前截断会隐藏
  注册顺序靠后的 HTTP/侦察工具族，规划只能退回到可见的少数工具。
- 后生成改写（`shell_exec → aws_cli/curl_get`）只有在目标工具**本机可用**
  且所需参数可从原任务推导时才执行，否则保留原命令；禁止改写后留下空
  `params`。不可用工具在计划校验阶段替换为同域可用替代，或标记
  skipped 并写明原因。
- HTTP 目标参数集合包含 `url | endpoint_url | target_url | base_url |
  ssrf_url`；需要替换时按 `http_method_probe → http_post → send_payload →
  curl_get` 的优先级取第一个可用者，取不到则保留原工具（不静默丢弃任务）。
- 结构化阶段（analyze/plan/plan_review）通过 `LLMSession.isolated_scope()`
  在无历史上下文中单发；超时重试用同 prompt + 更长超时，而不是发送
  schema 修复文案。

## plan review 触发条件

`_review_and_update_plan()` 的确定性记账（`attempt_count`、状态流转、
`_exhausted_task_ids`、`result_summary`、PlanMemory 同步）始终执行；
LLM 复审仅在“任务失败 / 本任务产生 DKG 增量 / 无 ready 任务的 stall
复审（`force=True`）”时调用。没有基线（`_cognition_before` 为空）的调用
保持旧行为，一定复审。

### 复审节律（`_review_skip_reason()`）

复审会重写整份计划，因此必须由“上一版计划被真实执行验证过”来支付：
每个 runtime cycle 的**第一次**复审始终允许；其后只有满足以下任一条才允许
再写：出现新证据（`_evidence_since_review`，如新发现的路由/端点）、上一次
失败类型属于 `_REVIEW_TRIGGERING_FAILURES`（`invalid_argument` /
`tool_error` / `strategy_failed`，说明计划本身有问题）、或距上次复审已执行
`_MIN_EXECUTIONS_BETWEEN_REVIEWS`（3）个任务。剩余预算低于
`_REVIEW_MIN_REMAINING_SECONDS`（120s）时直接跳过复审进入收尾扫描。
预算门在 `force=True` 之前判定：stall 复审只绕过节律，不会绕过预算；剩余预算
低于"一次 LLM 调用能产出可用结果的下限"时连发起都不发起
（`_generate_structured()` 同样在每次尝试前检查，记 `llm_skipped_low_budget`）。
该下限为 `_llm_min_remaining()` = `min(25s, 10% × time_budget)`：短预算的
冒烟/集成运行不会被 25s 的固定门槛挡死。
计划确实无任务可执行时允许一次 stall 复审（`task.id == "plan-exhausted"`），
但“上次复审后零执行”时不再连发。计数由
`execution._execute_task_with_policies()` 自增、复审调用后清零。

### 不可行工具记忆

`CoordinatorContext._unusable_tools()` 保存本 run 确认不可用的工具及原因：
规划侧（`is_available()` 判定二进制缺失）与执行侧（工具回
`not allow-listed` / `command not found`）写同一份记录，`_sanitize_plan_tools()`
命中即跳过任务，评审提示词里也会列出该清单要求不要再为其建任务。
`_note_skipped()` 保证同一任务的跳因只追加一次——cloud-30 的一个任务被 11 次
评审反复重建，同一指令里出现了 8 次 `[skipped: aws_cli binary not installed]`。

### 计划完成性与裁剪

- 评审提示词包含“已声明但未按声明方法访问过的路由”清单（由
  `execution._untested_documented_routes()` 计算）；只要清单非空，计划就
  不算完成。
- `_cap_pending_tasks()` 的裁剪顺序为：保留覆盖这些路由的任务 →
  优先保留签名（tool+url）尚未执行过的任务 → 再按依赖数/有无工具排序，
  同档取**最新**加入的任务（它写于最新证据之上）。

### 写意图护栏（`_enforce_write_intent()`）

blocked 任务不在 preserved 集合里，复审会整体替换它——历史上曾把
`http_method_probe(method=PUT)` 的写任务换成只能 POST 的工具，使写步骤
不可达。复审后对 id 未变、原方法属于 `POST/PUT/PATCH/DELETE` 的任务：
仅当新工具本身是写工具且携带相同方法（或无方法概念）时接受替换，
否则回滚到复审前的 tool+params 并记 WARNING。

### 工具契约与读写分流

- fix_analysis 提示词附带当前工具的紧凑参数契约
  （`_render_tool_params()`：名称/类型/必填/默认），避免 LLM 猜测
  `json=`、dict body 这类工具不接受的形状。
- `_guess_tool()` 在无 suggested_tool 时按语义分流：写类关键词
  （dependency/supply/poison/squat/publish/package/artifact）返回可表达
  写动词的工具，其余沿用读类默认，而不是一律 `curl_get`。
- plan 提示词要求写类任务使用可表达该动词的工具并带 `probe` 回读条件；
  analyze 提示词要求把写类机制命名成 `dependency_confusion` /
  `registry_poisoning` / `artifact_poisoning`，而不是 `IDOR`。
