# `darwin/orchestration/planning.py`

## 模块定位

`PlanCoordinator`：计划域方法分片，继承 `CoordinatorContext`。

## 关键入口

- `_generate_exploitation_plan()`：基于 DKG/CTEG/注册表生成利用计划。
- `_generate_with_registry_lookup()`：注册表查询 + LLM 生成（经门面转发，
  保证测试/调用方对门面的 patch 生效）；查询轮次耗尽且内容无效时执行一次
  无工具 JSON-only 收敛重试；DSML 工具调用会先被 `LLMSession` 归一化，最终
  JSON 校验结果与调用格式（dsml/openai）记录到日志。
- `_sanitize_plan_tools()`：黑名单清洗（`_BLACKLISTED_TOOLS`）。
- `_review_and_update_plan()`：计划评审与更新。
- `_analyze_and_fix_task()` / `_extract_credentials_from_task()`：失败分析与
  凭据提取。
- 空漏洞兜底：Analyze 无假设但 DKG 存在 API/POST/JSON 端点时，
  `_collect_api_verification_endpoints()` + `_build_api_verification_tasks()`
  生成有上限的路由验证任务（仅端点确认与响应结构获取，不宣称漏洞；无参数
  schema 时用 `{}` 通用 JSON 探测）。两者皆空时保留空 PLAN 并明确记录原因。

## 相关模块

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
