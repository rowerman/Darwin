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
