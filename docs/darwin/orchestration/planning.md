# `darwin/orchestration/planning.py`

## 模块定位

`PlanCoordinator`：计划域方法分片，继承 `CoordinatorContext`。

## 关键入口

- `_generate_exploitation_plan()`：基于 DKG/CTEG/注册表生成利用计划。
- `_generate_with_registry_lookup()`：注册表查询 + LLM 生成（经门面转发，
  保证测试/调用方对门面的 patch 生效）。
- `_sanitize_plan_tools()`：黑名单清洗（`_BLACKLISTED_TOOLS`）。
- `_review_and_update_plan()`：计划评审与更新。
- `_analyze_and_fix_task()` / `_extract_credentials_from_task()`：失败分析与
  凭据提取。

## 相关模块

`core/task.py`、`core/task_graph.py`、`core/schemas.py`、`cteg.py`、
`ports.py`。
