# `darwin/prompts/planner.py`

## 模块定位

定义规划器角色，要求 LLM 输出带目标、依赖、理由和工具参数的结构化 Task 计划。

## 关键入口

- `SYSTEM_PROMPT_PLANNER`：规划边界、Task 结构和工具发现要求。

## 相关模块

`core/schemas.py`、`core/task.py`、`core/task_graph.py`、`orchestrator.py`。

## 阅读建议

结合 `PlanTaskV1` 和 orchestrator 的 registry 查询循环阅读。

