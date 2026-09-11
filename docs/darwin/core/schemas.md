# `darwin/core/schemas.py`

## 模块定位

定义阶段间 LLM 输出的版本化 Pydantic schema，并提供宽松提取、严格校验和 legacy fallback 的解析入口。

## 所在链路

LLM 输出与 Orchestrator/Planner 输入之间的契约边界。

## 关键入口

- `AnalyzeOutputV1`、`ResearchFindingV1`、`ServiceResearchFindingV1`、`PlanTaskV1`：阶段模型。
- `AnalyzeOutputV1.vulnerabilities` 只收有观测证据的假设；无证据的模式猜测
  进新增的可选字段 `speculative`，不研究、不进计划、不写 DKG。
- `PlanTaskV1.success_condition`（可选）声明可机器校验的完成条件
  （tool_success / body_contains / body_not_contains / http_status_in /
  flag_captured / probe），由执行层校验后才判定任务成功。
- `parse_analyze_output()`、`parse_research_findings()`、`parse_plan_tasks()`：解析入口。
- `extract_json_value()`：从自然语言/围栏中提取 JSON。

## 相关模块

`orchestrator.py`、`prompts/`、`core/task.py`、`core/contracts.py`。

## 阅读建议

先看模型字段，再看提取、校验和失败返回的分层。

## 维护提示

schema 违规必须可观测并回退，不要因严格解析破坏旧输出兼容。
