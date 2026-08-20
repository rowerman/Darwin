# `darwin/orchestrator.py`

## 模块定位

DARWIN 的主编排器，负责目标初始化、侦察、LLM 阶段调用、Runtime 适配和最终结果汇总。

## 所在链路

贯穿完整 `recon → analyze → plan → execute → evaluate → replan → verify` 流程。

## 关键入口

- `Orchestrator`：主生命周期和阶段协调。
- `TaskExecution`：执行记录。
- `_RuntimePlannerAdapter`、`_RuntimeExecutorAdapter`、`_RuntimeEvaluatorAdapter`：旧阶段与 v2 Runtime 的边界。

## 输入/输出概览

输入是任务描述、目标、凭证、预算和 LLM 配置；输出是 `TaskResult`、DKG 状态、日志和 checkpoint。

## 相关模块

`core/runtime.py`、`core/schemas.py`、`dkg.py`、`dpm.py`、`dave.py`、`tools/`、`utils/`。

## 阅读建议

先读 `Orchestrator.run()` 的阶段顺序，再追踪 Runtime 适配器和 `_sanitize_plan_tools()`。

## 维护提示

编排器不得绕过 `core.Runtime` 或 MCP 网关直接执行外部工具；schema fallback 和上下文压缩不能破坏。

