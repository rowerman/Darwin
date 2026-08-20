# `darwin/core/executor.py`

## 模块定位

把已调度 Task 通过 capability 和 MCPGateway 执行，并统一包装工具结果。

## 所在链路

Runtime 的 execute 阶段，连接 Task/Capability 与外部工具。

## 关键入口

- `ToolExecutor`：任务执行协调。
- `ToolOutcome`、`ExecutionResult`：执行结果模型。

## 相关模块

`capabilities.py`、`parameters.py`、`task.py`、`tools/mcp_gateway.py`。

## 阅读建议

先看执行结果模型，再看参数校验、adapter/capability 和网关调用顺序。

## 维护提示

不得绕过 MCPGateway；未知工具必须失败，异常应包装为可供评估器处理的结果。

