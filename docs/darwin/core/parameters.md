# `darwin/core/parameters.py`

## 模块定位

提供工具 schema、参数验证和轻量纠错，阻止不符合工具契约的 Task 进入执行。

## 所在链路

Planner/Capability 与 Executor 之间的参数边界。

## 关键入口

- `ToolSchemaProvider`：读取工具参数 schema。
- `ParameterValidator`：发现缺失、类型或范围问题。
- `ParameterCorrector`：只补齐声明默认值；**不删除**未声明参数，交给
  `ParameterValidator` 判为 INVALID_ARGUMENT。静默改写调用会让工具在不同于
  计划的请求上运行，其否定结果不可信。
- `ToolSchema`、`ParamIssue`：结果模型。

## 相关模块

`tools/spec.py`、`tools/mcp_gateway.py`、`capabilities.py`、`executor.py`。

## 阅读建议

先看 schema 来源，再看验证和纠错的边界。

## 维护提示

纠错不能绕过 required 参数、目标限制或 `file://` 等安全门控。
