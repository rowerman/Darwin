# `darwin/core/capabilities.py`

## 模块定位

把 Task 的高层动作映射为可执行 capability，并负责前置条件、上下文解析和结果归一化。

## 所在链路

Planner 输出 Task 与 Executor 调用工具之间的能力边界。

## 关键入口

- `Capability`、`CapabilityRegistry`：能力定义和注册表。
- `default_registry()`：默认能力集合。
- `PreconditionValidator`、`ContextResolver`：执行前检查和参数上下文。
- `normalize_result()`：将工具结果统一为执行结果。

## 相关模块

`task.py`、`executor.py`、`parameters.py`、`tools/adapters/`。

## 阅读建议

先看能力注册和默认映射，再追踪一个 Task 从参数解析到结果归一化的路径。

## 维护提示

能力名、前置条件和 adapter 映射变化会影响 planner 与执行契约。

