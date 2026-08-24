# `darwin/core/context.py`

## 模块定位

管理 Runtime 每轮需要提供给 planner/evaluator 的上下文，并协调 DKG、记忆和压缩视图。

## 所在链路

Runtime 循环与 LLM prompt 之间的上下文边界。

## 关键入口

- `ContextManager`：构建、裁剪和刷新阶段上下文；云/K8s 环境由 DKG `topology_context()` 提供有界摘要、局部图和 coverage。

## 相关模块

`belief.py`、`memory.py`、`dkg.py`、`utils/llm.py`。

## 阅读建议

先看上下文生命周期，再确认压缩前后保留哪些结构化信息。

## 维护提示

上下文管理只能压缩或裁剪，不应丢失跨阶段 DKG 事实和关键执行结果。
