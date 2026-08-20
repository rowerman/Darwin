# `darwin/core/memory.py`

## 模块定位

实现 PlanMemory、ExecutionMemory 和 MemoryManager，负责保留、压缩和丢弃不同重要级别的运行信息。

## 所在链路

贯穿 Runtime 循环，为规划、评估、重规划和上下文压缩提供历史。

## 关键入口

- `PlanMemory`：保存任务 rationale、假设和证据。
- `ExecutionMemory`：保存归一化执行记录。
- `MemoryManager`、`ImportanceClassifier`：统一管理和分级。
- `CompressionView`：提供压缩后的视图。

## 相关模块

`context.py`、`belief.py`、`cteg.py`、`utils/llm.py`。

## 阅读建议

先看三类记忆的边界，再看压缩和重要性分类流程。

## 维护提示

压缩不能替代 DKG；关键事实和计划理由必须保留。

