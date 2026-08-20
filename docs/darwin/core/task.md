# `darwin/core/task.py`

## 模块定位

定义 v2 运行时的 Task 数据对象、依赖序列化和状态持久化边界。

## 所在链路

从 LLM 计划进入 TaskGraph、Scheduler、Executor 和 Memory 的基础对象。

## 关键入口

- `Task`：任务目标、动作、依赖、状态和结果摘要。
- `deps_from_task_ids()`：将计划依赖转换为结构化依赖。

## 相关模块

`contracts.py`、`task_graph.py`、`scheduler.py`、`memory.py`、`schemas.py`。

## 阅读建议

先看构造和 `to_dict()/from_dict()`，再看状态和依赖如何被调度器使用。

## 维护提示

序列化是 checkpoint 的唯一通道；状态值必须使用 `TaskStatus`。

