# `darwin/core/runtime.py`

## 模块定位

v2 控制面的唯一执行循环：消费计划、调度 Task、执行、评估、重规划并返回运行结果。

## 所在链路

核心链路本身：`plan → schedule → execute → evaluate → replan`。

## 关键入口

- `Runtime`：循环和阶段协作。
- `RuntimeOutcome`：循环结果。

## 相关模块

`contracts.py`、`task_graph.py`、`scheduler.py`、`executor.py`、`evaluator.py`、`replan.py`、`memory.py`。

## 阅读建议

先读 `Runtime.run()` 的循环边界，再分别进入五个组件；不要从 Orchestrator 的旧阶段实现推断执行路径。

## 维护提示

这是唯一执行路径；状态、预算、失败分类和部分成功提取必须保持一致。

