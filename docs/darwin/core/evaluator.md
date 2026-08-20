# `darwin/core/evaluator.py`

## 模块定位

将工具执行结果判定为成功、失败、阻塞或需要重规划，并对失败原因分类。

## 所在链路

Runtime 的 evaluate 阶段，位于 Executor 之后、Replanner 之前。

## 关键入口

- `Evaluator`：任务结果评估。
- `FailureAnalyzer`：失败分类和修复提示。
- `Evaluation`、`Classification`、`FailureType`：评估结果模型。

## 相关模块

`executor.py`、`contracts.py`、`replan.py`、`memory.py`。

## 阅读建议

先看失败类型，再看 `Evaluator` 如何组合成功条件和失败分析。

## 维护提示

评估结果驱动状态迁移和重规划，新增失败类型需检查两个消费者。

