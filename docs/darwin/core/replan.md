# `darwin/core/replan.py`

## 模块定位

根据评估结果修复失败任务或生成下一轮重规划建议。

## 所在链路

Runtime 的 evaluate 之后，连接失败分析与下一轮计划。

## 关键入口

- `LocalRepair`：局部、低成本的任务修复。
- `Replanner`：基于失败类型和上下文给出重规划决策。

## 相关模块

`evaluator.py`、`task.py`、`contracts.py`、`runtime.py`。

## 阅读建议

先看 `ReplanRecommendation`，再看局部修复和重规划的分界。

## 维护提示

失败最多重试和任务状态迁移约束由调用方共同保证。

