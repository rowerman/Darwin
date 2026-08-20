# `darwin/core/metrics.py`

## 模块定位

从任务执行、失败、token 和时间记录计算运行指标。

## 所在链路

Runtime/Orchestrator 的观测和结果汇总层。

## 关键入口

- `MetricsCalculator`：计算指标。
- `MetricsReport`：指标结果。

## 相关模块

`runtime.py`、`executor.py`、`memory.py`、`experiments/`（仅作为外部消费者）。

## 阅读建议

先看报告字段，再追踪计算器读取的执行记录。

## 维护提示

指标字段变化要考虑历史结果聚合和 CLI 输出兼容。

