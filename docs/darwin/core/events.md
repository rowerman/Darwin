# `darwin/core/events.py`

## 模块定位

集中定义 Runtime 和编排器可记录的事件名称。

## 所在链路

横跨计划、执行、评估、schema 违规和重规划的可观测性边界。

## 关键入口

- `RuntimeEvent`：事件枚举。

## 相关模块

`runtime.py`、`orchestrator.py`、`utils/phase_logger.py`、`core/metrics.py`。

## 阅读建议

结合事件使用点阅读，不需要单独追踪实现逻辑。

## 维护提示

事件名称会被日志和指标消费，重命名可能破坏分析脚本。

