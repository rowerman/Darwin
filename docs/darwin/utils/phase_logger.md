# `darwin/utils/phase_logger.py`

## 模块定位

按阶段记录结构化运行日志，支持结果汇总和调试。

## 关键入口

- `PhaseLogger`：阶段日志生命周期和写入。

## 相关模块

`orchestrator.py`、`core/events.py`、`config/darwin.yaml`。

## 阅读建议

先看 logger 初始化和阶段边界，再看输出目录和级别控制。

