# `darwin/runner.py`

## 模块定位

兼容入口层，重新导出 `Orchestrator` 和 `TaskResult`，保持旧调用路径可用。

## 所在链路

CLI 与编排器之间的兼容适配层。

## 关键入口

- `Orchestrator`：来自 `darwin.orchestrator` 的 re-export。
- `TaskResult`：来自 `darwin.orchestrator` 的结果类型。

## 相关模块

`run.py`、`orchestrator.py`。

## 阅读建议

通常直接跳到 `orchestrator.py`；只有排查旧导入路径时阅读本文件。

## 维护提示

不要在这里加入新的运行逻辑，优先保持兼容导出。

