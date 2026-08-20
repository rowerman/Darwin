# `darwin/core/scheduler.py`

## 模块定位

根据 TaskGraph 的依赖和优先级选择当前可运行任务，并保留 legacy 顺序语义。

## 所在链路

Runtime 的 schedule 阶段，位于计划生成和 Executor 之间。

## 关键入口

- `ParityScheduler`：默认调度器。

## 相关模块

`task.py`、`task_graph.py`、`contracts.py`、`runtime.py`。

## 阅读建议

先看 ready/running 状态过滤，再看依赖满足和优先级排序。

## 维护提示

调度不能运行依赖未满足或已失效的 Task，且要保持旧任务顺序兼容。

