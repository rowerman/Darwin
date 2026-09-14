# `darwin/core/scheduler.py`

## 模块定位

根据 TaskGraph 的依赖和优先级选择当前可运行任务，并保留 legacy 顺序语义。

## 所在链路

Runtime 的 schedule 阶段，位于计划生成和 Executor 之间。

## 关键入口

- `ParityScheduler`：默认调度器。

## 未填占位符守卫

依赖全部终态后，任务参数若仍含未填充的模板 token
（`http://host/<function-invoke-route>`），说明它是在生产者运行之前写下的：
把字面量占位符发出去只能得到 404 与一轮修复分析（benchmark 日志里同一个
任务这样空跑了三次）。此类任务由 `tools/arg_contract.unresolved_placeholders()`
识别并直接置为 ABANDONED，交由 replan 用真实值重写。

## 相关模块

`task.py`、`task_graph.py`、`contracts.py`、`runtime.py`。

## 阅读建议

先看 ready/running 状态过滤，再看依赖满足和优先级排序。

## 维护提示

调度不能运行依赖未满足或已失效的 Task，且要保持旧任务顺序兼容。
