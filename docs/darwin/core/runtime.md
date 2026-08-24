# `darwin/core/runtime.py`

## 模块定位

v2 控制面的唯一执行循环：消费计划、调度 Task、执行、评估、重规划并返回运行结果。

## 所在链路

核心链路本身：`plan → schedule → execute → evaluate → replan`。

## 关键入口

- `Runtime`：循环和阶段协作。
- `RuntimeOutcome`：循环结果。
- `state_provider`：可选的工作状态刷新回调；提供时在评估和重规划前重新读取 DKG。
- Scheduler 接收当前 world snapshot 中的 active attack paths，用于满足 `requires_attack_path`；旧的二参数 Scheduler 仍兼容。

## 相关模块

`contracts.py`、`task_graph.py`、`scheduler.py`、`executor.py`、`evaluator.py`、`replan.py`、`memory.py`。

## 阅读建议

先读 `Runtime.run()` 的循环边界，再分别进入五个组件；不要从 Orchestrator 的旧阶段实现推断执行路径。

## 维护提示

这是唯一执行路径；状态、预算、失败分类和部分成功提取必须保持一致。拓扑状态必须在 execute 后通过 state provider 刷新，避免 replan 使用过期图快照。

plan-review/replan 的拓扑 diff 只在存在任务级基线（`_topology_before`）时注入；stall/plan-exhausted 等无基线路径会省略该区块，避免把整个图误报为新增。
