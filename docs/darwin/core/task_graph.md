# `darwin/core/task_graph.py`

## 模块定位

维护 Task 之间的依赖关系、可运行性和失效传播。

## 所在链路

计划进入调度器前的结构化任务图。

## 关键入口

- `TaskGraph`：添加、查询、更新和依赖遍历。
- `DependencyType`、`dependency_task_ids()`：依赖语义和兼容读取；`requires_attack_path` 依赖当前 DKG 中处于 active 的 `path_id`。

## 相关模块

`task.py`、`scheduler.py`、`contracts.py`、`runtime.py`。

## 阅读建议

先看依赖类型，再看 ready 判定和状态传播。

## 维护提示

图更新必须保持无循环依赖和状态转换一致。带攻击路径依赖的任务在路径变为 stale/rejected 时保持 blocked，等待局部 replan。
