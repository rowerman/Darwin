# `darwin/orchestration/execution.py`

## 模块定位

`ExecutionCoordinator` 与三个 Runtime 适配器：执行域方法分片，继承
`CoordinatorContext`；同时保留 `TaskExecution`、`_RuntimeFlagFound`、
`_RuntimePlannerAdapter`、`_RuntimeExecutorAdapter`、`_RuntimeEvaluatorAdapter`
（原 `darwin.orchestrator` 模块级导出，继续由 `darwin.orchestrator` re-export）。

## 关键入口

- `_execute_task_with_policies()`：带策略的任务执行（防御探测/格式化重试/
  凭据提取/flag 验证）。
- `_run_with_runtime()`：v2 Runtime 路径（planner/executor/evaluator 适配）。
- `_execute_privesc()` / `_try_db_default_credentials()` /
  `_systematic_exploit_pass()`：提权与系统化利用。

## 相关模块

`core/runtime.py`、`core/executor.py`、`core/evaluator.py`、`dave.py`、
`ports.py`。
