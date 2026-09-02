# `darwin/orchestration/lifecycle.py`

## 模块定位

`LifecycleCoordinator`：生命周期与共享工具方法分片，继承 `CoordinatorContext`。

## 关键入口

- `run()`：solo 主循环（recon → analyze → plan → execute → evaluate →
  replan → verify）。
- `_should_terminate()` / `_detect_chain_topology()` /
  `_count_unexploited_services()`：终止判定与链式多 flag 模式。
- `_get_state()` / `_belief_context()` / `_build_truncation_context()`：
  状态快照与上下文构建。
- `_task_log_event()` / `metrics_report()` / `provenance_summary()`：
  日志、指标与溯源。
- `_apply_final_defense_state()`：在所有返回路径将最终 DPM 快照投影到
  `TaskResult`；`run()` 同时释放普通 HTTP 与防御探测客户端。
- `_extract_json()` / `_extract_json_array()`：JSON 宽容解析。

## 相关模块

`core/context.py`、`core/memory.py`、`core/metrics.py`、`data_model.py`。

阶段预算包装器同时返回阶段状态与协程结果，确保 Runtime 生成的
`TaskResult`（包括已验证 flag）不会在生命周期层丢失。
