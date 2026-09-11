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

## 阶段预算与收尾

- 阶段预算比例可通过 `darwin.phase_ratios`（config/darwin.yaml）覆盖，默认
  recon 0.15 / service_research 0.05 / analyze 0.12 / vulnerability_research 0.08
  / exploit 0.55 / finalize 0.05；未使用额度仍按原 carryover 语义顺延。
- 深侦察若在“发现即校验”阶段命中已验证 flag，`run()` 用 `_RunFinished`
  直接结束（`phase=done`），跳过研究/分析/利用阶段。
- 收尾的 `_check_response_for_flag()` 先逐字请求每个已发现 Endpoint URL，
  再对服务根拼接通用诊断路径（health/status/metrics/logs/api/docs/
  openapi.json/swagger.json/api-docs 与经典 flag 路径），全部为协议级通用
  约定，不含任何场景名。
- `Result.tokens_used` 取 `LLMSession.total_tokens`（累计真实用量），
  `token_count` 仅表示当前上下文规模。
- token 预算默认 `0` = 不限：`_tokens_exceeded()` 只在累计用量跨过 200k
  软上限时记一次 warning，不再终止运行；运行由时间预算约束。传
  `--token-budget N`（N>0）可恢复硬上限语义。
- 主循环退出必须可解释：`_should_terminate()` 的每条分支都会调用
  `_set_stop_reason()`，原因写入 task log 事件 `run_stopped` 与
  `TaskResult.stop_reason`（run.py 也会打印 `Stop reason` 行）。
- solo 耗尽不再直接终止：`_request_forced_reconsideration()` 在剩余时间
  `> max(60s, 20%×budget)` 时最多批准 2 轮强制 [RECONSIDER] 计划评审
  （重置 `_plan_review_exhausted`，并要求产出新任务或明确无可行动作）；
  同时置 `_force_plan_reconsider`，让该轮的确定性探测可以消费被推迟的
  无证据猜测（见 execution.md 的 speculative 兜底）。
