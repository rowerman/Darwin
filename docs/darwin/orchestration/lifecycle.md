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
- `_publish_knowledge_prior()` / `_record_task_memory()`：跨任务图记忆的读端与写端；
  读端在 recon 后按当前图指纹发布 RAG 先验并发布结构前置条件快照，写端在任务结束
  落库图快照与知识账本。
- `_load_remembered_credentials()`：按 scope + host + port + service 完整身份
  复用历史凭据；替代原先"端口或服务名匹配"的 CTEG 凭据通道。

## 相关模块

`core/context.py`、`core/memory.py`、`core/metrics.py`、`data_model.py`。

阶段预算包装器同时返回阶段状态与协程结果，确保 Runtime 生成的
`TaskResult`（包括已验证 flag）不会在生命周期层丢失。

## 阶段预算与收尾

- 阶段预算比例可通过 `darwin.phase_ratios`（config/darwin.yaml）覆盖，默认
  recon 0.10 / deep_recon 0.10 / defense 0.05 / service_research 0.05 /
  analyze 0.12 / vulnerability_research 0.08 / exploit 0.45 / finalize 0.05；
  未使用额度仍按原 carryover 语义顺延。
- `_deep_recon()`、`_cloud_discovery_hint()`、`_detect_defenses()` 必须在
  `_run_phase_with_budget()` 内运行（分别是 `deep_recon` 与 `defense` 阶段）。
  裸跑时一次不可达端点的 CMS/目录探测就吃掉过约 220s，加上 DPM 的 65s，
  600s 预算里只剩 110~160s 给 exploit。
- `finally` 分支统一停止 OOB 回调监听（`darwin.tools.oob_listener.
  stop_all_listeners()`），监听端口不会跨场景残留。
- 深侦察若在“发现即校验”阶段命中已验证 flag，`run()` 用 `_RunFinished`
  直接结束（`phase=done`），跳过研究/分析/利用阶段。
- 收尾的 `_check_response_for_flag()` 先跑 `_sweep_exploit_primitives()`：
  对 DKG 里每个 `ExploitPrimitive` 用**它自己的请求形状**回放 flag 路径族
  （通用 flag 文件名 + 由目标披露推导出的相邻主体，如 `tenant-a` → `../tenant-b/secret.txt`）。
  通用 GET 扫描只作为兜底——无凭据无 body 的 GET 结构上无法复用一次已证实的
  JSON POST 原语（cloud-29 就是这样带着"任意文件读"结束却拿不到 flag）。
  再逐字请求每个已发现 Endpoint URL，
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
