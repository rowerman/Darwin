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

已迁移的 curl/SSRF 任务在参数完整时按计划 direct 执行；Runtime Adapter 保留底层 stderr、退出码和规范化结果供 Evaluator 使用。

systematic exploit pre-pass 仅在本轮内部去重；无明确成功时不会阻断 Runtime
计划任务，后续可用不同参数或策略再次尝试。

## 防御探测已移除

每任务自动防御探测（`_probe_for_defense`）、`BLOCKED` 后的自动 payload
绕过重试，以及由它触发的二次 `_detect_defenses()` 已删除。理由：它对每个
HTTP 类任务额外发出 2–5 次请求，在全套 benchmark 中从未产生过 flag，
唯一可测效果是把普通的 403/AccessDenied 判成“有 WAF”。防御感知现在只在
侦察期执行一次（见 `recon.md`），`_format_tool_feedback()` 不再接收
防御探针文本。

## JSON 过滤参数探测（响应驱动）

`_probe_json_filter_parameters()` 在 systematic pre-pass 之前运行：
对每个已发现端点取一次响应，从**响应记录自身的字段名**推导候选过滤参数，
取值依次尝试「同目标其他已发现端点路径 → 响应中出现过的值 → 必然不匹配的值」，
命中 flag 后走 `_verify_flag`（DAVE）。纯函数
`_derive_filter_candidates()` 负责推导，便于单测。
边界：≤6 个端点、≤12 次请求、仅 GET；解析用 `_json_body()`（容忍工具输出里
的 HTTP 头前缀）。
