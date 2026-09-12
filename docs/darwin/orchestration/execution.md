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

计划优先执行：`_plan_params_complete()` 用工具自身的 ToolSpec（必填参数，
经网关别名归一化）判断计划是否可直接执行，参数齐全即按计划 direct 执行，
不再依赖固定的 `_direct_tools` 白名单——计划里的写入调用（如
`http_method_probe` method=PUT）不会被 LLM 换成别的工具。参数不齐才回退到
LLM 选择工具。Runtime Adapter 保留底层 stderr、退出码和规范化结果供
Evaluator 使用。

## 任务成功判定（success_condition）

`_verify_success_condition()` 按任务自身声明的完成条件判定成败，支持
`tool_success` / `body_contains` / `body_not_contains` / `http_status_in` /
`flag_captured` / `probe`（一次有界 GET 读回副作用）。条件未达成即判
FAILED，进入既有 fix-retry 并把"未达成的条件 + 实际观测"写入 result_text。
计划未给条件时：探索类任务维持原语义，写入类任务（POST/PUT/PATCH/DELETE、
upload 等）自动合成 `tool_success`，避免"计划 PUT、实际 GET 也算成功"。
任务日志记录 `success_condition` 事件（condition/met/detail）。

## 身份传播探测

`_probe_identity_propagation()`：当某次读取被 401/403 拒绝，且目标自身在
别处披露过身份/令牌值（`caller_arn`、`arn:`、token 类字段）时，用**观测到的
原值**按通用 header 约定（X-Caller-ARN / X-Amz-Caller-Arn / Authorization /
X-User / X-Username / X-User-Id）重试被拒 URL；有界（≤10 次请求）且跨任务
去重（`_identity_probe_tried`），命中 flag 走 DAVE 校验。

## 无证据猜测的兜底

`_systematic_exploit_pass(extra_vulns=...)` 接受分析阶段推迟的
`speculative` 猜测：它们不进入研究、不进计划、不写 DKG Vulnerability 节点，
只在强制重考虑轮作为确定性探测输入，仍受 `MAX_TESTS` 与去重约束。
HTTP 端点只尝试合同里确实带 HTTP 参数（url/target_url/ssrf_url）的工具；
去重键含参数指纹，避免后续轮次因"同 tool+url+param"被静默跳过。

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

## 写请求的路由变体重试

写意图任务（方法 ∈ POST/PUT/PATCH/DELETE）首次返回 `404/405` 时，在
LLM 修复回路之前执行一次**确定性**变体重试：用
`utils.urls.route_variants()` 从「任务自身参数 + 同主机端点响应 + 本次失败
输出」抽出的标识符推导相邻路径，并用**原方法**重试（≤6 个候选、≤2 个追加
段）。REST 集合路由与详情路由的形状差异（`/packages` vs
`/packages/<name>/<version>`）就属于这一类。

每次尝试都写任务日志 `route_variant_probe`，并把
`_record_route_probe()` 的结果写进 DKG Endpoint（含 method/status），供
planner 直接使用；命中 flag 走既有 DAVE 校验。

## 系统性兜底的读写分流

- `_VULN_TOOL_MAP` / `_VULN_FUZZY_MAP` 为**写类**漏洞族
  （dependency_confusion / supply_chain / package_poisoning /
  registry_poisoning / artifact_poisoning，以及 dependency/supply/poison/
  squat/publish/package 模糊匹配）映射到 `http_method_probe`，并排在
  cloud 的 `registry` 条目前，避免被容器 registry 助手截胡。
- 未映射类型回退到 `_FALLBACK_HTTP_TOOLS`（首个是 `http_method_probe`），
  保证“写类但标签不正确”的假设仍有可表达写动词的工具可用。
