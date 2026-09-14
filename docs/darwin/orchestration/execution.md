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
- `_recovery_call()`：计划外修复调用（fix 重试 / 路由变体 / 动词升级）的统一
  派发入口——与主路径写同样的 task 事件、executed-call 记录、路由探测持久化
  和 flag 验证，避免"第二条更薄的执行路径"。
- `_method_upgrade_candidate()`：目标用 `405 + Allow` 或自述清单声明了工具
  无法表达的动词时，返回能表达该动词的工具与重映射后的参数；仅在同一 HTTP
  能力族内替换，且计划工具本已能表达该动词时不触发（防止自我循环）。
- `_endpoint_is_verified()` / `_endpoint_declared_methods()` /
  `_untested_documented_routes()`：世界状态可信度与计划完成性——只有目标真实
  响应过的路由才算事实；服务自己声明但尚未按该方法访问过的路由必须继续出现在
  评审提示与裁剪豁免中。
- `_route_identifiers()` 按参数名排除控制键（`method`/`body_format`/
  `encode_type`/`content_type`/`insecure`/`follow_redirects`/`timeout` 等），
  路由变体只在 verified 基址上派生；`_ingest_observed_routes()` 把
  ffuf/gobuster/dirb 解析出的路径写回 Endpoint（非 404 记 verified）。

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
upload 等）自动合成 `http_status_in([200,201,202,204])`——工具退出 0 不等于
服务接受了写操作。计划给的未知条件类型在入库时就被丢弃（见 planning 的
`normalize_success_condition()`），不会静默退化成"工具成功"。
任务日志记录 `success_condition` 事件（condition/met/detail）。

工具被合法替换时（fix 换工具、确定性动词升级、plan review 回退写任务），
`core/task.realign_success_condition()` 会把 `tool_success` 条件里钉住的旧
工具名改成实际执行的新工具名。否则条件永远无法达成，任务会一直循环在
"expected X to run, but ran: Y"上直到预算耗尽。

## 响应证据摄入（`_ingest_response_evidence`）

## 重复调用缓存（`_execute_tool_call`）

以 `(tool, args)` 指纹缓存**路由级终态失败**（仅 HTTP 404/405）：同一请求在同一
次运行内再次出现时直接复用判定，不再发网络请求，命中记入 `_redundant_calls`
并打印 `[DEDUP]`。连接错误与 500 不入缓存——它们可能因后续步骤改变。

## 兜底通道的完成口径

系统性兜底统计 tested / unexpressible / skipped：当 `tested == 0` 而存在跳过
时打印"框架侧契约缺口，不是目标干净"，不再用一个 "Done" 掩盖零请求
（cloud-29 曾三次打印 `tested 0 ... no flag found`）。

每次工具调用后运行 `darwin/response_evidence.py`：响应里出现请求未提供过的
绝对服务器路径（路径预言机）或另一主体标识时，把它写成带证据的 DKG
`Vulnerability` 节点（`source=response_evidence`），路径预言机还会展开成具体
遍历 payload 的后续假设，并置位 `_evidence_since_review` 触发 plan review。
同一 `(vuln_type, endpoint, param)` 只提升一次，重复探测不会放大计划。

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
- 每个候选工具的调用参数在分发前经 `tools/arg_contract.project_args()` 投影：
  漏洞的 `param` 是目标属性而非工具参数，只有该工具声明了对应槽位时才进入
  请求；工具无法表达的键会打印说明并留在请求之外，而不是原样发出去被网关
  整调用拒绝（旧行为：每次调用白烧一轮 fix 分析，系统性兜底统计为
  "tested 0 combinations"）。
