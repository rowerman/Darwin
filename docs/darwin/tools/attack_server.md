# `darwin/tools/attack_server.py`

## 模块定位

注册攻击、研究、凭证、云/K8s 和验证域工具；按工具族封装 shell 或 Python 调用。

## 所在链路

Planner 发现工具、Executor 执行工具的攻击域注册层。

## 关键入口

- `register_attack_tools()`：集中注册工具。
- `create_attack_gateway()`：创建攻击 gateway。
- `_apply_domain_filter()`：按启用域过滤。

## 契约要点（通用工具）

- `send_payload`：`param`/`payload` 均可为空（与实现的空值分支对齐），
  支持用完整 JSON 字符串作为 body；`headers` 支持
  `Key: v|Key2: v2` 或换行分隔，用于 header 驱动的鉴权（如 `X-Api-Key`）。
- `ffuf_fuzz`：`normalize_fuzz_url()` 在 URL 缺少 `FUZZ` 时自动补 `/FUZZ`
  （ffuf 缺占位符时会打印错误却仍以 0 退出）；字典默认走逻辑名，
  运行时由 `tools/paths.resolve_wordlist()` 解析，解析失败时
  `resolve_fuzz_wordlist()` 回退到内置 `common.txt` 并告警——幻觉路径会让
  ffuf 在发出第一个请求前中止，任务却记为"未发现路径"。输出经
  `_parse_ffuf_output()` 解析为 `discovered_paths`（`path` + `code`）+
  `scan_completed` / `enumeration_error`（区分"扫了没发现"与"扫描没跑起来"），由
  `execution._ingest_observed_routes()` 写回 Endpoint 世界状态——此前没有
  解析器，整轮 fuzz 结果被丢弃并记为"无新状态"。命令行改为 `-of json` 输出到
  临时文件并原样透传 ffuf 退出码（旧模板的 `| head -200` 让下游退出码冒充
  ffuf 的结论）；解析优先读 JSON 文档，文本回退会 strip ANSI 并按 `[\r\n]+`
  切分——ffuf 用 `\r` 重绘进度且行首带 `\x1b[2K`，按 `\n` 切分 + `^` 锚定的
  旧解析器对真实输出恒返回 0 条。spec 1.2.0。
- `send_payload`：HTTP 回应用同一个信封回报，4xx/5xx 现在
  `success=False, exit_code=<status>` 且 `parsed_output={status, headers, body,
  method, url}`（保留 `Allow` 与错误响应体）。此前异常被打印成 `ERROR:` 而
  python 进程仍以 0 退出，一次 404 被记成 `OK (exit=0, 32 bytes)`。
- `parallel_request`：`normalize_parallel_urls()` 同时接受逗号分隔字符串与
  JSON 数组（规划层发数组，旧实现直接 `urls.split` 崩溃）；URL 少于并发数时
  复制同一 URL 以形成真实竞态，构建逻辑只保留一份（旧实现重复构建 coroutine
  列表，产生 `never awaited` 警告）。

## 相关模块

`mcp_gateway.py`、`spec.py`、`manifest.py`、`core/capabilities.py`。

## K8s 工具族（宿主侧 kubeconfig 语义）

- `kubectl_logs(pod, namespace, tail_lines, container)`：读 pod 日志。已跑完
  （Completed/Failed）的脆弱性 PoC pod 的输出仍在这里，是恢复 flag 最便宜
  的一步；此前工具面里没有读日志的能力。
- `kubectl_auth_check(sa="", namespace="")`：默认查**当前身份**
  （`kubectl auth can-i --list`）。旧实现总是拼 `--as={sa}`，空 SA 名会把自己
  降级成 `system:anonymous`，于是"集群什么都没授权"成了错误结论。
- `k8s_secret_dump` / `k8s_configmap_dump`：kubeconfig 优先
  （`kubectl get ... -A -o json`），SA token 与 API URL 回退，并在输出里标注
  用了哪条路径。旧实现只认 pod 内挂载点，且 `_k8s_api_url()` 之前用
  "第一个点分数字"正则解析 kubeconfig，会把 `https://127.0.0.1:45889` 变成
  `https://127.0.0.1/api/...`（丢端口）。
- `k8s_backdoor_daemonset(image, shell_cmd, namespace, image_pull_policy)`：
  YAML 用 quoted heredoc 写入（不再 `echo '...'` 拼多行清单）；
  `imagePullPolicy` 默认 `IfNotPresent`，命中 `ErrImagePull`/`ImagePullBackOff`
  时自动用 `Never` 重试一次——`:latest` 的隐式 Always 拉取会让节点上已加载的
  镜像失败；默认 `shell_cmd` 扫描 `/host` 下的 flag 文件。
- `container_escape_runc`：仅针对 CVE-2019-5736；先解析 `runc version x.y.z`，
  已修补时直接失败并建议换路线。版本横幅只作为输出上报，不再拼接进 shell
  命令（旧实现会把多行 runc 输出按词拆开，报 `/bin/sh: 1: [Checking: not found`）。
- `k8s_etcd_keys(..., keys_only=)`：参数名与 CLI 语义一致（旧名 `prefix` 是
  布尔，planner 传 key 路径时被参数归一化丢弃）；`etcdctl` 不在宿主时快速返回
  127 并建议改用 `kubectl_get_secrets` / `k8s_secret_dump`。

## 阅读建议

先看注册函数按能力/域的组织，再看具体工具的 parser 和契约；完整清单查 `tools_manifest.json`。

## 维护提示

工具注册不得直接暴露未声明参数、危险 shell 拼接或错误域标签。注册完成后由 `darwin.tools.contracts.apply_explicit_contracts` 绑定显式 `ToolSpec`；新增工具还必须补充域、capability、依赖和输出契约分类。

`ssrf_probe` 使用显式 `max_probes` 安全预算（默认 30、上限 200），配合
`probe_timeout`、`max_duration` 和 `concurrency` 在预算内受控并发；先覆盖
host/port/path，再根据对象列表派生读取候选，并在结果中返回超时、错误和预算信息。
`object_store_get` 将列表响应视为发现证据，只有实际对象内容或 flag 才算成功。
## `send_payload` 的动词与头

`send_payload` 的 `method` 对非 GET 请求真实生效（`POST/PUT/PATCH/DELETE`），
不再一律 POST；非法动词返回 `unsupported method`。`headers` 接受
str/dict/list，经 `tools/params.py` 归一化为换行分隔的 `K: v` 交给
`_python_request`；dict 头不会被 `str(dict)` 拼成垃圾头名。
