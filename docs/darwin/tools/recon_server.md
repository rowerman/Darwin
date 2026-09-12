# `darwin/tools/recon_server.py`

## 模块定位

注册侦察域工具并将 nmap、masscan、dirb、whatweb 和 HTTP 响应解析为结构化结果。

## 所在链路

bootstrap recon 和后续服务研究阶段的工具注册层。

## 关键入口

- `register_recon_tools()`、`create_recon_gateway()`：注册入口。
- `parse_response()`：统一 HTTP 内容解析。
- `http_method_probe`：通用 HTTP 方法探测（OPTIONS/POST/HEAD 等），返回状态、
  响应头与 body；用于自适应侦察的 API 路由发现与 POST/JSON 验证。
- 各 `_parse_*` 函数：外部 CLI 输出适配。

## HTTP 写请求（`http_post`）

`http_post` 是 HTTP **写**工具：`method` 默认 `POST`，可选
`PUT/PATCH/DELETE`（用于注册/覆盖资源这类 REST 写），其它动词返回明确的
`unsupported method` 错误而不会静默改成 POST。`data` 接受原始字符串或
dict/list（后者按 JSON 发送），`headers` 接受 str/dict/list，统一经
`tools/params.py` 归一化——LLM 传 dict 头不会再触发
`'dict' object has no attribute 'split'`。

`content_type` 优先级：显式 `Content-Type` 头 > 非默认的 `content_type`
参数 > 由 body 类型推断（dict/list → `application/json`）> 表单默认值。
`http_method_probe` 的 `headers` 走同一套归一化。

## gobuster 目录枚举

`gobuster_dir` 使用 gobuster 3.x 的子命令形式
（`gobuster dir -u URL -w WORDLIST -k -q`），字典参数是**逻辑名**
（默认 `raft-large-directories.txt`），由 `prepare_params` 钩子在执行前经
`tools/paths.resolve_wordlist()` 解析为绝对路径。这样 `tools_manifest.json`
保持机器无关，同时仍能优先命中仓库自带的 `wordlists/`。
注册时若解析失败，命令会带着明确的“字典不存在”错误返回，而不是静默产出空结果。

## nmap 云探针自动准备

四个 nmap 工具（`nmap_scan` / `nmap_full_scan` / `nmap_port_range` /
`nmap_vulners_scan`）首次执行前，会尝试把 benchmark 的云服务探针片段
（`nmap-cloud-probes.txt`，默认读取 `../benchmark/cve_challenges/scripts/` 下的
同文件，单一事实来源）合并进系统 `nmap-service-probes`，写入 nmap 用户
datadir，使 `-sV` 自动识别 DARWIN Cloud Benchmark 的模拟服务（IMDS/S3/OIDC/
STS/SAML/云控制面等）。

- 目标目录：环境变量 `NMAP_DATADIR`（与 benchmark 校验脚本一致），否则 `~/.nmap`。
- 覆盖/跳过策略：目标文件缺失时创建；含 DARWIN 标记但过期时原子重建；不含
  标记（用户自管文件）时不触碰；源缺失或写入失败时仅记录日志，扫描退化到
  原生 nmap 行为。
- 自定义探针路径可用 `DARWIN_NMAP_CLOUD_PROBES` 覆盖。
- 探针合并逻辑不影响工具参数/命令模板，manifest 无变化。

## HTTP 写工具语义

- `http_post`（v1.1.0）：4xx/5xx 不再是"无输出失败"——HTTPError 的
  status/headers/body 会写进 stdout（`success` 仍为 False），据此可区分
  路由缺失（404）与方法不对（405 + Allow）。
- `http_method_probe`：描述明确其为 PUT/PATCH/DELETE 写入的入口（`method`
  + `data` + `content_type`），4xx/5xx 同样返回 status/headers/body。
- 两者参数/语义变化需同步 `tools_manifest.json` 与 version。

## 相关模块

`mcp_gateway.py`、`spec.py`、`utils/http_client.py`、`orchestrator.py`。

## 阅读建议

先看 gateway 创建，再按工具解析器和输出契约阅读。

## 维护提示

新增工具要补注册参数、`darwin/tools/contracts.py` 中的域/capability 分类、manifest 和相关 parser 测试。
