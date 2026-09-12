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
  运行时由 `tools/paths.resolve_wordlist()` 解析。

## 相关模块

`mcp_gateway.py`、`spec.py`、`manifest.py`、`core/capabilities.py`。

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
