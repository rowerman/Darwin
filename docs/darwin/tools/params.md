# `darwin/tools/params.py`

## 模块定位

HTTP 工具的**参数形状归一化**。ToolSpec 把参数声明为 `string`，但规划
LLM 会按语义发送 dict/list（`headers={"X-Api-Key": "k"}`、
`data={"name": "pkg"}`）。这里集中处理这些形状，避免每个工具各自实现
（并实现错）一遍切分逻辑。

## 关键入口

- `normalize_headers(value)`：str / dict / list → `{name: value}`。
  str 支持换行与 `|` 分隔；list 支持 `"K: v"` 字符串与二元组。
- `headers_to_lines(value)`：归一化后拼成 `_python_request` 需要的
  换行分隔头文本。
- `coerce_body(value)`：返回 `(body_bytes, inferred_content_type)`；
  dict/list 序列化为 JSON 并给出 `application/json`。

## 使用方

`recon_server.py`（`http_post`、`http_method_probe`）与
`attack_server.py`（`send_payload`，经 `_normalize_header_arg()`）。

## 约束

- 不做参数名映射（别名由 `mcp_gateway._normalize_params()` 与
  `tools/contracts.py` 负责），只做**值形状**归一化。
- 未知形状按字符串处理，不得抛出异常：工具层必须永远比 LLM 宽容。
