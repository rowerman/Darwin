# `darwin/tools/spec.py`

## 模块定位

定义 `ToolSpec` 契约及注册工具的 schema、模板、alias、executor 和依赖校验。

## 关键入口

- `ToolSpec`：机器可读工具契约。
- `auto_spec()`：从注册参数派生契约。
- `validate_spec()`、`check_all_specs()`：契约检查。
- `shlex_split_value()`：安全拆分 argv 参数。
- `HTTP_REQUEST_CAPABILITIES`：HTTP 工具能力表 `(可表达的方法集合, 可承载的
  body 形状)`；`http_tools_for(methods, available, body_kind)` 按偏好顺序返回
  能表达该请求的工具，`http_tool_can_express()` 做单点判断，
  `request_body_kind(params)` 从调用参数推断 `none|raw|json`。
- `capability_family(name)`：工具所属粗粒度能力族，用于约束"修复只能在同一
  能力族内换工具"（HTTP 请求族、SQL 族等）。

## 相关模块

`mcp_gateway.py`、`manifest.py`、`attack_server.py`、`recon_server.py`、`core/parameters.py`。

## 阅读建议

先看字段和 executor 类型，再看模板变量、alias 和 Python 签名校验。

## 维护提示

契约变化要升版本并重新生成 `tools_manifest.json`。
