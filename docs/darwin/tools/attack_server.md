# `darwin/tools/attack_server.py`

## 模块定位

注册攻击、研究、凭证、云/K8s 和验证域工具；按工具族封装 shell 或 Python 调用。

## 所在链路

Planner 发现工具、Executor 执行工具的攻击域注册层。

## 关键入口

- `register_attack_tools()`：集中注册工具。
- `create_attack_gateway()`：创建攻击 gateway。
- `_apply_domain_filter()`：按启用域过滤。

## 相关模块

`mcp_gateway.py`、`spec.py`、`manifest.py`、`core/capabilities.py`。

## 阅读建议

先看注册函数按能力/域的组织，再看具体工具的 parser 和契约；完整清单查 `tools_manifest.json`。

## 维护提示

工具注册不得直接暴露未声明参数、危险 shell 拼接或错误域标签。注册完成后由 `darwin.tools.contracts.apply_explicit_contracts` 绑定显式 `ToolSpec`；新增工具还必须补充域、capability、依赖和输出契约分类。

`ssrf_probe` 使用显式 `max_probes` 安全预算（默认 30、上限 200），在预算内
先分层覆盖 host/port/path，再填充剩余组合，并在结果中返回预算使用信息。
