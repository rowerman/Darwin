# `darwin/tools/recon_server.py`

## 模块定位

注册侦察域工具并将 nmap、masscan、dirb、whatweb 和 HTTP 响应解析为结构化结果。

## 所在链路

bootstrap recon 和后续服务研究阶段的工具注册层。

## 关键入口

- `register_recon_tools()`、`create_recon_gateway()`：注册入口。
- `parse_response()`：统一 HTTP 内容解析。
- 各 `_parse_*` 函数：外部 CLI 输出适配。

## 相关模块

`mcp_gateway.py`、`spec.py`、`utils/http_client.py`、`orchestrator.py`。

## 阅读建议

先看 gateway 创建，再按工具解析器和输出契约阅读。

## 维护提示

新增工具要补 `ToolSpec`、manifest 和相关 parser 测试。

