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

## 相关模块

`mcp_gateway.py`、`spec.py`、`utils/http_client.py`、`orchestrator.py`。

## 阅读建议

先看 gateway 创建，再按工具解析器和输出契约阅读。

## 维护提示

新增工具要补注册参数、`darwin/tools/contracts.py` 中的域/capability 分类、manifest 和相关 parser 测试。
