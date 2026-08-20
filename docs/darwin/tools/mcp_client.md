# `darwin/tools/mcp_client.py`

## 模块定位

管理可选的 stdio MCP 服务器配置、连接、工具发现和调用池。

## 关键入口

- `MCPClient`：单服务器生命周期。
- `MCPClientPool`：多服务器路由和复用。
- `load_mcp_config()`：读取 `config/mcp_servers.yaml`。

## 相关模块

`mcp_gateway.py`、`orchestrator.py`、`config/mcp_servers.yaml`。

## 阅读建议

先看配置模型，再看单连接和池的启动/关闭边界。

## 维护提示

MCP 是可选扩展，配置缺失或服务器不可用不应破坏本地工具网关。

