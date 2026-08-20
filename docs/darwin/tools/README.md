# `darwin.tools`

工具边界层。`mcp_gateway.py` 统一调用，`spec.py` 定义契约，`attack_server.py`/`recon_server.py` 注册工具，`mcp_client.py` 连接可选外部 MCP，`adapters/` 负责能力到工具的参数适配。

## 推荐阅读顺序

`spec.py` → `mcp_gateway.py` → `recon_server.py` / `attack_server.py` → `manifest.py` → `adapters/`。

所有外部工具执行必须经过本目录并由 `core/executor.py` 调用。

