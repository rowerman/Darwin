# `darwin.tools.adapters`

能力层与工具层之间的轻量适配器。它们负责参数映射和结果入口，不负责重新实现工具或绕过 MCPGateway。

## 推荐阅读顺序

`_common.py` → 具体 adapter → `core/capabilities.py`。

