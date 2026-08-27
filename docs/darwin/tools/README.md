# `darwin.tools`

工具边界层。`mcp_gateway.py` 统一调用，`spec.py` 定义契约，`attack_server.py`/`recon_server.py` 注册工具，`mcp_client.py` 连接可选外部 MCP，`adapters/` 负责能力到工具的参数适配。

## 推荐阅读顺序

`spec.py` → `mcp_gateway.py` → `recon_server.py` / `attack_server.py` → `manifest.py` → `adapters/`。

所有外部工具执行必须经过本目录并由 `core/executor.py` 调用。

所有内置工具都在注册完成后绑定显式 v2 `ToolSpec`。契约目录统一提供域（web/db/ad/cloud/k8s/container/network/lnx/research）、意图型 capability、参数默认值、别名、依赖、executor 和输出契约；LLM registry、域过滤、manifest 与 Executor 均读取同一份规格。复杂命令可继续使用 shell executor，适合无 shell 执行的命令使用 shell_argv。

新增或修改工具时，必须更新对应注册参数和 `darwin/tools/contracts.py` 的分类规则，并重新生成、校验 `tools_manifest.json`：

```bash
python -m darwin.tools.manifest --out tools_manifest.json --check
```
