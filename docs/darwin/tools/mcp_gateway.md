# `darwin/tools/mcp_gateway.py`

## 模块定位

工具注册和统一调用网关，封装 Python、shell、argv 和 MCP 工具，返回统一 `ToolResult`。

## 所在链路

Executor 与所有外部工具之间的唯一执行边界。

## 关键入口

- `MCPGateway`：注册、查找、调用和工具定义生成。
- `ToolResult`：成功、输出、退出码和解析结果。

`register_shell_argv_tool()` 默认使用无 shell 的 argv 执行；为保持跨平台
契约，显式的 Windows `cmd /c {cmdline}` 模板在 POSIX 环境等价转为
`/bin/sh -c`，并保留原始命令字符串（包含重定向等 shell 语法）。

## 相关模块

`core/executor.py`、`tools/spec.py`、`attack_server.py`、`recon_server.py`、`mcp_client.py`。

## 阅读建议

先看 `call()` 和参数归一化，再看不同 executor 的分发和异常包装。

## 维护提示

未知工具必须失败；不要让编排器绕过网关直接调用外部命令。
