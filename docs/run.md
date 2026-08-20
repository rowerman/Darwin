# `run.py`

## 模块定位

命令行入口。负责解析目标、凭证、预算和端口范围，加载 LLM/MCP 配置，并调用 `darwin.runner.Orchestrator`。

## 所在链路

CLI 启动层，位于 `Orchestrator.run()` 之前。

## 关键入口

- `normalize_target()`：将 IP、hostname 或 URL 统一为目标 URL。
- `main()`：异步 CLI 主函数和结果输出。

## 输入/输出概览

输入来自命令行和 `config/` 配置；输出为一次 `TaskResult` 的摘要、flag 和错误信息。

## 相关模块

`darwin/runner.py`、`darwin/orchestrator.py`、`darwin/utils/llm.py`、`darwin/tools/mcp_client.py`。

## 阅读建议

先看参数解析和配置加载，再沿 `Orchestrator.run()` 阅读运行时链路。

## 维护提示

新增 CLI 参数时同步更新 README、配置说明和本导航文档。

