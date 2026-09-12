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
`--token-budget` 默认 `0` = 不限（用量仍计量，跨 200k 只告警）；`--time-budget`
是主要约束。摘要额外打印 `Stop reason`（来自 `TaskResult.stop_reason`），
用于解释主循环为何结束。

## 相关模块

`darwin/runner.py`、`darwin/orchestrator.py`、`darwin/utils/llm.py`、`darwin/tools/mcp_client.py`。

## 阅读建议

先看参数解析和配置加载，再沿 `Orchestrator.run()` 阅读运行时链路。

## 维护提示

新增 CLI 参数时同步更新 README、配置说明和本导航文档。

## 结果摘要的语义

摘要中的 `Vulnerability hypotheses: N (tested: M)` 只报告**假设**及其被
探测条数（DKG Vulnerability 节点的 `tested_at`），不把未验证假设当成
“发现的漏洞”。`M == 0` 表示这些假设都还没有被任何工具验证过。
