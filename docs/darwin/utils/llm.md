# `darwin/utils/llm.py`

## 模块定位

封装 LiteLLM 调用、token 预算、工具调用结果和上下文压缩。

## 所在链路

所有 LLM 阶段和 memory compression 的外部模型边界。

## 关键入口

- `LLMSession.generate()`：统一生成接口。
- `LLMSession.compress()`：接近上下文阈值时压缩。
- `LLMSession.isolated_scope()`：结构化阶段（analyze/plan/plan_review、
  fix_analysis、flag_search）在这些自包含 prompt 上不共享会话历史，
  退出后原样恢复 `conversation_history`。
- `LLMFunctionMapping`：函数/工具调用映射。
- `estimate_tokens()`：近似 token 统计。

## 上下文与计量

- `token_count`：当前上下文规模（压缩阈值判定仍用它）。
- `total_tokens` / `last_call_tokens`：累计真实用量，供 token 预算与报告使用。
- `_carried_digest`：压缩摘要的持久副本。隔离调用不读会话历史，压缩掉的
  记忆由它注入，保证隔离不丢记忆；历史压缩与硬截断都会同步写入该摘要。

## 相关模块

`prompts/`、`core/context.py`、`core/memory.py`、`orchestrator.py`。

## 阅读建议

先看 generate 返回契约，再看压缩、重试和 provider 配置。

## 维护提示

上下文接近阈值时使用压缩而不是硬重置；API key 不应写入日志。
