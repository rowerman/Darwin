# `darwin/utils/llm.py`

## 模块定位

封装 LiteLLM 调用、token 预算、工具调用结果和上下文压缩。

## 所在链路

所有 LLM 阶段和 memory compression 的外部模型边界。

## 关键入口

- `LLMSession.generate()`：统一生成接口。
- `LLMSession.compress()`：接近上下文阈值时压缩。
- `LLMFunctionMapping`：函数/工具调用映射。
- `estimate_tokens()`：近似 token 统计。

## 相关模块

`prompts/`、`core/context.py`、`core/memory.py`、`orchestrator.py`。

## 阅读建议

先看 generate 返回契约，再看压缩、重试和 provider 配置。

## 维护提示

上下文接近阈值时使用压缩而不是硬重置；API key 不应写入日志。

