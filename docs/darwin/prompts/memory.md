# `darwin/prompts/memory.py`

## 模块定位

定义上下文压缩 prompt，指导 LLM 保留事实、计划理由、执行结果和待办事项。

## 关键入口

- `SYSTEM_PROMPT_MEMORY`：压缩规则和保留边界。

## 相关模块

`utils/llm.py`、`core/memory.py`、`core/context.py`。

## 阅读建议

结合 `LLMSession.compress()` 阅读压缩输入、输出和快照标记。

