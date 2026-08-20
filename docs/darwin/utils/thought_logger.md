# `darwin/utils/thought_logger.py`

## 模块定位

记录 LLM 思考/阶段上下文的调试信息，受运行配置控制。

## 关键入口

- `ThoughtLogger`：思维日志写入。

## 相关模块

`utils/llm.py`、`orchestrator.py`、`config/darwin.yaml`。

## 阅读建议

结合配置中的 `log_thoughts` 查看启用条件和日志路径。

## 维护提示

日志可能包含目标或凭证上下文，修改时保持敏感信息处理边界。

