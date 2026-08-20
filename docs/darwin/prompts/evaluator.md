# `darwin/prompts/evaluator.py`

## 模块定位

定义失败分析 prompt，帮助 Runtime 区分参数、工具、目标、权限和防御等失败类型。

## 关键入口

- `SYSTEM_PROMPT_EVALUATOR`：失败分析角色和输出边界。

## 相关模块

`core/evaluator.py`、`core/replan.py`、`core/schemas.py`。

## 阅读建议

先看失败类型枚举，再对照 prompt 输出如何转为 `Classification`。

