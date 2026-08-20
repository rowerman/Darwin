# `darwin/cteg.py`

## 模块定位

CTEG（Cross-Task Experience Graph）跨挑战积累 exploit、bypass 和 credential 模式，并按场景匹配和衰减。

## 所在链路

编排器的经验记忆层，参与规划前提示和任务结束后的经验沉淀。

## 关键入口

- `CTEG`：经验读写、匹配和持久化。
- `build_scenario_profile()`：从当前挑战构造匹配画像。
- `match_score()`：计算模式与画像的相关度。
- `BypassPattern`、`ExploitPattern`、`CredentialPattern`：经验记录模型。

## 输入/输出概览

输入是任务记录、漏洞和工具结果；输出是排序后的经验提示，并可写入 `cteg_state.json`。

## 相关模块

`orchestrator.py`、`core/memory.py`、`core/executor.py`。

## 阅读建议

先看模式和画像模型，再看 `CTEG` 的生命周期及衰减策略。

## 维护提示

持久化字段、半衰期或匹配权重变化时需要考虑旧状态兼容。

