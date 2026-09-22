# `darwin/cteg.py`

## 模块定位

CTEG（Cross-Task Experience Graph）跨挑战积累 exploit、bypass 和 credential 模式，并按场景匹配和衰减。

**当前状态（feat_20260922_1 起）：CTEG 的检索通道已下线。** 运行时不再调用
`get_suggestions()` 注入提示词，跨任务经验改由"环境图相似度 → RAG 先验"提供
（见 `graph_fingerprint.md` / `precedent_store.md`），凭据通道由 `credential_memory.py`
承接。本模块保留的原因：`core/memory.py` 的执行级经验写入仍指向它，旧状态
`cteg_state.json` 仍可读；它已不再影响规划或分析提示词。

## 所在链路

不再位于主链路。历史链路（规划前提示、任务结束提交）已被跨任务图记忆取代；
仅 `MemoryManager.record_execution()` 的鸭子类型写入仍会触达它。

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
若要彻底删除本模块，需要同时处理 `core/memory.py` 的 `experience` 写入路径与
`tests/test_cteg_experience.py`；删除前确认 `precedent_store` 的知识账本已覆盖
同样的效果归因。
