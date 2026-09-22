# `darwin/precedent_store.py`

## 模块定位

跨任务记忆的存储与检索：把"某次任务的环境图 + 当时奏效的知识"存下来，新任务用
图相似度召回，产出 RAG 的先验权重。它替代了 CTEG 的检索通道——CTEG 用机制字符串
对场景指纹，这里直接用环境图作为索引键。

## 所在链路

任务结束：`lifecycle._record_task_memory()` → `record_task_snapshot()`；
任务开始：`lifecycle._publish_knowledge_prior()` → `prior()` → `publish_prior()`，
随后 planning / research / `knowledge_search` 在 `DarwinRAG.retrieve()` 时传入。

## 关键入口

- `record_task_snapshot(task_id, fingerprint=, snapshot=, knowledge=, labels=)`：
  写 Neo4j（主存），失败自动降级本地 JSON，两者都留痕。
- `query(fingerprint, top_k=, threshold=, exclude_same_family=)`：高于阈值的
  历史图，按相似度排序。
- `prior(fingerprint, **kwargs)`：条目 id → 提升量；只有被验证成功过的知识才计入。
- `publish_prior()` / `current_prior()` / `clear_prior()`：进程级先验发布（与
  `rag.set_environment` 同一模式，供无 DKG 句柄的网关工具使用）。
- `build_knowledge_record()`：单条知识的 surfaced/used/attempts/successes 记账。
- `knowledge_decay()`：按最近一次验证成功做半衰期衰减。

## 输入/输出概览

输入是 fingerprint / snapshot / 知识账本；输出是排序后的历史命中与 `{知识 id: 提升量}`。
Neo4j 侧写入 `(:GraphSnapshot)-[:HAS_NODE_TYPE]->(:ResourceType)` 与
`(:GraphSnapshot)-[:USED_KNOWLEDGE]->(:Knowledge)`，便于 Cypher 查询与出图。

相似度在 Python 内计算而非 Cypher：权重来自 Darwin 配置，且本机 Neo4j 未安装
GDS 插件；这也保证两个后端行为一致。

## 相关模块

`graph_fingerprint.py`、`memory_config.py`、`rag.py`、`orchestration/lifecycle.py`。

## 阅读建议

先看 `record_task_snapshot()` 的降级分支与 `query()` 的阈值过滤，再看 `prior()`
如何把多次命中的可靠性合成成一个提升量。

## 维护提示

记忆层任何异常都不得中断运行（这是设计约束，不是容错兜底）；新增后端时必须与
JSON 后端共用同一组契约测试。
