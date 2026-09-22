# `darwin/rag.py`

## 模块定位

DarwinRAG 对统一语料产物 `knowledge/corpus/*.jsonl` 做混合检索：向量通道（多语言
embedding + Faiss 内积）与文本通道（BM25，中英混合 tokenizer）各自召回，RRF 融合，
再按环境硬过滤、域降权，最后用 cross-encoder 重排并过闸门，最多返回 3 条（可为 0）。

## 所在链路

研究和攻击规划阶段的知识检索层；语料由 `tools/build_rag_corpus.py` 生成，
向量缓存落在 `checkpoints/rag_index/`。

## 关键入口

- `DarwinRAG.retrieve(query, environment="", domains=None, top_k=None, prior=None)`：
  唯一检索入口。`prior` 是跨任务图相似度给出的 `{语料 id: 提升量}`。
- `RagConfig`：来自 `config/darwin.yaml` 的 `rag:` 段（候选数、闸门阈值、上限）。
- `BM25`：稀疏通道；`_environment_allows()` 是环境硬过滤唯一判定点。
- `get_rag()` / `set_environment()`：共享实例与进程级环境分类（供网关工具使用）。
- `set_graph_context()`：发布当前攻击面快照，用于校验语料条目的 `graph_pattern`
  结构前置条件；未发布时该过滤不生效。
- `note_surfaced()` / `surfaced_ids()` / `reset_surfaced()`：本轮注入过哪些语料条目，
  供跨任务知识账本区分"展示过"与"被采用"。

## 输入/输出概览

输入是查询文本 + 环境类型 + 观测域；输出是带 `score`、`retrieval`（dense/sparse
排名、融合分、重排分）与 provenance 的条目列表，长度 ≤ `rag.max_results`。

## 相关模块

`rag_corpus.py`、`rag_embedder.py`、`rag_query.py`、`search_evidence.py`、
`tools/build_rag_corpus.py`、`tools/build_rag_index.py`、`tools/eval_knowledge_retrieval.py`。

## 阅读建议

先看 `retrieve()` 的管线顺序（双通道 → RRF → 环境过滤 → 结构前置条件 → 先验 →
重排 → 闸门），再看 `_gate_thresholds()` 和 `_environment_allows()`。

## 维护提示

检索语义或阈值变化时同步 `knowledge/eval/baseline.json` 与
`tools/eval_knowledge_retrieval.py --calibrate` 的结果；语料变化后必须
`python -m tools.build_rag_corpus --check`。

**先验只作用于排序，不作用于闸门**：`RetrievalTrace.prior` 参与候选与最终选择的
排序，闸门判定始终读未加权的 `rerank`，因此历史经验无法让被门控拒绝的条目进入结果。
这一不变量由 `tests/test_rag_memory_prior.py` 锁定。
