# `tools/build_rag_index.py`

## 模块定位

构建 DarwinRAG 的向量索引缓存：把语料 `search_text_dense` 编码为向量矩阵，写入
`checkpoints/rag_index/<key>.npz`（key = 语料 hash + 模型名）。

## 所在链路

语料重建之后、评测或实跑之前；运行时 `DarwinRAG.load()` 命中缓存即秒级加载。

## 关键入口

- `python -m tools.build_rag_index`：缺缓存时构建。
- `--rebuild`：丢弃缓存重建；`-j N`：并行 worker 数（默认 cores/2、上限 4）。
- `--stats`：打印语料分布与 backend/embedder/reranker。

## 输入/输出概览

输入是 `knowledge/corpus/**` 与 `models/` 下的嵌入模型；输出是 npz 缓存与构建统计
（实测 8232 条 / 4 worker / 253s）。每个 worker 持有独立模型副本，故并行度受内存约束。

## 相关模块

`darwin/rag.py`（`corpus_cache_key()`）、`darwin/rag_embedder.py`、`tools/build_rag_corpus.py`。

## 阅读建议

先看 `build_vectors()` 的分片与 worker 线程限制，再看缓存键与命中逻辑。

## 维护提示

换嵌入模型或改语料后必须重建；并行度调高前先确认可用内存（每 worker 约 0.5 GB）。
