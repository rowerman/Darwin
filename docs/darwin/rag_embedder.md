# `darwin/rag_embedder.py`

## 模块定位

向量通道与重排通道的后端实现与解析：多语言 SentenceTransformer 嵌入、
mmarco cross-encoder 重排，以及无权重环境下的确定性替身。

## 所在链路

`DarwinRAG.load()` 通过 `resolve_embedder()` / `resolve_reranker()` 选择后端。

## 关键入口

- `SentenceTransformerEmbedder`：本地权重目录加载，`max_seq_length=128`。
- `CrossEncoderReranker`：query-doc 对数打分（logits）。
- `HashEmbedder` / `TokenOverlapReranker`：测试与无权重替身。
- `tokenize_mixed()`：ASCII 词 + 中文 bigram，BM25 与替身共用。

## 输入/输出概览

输入是文本序列；输出是 L2 归一化的 float32 向量矩阵或逐条相关性分数。

## 相关模块

`rag.py`、`rag_corpus.py`（`search_text_dense`/`search_text_sparse` 的消费方）。

## 阅读建议

先看 `resolve_embedder()` 的 auto/st/hash/none 语义，再看两个替身的确定性实现。

## 维护提示

换模型只需改 `config/darwin.yaml` 的 `rag.model_dir`/`reranker_dir`；语料向量缓存
按“语料 hash + 模型名”失效，换模型会自动重建。
