# `tools/build_rag_corpus.py`

## 模块定位

生成 DarwinRAG 运行时语料产物：把 `knowledge/**`（排除 `scenarios/**`）转换成
`darwin.rag.entry.v1` 条目，写入 `knowledge/corpus/*.jsonl` 与 `manifest.json`。

## 所在链路

知识库改动后的第一步；产物由 `darwin/rag_corpus.py` 定义、`darwin/rag.py` 消费。

## 关键入口

- `python -m tools.build_rag_corpus`：重建产物。
- `--check`：断言产物与源文件一致（CI 与提交前必跑）。

## 输入/输出概览

输入是 `knowledge/` 源文件；输出是分域 JSONL、manifest（计数/源哈希/排除清单/
lint 备注）与退出码（curated 条目有阻塞性问题时非 0）。

## 相关模块

`darwin/rag_corpus.py`、`tools/rag_lint.py`、`tools/build_rag_index.py`。

## 阅读建议

先看 `darwin/rag_corpus.py` 的 schema 与转换分支，再看本工具的 `--check` 比对逻辑。

## 维护提示

新增知识来源或改变字段映射时同步 `darwin/rag_corpus.py` 与对应测试。
