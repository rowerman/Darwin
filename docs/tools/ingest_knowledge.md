# `tools/ingest_knowledge.py`

## 模块定位

知识维护入口（重写后）：校验语料、重建语料产物、刷新向量缓存，或打印语料统计。

## 所在链路

新增/修改知识后的收口命令，串起 `tools/rag_lint.py` → `tools/build_rag_corpus.py`
→ `tools/build_rag_index.py`。

## 关键入口

- `python -m tools.ingest_knowledge --check`：lint + 产物一致性校验。
- `--rebuild`：重建语料与向量缓存；`--stats`：打印 backend/条目分布。

## 输入/输出概览

输入是 `knowledge/**`（新能力条目或存量文件）；输出是同上的校验/统计结果与退出码。

## 相关模块

`darwin/rag_corpus.py`、`tools/rag_lint.py`、`tools/build_rag_corpus.py`、
`tools/build_rag_index.py`。

## 阅读建议

先看 `main()` 的参数组合，再回到三个被串联的子工具。

## 维护提示

不要再引入"直接向内存索引追加文档"的旧语义：运行时只读 `knowledge/corpus/**`。

## 模块定位

对 DarwinRAG 执行知识条目/目录入库、重建索引和统计查询。

## 关键入口

- `cmd_ingest_file()`、`cmd_ingest_dir()`：入库操作。
- `cmd_rebuild()`：重建 collection 索引。
- `cmd_stats()`：查看索引统计。

## 相关模块

`darwin/rag.py`、`tools/convert_knowledge.py`、`knowledge/`。
