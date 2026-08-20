# `tools/ingest_knowledge.py`

## 模块定位

对 DarwinRAG 执行知识条目/目录入库、重建索引和统计查询。

## 关键入口

- `cmd_ingest_file()`、`cmd_ingest_dir()`：入库操作。
- `cmd_rebuild()`：重建 collection 索引。
- `cmd_stats()`：查看索引统计。

## 相关模块

`darwin/rag.py`、`tools/convert_knowledge.py`、`knowledge/`。

