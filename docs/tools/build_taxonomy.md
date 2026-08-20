# `tools/build_taxonomy.py`

## 模块定位

从场景和知识条目构建 `knowledge/taxonomy.json`，为分层 RAG 提供路由树。

## 关键入口

- `build_taxonomy()`：构建 taxonomy 数据。
- `main()`：读取场景并写入文件。

## 相关模块

`darwin/rag.py`、`tools/ingest_benchmark_guides.py`、`knowledge/`。

## 阅读建议

先看叶子路径规则，再看输出树结构和 slug 生成。

