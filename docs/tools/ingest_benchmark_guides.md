# `tools/ingest_benchmark_guides.py`

## 模块定位

解析 benchmark GUIDE，提取漏洞、步骤、工具和分类信息，生成可检索知识。

## 关键入口

- `parse_guide()`：解析单个指南。
- `main()`：批量入库入口。

## 相关模块

`darwin/rag.py`、`tools/build_taxonomy.py`、`knowledge/scenarios/`。

