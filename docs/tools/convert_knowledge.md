# `tools/convert_knowledge.py`

## 模块定位

将外部 Markdown/文本知识转换为 DarwinRAG 使用的结构化条目。

## 关键入口

- `convert_directory()`：批量转换目录。
- `guess_category()`、`extract_title_and_content()`：分类和内容提取。
- `main()`：命令行入口。

## 相关模块

`darwin/rag.py`、`tools/ingest_knowledge.py`、`knowledge/`。

