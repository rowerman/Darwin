# `darwin/knowledge_base.py`

## 模块定位

提供轻量静态知识条目的加载和基础查询接口；复杂向量检索由 `rag.py` 负责。

## 所在链路

研究和分析阶段的知识读取层。

## 关键入口

- `KnowledgeEntry`：知识条目模型。
- `KnowledgeBase`：加载、过滤和查询容器。

## 输入/输出概览

输入是知识文件和查询条件；输出是匹配的条目集合。

## 相关模块

`rag.py`、`search_evidence.py`、`tools/ingest_knowledge.py`。

## 阅读建议

先看条目模型，再确认知识来源和查询结果如何被格式化。

## 维护提示

数据格式变化时同步入库脚本和 RAG 适配层。

