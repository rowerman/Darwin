# `darwin/rag.py`

## 模块定位

DarwinRAG 管理静态知识的加载、索引和检索，支持 SentenceTransformer/Faiss 与 Tfidf 回退，并提供 taxonomy 路由。

## 所在链路

研究和攻击规划阶段的知识检索层。

## 关键入口

- `DarwinRAG`：索引、加载和搜索生命周期。
- `search_hierarchical()`：先 taxonomy 路由再在子树内打分。
- `get_rag()`：共享实例入口。
- `COLLECTIONS`：知识域集合。

## 输入/输出概览

输入是 `knowledge/` 内容和自然语言查询；输出是带来源和 taxonomy 信息的结果。

## 相关模块

`knowledge_base.py`、`search_evidence.py`、`tools/build_taxonomy.py`、`orchestrator.py`。

## 阅读建议

先看集合和文件到 collection 的映射，再看索引构建、回退和分层搜索。

## 维护提示

索引格式、taxonomy 或 embedding 回退变化时同步入库工具和评测脚本。

