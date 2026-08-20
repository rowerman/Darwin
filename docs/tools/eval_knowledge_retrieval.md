# `tools/eval_knowledge_retrieval.py`

## 模块定位

用场景查询比较 flat RAG 与 hierarchical RAG 的召回表现。

## 关键入口

- `_build_queries()`：从场景生成评测查询。
- `_evaluate()`：执行单种检索模式评测。
- `main()`：命令行入口和结果输出。

## 相关模块

`darwin/rag.py`、`knowledge/scenarios/`。

