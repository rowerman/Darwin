# `tools/`

知识库入库、taxonomy 构建、检索评测和覆盖率审计脚本。它们处理离线数据和报告，不参与 `Orchestrator` 的在线执行链路。

## 推荐阅读顺序

`ingest_knowledge.py` → `build_taxonomy.py` → `eval_knowledge_retrieval.py` → `audit_coverage.py`；需要转换外部格式时再看 `convert_*`。

