# `tools/build_rag_eval.py`

## 模块定位

生成检索评测 gold 集：把"运行期目标指纹"与"覆盖该场景的能力条目"配对，另附无对症
知识的负样本，输出 `knowledge/eval/runtime_queries.json`。

## 所在链路

评测链路的数据端，供 `tools/eval_knowledge_retrieval.py` 消费。

## 关键入口

- `python -m tools.build_rag_eval`：重建 gold 集。
- `--results-dir` / `--benchmark-dir`：指定运行报告与场景目录。

## 输入/输出概览

输入是 `experiment/result/<domain>-NN.md`（按 GUIDE 的 ID 对应）与 benchmark
GUIDE 的环境/技术描述；输出是 88 条有 gold 的场景查询 + 12 条负样本。gold 由
能力条目的 `provenance.derived_from` 反查得到，避免重复维护映射。

## 相关模块

`tools/eval_knowledge_retrieval.py`、`darwin/rag_corpus.py`（`derived_from` 约定）。

## 阅读建议

先看 `_fingerprint_from_report()` 与 `_scenario_capabilities()`。

## 维护提示

查询只描述目标指纹（环境/服务/漏洞类别），不得包含场景 ID 或标题词，否则评测会退化。
