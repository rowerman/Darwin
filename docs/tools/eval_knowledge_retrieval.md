# `tools/eval_knowledge_retrieval.py`

## 模块定位

跑 DarwinRAG 混合检索的 gold 集评测：recall@1/@3、MRR、负样本空返回率、注入量，
外加两条硬不变量（不得召回 benchmark GUIDE 来源条目、不得出现与环境不符的条目）。

## 关键入口

- `python -m tools.eval_knowledge_retrieval`：跑评测并写入 `knowledge/eval/baseline.json`。
- `--check`：与基线比对，召回下降或违规增加即失败。
- `--calibrate`：打印 gold / 非 gold 候选的重排分分布，用于定闸门阈值。
- `--from-dump`：复用已采集的候选分 dump 离线扫阈值（不加载模型）。

## 相关模块

`darwin/rag.py`、`tools/build_rag_eval.py`、`knowledge/eval/runtime_queries.json`。

## 阅读建议

先看 `_evaluate()` 的指标定义与 `_evaluate_dump()` 的闸门复算，再看 `_compare()`。

## 维护提示

阈值改动后必须重跑并更新基线；`recall@3` 与 `negative_empty_rate` 是一对手感相反的
指标，调闸门时以"负样本空返回率保持 1.0"为前提再看召回。
