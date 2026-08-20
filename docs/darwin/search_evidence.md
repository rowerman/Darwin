# `darwin/search_evidence.py`

## 模块定位

将 RAG 和 Web 搜索结果统一格式化为可放入 LLM 上下文的证据文本。

## 所在链路

研究阶段的证据呈现层，位于搜索结果和 prompt 之间。

## 关键入口

- `format_rag_evidence()`、`format_web_evidence()`：按来源格式化。
- `format_evidence()`、`empty_evidence()`：通用和空结果处理。

## 输入/输出概览

输入是来源、查询和结果字典；输出是带来源标记的文本。

## 相关模块

`rag.py`、`knowledge_base.py`、`prompts/research.py`、`orchestrator.py`。

## 阅读建议

先看不同来源的格式化入口，再确认输出如何拼进研究 prompt。

## 维护提示

输出格式变化会影响 LLM 解析和证据引用，保持来源信息可追溯。

