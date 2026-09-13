# `tools/rag_lint.py`

## 模块定位

语料 lint CLI：检查统一语料条目是否满足 schema、是否残留目标专属值（IP/端口/flag/
`{{占位符}}`）、是否缺少 applies_when 与 verification。

## 所在链路

知识库改动后的快速自检，位于 `tools/build_rag_corpus.py` 之前或之后。

## 关键入口

- `python -m tools.rag_lint`：检查已生成语料产物。
- `--sources`：直接转换源文件后检查；`--max-report N`：限制打印条数。

## 输入/输出概览

输出违规原因计数与样例；curated 条目存在阻塞性问题（空判据、目标专属值等）时退出码非 0。

## 相关模块

`darwin/rag_corpus.py`（`lint_entry()`）、`tools/build_rag_corpus.py`。

## 阅读建议

先看 `darwin/rag_corpus.py` 的 `lint_entry()` 规则集。

## 维护提示

新增 schema 字段时同步 lint 规则与 `tests/test_rag_corpus.py`。
