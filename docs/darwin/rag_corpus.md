# `darwin/rag_corpus.py`

## 模块定位

运行时语料的唯一事实来源：定义 `darwin.rag.entry.v1` schema，把 legacy 知识文件
（JSON / Markdown / Nuclei 模板 / 扫描笔记 / 修复方案）转换为统一条目，并生成
`knowledge/corpus/*.jsonl` + `manifest.json`。

## 所在链路

构建期（`tools/build_rag_corpus.py`）与运行期加载（`darwin/rag.py`）之间的契约层。

## 关键入口

- `build_corpus()` / `write_corpus()` / `load_corpus()`：转换、落盘、加载。
- `build_entry()` + `source_fields()`：按来源形状抽取 applies_when/signals/technique_class。
- `sanitize_text()` / `sanitize_technique()`：剥离目标专属值与 payload/请求体。
- `lint_entry()`：schema 与目标值校验；`DOMAIN_ENVIRONMENTS` 定义域 → 环境前提。
- `graph_pattern`（可选字段）：条目的**结构前置条件**，声明它需要当前环境图包含
  哪个子图才适用（节点/边条件 + `requires_subgraph`）。由
  `graph_fingerprint.match_graph_pattern()` 在检索候选阶段判定，不满足即丢弃。

## 输入/输出概览

输入是 `knowledge/**`（`scenarios/**` 除外，记为 `answer_leak` 排除）；输出统一
条目，含 `applies_when` / `signals` / `technique_class` / `verification` /
`failure_boundary` / `requires_environment` / `graph_pattern` / `provenance` 与
两路检索文本。

## 相关模块

`rag.py`、`rag_query.py`、`tools/build_rag_corpus.py`、`tools/rag_lint.py`。

## 阅读建议

先看 `ENTRY_FIELDS` 与 `DOMAIN_ENVIRONMENTS`，再看各 `source_fields()` 分支。

## 维护提示

新增知识来源时补 `source_kind_for()`/`source_fields()` 分支与测试；schema 变化要升
`SCHEMA_VERSION` 并重建语料。
