# `darwin/rag_query.py`

## 模块定位

把运行期观测（服务/banner/漏洞假设/证据文本）翻译成检索所需的查询文本、环境类型
与观测域，避免各调用点各写一套查询拼接。

## 所在链路

planning / research / fix 分析与 `knowledge_search` 工具调用 `DarwinRAG.retrieve()` 之前。

## 关键入口

- `build_capability_query()`：服务 + 漏洞类型（canonical 英文）+ 证据 → 查询串。
- `active_domains()`：文本 → 域标签（web/cloud/k8s/container/db/ad/network）。
- `environment_from_dkg()` / `domains_from_dkg()`：读 DKG 的环境分类与观测域。

## 输入/输出概览

输入是 services/vulns/observations 或 DKG；输出是查询字符串、环境类型、域列表。

## 相关模块

`rag.py`、`darwin/environment.py`、`orchestration/planning.py`、`orchestration/research.py`。

## 阅读建议

先看 `TECHNIQUE_TERMS` 与 `DOMAIN_SIGNATURES` 两张表，再看两个 DKG 读取函数。

## 维护提示

新增漏洞类型或域指纹时同步这两张表；查询里不得出现场景 ID 或 benchmark 名称。
