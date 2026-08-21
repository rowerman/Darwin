# `darwin/orchestration/research.py`

## 模块定位

`ResearchCoordinator`：分析与研究域方法分片，继承 `CoordinatorContext`。

## 关键入口

- `_analyze_phase()`：LLM 漏洞分析 + DKG 增强（`_augment_from_dkg`）。
- `_service_research()` / `_active_service_research()`：服务与主动研究。
- `_research_phase()`：研究主流程（RAG / 搜索引擎 / exploit-db）。
- `_probe_endpoints()`：端点探测。

## 相关模块

`rag.py`、`cteg.py`、`core/schemas.py`、`ports.py`。
