# `darwin/orchestration/research.py`

## 模块定位

`ResearchCoordinator`：分析与研究域方法分片，继承 `CoordinatorContext`。

## 关键入口

- `_analyze_phase()`：LLM 漏洞分析 + DKG 增强（`_augment_from_dkg`）。
  `vulnerabilities` 只接收有观测证据的假设；无证据的模式猜测写入
  `speculative`，只保存在内存（`speculative_hypotheses`），不进入研究、
  计划与 DKG Vulnerability 节点，仅在强制重考虑轮作为确定性探测输入。
- `_service_research()` / `_active_service_research()`：服务与主动研究。
- `_research_phase()`：研究主流程（RAG / 搜索引擎 / exploit-db）。
- `_probe_endpoints()`：端点探测。

## 相关模块

`rag.py`、`cteg.py`、`core/schemas.py`、`ports.py`。

`_augment_from_dkg()` 仅基于成功响应和真实输入参数生成假设；URL 获取型参数优先映射到 `ssrf_probe`。
