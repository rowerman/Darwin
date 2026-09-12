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

## Analyze 端点的归一化与存在性校验

analyze LLM 偶尔把端口写成路径段（`http://host/10726`），这类 URL 指向
错误的服务并会浪费一个任务。`_normalize_hypothesis_endpoint()`：

- 路径首段是数字且 `host:port` 确实被发现 → 重写为 `http://host:port/...`；
- 端口所在服务从未被发现 → 丢弃该假设并计数
  （`[SCHEMA] analyze: dropped N hypothesis(es) whose endpoint host:port
  was never discovered`）；
- 非 URL 形态的 endpoint（文件路径等）原样保留。

发现集合来自 DKG 的 Endpoint/Service 节点与 target_url
（`_discovered_host_ports()`）。
