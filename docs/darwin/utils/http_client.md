# `darwin/utils/http_client.py`

## 模块定位

提供异步 HTTP 请求、基线比较、探测和 WAF 相关响应采集。

## 所在链路

bootstrap recon、DPM 防御感知和 DAVE HTTP 验证的网络基础设施。

## 关键入口

- `HTTPClient`：请求和响应封装。
- `ProbeClient`：探测序列和基线分析。
- `HTTPResponse`、`ProbeResult`、`BaselineResult`：结果模型。

## 相关模块

`dpm.py`、`dave.py`、`tools/recon_server.py`、`orchestrator.py`。

## 阅读建议

先看响应模型和请求生命周期，再看 ProbeClient 的差异分析。

## 维护提示

请求超时、重定向和响应截断策略会影响防御检测和验证结果。

