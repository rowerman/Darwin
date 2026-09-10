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

## 探针拦截判定（ProbeClient）

`_analyze_response()` 采用**基线对比**：先记录无探针时的状态/长度，
只有探针相对基线发生“被拦截式”变化（如基线 2xx → 探针 403）才置
`blocked`。基线本身就是 403/406/429 的端点（典型的授权/身份 oracle）
不再被判成 WAF；`mod_security`/`naxsi`/`cloudflare` 等指纹仍单独识别。
调用方在探测前必须先用 `get_baseline(url)` 建立基线（`_detect_defenses()`
已如此实现），否则判定退化为“无基线”。
