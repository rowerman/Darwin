# `darwin/orchestration/recon.py`

## 模块定位

`ReconCoordinator`：侦察域方法分片，继承 `CoordinatorContext`，通过共享
Orchestrator 上下文读写状态并调用工具端口。

## 关键入口

- `_bootstrap_scan()`：基础 nmap/HTTP 发现、规则环境分类、Host/Service/Endpoint 关系记录。
- `_adaptive_web_probe()`：证据驱动的分层 GET 发现（替代固定路径列表）。
  从 HTML 链接/脚本、JS fetch/XHR、`response_parse` 的 api_paths/endpoints、
  纯文本路由文档与 OpenAPI/Swagger 文档中提取同源候选 URL，有界、去重地
  GET 探测，并以 `discovered_by="adaptive-web-probe"` 记录。跨域候选被过滤，
  候选数量与递归深度受 `_MAX_ROUTE_CANDIDATES` / `_MAX_ROUTE_DEPTH` 限制。
- `_api_route_discovery()`：POST/JSON API 路由发现层。解析 OpenAPI/Swagger、
  JSON 路由/link 字段和纯文本路由文档；对候选路径先发安全的 OPTIONS 探测，
  记录 Allow/状态码/Content-Type。明确支持 POST 的路径写入
  `method="POST"`、`body_format="json"`，参数仅来自 schema/示例（无 schema 时
  不伪造参数）。`/invoke` 类路径仅打 `invoke_signal` 候选标记，不判定漏洞。
- `_k8s_cluster_discovery()`：仅在分类为 private cloud/hybrid 后通过 discovery tool port 执行 K8s 只读发现；bootstrap 完成后 `CloudTopologyMapper` 写入扩展资源，并由 `RelationAnalyzer` 建立 canonical 关系。
- `_deep_recon()`：HTTP 端点深侦察。HTML 主站继续运行 gobuster/nikto/form_extract；
  JSON、纯文本与 API 响应跳过这三类重型工具，改为 JSON 结构解析、路由提取与
  HTTP 方法验证（复用 `_api_route_discovery`）。
- `_detect_defenses()`：DPM 防御检测。
- `_verify_flag()`：DAVE L4 flag 验证与蜜罐拒绝。

## 相关模块

`dkg.py`、`dpm.py`、`dave.py`、`ports.py`。

HTTP 方法探测会根据 `key=value` 请求体自动选择表单编码；HTTP 响应中经
DAVE 验证的 flag 会带来源和位置写入 DKG。

深侦察的预检通过带 timeout 的 `curl_get` 完成；路径探测将工具解析出的真实
HTTP 状态码写入 DKG，非 HTML 或错误状态端点不会进入 gobuster/nikto 重扫描。
API 方法探测使用 recon 域的 `http_method_probe` 工具（OPTIONS/POST/JSON），
工具调用统一经 `_call_tool()` → `MCPGateway`，不绕过工具契约。
