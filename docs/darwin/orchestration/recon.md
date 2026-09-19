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
  JSON 路由/link 字段、`extract_documented_routes()`（服务自述清单里的
  `METHOD /path {字段...}`，含 JSON 字符串值内的形态）与纯文本路由文档；
  对候选路径先发安全的 OPTIONS 探测，记录 Allow/状态码/Content-Type。明确
  支持写动词的路径写入 `method`、`body_format`、`documented_methods`（服务
  自己声明的动词）与 `params`（字段名仅来自清单/schema，不伪造）。
  `/invoke` 类路径仅打 `invoke_signal` 候选标记，不判定漏洞。
- `_k8s_cluster_discovery()`：在 `k8s_signal`（无开放端口 / private cloud /
  hybrid / 服务文本带 k8s 关键词）成立后通过 discovery tool port 执行 K8s
  只读发现；bootstrap 完成后 `CloudTopologyMapper` 写入扩展资源，并由
  `RelationAnalyzer` 建立 canonical 关系。发现的节点 Host 节点带
  `provider=k8s`（环境分类的 `dkg:k8s-host` 信号依赖它，缺失时 KIND 集群会
  被判成 public cloud 而丢掉 K8s 知识集）；Service 节点经
  `cloud_topology.write_k8s_service_nodes()` 写入，与 CTAGE 共用同一形状与 id。
- `_deep_recon()`：HTTP 端点深侦察。HTML 主站继续运行 gobuster/nikto/form_extract；
  JSON、纯文本与 API 响应跳过这三类重型工具，改为 JSON 结构解析、路由提取与
  HTTP 方法验证（复用 `_api_route_discovery`）。**JSON 根不再直接返回**：
  自述清单里的路由必须先解析为带方法/字段名的 Endpoint，否则计划会在从未
  用正确动词访问过声明路由的情况下判定耗尽。
- `_detect_defenses()`：DPM 防御检测。
- `_verify_flag()`：DAVE L4 flag 验证与蜜罐拒绝。
- `_probe_cms()` / `_probe_service_hint_paths()`：CMS 入口与标签暗示路径探测。

### 宿主可达性（`darwin/reachability.py`）

`relation_analyzer:*` 合成的 ClusterIP/云暴露端点（`virtual: True`）只存在于
集群网络内，宿主没有到 Service CIDR 的路由。`is_host_reachable()` 是唯一判定
入口，CMS 探测、端点深侦察、标签路径探测、DPM 探测与 systematic pass 都据此
跳过它们；它们仍作为拓扑事实进入 planner 上下文。

CMS 路径探测只对 HTML 型端点执行（`_looks_like_html`），单次 `curl_get`
超时 5s，并且只有响应体带真实 CMS 指纹（`_has_cms_marker`：`wp-content`
/`wp-includes`/`wordpress`/`joomla`/`drupal`/`typo3`，或 2xx 且含 password
表单）才登记 Endpoint。Kubernetes API server 对任意路径都返回同一份 403
Status JSON，旧规则把它当成 10 个"认证墙 CMS 端点"，既污染假设生成又让
`/wp-json/wp/v2/` 触发假的 Docker Registry 检测。

`_detect_defenses()` 先做 3s 可达性预检，最多对 3 个可达端点发探针：不可达
端点的完整探针族只会消耗预算而不产生任何 DPM 证据。

## 相关模块

`dkg.py`、`dpm.py`、`dave.py`、`ports.py`。

HTTP 方法探测会根据 `key=value` 请求体自动选择表单编码；HTTP 响应中经
DAVE 验证的 flag 会带来源和位置写入 DKG。

深侦察的预检通过带 timeout 的 `curl_get` 完成；路径探测将工具解析出的真实
HTTP 状态码写入 DKG，非 HTML 或错误状态端点不会进入 gobuster/nikto 重扫描。
API 方法探测使用 recon 域的 `http_method_probe` 工具（OPTIONS/POST/JSON），
工具调用统一经 `_call_tool()` → `MCPGateway`，不绕过工具契约。

## 深侦察的失败可见性与发现即校验

- gobuster/dirb/nikto 的失败会写 WARNING 日志并进入任务日志，不再静默吞掉；
  字典缺失、CLI 语法不匹配这类问题会直接暴露。
- 目录枚举新发现的路径会被**立即** GET 一次（上限
  `_MAX_DISCOVERY_VERIFY`，默认 15）：响应写入对应 Endpoint 的
  `sample_response`，并用统一 flag 正则扫描，命中后走 DAVE 校验；验证通过
  则 `_recon_flag_result` 置位，`LifecycleCoordinator.run()` 会以 `_RunFinished`
  结束本次运行，不再进入利用阶段。
- `_detect_defenses()` 在探测前先用 `get_baseline(url)` 建立基线，
  使 `ProbeClient` 的拦截判定只在“探针改变了结果”时成立。

## JSON / API 端点的判定与子路径探测

pre-flight 与 `sample_response` 判定 JSON/API 时先经
`utils.urls.response_body()` 剥离响应头块——curl/urllib 输出以
`HTTP/1.1 200 OK` 开头，直接 `startswith("{")` 永远不成立，会把所有 JSON
API 误判成“plain text/API”。

判定为 JSON 集合端点后调用 `_probe_collection_children()`：从**同主机所有
已发现端点**的响应里抽取标识符（`_observed_host_identifiers()`），用
`route_variants()` 推导子路径并只发 **OPTIONS**（安全动词，不在目标上创建
任何东西），把存在且非 4xx 的路径连同 `Allow` 方法写入 DKG Endpoint
（`discovered_by="collection-child-probe"`）。`_api_route_discovery()` 在
没有任何候选路由时同样走这条路径。
