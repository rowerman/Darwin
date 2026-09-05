# `darwin/tools/recon_server.py`

## 模块定位

注册侦察域工具并将 nmap、masscan、dirb、whatweb 和 HTTP 响应解析为结构化结果。

## 所在链路

bootstrap recon 和后续服务研究阶段的工具注册层。

## 关键入口

- `register_recon_tools()`、`create_recon_gateway()`：注册入口。
- `parse_response()`：统一 HTTP 内容解析。
- `http_method_probe`：通用 HTTP 方法探测（OPTIONS/POST/HEAD 等），返回状态、
  响应头与 body；用于自适应侦察的 API 路由发现与 POST/JSON 验证。
- 各 `_parse_*` 函数：外部 CLI 输出适配。

## nmap 云探针自动准备

四个 nmap 工具（`nmap_scan` / `nmap_full_scan` / `nmap_port_range` /
`nmap_vulners_scan`）首次执行前，会尝试把 benchmark 的云服务探针片段
（`nmap-cloud-probes.txt`，默认读取 `../benchmark/cve_challenges/scripts/` 下的
同文件，单一事实来源）合并进系统 `nmap-service-probes`，写入 nmap 用户
datadir，使 `-sV` 自动识别 DARWIN Cloud Benchmark 的模拟服务（IMDS/S3/OIDC/
STS/SAML/云控制面等）。

- 目标目录：环境变量 `NMAP_DATADIR`（与 benchmark 校验脚本一致），否则 `~/.nmap`。
- 覆盖/跳过策略：目标文件缺失时创建；含 DARWIN 标记但过期时原子重建；不含
  标记（用户自管文件）时不触碰；源缺失或写入失败时仅记录日志，扫描退化到
  原生 nmap 行为。
- 自定义探针路径可用 `DARWIN_NMAP_CLOUD_PROBES` 覆盖。
- 探针合并逻辑不影响工具参数/命令模板，manifest 无变化。

## 相关模块

`mcp_gateway.py`、`spec.py`、`utils/http_client.py`、`orchestrator.py`。

## 阅读建议

先看 gateway 创建，再按工具解析器和输出契约阅读。

## 维护提示

新增工具要补注册参数、`darwin/tools/contracts.py` 中的域/capability 分类、manifest 和相关 parser 测试。
