# `darwin/tools/oob_listener.py`

## 模块定位

带外（OOB）回调监听：盲打与异步漏洞的唯一可信验证通道。SSRF、盲命令注入、
runbook/webhook 执行这类目标不会把结果写回 HTTP 响应，必须让目标反连攻击者。

历史上没有这个能力：`shell_exec` 里 `nohup nc -l` 会被工具超时 SIGTERM 掉，
而且交给目标的回调地址写成 `127.0.0.1`——在目标自己的容器里那指向它自己。

## 关键入口

- 工具 `oob_listener(action, listener_id, port, wait_seconds, filter, limit)`：
  `start` 绑定 `0.0.0.0`（端口 0 自动分配），返回 `listener_id`、`port`、
  `callback_urls` 与现成 payload（curl/python3/sh/nc）；`read` 可等待最长 30s
  并返回命中的 method/path/query/body 与 flag 提取结果；`stop`/`list` 管理
  生命周期。
- `callback_urls(port)` / `callback_payloads(url)`：回调地址与载荷模板。
- `stop_all_listeners()`：`LifecycleCoordinator.run()` 的 `finally` 调用，
  进程内端口不跨场景残留。

## 约束

- 并发上限 `MAX_LISTENERS=2`、命中上限 `MAX_HITS=200`、单条 body 上限 8KB、
  `wait_seconds` 上限 30s。监听是双向攻击面，必须保持有界。
- 回调地址来自 `_local_ipv4_addresses()`（`ip -4 -o addr` + 主机名解析，
  路由查询兜底）；目标容器要访问的是 docker 网关地址（如 10.42.0.1），
  而不是回环地址。工具输出里明确写出这一点。
- 只用标准库 `http.server.ThreadingHTTPServer`，不引入新依赖。

## 相关模块

`tools/attack_server.py`（注册入口）、`tools/contracts.py`（capability
`oob_callback`）、`orchestration/planning.py`（"服务端执行字段 → OOB 三步"
提示）、`orchestration/lifecycle.py`（收尾清理）。
