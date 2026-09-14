# `darwin/response_evidence.py`

## 模块定位

把一次工具响应变成**世界模型证据**。判据是通用的：请求没有提供、但响应里
出现过的值，就是目标主动泄露的信息。两类泄露值得直接升级为假设：

- **路径预言机**：响应出现绝对服务器路径（`/app/workspaces/default/test`）。
  说明服务端把调用方输入解析成了文件系统位置——这正是路径穿越需要的信息。
- **跨主体回显**：响应出现调用方自己的请求里没有的另一主体标识
  （`tenant-a`、`workspace=acme`），说明越过了授权边界。

两者都是**观测**而非猜测，因此进入计划时带着证据，不必在猜测队列里等待。

## 关键入口

- `detect_response_anomalies(tool, params, response_text, endpoint, param)`：
  返回 `ResponseAnomaly` 列表（kind / detail / evidence / signals）。
- `disclosed_paths(response_text, request_blob)`：请求中不含的绝对路径。
  只认可已知根（`/app`、`/srv`、`/opt`、`/etc`、`/var`、`/home`、`/usr`…），
  避免把 URL 与 MIME 里的斜杠当成文件系统泄露。
- `disclosed_subjects(response_text, request_blob)`：`tenant-a` / `workspace=acme`
  这类主体标识。分隔符是必需的，路径片段（`workspaces/`）不会误命中。
- `traversal_hypotheses(anomaly)`：把路径预言机展开成具体 payload 族的后续假设
  （`<resolved>/../flag` 等），而不是丢给通用字典盲打。

## 消费方

`orchestration/execution._ingest_response_evidence()` 在每次工具调用后运行：
命中的证据写成 DKG `Vulnerability` 节点（`source=response_evidence`），并按
`(vuln_type, endpoint, param)` 去重，重复探测不会反复放大计划；同时置位
`_evidence_since_review`，让 plan review 有真实增量可评审。

## 约束

- 只上报观测到的值；不做"可能存在"的推断（那是 analyze 阶段的职责）。
- 同一 `(vuln_type, endpoint, param)` 只提升一次。
- 路径识别要求已知根前缀；宁可漏报也不要把普通文本当成路径泄露。
