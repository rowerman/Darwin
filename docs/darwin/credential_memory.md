# `darwin/credential_memory.py`

## 模块定位

跨任务凭据记忆：把任务中拿到的可用凭据持久化，供后续任务复用。相比被替代的
CTEG 凭据通道，这里要求**完整身份四元组**匹配——scope、host、port、service_type
全部一致才复用。

这是针对 benchmark 的实际风险：所有场景都跑在 `localhost`，端口（10601/10670/…）
会跨挑战重复，仅按端口匹配会把一个挑战的凭据试到另一个挑战上。

## 所在链路

写入：`planning._extract_credentials_from_task()`、`execution` 的部分成功分支。
读取：`lifecycle._load_remembered_credentials()` 在 recon 后按已发现服务逐条查询，
命中后写回 DKG 的 Credential 节点并作为 `known_credentials` 进入规划提示词。

## 关键入口

- `record(host, port, service_type, username, password, source, scope, environment)`。
- `lookup(host, port, service_type, scope, environment)`：全等匹配 + 14 天有效期。
- `CredentialMemory._persist()`：落在 `memory/credentials.json`（gitignore）。

## 输入/输出概览

输入是发现到的凭据与当前目标的环境标识；输出是匹配到的凭据列表（按成功次数排序）。
scope 取 `dkg.scope.target_scope`，environment 取 recon 写入 DKG 的环境分类。

## 相关模块

`memory_config.py`、`orchestration/lifecycle.py`、`orchestration/planning.py`、
`orchestration/execution.py`。

## 阅读建议

先看 `_identity()`（匹配判据就是它），再看 `_is_active()` 的半衰期判断。

## 维护提示

放宽匹配条件等于重新引入跨场景凭据泄漏；若确需放宽，必须同时补一条负向测试。
