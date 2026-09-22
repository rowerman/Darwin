# `darwin/memory_config.py`

## 模块定位

跨任务图记忆的配置装配：`config/darwin.yaml` 的 `memory` 节（权重、阈值、投影参数、
存储位置）与 `config/neo4j.yaml` 的连接信息。两个文件都可缺省，缺省时用内置默认值，
记忆功能保持可用但只走本地 JSON。

## 所在链路

`Orchestrator.__init__` 构造 `MemoryConfig.from_files()`，随后注入 `PrecedentStore`
与 `CredentialMemory`；`lifecycle` 从同一对象读取投影参数。

## 关键入口

- `MemoryConfig.from_files(darwin_path, neo4j_path)`：读取两个配置并合并默认值。
- `Neo4jConfig.usable`：未配置密码时不尝试连接（避免每次落盘都等待超时）。
- 环境变量 `NEO4J_URI` / `NEO4J_PASSWORD` 覆盖文件配置，便于临时切换实例。

## 输入/输出概览

输入是两个 YAML 文件；输出是带默认值的 `MemoryConfig` / `Neo4jConfig`。`config/`
整体已 gitignore，真实凭据只存在于本地文件或环境变量中，文档不记录密钥。

## 相关模块

`precedent_store.py`、`credential_memory.py`、`graph_fingerprint.py`。

## 阅读建议

先看数据类字段（它们就是 `config/darwin.yaml` 里 `memory:` 的全部可调项），再看
`_apply()` 的类型保护。

## 维护提示

新增可调项时同步 `config/darwin.yaml` 的注释与本文档；解析失败必须静默退回默认值，
不要让损坏的配置文件阻断渗透测试。
