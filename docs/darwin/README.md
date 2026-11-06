# `darwin` 包

DARWIN 的生产运行包按领域分层：

| 包 | 职责 |
|---|---|
| `app/` | Orchestrator、runner 和 CLI 调用入口 |
| `core/` | Task、Runtime、Executor、Evaluator、Replanner、Memory 等 v2 控制面 |
| `orchestration/` | recon、research、planning、execution、lifecycle 阶段协调器 |
| `world/` | DKG、类型化状态、环境、拓扑、可达性和响应证据 |
| `knowledge/` | RAG 构建、检索、查询和证据格式化 |
| `memory/` | CTEG、凭据、图指纹、先验存储和记忆配置 |
| `security/` | DPM 防御感知 |
| `verification/` | DAVE 四级验证 |
| `tools/` | 工具契约、注册和统一网关 |
| `prompts/`、`utils/` | 角色提示词与外部服务支持 |

推荐阅读顺序：`app/orchestrator.py` → `orchestration/README.md` →
`core/runtime.py` → `core/task.py` / `core/executor.py` →
`world/dkg.py` / `world/data_model.py` → `security/dpm.py` / `verification/dave.py`。

旧顶层 import 路径保留为 re-export 兼容层。顶层编排器不直接执行外部命令，工具调用
必须经过 `darwin/tools/`、`core/executor.py` 或 `orchestration/ports.py` 注入的端口。

`world/reachability.py` 是端点“宿主可达性”的唯一判定入口：由集群关系推导出的
ClusterIP/云暴露端点（`virtual: True`）只在集群网络内可路由，侦察、DPM 与
systematic pass 都据此跳过，避免为一个不可达地址付满超时代价。

跨任务记忆由 `memory/` 下四个模块组成：`graph_fingerprint.py` 把 DKG 投影成攻击面图并算相似度，
`precedent_store.py` 存历史图与知识账本（Neo4j 主存 + JSON 降级），
`credential_memory.py` 管理跨任务凭据，`memory_config.py` 装配两个配置文件。
它们的检索结果是 RAG 的排序先验，不绕过 RAG 门控。
