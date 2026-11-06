# DARWIN 架构与包边界

## 运行链路

```text
run.py
  → darwin.app.orchestrator.Orchestrator
  → orchestration/lifecycle
  → bootstrap recon → DKG
  → core.Runtime: plan → schedule → execute → evaluate → replan
  → security.DPM / verification.DAVE
```

`core.Runtime` 是唯一主执行路径。所有外部工具调用必须经过
`darwin/tools/mcp_gateway.py` 和 `darwin/core/executor.py`；阶段 Coordinator
只能通过 `darwin/orchestration/ports.py` 注入的工具端口执行任务。

## 领域包

| 包 | 主要职责 | 典型入口 |
|---|---|---|
| `darwin.app` | 编排门面和应用入口 | `Orchestrator`、`runner` |
| `darwin.core` | Task、图、调度、执行、评估、重规划、记忆和 schema | `Runtime`、`Task` |
| `darwin.orchestration` | 按阶段拆分的 Coordinator | `LifecycleCoordinator` |
| `darwin.world` | DKG、类型化状态、环境与云拓扑 | `DKG`、`PipelineState` |
| `darwin.knowledge` | RAG 语料、检索、查询和证据格式化 | `DarwinRAG` |
| `darwin.memory` | CTEG、凭据、图指纹和历史先验 | `CTEG`、`PrecedentStore` |
| `darwin.security` | 防御感知和绕过状态 | `DefensePerceptionModule` |
| `darwin.verification` | HTTP、浏览器、完整性和影响验证 | `DAVE` |
| `darwin.tools` | 工具规格、注册、网关和适配器 | `MCPGateway` |
| `darwin.prompts` | 各阶段系统提示词 | `SYSTEM_PROMPT_*` |
| `darwin.utils` | LLM、HTTP、日志和 URL 基础设施 | `LLMSession` |

依赖方向以领域边界为准：`app` 组合各领域，`orchestration` 调用 `core` 与领域服务，
`core` 不依赖 `app` 或 `orchestration`。现有两处历史循环依赖继续使用惰性 import，
迁移不得新增模块级环。

## 兼容路径

迁移前的顶层模块路径保留为薄 re-export，例如：

```python
from darwin.orchestrator import Orchestrator  # 兼容入口
from darwin.app.orchestrator import Orchestrator  # 规范入口
```

兼容层保证公开符号身份一致，但新代码、测试和文档必须使用领域包路径。兼容层不承诺
旧路径上的模块级 monkeypatch 会影响规范模块。

## 数据与产物

- `knowledge/` 保存知识源与构建后的语料；运行期由 `darwin.knowledge.rag` 读取。
- `tools_manifest.json` 是工具契约锁文件。
- `log/`、`checkpoints/`、`artifacts/`、`memory/`、`models/`、`config/` 和
  `cteg_state.json` 是本地或敏感产物，不进入版本库。
- `plans/` 与 `CHANGES/` 保存本地开发过程记录，同样不提交。
