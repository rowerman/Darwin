# `darwin/orchestration` 包

编排器的阶段协调层：将原 `darwin/orchestrator.py` 中按域耦合的方法拆分为 5 个
Coordinator，通过「组合 + 共享上下文」协作，`Orchestrator` 退化为薄门面。

## 协作契约

- `CoordinatorContext`（`context.py`）：所有 Coordinator 的基类。每个
  Coordinator 持有 `_orch`（所属 `Orchestrator` 实例）引用；未知属性读/写
  与方法调用全部转发到该实例。状态只存在 `Orchestrator` 上，Coordinator
  是纯行为分片。
- `ToolCallPort` / `GatewayToolCallPort`（`ports.py`）：Coordinator 调用外部
  工具的唯一通道是 `self._call_tool(name, params)`，由 Orchestrator 注入的
  端口实现路由（先 attack 网关、后 recon 网关，按 `get_tool_names()` 匹配）。
- 门面委托：`Orchestrator` 对全部既有方法保留一行委托（名称/签名不变），
  因此 `run.py`、`darwin.runner` 与既有测试入口无感；跨 Coordinator 调用
  也统一经门面转发。

## 模块清单

| 模块 | 职责 |
|------|------|
| `context.py` | `CoordinatorContext` 共享上下文基类与 `_call_tool` |
| `ports.py` | 工具调用端口协议与网关路由实现 |
| `recon.py` | `ReconCoordinator`：bootstrap/深侦察/防御检测/flag 验证 |
| `research.py` | `ResearchCoordinator`：analyze/DKG 增强/服务研究 |
| `planning.py` | `PlanCoordinator`：计划生成/清洗/评审/凭据提取 |
| `execution.py` | `ExecutionCoordinator` + Runtime 适配器：任务执行策略/提权 |
| `lifecycle.py` | `LifecycleCoordinator`：`run()` 主循环/状态与日志/工具检查 |

## 阅读建议

先读 `context.py` 与 `ports.py` 理解共享上下文与端口契约，再按
`lifecycle.py` → `recon.py` → `research.py` → `planning.py` → `execution.py`
的顺序阅读阶段流。
