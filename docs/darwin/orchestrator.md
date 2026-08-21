# `darwin/orchestrator.py`

## 模块定位

DARWIN 的主编排器门面（薄门面）：保留全部状态与构造逻辑，方法体按域迁移到
`darwin/orchestration/` 下的 5 个 Coordinator，`Orchestrator` 对全部既有方法
保留一行委托。行为与测试入口不变。

## 所在链路

贯穿完整 `recon → analyze → plan → execute → evaluate → replan → verify` 流程；
各阶段由对应 Coordinator 实现，`run()` 委托给 `LifecycleCoordinator.run()`。

## 关键入口

- `Orchestrator`：状态容器 + 门面委托；构造时创建
  `self.recon/research/planning/execution/lifecycle` 五个 Coordinator 与
  `self._tool_port`（`GatewayToolCallPort`）。
- 委托方法：`run()` 与全部 `_xxx` 私有方法保持原名称/签名，转发到对应
  Coordinator（如 `_generate_exploitation_plan` → `planning`、
  `_run_with_runtime` → `execution`、`_analyze_phase` → `research`）。
- 模块级导出：`TaskExecution`、`_RuntimeFlagFound`、
  `_RuntimePlannerAdapter`、`_RuntimeExecutorAdapter`、`_RuntimeEvaluatorAdapter`
  继续从 `darwin.orchestration.execution` re-export。

## 输入/输出概览

输入是任务描述、目标、凭证、预算和 LLM 配置；输出是 `TaskResult`、DKG 状态、
日志和 checkpoint。

## 相关模块

`orchestration/`（5 个 Coordinator + `context.py`/`ports.py`）、`core/runtime.py`、
`core/schemas.py`、`dkg.py`、`dpm.py`、`dave.py`、`tools/`、`utils/`。

## 阅读建议

先读 `orchestration/README.md` 了解组合契约，再读 `Orchestrator.__init__` 的
Coordinator 装配，最后按阶段阅读对应 Coordinator。

## 维护提示

编排器不得绕过 `core.Runtime` 或 MCP 网关直接执行外部工具；Coordinator 内
`self.<attr>` 与 `self.<method>` 经共享上下文转发，工具调用必须走
`self._call_tool()` 端口；schema fallback 和上下文压缩不能破坏。
