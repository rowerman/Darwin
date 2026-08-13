# DARWIN v2 重构进度交接（2026-08-13）

> 本文件用于跨 session 续接。新 session 先读本文件 + `Darwin_v2_architecture_plan.md`（v2 目标方案），
> 然后按“待确认问题”继续。当前进度：**M0、P1–P7 已完成；P8（Capability 层）讨论中，等用户确认 4 个决策点**。
> 然后按“待执行清单”继续。当前进度：**M0、P1–P8 已完成；P9（工具参数可靠性）待做**。

---

## 1. 项目与运行环境

- 仓库：`C:\Users\hanwenZ\Desktop\小论文\Darwin`（单 agent 的 LLM 驱动渗透测试框架）
- 入口：`run.py`；`config/` 目录在仓库外（gitignore，含 API key），本地验证不依赖它
- 推荐 Python：`C:\Users\hanwenZ\anaconda3\envs\deeplearn\python.exe`（已装 litellm 1.96.2、pydantic、pytest 等）
- 跑测试：`& 'C:\Users\hanwenZ\anaconda3\envs\deeplearn\python.exe' -m pytest tests/ -q` → 当前 **247 passed**
- 注意：litellm/tiktoken 首次导入需联网（沙箱禁网时用提权运行）；deeplearn 是用户指定环境

## 2. 已完成阶段（按顺序）

### M0 修复基线（orchestrator 可运行）
- 删除坏引用：`DynamicScalingEngine` / `compute_task_breadth` / `ScalingLevel`（符号随 `dynamic_scaling.py` 删除而消失）
- 主循环改纯 Solo（去掉 Coordinated/Distributed 分派）；`_should_terminate` 简化
- 删除 778 行多 agent 死代码（`_run_multi_agent_cycle` 等 4 方法 + `_scan_collaboration_opportunities` + DKG 快照 3 件套）
- checkpoint 保存/恢复去 multi-agent 字段
- trace 种子：`plan_generated` / `task_scheduled` / `tool_result` 写入 task_log
- 修 `test_phase_logger.py` 8 处 `open()` 加 `encoding="utf-8"`（中文 Windows GBK 问题）

### P1 消除双份实现
- 函数比对结论：4 个死模块与 orchestrator 61 对函数，仅 2 一致，大函数（`generate_exploitation_plan` 0.637、`deep_recon` 0.243 等）显著漂移；bootstrap.py 还有顶层循环导入隐患
- **删除** `darwin/planner.py`、`state.py`、`analyzer.py`、`bootstrap.py`（git 可恢复）
- **存档** `validate_plan` / `classify_and_replan` 到 `%TEMP%\darwin_v2_legacy_validate_replan.py`（P2/P6 讨论过是否复活，未定）
- 修正 `darwin/runner.py` docstring

### P2 职责边界与接口契约 → `darwin/core/`
- `contracts.py`：Planner/Scheduler/Executor/Evaluator Protocol + TaskStatus/TaskOutcome/ReplanRecommendation + Objective/Budget；`WorldState = PipelineState`（复用 data_model）
- `events.py`：15 个规范事件（run_started → … → run_finished）
- `runtime.py`：薄循环骨架（`run()` 抛 NotImplementedError，P15 实现）
- 约定：**接口先行，新建 core 包逐步委托，orchestrator 保持行为基线**

### P3 Task 数据模型 → `darwin/core/task.py`
- `Task` dataclass：必填 `id/type/goal`；hypothesis/rationale/evidence/confidence、action、required_context、success_condition、failure_policy（默认 `{retry:1, replan_on_failure:True}`）、dependencies、priority、status、attempt_count 等
- `from_legacy_dict()` / `to_legacy_dict()` 兼容层（含 params JSON 字符串、状态/依赖映射）

### P4 依赖语义与任务状态机 → `darwin/core/task_graph.py`
- `TaskStatus` 升级 9 态：CREATED→READY→RUNNING→SUCCESS/FAILED + BLOCKED/NEEDS_REPLAN/INVALIDATED/ABANDONED
- `Task.dependencies` 升级为结构体：`{"type":"requires_task_success","task_id":...}` / `requires_evidence` / `requires_credential` / `requires_access` / `requires_capability`
- `TaskGraph`：非法迁移拦截（转移表）、`refresh_states()` 推导 READY/BLOCKED、`topological_order()`；FAILED 不级联（下游 BLOCKED 可复活）

### P5 Executor → `darwin/core/executor.py`
- `ExecutionResult` 具体化（含 `planned_tool` + `adherence`）+ `ToolExecutor`（按 task.action 调 attack/recon/MCP 网关）
- **接入**：orchestrator `__init__` 建 `self.executor`；fix-retry 路径改 `self.executor.execute(Task.from_legacy_dict(task))`；删除被取代的 `_execute_single_tool`
- `tool_result` trace 加 `planned_tool` / `adherence` 字段（plan adherence 指标数据源）
- 延迟项 **P5c**：LLM 驱动分支改严格 Task 消费（等 P6 后做，尚未做）

### P6 Evaluator / FailureAnalyzer → `darwin/core/evaluator.py`
- `FailureType` 11 类 + `FailureAnalyzer` 纯规则分类（零 token；复活存档的 EXPLORATORY_TOOLS/关键词表）+ `Evaluator` 组装 Evaluation（outcome/failure_type/evidence/confidence_delta/replan）
- **接入**：`_analyze_and_fix_task` 开头先规则分类并打 `task_evaluated` trace；HYPOTHESIS_REJECTED/TARGET_UNREACHABLE/DEFENSE_BLOCKED/BUDGET_EXCEEDED/STRATEGY_FAILED 短路（省 LLM 调用）
- 修复 bug：`exit_code=0` 被 `or -1` 吞（evaluator+executor 两处）；403 命中顺序（DEFENSE 先于 AUTH）

### P7 Replan v2 → `darwin/core/replan.py`
- `Replanner.local_repair(task, evaluation)`：按 failure_type 本地修复（retry/replace/invalidate/abandon/defer/global_stop）+ 失败签名表（tool+params 哈希）防重复 + `novelty_ratio` 指标
- **接入**：任务失败时在 fix-retry 之后、LLM 计划重审之前插本地修复，打 `replan_requested` trace；`replace` 的替代任务直接入计划（source=replanner），`invalidate` 将下游标 skipped
- 删除死方法 `_replan_after_failure`；`_review_and_update_plan` 保留为全局兜底

## 3. P8 Capability 层（已完成）

目标：Task → Capability → Precondition Validator → Context Resolver → Tool → Result Normalizer，
让 Task 表达"想做什么"，系统决定"用哪个工具、怎么填参数"。

### P8 实现内容（设计已与用户确认：按意图、首批 4 能力、不动 prompt、单文件）
- `darwin/core/capabilities.py`：`Capability` dataclass + `CapabilityRegistry`（数据驱动，可自由注册）
  + `default_registry()` 内置 4 个能力；`PreconditionValidator`（`credential/access` 斜杠 = 任一满足）；
  `ContextResolver`（纯字段映射，无 DKG/LLM）；`normalize_result` 给 ExecutionResult 盖章 capability/tool_attempts
- 首批能力（默认工具在前）：
  | Capability | 前置条件 | 支持工具 |
  |---|---|---|
  | fetch_url | endpoint | curl_get → http_post |
  | verify_sql_injection | endpoint + parameter | sqlmap_test → http_post |
  | test_credentials | credential | test_credential → hydra_http_brute |
  | acquire_shell | credential/access | ssh_exec → ssh_key_exec → shell_exec |
- `darwin/core/executor.py`：`ExecutionResult` 加 `capability`/`tool_attempts`；
  `ToolExecutor.execute()` 双路径——有 capability 走注册表 → 前置校验（缺失 → stderr
  "precondition missing: ..." 命中 P6 PRECONDITION_MISSING）→ 按 supported_tools 顺序尝试，
  仅 TOOL_ERROR/INVALID_ARGUMENT 触发换下一个，有意义的失败（auth/hypothesis/defense 等）立即停；
  **未知 capability 显式失败**（"unknown capability: ..."），绝不静默回落 tool 字段；
  capability 与 tool 并存时 capability 优先；无 capability 走旧 tool 直调（~130 个工具行为不变）
- `darwin/core/task.py`：`from_legacy_dict`/`to_legacy_dict` 双向携带 capability（否则 fix-retry seam 会丢字段）
- `darwin/core/evaluator.py`：`_INVALID_ARGUMENT_MARKERS` 加 "unknown capability"，让未知能力被 P6 分类为 INVALID_ARGUMENT
- `darwin/core/__init__.py`：导出 Capability/CapabilityRegistry/ContextResolver/PreconditionValidator/default_registry
- 测试：`tests/test_core_capabilities.py`（18 例）+ `test_core_task.py` 加 2 例往返用例；
  全套 **267 passed**（原 247 + 20）

### 关键语义（实现与设计一致）
- adherence：capability 模式下 True（计划单位是 capability，工具降级不算意图偏离），
  planned_tool = default_tool，降级明细在 tool_attempts（供 P19 指标）
- 未覆盖工具：保持旧直调，加性层不替代工具路由；后续按需增量注册（~10 行 + 单测）
- `Replanner._TOOL_ALTERNATIVES` 与 supported_tools 顺序对齐（sqlmap→http_post、ssh_exec→ssh_key_exec、hydra→test_credential），
  未来可合并为统一的能力层替代逻辑
- shell_exec 是本地执行（工具文档如此），acquire_shell 里保留为批准的末位兜底，代码注释已注明

## 4. 待执行清单（P8 之后）

- **P9 工具参数可靠性**（当前）：INVALID_ARGUMENT 与执行失败彻底分开；`_analyze_and_fix_task` 的 corrected_params
  职责迁移（Context Resolver 已就位，可并入）
- **P5c（延迟项）**：LLM 驱动分支改严格 Task 消费（Planner 只规划、Executor 只执行；P6 已就绪，可以做了）
- **P10–P14 记忆与状态**：Memory 四层（Working=DKG / Plan / Execution / Experience=CTEG）、压缩分级（preserve/compress/discard）、DKG provenance、CTEG 与 Execution Memory 打通、ExecutionRecord 统一
- **P15 Runtime 提取**：薄循环（`core/runtime.py` 已占位）
- **P16 Prompt 拆分**：planner/research/evaluator/memory 角色 prompt
- **P17 配置与环境**：config 骨架、外部工具依赖、Windows/Linux 差异
- **P18 测试与回归**：mock LLM 的测试策略、失败样本集、每个 milestone 验收测试
- **P19 指标**：plan adherence / invalid tool invocation / recovery / replan novelty / duplicate action。数据已部分埋点（tool_result.adherence、task_evaluated、replan_requested、Replanner.novelty_ratio），需聚合计算器
- **P20 文档同步**：README/CLAUDE.md 仍描述已删除的 multi-agent 与 dynamic scaling；`_transform_runner.py`（过时转换脚本）建议删除

## 5. 技术要点与坑

- **代码模式**：每个 P = core 组件 + 单测 + 低风险接入点；协议（Protocol）在 `contracts.py`，具体实现为同名 dataclass，`darwin/core/__init__.py` 导出具体类
- `darwin/core/` 目前被 orchestrator 引用的：task、executor、evaluator、replan；未引用的：contracts（间接）、events、runtime（占位）
- orchestrator 主执行循环仍在 `_unified_llm_loop`（约 2650–3260 行）：工具直调 + 后处理（defense probe、format retry、凭据提取、flag 校验）——P5c 迁移时这些后处理不能丢
- Task 兼容层：旧 dict ⇄ Task 双向转换已就绪（`from_legacy_dict` / `to_legacy_dict`）
- 死代码检查习惯：改动后 `rg` 残留符号；`py_compile` 全部模块；pytest 全绿
- 沙箱：deeplearn 环境安装依赖/联网需要提权（用户已批准该环境）

## 6. 未提交的 git 改动

```
M darwin/core/__init__.py
M darwin/core/evaluator.py
M darwin/core/executor.py
M darwin/core/task.py
M tests/test_core_task.py
M REFACTOR_PROGRESS.md
?? darwin/core/capabilities.py
?? tests/test_core_capabilities.py
```

P1–P7 的 core 组件与测试此前已随 `fix: P7 faliure retry` 等 commit 入库；本轮 P8 改动尚未提交。
备份/存档位置：`%TEMP%\orchestrator_m0_backup_*.py`（M0 删除的 778 行）、`%TEMP%\darwin_v2_legacy_validate_replan.py`、`%TEMP%\darwin_module_compare.md`（P1 比对报告）

## 7. 新 session 的第一步

1. 读本文件 + `Darwin_v2_architecture_plan.md`
2. 从 P9（工具参数可靠性）开始：INVALID_ARGUMENT 与执行失败彻底分开，
   `_analyze_and_fix_task` 的 corrected_params 职责迁移（Context Resolver 已就位，可并入）
3. 之后按 §4 待执行清单继续（P5c → P10–P14 → P15 → ...）
