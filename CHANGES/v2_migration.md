# v2 迁移与阶段间数据契约标准化(2026-08-18)

## 目标

废弃 legacy dict 主路径,全面采用 v2 类型化架构;四个阶段边界
(analyze→plan、research→plan、plan→exploit、exploit→replan)的
数据格式与任务状态存储字段固定、可校验。

## 终态

- `core.Runtime` 是唯一主循环(plan → schedule → execute → evaluate →
  replan);`DARWIN_USE_RUNTIME` 开关与 `_unified_llm_loop` 已删除。
- `TaskGraph` + `TaskStatus`(9 态)是任务状态的唯一权威;计划任务全部为
  类型化 `Task`,不再有 `pending/done/failed/skipped/exhausted` 字符串。
- DKG 作为 WorkingMemory(世界事实)与 PlanMemory/ExecutionMemory/CTEG
  四层共存,通过 `MemoryManager` 组合;`MemoryManager.working` 已接线 DKG,
  `working_snapshot()` 提供类型化世界状态读取。

## Stage A — 数据契约

- 新增 `darwin/core/schemas.py`:pydantic v2 版本化模型
  `AnalyzeOutputV1 / ResearchFindingV1 / ServiceResearchFindingV1 /
  PlanTaskV1`,外加容错抽取与校验;校验失败记 `schema_violation` 事件并
  回退旧 lenient 解析(零回归)。
- 接线点:`_analyze_phase`、`_research_phase`、`_generate_exploitation_plan`、
  `_review_and_update_plan`、`_active_service_research`。
- research 的 `credentials_to_try` 不再拼进 evidence 字符串,改为结构化
  `tool_args["credentials"]`。

## Stage B — 状态存储

- `ExploitationPlan.tasks` 变为 `list[Task]`;状态只允许 `TaskStatus`。
- 任务级状态落盘:`checkpoints/plan_{target}_{phase}.json`(Task 结构化
  dependencies/status/attempts/result_summary);删除 DKG 聚合 Plan 节点
  写入;DKG `Task` 节点类型从 `NODE_TYPES` 移除。
- DKG 字段规范化:`NODE_PROPERTY_SCHEMAS` 统一别名
  (Vulnerability `param→parameter`、Credential `user→username`),
  Endpoint `params` 统一逗号字符串存储;Host 保持自由字段。
- `PlanSummary` 不再 `json.dumps` 二次编码。

## Stage C — Runtime 唯一循环

- `run()` 直接走 `_run_with_runtime()`。
- 新增 `darwin/core/scheduler.py::ParityScheduler`:精确复刻 legacy
  `_select_next_plan_task` 语义(拓扑序、exploit 优先、全部依赖失败置
  ABANDONED、exhausted 跳过、hydra 低优先)。
- Runtime stall(无就绪任务)时 planner 适配器执行 legacy plan-exhausted
  审查(thin-plan 警告 + `[RECONSIDER]`),LLM 新增任务则继续,否则终止。
- 删除 `from_legacy_dict / to_legacy_dict / _coerce_status /
  _status_to_legacy` 桥接及相关测试。

## Stage D — 清理

- reader 侧别名容错移除(`VulnerabilityInfo`、`CredentialInfo`)。
- README/CLAUDE.md 更新为 Runtime 唯一循环、四层记忆、阶段数据契约。

## 测试

- 新增:`test_core_schemas.py`(22)、`test_v2_state.py`(11)、
  `test_core_scheduler.py`(9)。
- 更新:legacy 桥接用例删除,plan 构造改为类型化 `Task`。
- 全量 `pytest tests/`:457 passed。

## 验收门槛说明

计划中的真实 benchmark 行为等价验证(89 场景精选 12-15 个)依赖本地
docker/kubectl 与 LLM API key。当前环境无法运行真实场景,以单元/集成
等价测试兜底:ParityScheduler 排序、Runtime stall 审查、direct/LLM 驱动
执行、plan review 等均有测试覆盖;真实场景对比待具备条件后执行并记录差异。
