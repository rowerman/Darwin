# DARWIN v2 重构进度交接（2026-08-14，session 清理版）

> 本文件用于跨 session 续接。新 session 先读本文件 + `Darwin_v2_architecture_plan.md`（v2 目标方案）。
> 当前进度：**M0–P7（已提交）+ P8–P15 阶段 2b（用户已提交）+ 缺口补齐 G1–G5（本 session，未提交）全部完成；364 passed**。
> 剩余：P15 2d/3（等真实场景行为等价）、P17 配置与环境、目录化（见 §4）。

---

## 1. 项目与运行环境

- 仓库：`C:\Users\hanwenZ\Desktop\小论文\Darwin`（单 agent 的 LLM 驱动渗透测试框架）
- 入口：`run.py`；`config/` 目录在仓库外（gitignore，含 API key），本地验证不依赖它
- 推荐 Python：`C:\Users\hanwenZ\anaconda3\envs\deeplearn\python.exe`（已装 litellm 1.96.2、pydantic、pytest 等）
- 跑测试：`& 'C:\Users\hanwenZ\anaconda3\envs\deeplearn\python.exe' -m pytest tests/ -q` → 当前 **364 passed**
- 验收样本单独跑：`pytest tests/ -m acceptance -q`（4 个失败样本回归）
- Runtime 路径开关：环境变量 `DARWIN_USE_RUNTIME=1` 时主循环走 `_run_with_runtime()`，默认走旧路径
- 注意：litellm/tiktoken 首次导入需联网（沙箱禁网时用提权运行）；deeplearn 是用户指定环境

## 2. 上个 session 已完成（M0–P7，均已提交）

- **M0** 修复基线：删 multi-agent 分派/死代码（778 行）、checkpoint 去 multi-agent 字段、trace 种子（plan_generated/task_scheduled/tool_result）、phase_logger 中文编码修复
- **P1** 删死模块：`planner.py`/`state.py`/`analyzer.py`/`bootstrap.py`（git 可恢复）；存档 validate_plan/classify_and_replan
- **P2** 接口契约 `darwin/core/`：contracts/events/runtime 骨架
- **P3** Task 数据模型 + 旧 dict ⇄ Task 兼容层
- **P4** TaskGraph 9 态状态机 + 结构化依赖（requires_task_success/evidence/credential/access/capability），FAILED 不级联
- **P5** ToolExecutor + fix-retry seam 接入；`tool_result` trace 带 planned_tool/adherence
- **P6** FailureAnalyzer 11 类 + Evaluator；`_analyze_and_fix_task` 规则分类短路
- **P7** Replanner 本地修复（retry/replace/invalidate/abandon/defer/global_stop）+ 失败签名去重 + novelty_ratio

## 3. 完成项（P8 – P15 阶段 2b + 缺口补齐 G1–G5）

> P8–P15 2b 已由用户提交（commit：P10/P11/P13/P12/P19/P18/P16/end tail 等）；G1–G5 未提交。

### P8 Capability 层
- `darwin/core/capabilities.py`：`Capability` + `CapabilityRegistry` + `default_registry()`（4 个能力：
  fetch_url / verify_sql_injection / test_credentials / acquire_shell）+ `PreconditionValidator`（`credential/access`=任一满足）+
  `ContextResolver`（纯字段映射）+ `normalize_result`
- Executor 双路径：有 capability → 前置校验（缺失 → PRECONDITION_MISSING）→ supported_tools 顺序尝试（仅
  TOOL_ERROR/INVALID_ARGUMENT 换下一个，有意义失败立即停）；未知 capability 显式失败；capability 优先于 tool；
  无 capability 走旧 tool 直调
- `Task` 兼容层双向携带 capability；evaluator 加 "unknown capability" marker

### P9 工具参数可靠性
- `darwin/core/parameters.py`：`ToolSchemaProvider`（从 gateway `get_tool_definitions()` 收集 schema）+
  `ParameterValidator` + `ParameterCorrector`（丢未知参数、补默认值）
- Executor capability 路径**调用前**做 schema 校验：不可修复 → INVALID_ARGUMENT（零工具调用，按 P8 规则降级）；
  可修复 → 原地修正；legacy 路径不动（orchestrator LLM 修参循环保留作兜底）

### P5c 主循环改严格 Task 消费
- `_unified_llm_loop` 纯执行分派段（attack/recon/mcp 三路直调）替换为 `executor.execute(Task.from_legacy_dict(...))`；
  后处理全部留在 orchestrator；prompt 未动（LLM 仍发 tool+params）
- 新增 mock LLM 冒烟测试（`tests/test_smoke_main_loop.py`）：LLM 驱动 flag / direct 跳过 LLM

### P10–P13 Memory 层
- P10 `darwin/core/memory.py`：`ExecutionRecord`（统一 ExecutionResult + trace 字段）、`PlanMemory`、
  `ExecutionMemory`、`ImportanceClassifier`（preserve/compress/discard 纯规则、零 token）、`MemoryManager`
- P11 记忆消费：`CompressionView` + `compression_view()` API（**未接入** `_maybe_compress` LLM 摘要流程）；
  `_review_and_update_plan` 注入 `## Preserved Memory`（task rationale + 执行历史）；主循环记录 plan/execution
- P13 CTEG 打通：`CTEG.record_execution(record)` 窄适配（复用 commit_task/extract_patterns，存储结构未动）；
  MemoryManager 过滤——preserve 级必写 + 成功的关键 exploit/auth 工具写，discard 永不写；orchestrator 一行接线
- P12 DKG Provenance：`add_node` 可选 source/evidence/timestamp（嵌套 `provenance` dict，不与扁平 `source`
  领域属性冲突）；`get_provenance()`（老节点返回 unknown）；`query_nodes(with_provenance=True)`；**只存未消费**
- P14（ExecutionRecord 统一）已并入 P10，无需单独做

### P19 指标聚合
- `darwin/core/metrics.py`：`MetricsCalculator` + `MetricsReport`，消费 tool_result / task_evaluated /
  replan_requested trace + Replanner 统计，产出五指标：plan adherence、invalid tool invocation、
  recovery、replan novelty、duplicate action + 分布计数；分母为零返回 None
- orchestrator 加 `metrics_report()` 访问器

### P18 测试与回归
- `tests/conftest.py`：共享 FakeLLM / FakeGateway（含 schema）/ FakeCTEG / FakeMCPPool / make_orchestrator
- `tests/test_failure_samples.py` 4 个验收样本（`@pytest.mark.acceptance`）：M2 执行偏离 → adherence=0、
  M5 错误参数被前置拦截、M7 replan 重复变体 → novelty<1、重复动作去重
- pyproject 注册 acceptance marker

### P16 Prompt 拆分
- 新增 4 个角色 prompt（从统一 prompt/现有代码切段，未重写）：`prompts/planner.py`（已接
  `_review_and_update_plan`）、`prompts/evaluator.py`（已接 `_analyze_and_fix_task`）、`prompts/memory.py`
  （llm.py 按身份导入，行为不变）、`prompts/research.py`（**备用资产，未接线**）

### P20 文档同步
- README/CLAUDE.md 更新为 Solo + v2 现状（core/、角色 prompt、334→345 测试）；删除 `_transform_runner.py`

### P15 Runtime 提取（2c + 2b）
- **2c** `core/runtime.py` 从占位改为可运行薄循环：plan→schedule→execute→evaluate→replan→terminate，
  预算/状态机/内存记录；7 个 mock 场景测试
- **2b** 主循环结构迁移：630 行任务执行+后处理提取为 `_execute_task_with_policies()`（旧路径行为不变）；
  新增 `_run_with_runtime()`（Runtime 驱动外层循环，4 个适配器注入规划/调度/执行/评估）+ `DARWIN_USE_RUNTIME=1`
  开关（默认关）；修了 2 个迁移暴露的差异（flag 命中即终止；review 状态回写 exploitation_plan）
- 已知 2b 限制（等真实场景验证）：调度顺序简化（graph READY 序 vs 旧 exploit 优先级）、plan-exhausted 审查流程简化

### 缺口补齐（G1–G5，本 session）

**G5 Tool Adapter 独立层**：`darwin/tools/adapters/`（ToolAdapter 基类 + 4 个能力适配器：
fetch_url / verify_sql_injection / test_credentials / acquire_shell）；ContextResolver 改为按 capability
分发到适配器，自定义能力回落旧 per-tool 映射；其余 ~130 工具保持旧直调

**G3 CTEG 双向闭环**：`MemoryManager.experience_hints()` 统一反向入口；run() 传主漏洞类型——
修复真实缺口（get_suggestions 传空 vuln_type 时 exploit_strategies 恒为空，P13 经验回不来）；
闭环测试（ExecutionRecord → CTEG pattern → 下一轮 hints）；已知限制：漏洞类型精确匹配，
"SQL Injection" 等变体暂不命中

**G2 DKG provenance 消费**：`provenance_summary()`（嵌套 provenance 优先、回退扁平 source，
有来源排序在前、上限 10 条）；`_review_and_update_plan` prompt 注入 `## World State Provenance`

**G1 压缩分级接入**：`MemoryManager.compression_payload()` 三桶渲染；`LLMSession.compress()` 加
`preserved_context`（摘要路径 + 硬截断路径都原样注入 `## PRESERVED MEMORY`）；`_maybe_compress`
把 preserved 传进 compress、discard 只记日志；`ExecutionRecord.from_result` 兼容 dict 输入

**G4 research prompt 接线**：`SYSTEM_PROMPT_RESEARCH` 升级为完整研究角色（身份/工具/流程/JSON
输出，并入 `_research_phase` 与 `_active_service_research` 内嵌指令）；两个研究方法的 4 个 LLM
调用从 ANALYZE prompt 切到 RESEARCH prompt

## 4. 剩余/待办

- **P15 2d + 3**：后处理抽 lifecycle hook → orchestrator 变薄装配层。**前提：真实 benchmark 场景做行为等价
  （P19 指标对比），当前用户暂无场景条件，暂停**
- **P17 配置与环境**：config 骨架、外部工具依赖、Windows/Linux 差异
- **目录化**：架构计划 §15 的 planner/scheduler/executor/memory/capabilities 目录未拆（core/ 单文件模式）
- **真实运行验证**：所有验证均为 mock 层（364 测试），P19 指标无真实基线；G1/G2/G4 改了 LLM 可见内容，
  真实质量只能等场景验证
- 已知限制汇总：CTEG 漏洞类型精确匹配；2b 调度顺序/plan-exhausted 简化；research 质量仅 mock 验证

## 5. 技术要点与坑

- **代码模式**：每个 P = core 组件 + 单测 + 低风险接入点；Protocol 在 contracts.py，具体实现为 core 单文件类，
  `darwin/core/__init__.py` 导出
- **主循环现状**：`_unified_llm_loop` 外层仍是 orchestrator 自己写（旧路径）；执行段走
  `_execute_task_with_policies()` → Executor；`DARWIN_USE_RUNTIME=1` 时外层交给 `core.Runtime`
- **迁移踩过的坑**：① 提取方法时局部变量（MAX_ITER）与循环语义（skip 的 `continue`）要处理；② Runtime 路径的
  plan task 是副本，review 后必须把 status/attempts 回写 exploitation_plan，否则任务被反复执行（测试抓到 25 次）；
  ③ flag 命中旧路径直接 return，Runtime 路径要抛哨兵异常终止；④ 脚本批量改文件会改行尾（本次 orchestrator.py
  已由 CRLF 变 LF，git 会提示，无内容损坏）
- **外部事件**：`knowledge/web/web_exploitation_supplement.json` 在 session 中被杀毒软件隔离删除（git 有记录可恢复）
- **补丁坑**：apply_patch 用过于宽泛的上下文（`except Exception: pass`）会把块插到错误的同名位置
  （G2 provenance 块曾误插进 `_research_phase`），补丁后要 `rg` 定位确认
- **死代码检查习惯**：改动后 `rg` 残留符号；`py_compile` 全部模块；pytest 全绿
- **沙箱**：deeplearn 环境安装依赖/联网需要提权（用户已批准该环境）

## 6. 未提交的 git 改动（仅 G1–G5；P8–P15 2b 已提交）

```
M darwin/core/capabilities.py
M darwin/core/memory.py
M darwin/orchestrator.py
M darwin/prompts/research.py
M darwin/utils/llm.py
M tests/conftest.py
M tests/test_core_memory.py
M tests/test_cteg_experience.py
M tests/test_prompts.py
M tests/test_runtime_path.py
?? darwin/tools/adapters/
?? tests/test_provenance.py
?? tests/test_tool_adapters.py
```

备份/存档位置：`%TEMP%\orchestrator_m0_backup_*.py`、`%TEMP%\darwin_v2_legacy_validate_replan.py`、
`%TEMP%\darwin_module_compare.md`

## 7. 新 session 的第一步

1. 读本文件 + `Darwin_v2_architecture_plan.md`
2. 对照 §4 剩余清单决定优先级（建议：先提交 G1–G5，再 P17 或等真实场景做 P15 2d/3）
3. 提交建议：G1–G5 按功能拆 2 个 commit（G5/G3/G2 一组、G1/G4 一组），或一个 commit 收尾
