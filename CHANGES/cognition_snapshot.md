# DARWIN 认知快照与信念闭环（2026-08-15，task-status 分支）

> 本文件记录 task-status 分支的本次改动：统一认知快照（O1）、信念层补全（O2）、
> 压缩保护（O3）、兼容性与回归保障（O4），以及分支基线补救。
> 设计契约见会话内设计 v2（O1.1–O4.2），本文档按该结构回写。

---

## 1. 背景与目标

原问题：LLM 对一个渗透任务的认知分散在至少 5 处（对话历史 / DKG / exploitation_plan /
vulnerabilities / MemoryManager），不同环节的 LLM 调用看到不同的世界视图，导致：

1. **忽视最新发现**：`_review_and_update_plan` 的 `new_discoveries` 只渲染最后 5 个
   endpoint + 凭据，本任务新发现的漏洞假设/会话/flag 不在其中，review LLM 无法及时
   更新 plan。
2. **认知退化**：`LLMSession.compress()` 把旧消息整段交给 LLM 摘要，preserved 只来自
   ExecutionMemory——漏洞假设、plan rationale、analysis 结论不在保护范围内，压缩后
   "为什么选这条路"的决策依据丢失。

目标：所有 LLM 调用看到同一份权威认知快照；任务结果真实回写信念（置信度/状态）；
压缩只允许损失低价值工具输出，决策内容原样保留。

## 2. 实现项（按设计 v2 的稳定 ID）

### O1 统一认知快照

- **O1.1** 新增 `darwin/core/belief.py`：`render_belief_snapshot()` 渲染
  `## [COGNITION SNAPSHOT] Current Cognition` 块（事实 services/endpoints/credentials/
  sessions/flags → 信念 vulns+confidence+status → plan 进度 → defense → 保留 rationale）；
  `SnapshotCaps` 控制每段条数与行宽，`compact=True` 收紧；`SNAPSHOT_MARKER` 常量供压缩分流。
- **O1.2** 增量发现 diff：`node_ids_by_type()` 快照 DKG 节点 ID，
  `render_new_discoveries()` 只报告本任务新增节点；`_execute_task_with_policies` 开头捕获
  `self._cognition_before`，`_review_and_update_plan` 渲染 `## New This Task`，
  无基线时回退旧的"最后 5 个 endpoint"逻辑（旧流程不回归）。
- **O1.3** 注入点（均为附加式，旧提示词段不删）：主循环 initial prompt（compact）、
  任务执行 prompt（full）、plan review prompt（compact）。统一走
  `Orchestrator._belief_context()`，任何异常返回空串，绝不打断主流程。

### O2 信念层补全

- **O2.1** 置信度闭环：`_apply_vulnerability_feedback()` + `_find_vuln_dkg_id()`。
  成功 → +0.05（status=tested）/ flag 命中 +0.2（confirmed）；失败应用 Evaluator 的
  `confidence_delta`（hypothesis_rejected→rejected、defense_blocked→blocked、
  inconclusive→inconclusive，TOOL_ERROR/INVALID_ARGUMENT 不变）。同时回写 DKG
  Vulnerability 节点 confidence/status/last_tested_at。`VulnerabilityHypothesis`
  新增 `status` 字段（默认 ""，向后兼容）。
- **O2.2** PlanMemory 状态同步：`_review_and_update_plan` 确定任务状态后追加
  `memory.record_task(task)`；`PlanMemory.record_task` 增加合并逻辑——状态同步用
  瘦身 dict 时保留旧 rationale/hypothesis/evidence，防止决策依据被抹掉。
- **O2.3** research 结论入 DKG：**已存在**（`_research_phase` 已写
  research_cves/research_techniques 到节点），本轮无需改动。

### O3 压缩保护

- **O3.1** `MemoryManager.belief_provider`（orchestrator 接线为
  `_belief_context(compact=True)`）；`compression_payload()` 把认知块前置到 preserve 桶。
- **O3.2** `LLMSession.compress()` 按 `SNAPSHOT_MARKER` 分流：带标记消息不进摘要 LLM
  的序列化输入与对话历史、原样并入 preserved；全部为标记时跳过摘要调用；硬截断路径
  保留标记消息只截可压缩历史。`stage="compress"` 改为按 generate 签名条件传递
  （main 无 stage 参数，think-chain 有；两边兼容）。
- **O3.3** 压缩前 flush：无需显式步骤——provider 是闭包，压缩时实时渲染当前信念。
- **O3.4** `_build_truncation_context()` 优先 `_belief_context(compact=True)`，
  失败回退旧手工 DKG 摘要。

### O4 兼容性与回归保障

- **O4.1** 旧流程不回归：不改 Executor/网关/task 状态机/终止条件/DAVE/plan 合并逻辑；
  全量 405（think-chain 基线）/ 389+1 skip（main 基线）全绿，4 个 acceptance 通过。
- **O4.2** 思维链日志兼容：`generate()`/`add_tool_result()` 签名未动；压缩仍触发
  stage="compress" 的 llm_call 事件（有 logger 时）；`test_thought_log_records_compress_call`
  用 `importorskip("darwin.utils.thought_logger")`——main 上跳过、合并 think-chain 后恢复。

## 3. 分支基线补救

- 原状态：`task-status` 与 `think-chain` 都指向 `998fdf0`（思维链日志提交），task-status
  错误继承了 think-chain 的 feat。
- 补救：`git stash push -u` 保存全部改动 → `task-status` 重指向 `main`（`6c2e328`）→
  `git stash pop` 3-way 合并 → 解决 `llm.py` 唯一冲突（compress 区域）。
- 适配：llm.py 的 `stage=` 条件传递；测试 `importorskip`。
- 结果：`task-status` 基于 main、`think-chain` 保持 `998fdf0` 不动，两个 feat 完全独立。

## 4. 验证

- think-chain 基线（合并前）：**405 passed**；main 基线（当前 task-status）：**389 passed,
  1 skipped**（skip = 思维链日志兼容测试，main 无该模块，预期行为）。
- acceptance：**4 passed**。
- `py_compile` 全部改动模块通过。
- 新增测试：`tests/test_belief_snapshot.py`（9）、`tests/test_cognition_compression.py`（9）、
  `tests/test_cognition_loop.py`（10），共 26 项（其中 1 项在 main 上按预期跳过）。

## 5. 技术要点与坑

- **f-string 隐式拼接陷阱**：`f"头\n" f"\n".join(x)` 会被拼接成一个字面量，导致
  `## PRESERVED MEMORY` 头变成 `.join()` 的分隔符、单元素时整个头消失。修复为
  `"头\n" + "\n\n".join(x)`。
- **aiohttp 需要运行中事件循环**：直接构造 `Orchestrator` 的同步测试会崩
  （`CookieJar()` 取不到 loop），此类测试必须 `async def`。
- **git stash 中断遗留 stat 伪差异**：stash push 中途失败（`.pytest_cache` 权限）后
  `git status` 显示 M 但 `git diff` 为空（index blob == 工作区 hash），
  `git add -u` 重记 stat 后清除。
- **PlanMemory 状态同步的副作用**：直接 `record_task(瘦身 dict)` 会覆盖原 rationale，
  必须先做字段合并。
- **补丁后核查**：所有新符号已用 `rg` 定位确认，无错位插入。

## 6. 未提交的 git 改动（task-status，基于 main）

```
M  darwin/core/memory.py
M  darwin/data_model.py
M  darwin/orchestrator.py
M  darwin/utils/llm.py
A  tests/test_cognition_compression.py
?? darwin/core/belief.py
?? tests/test_belief_snapshot.py
?? tests/test_cognition_loop.py
```

备份：`stash@{0}`（基于 998fdf0 的完整副本，确认后可 `git stash drop`）、
`%TEMP%\task_status_o1o4_backup.patch`。

## 7. 剩余/待办与已知限制

- flag 命中路径提前 return，置信度反馈在该路径不执行（运行已终止，影响可忽略）。
- 漏洞匹配用 endpoint（子串/精确），多命中时置信度分别更新，精度有上限；
  若要精确需让 plan task 携带 vuln_id（改 prompt 契约，列为后续）。
- 快照为每个 LLM 调用增加少量 token（caps 已控制）。
- MemoryManager 仍不持久化（进程内），跨 run 恢复不在本轮范围。
- 所有验证均为 mock 层，真实场景的认知改善效果需 benchmark 验证。

## 8. 新 session 的第一步

1. 读本文件 + `Darwin_v2_architecture_plan.md` + `CHANGES/refactor_v1.md`。
2. 确认分支状态：`task-status`（main 基，改动未提交）、`think-chain`（998fdf0）。
3. 测试：`& 'C:\Users\hanwenZ\anaconda3\envs\deeplearn\python.exe' -m pytest tests/ -q`。
4. 提交建议：O1–O4 按功能拆 2–3 个 commit（belief 快照一组、信念闭环一组、压缩保护一组）。
