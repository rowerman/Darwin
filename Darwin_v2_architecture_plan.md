# Darwin v2 Architecture Plan

## 1. 总体目标

Darwin v2 的重点不是继续把 `orchestrator.py` 拆成更多文件，而是把当前系统从：

```text
LLM -> Tool -> Result
```

演化为：

```text
World State
    |
Planner
    |
Task Graph
    |
Scheduler
    |
Executor
    |
Evaluator
    |
Evidence / State Update
    |
Memory
    |
Planner / Replan
```

核心原则：

> LLM 负责决策与推理，系统负责状态、约束、执行和可追踪性。

Darwin v1 已经完成了相当一部分“组件化”：

- DKG：目标环境知识状态
- CTEG：跨任务经验
- DPM：防御感知
- DAVE：验证
- Tool Gateway：工具调用抽象
- LLM Session：模型调用与上下文管理
- Orchestrator：主流程

但 v1 仍然存在一个核心架构问题：

> 组件已经被拆开，但 Planner、Executor、Memory、Task State 和 Tool Invocation 之间的控制边界仍然不清晰。

因此 v2 的目标是完成“控制流架构化”。

---

# 2. 当前主要问题

目前需要重点解决四类问题：

1. **Plan 与 Execution 脱节**
   - plan 可能规划得很好，但 executor 会重新自由推理。
   - plan 更像建议，而不是系统约束。

2. **Memory 压缩损失决策依据**
   - 压缩更偏向减少 token，而不是保留决策所需要的结构化信息。
   - replan 时可能知道“之前做过什么”，却不知道“为什么这么做”。

3. **Tool 调用参数容易错误**
   - LLM 直接面对过于底层的工具 schema。
   - 参数合法不代表语义合法。
   - 工具缺少统一的前置条件验证与参数推导层。

4. **Task dependency 采用传统 DAG failure 语义**
   - 一个前置任务失败后，下游任务被直接判定失败。
   - 系统没有把 failure 视为新的 evidence，并触发替代路径规划。

---

# 3. Darwin v2 目标架构

```text
                         Runtime

                            |
       ------------------------------------------------
       |                    |                         |
    Planner              Scheduler                Evaluator

                            |
                       Task Graph

                            |
                        Executor

                            |
                    Capability Layer

                            |
       ------------------------------------------------
       |                    |                         |
     Recon                Exploit                   Verify

                            |
                          Tools


                       Memory System

                            |
       ------------------------------------------------
       |                    |                         |
  Working Memory       Plan Memory            Execution Memory
                                                   |
                                              Experience Memory
                                                   |
                                                  CTEG

                            |
                           DKG
```

职责原则：

- Planner：决定应该做什么。
- Scheduler：决定当前做哪个 Task。
- Executor：执行已有 Task，不重新规划。
- Evaluator：解释执行结果以及是否需要 replan。
- Memory：保存世界状态、规划原因、执行证据和经验。
- Capability Layer：将高层行为映射到底层工具。
- Runtime：只负责驱动状态机。

---

# 4. Phase 0：建立 v1 行为基线

## 4.1 目标

在重构之前先确保可以回答：

- Planner 当时看到了什么？
- 为什么生成了这个 Task？
- Executor 实际执行了什么？
- 是否按照 Plan 执行？
- Tool 参数从哪里产生？
- 为什么触发 Replan？
- 某个 Task 为什么失败？
- Failure 如何影响后续 Task？

没有这层观测能力，很难判断重构到底有没有改善行为。

---

## 4.2 增加统一 Agent Trace

建议定义统一事件：

```text
RunStarted
StateObserved
PlanGenerated
TaskCreated
TaskScheduled
TaskStarted
CapabilitySelected
ToolCalled
ToolSucceeded
ToolFailed
TaskEvaluated
TaskStateChanged
ReplanRequested
PlanRevised
RunFinished
```

例如：

```json
{
  "event": "TaskCreated",
  "task_id": "exploit_sql_001",
  "goal": "Verify SQL injection",
  "reason": "POST /login username parameter produced SQL syntax error",
  "confidence": 0.78
}
```

---

## 4.3 建立失败样本集

优先保存现有 Darwin 中出现过的真实失败：

- Plan 正确但 Executor 偏离。
- LLM 构造错误 tool 参数。
- 前置 Task failure 导致整链死亡。
- Replan 重复原方案。
- Memory compression 后遗忘关键 evidence。
- 同一个已经失败的工具路径反复尝试。

这些 case 将成为 v2 每个阶段的 regression test。

---

# 5. Phase 1：Task Object 化

这是 Darwin v2 的最高优先级。

## 5.1 当前问题

如果 Plan 只是：

```text
1. Try SQL injection on login.
2. Enumerate database.
3. Search credentials.
```

那么 Executor 必须重新解释：

- 哪个 endpoint？
- 哪个 parameter？
- 为什么认为存在 SQLi？
- 什么算验证成功？
- 失败以后应该怎么办？

这会导致 Planning 阶段做出的决策丢失。

---

## 5.2 新的 Task 数据模型

建议新增：

```text
darwin/core/task.py
```

核心结构：

```python
Task
```

包含：

```text
id
type
goal
hypothesis
rationale
evidence
required_context
action
success_condition
failure_policy
dependencies
priority
confidence
status
created_at
attempt_count
```

示例：

```json
{
  "id": "sql_001",
  "type": "exploit",
  "goal": "Confirm SQL injection on login endpoint",
  "hypothesis": "username parameter is injectable",
  "rationale": "A quote caused a database syntax error",
  "evidence": [
    "POST /login exists",
    "username parameter observed",
    "single quote produced SQL error"
  ],
  "action": {
    "capability": "verify_sql_injection",
    "target": "/login",
    "parameter": "username"
  },
  "success_condition": {
    "type": "database_fingerprint_observed"
  },
  "failure_policy": {
    "retry": 1,
    "replan_on_failure": true
  },
  "priority": 0.9,
  "confidence": 0.78
}
```

---

## 5.3 Phase 1 关键原则

Planner 不能只输出自然语言计划。

Planner 必须生成系统能够执行和验证的 Task。

自然语言解释可以保留，但必须成为 Task metadata，而不是唯一的信息载体。

---

# 6. Phase 2：Task Graph 与 Dependency 语义

## 6.1 当前问题

传统工作流：

```text
A -> B -> C

A failed
=> B failed
=> C failed
```

不适合渗透测试。

渗透测试中的失败通常意味着：

> 某个假设被削弱，而不是整个目标失效。

---

## 6.2 新 Task 状态

建议：

```text
CREATED
READY
RUNNING
SUCCESS
FAILED
BLOCKED
INVALIDATED
NEEDS_REPLAN
ABANDONED
```

其中：

### FAILED

当前 Task 的执行没有达到成功条件。

不代表依赖它的任务全部失败。

### BLOCKED

当前缺少前置条件。

未来可能重新 READY。

### INVALIDATED

新的 evidence 已经证明这个 Task 不再合理。

### NEEDS_REPLAN

当前执行路径失效，需要 Planner 修改局部计划。

### ABANDONED

Planner 明确判断继续尝试的成本高于收益。

---

## 6.3 Dependency 不只是 Task ID

建议 dependency 表达：

```text
requires_evidence
requires_capability
requires_credential
requires_access
requires_task_success
```

例如：

Privilege Escalation 不应该：

```text
depends_on = ["ssh_bruteforce"]
```

而应该：

```text
requires_access = "shell"
```

因为 Shell 可能来自：

- SSH credentials
- Web shell
- RCE
- deserialization
- command injection

这样一个获取 Shell 的路径失败，不会使 privilege escalation 永久死亡。

---

# 7. Phase 3：Memory v2

Memory v2 是解决 Plan/Replan 质量的第二关键阶段。

## 7.1 当前核心问题

Context compression 主要解决：

```text
历史太长
```

但 Agent 真正的问题是：

```text
哪些信息绝对不能被压缩掉？
```

如果 Planner 原本知道：

```text
SQLi hypothesis
because:
username=' caused MySQL syntax error
```

压缩后变成：

```text
SQL injection suspected.
```

虽然 token 少了，但关键推理依据消失。

---

# 8. Memory 四层模型

```text
Memory
 |
 -------------------------------------------------------
 |                 |                 |                 |
Working          Plan             Execution          Experience
Memory           Memory           Memory             Memory
```

---

## 8.1 Working Memory

保存“世界现在是什么样”。

主要来自 DKG：

```text
Hosts
Services
Endpoints
Parameters
Credentials
Sessions
Vulnerabilities
Defenses
Privileges
Access paths
```

DKG 应主要承担：

> World Model

而不是承担完整 Agent Memory。

---

## 8.2 Plan Memory

这是 v2 应新增的关键组件。

保存：

```text
当前目标是什么？
为什么选择这条攻击路径？
基于哪些 evidence？
成功条件是什么？
失败以后预期怎么处理？
哪些 Task 依赖该结论？
```

例如：

```json
{
  "task_id": "sql_001",
  "goal": "Verify SQL injection",
  "reason": "SQL syntax error after quote",
  "expected_result": "DBMS fingerprint",
  "fallbacks": [
    "boolean-based test",
    "time-based test"
  ]
}
```

Plan Memory 不应该被普通 compression 丢弃。

---

## 8.3 Execution Memory

保存实际发生过什么：

```text
tool
parameters
timestamp
stdout
stderr
normalized_result
duration
error_type
retry_count
```

用途：

- 避免重复失败。
- Replan。
- Debugging。
- Benchmark。
- CTEG experience extraction。

---

## 8.4 Experience Memory

CTEG 更适合承担：

> 在什么上下文中，什么动作产生了什么结果。

而不是：

```text
Apache -> SQLi
```

更好的记录：

```json
{
  "context": {
    "service": "Apache",
    "technology": "PHP",
    "endpoint_type": "login"
  },
  "action": {
    "type": "sql_error_probe",
    "parameter": "username"
  },
  "observation": {
    "sql_error": true
  },
  "outcome": {
    "followup_strategy": "boolean_sqli",
    "success": true
  },
  "confidence": 0.84
}
```

---

# 9. Compression v2

不要再做：

```text
messages -> summary
```

建议：

```text
Event
  |
Importance Classification
  |
----------------------------------------
|                    |                 |
Discard          Compress          Preserve
```

必须 Preserve 的信息：

- confirmed vulnerability
- credential
- shell/session
- defense discovery
- Task rationale
- active plan
- unsuccessful strategy with high cost
- contradiction
- privilege transition
- dependency-changing evidence

低价值信息才允许 aggressive compression：

- 重复工具 stdout
- 无意义 banner
- 重复 timeout
- 已归一化的超长扫描结果

---

# 10. Phase 4：Capability Layer

这是解决 Tool 参数问题的核心阶段。

## 10.1 当前问题

如果 LLM 直接调用：

```python
sqlmap(url, parameter, method, cookie, ...)
```

LLM 同时承担：

1. 决定攻击策略；
2. 查询世界状态；
3. 选择工具；
4. 填参数；
5. 判断工具约束。

职责过多。

---

## 10.2 新模型

让 LLM 调用：

```text
verify_sql_injection(task_id)
```

系统负责：

```text
Task
 |
Capability
 |
Precondition Validator
 |
Context Resolver
 |
Tool Adapter
 |
Actual Tool
 |
Result Normalizer
```

---

## 10.3 Capability 示例

```text
capabilities/
    recon/
        discover_services.py
        enumerate_http.py

    exploit/
        verify_sql_injection.py
        verify_xss.py
        verify_command_injection.py
        acquire_shell.py

    auth/
        test_credentials.py

    verify/
        verify_exploit.py
```

---

## 10.4 Capability Contract

每个 capability 应至少定义：

```text
name
required_context
input_model
preconditions
supported_tools
execution_policy
success_condition
result_schema
```

例如：

```text
VerifySQLInjection

Requires:
- Endpoint
- HTTP method
- Parameter

Optional:
- Session
- Cookie
- Headers

Tools:
- sqlmap
- manual HTTP probe

Returns:
- confirmed
- rejected
- inconclusive
```

---

# 11. Tool Adapter 层

真正的工具：

```text
sqlmap
nmap
curl
ffuf
nikto
...
```

应该移动到更底层：

```text
tools/adapters/
```

Tool Adapter 只负责：

```text
typed input
    ->
command/API call
    ->
typed output
```

Tool Adapter 不负责：

- Planning
- Strategy
- Replan
- Memory

---

# 12. Phase 5：Planner / Executor / Evaluator 解耦

## Planner

负责：

```text
World State
+
Plan Memory
+
Experience
+
Objective

->

Task Graph
```

Planner 不执行 Tool。

---

## Executor

输入：

```text
Task
```

职责：

```text
选择对应 Capability
执行
返回 ExecutionResult
```

Executor 不修改战略。

---

## Evaluator

这是目前 Darwin 非常需要的组件。

输入：

```text
Task
ExecutionResult
WorldState
```

输出：

```text
TaskOutcome
EvidenceUpdate
ConfidenceUpdate
ReplanRecommendation
```

例如：

```json
{
  "task_id": "sql_001",
  "outcome": "FAILED",
  "failure_type": "hypothesis_rejected",
  "confidence_delta": -0.5,
  "new_evidence": [
    "parameter appears non-injectable"
  ],
  "replan": true
}
```

---

# 13. Phase 6：Failure Analyzer

Failure 不能只表示：

```text
工具返回非零
```

建议至少区分：

```text
TOOL_ERROR
INVALID_ARGUMENT
PRECONDITION_MISSING
ENVIRONMENT_ERROR
AUTH_FAILURE
TARGET_UNREACHABLE
HYPOTHESIS_REJECTED
STRATEGY_FAILED
DEFENSE_BLOCKED
INCONCLUSIVE
BUDGET_EXCEEDED
```

这些 failure 的含义完全不同。

例如：

```text
sqlmap executable missing
```

不应该降低 SQLi hypothesis confidence。

而：

```text
manual probes + sqlmap both strongly negative
```

应该降低 hypothesis confidence。

---

# 14. Phase 7：Runtime 重构

这一步最后做。

不要一开始重写 orchestrator。

等前面 abstraction 稳定之后再迁移。

最终：

```python
while not runtime.finished():

    state = memory.snapshot()

    if planner.should_plan(state):
        plan = planner.plan(state)
        task_graph.update(plan)

    task = scheduler.next_ready_task()

    if task is None:
        runtime.handle_stall()
        continue

    result = executor.execute(task)

    evaluation = evaluator.evaluate(
        task,
        result,
        state
    )

    memory.apply(evaluation)
    task_graph.apply(evaluation)
```

此时 Runtime 本身应该非常薄。

---

# 15. 建议目录结构

```text
darwin/

    core/
        runtime.py
        events.py
        task.py
        task_graph.py
        state.py

    planner/
        planner.py
        replan.py
        schemas.py

    scheduler/
        scheduler.py

    executor/
        executor.py
        result.py

    evaluator/
        evaluator.py
        failure_analyzer.py

    memory/
        manager.py
        working.py
        plan.py
        execution.py
        compression.py

    knowledge/
        dkg.py
        cteg.py

    capabilities/
        recon/
        exploit/
        auth/
        verify/

    tools/
        adapters/
        mcp/

    prompts/
        planner/
        evaluator/
        research/
        memory/
```

这是目标方向，不建议第一轮直接移动所有文件。

---

# 16. Phase 8：Prompt Architecture

Prompt 应跟系统职责一致。

不要再依赖一个巨大的统一 Agent Prompt。

---

## Planner Prompt

只负责：

- 分析状态
- 提出 hypothesis
- 生成/修改 Task Graph
- 给出 rationale

禁止：

- 调工具
- 编造 tool result

---

## Research Prompt

负责：

- 根据 service/version/CVE/evidence 做研究
- 给 Planner 提供信息

不负责执行攻击。

---

## Evaluator Prompt

负责：

- 判断 Task outcome
- 判断 evidence
- 判断是否需要 replan

---

## Memory Compression Prompt

只处理：

```text
historical execution trace
```

不能修改：

```text
active task
current plan
confirmed evidence
credentials
sessions
```

---

# 17. 推荐的实施顺序

不要一次完成 v2。

推荐：

## Milestone 0

Observability / Trace。

目的：

建立行为基线。

---

## Milestone 1

Task Object。

先不修改整体 Orchestrator。

让旧 Planner 输出 Task。

---

## Milestone 2

Executor consume Task。

停止让 Executor 自由解释自然语言 plan。

---

## Milestone 3

TaskGraph + 新 dependency semantics。

解决 cascade failure。

---

## Milestone 4

Plan Memory + Execution Memory。

先保留现有 DKG 和 CTEG。

---

## Milestone 5

Capability Layer。

首先迁移最容易出参数问题的 Tool。

例如：

```text
sqlmap
curl
ssh
```

不需要一次迁移全部工具。

---

## Milestone 6

Evaluator / Failure Analyzer。

让失败真正产生新的 evidence。

---

## Milestone 7

Replan v2。

Planner 基于：

```text
World State
+
Plan Memory
+
Failure Evidence
```

修改局部 Task Graph。

---

## Milestone 8

Runtime extraction。

最后把 Orchestrator 瘦身。

---

## Milestone 9

Prompt cleanup。

当职责边界稳定之后，再清理 Prompt。

否则 Prompt 会随着架构反复修改。

---

# 18. 每个 Milestone 的验收标准

## M1 Task Object

能够回答：

> Executor 当前执行哪个 Plan Task？

必须有唯一 Task ID。

---

## M2 Plan adherence

记录：

```text
planned capability
vs
executed capability
```

目标：

大多数执行都能够直接映射回 Task。

---

## M3 Dependency recovery

前置 Task failed：

下游 Task 不自动全部 FAILED。

系统能：

```text
BLOCKED
or
NEEDS_REPLAN
```

---

## M4 Memory

Replan 时必须能够看到：

- 当前目标
- 当前 Task rationale
- 已验证 evidence
- 已失败 strategy

---

## M5 Tool reliability

区分：

```text
invalid tool arguments
```

和：

```text
valid execution but exploit failed
```

---

## M6 Failure reasoning

失败必须有 classification。

禁止只有：

```text
success=False
```

---

## M7 Replan

Replan 应优先进行局部修复。

例如：

```text
replace Task B
```

而不是每次完全重写整个攻击计划。

---

## M8 Runtime

Runtime 不应该包含大量：

- vulnerability-specific logic
- tool-specific logic
- prompt-specific logic

---

# 19. 不建议 v2 初期做的事情

## 不要首先增加更多 Agent

当前 single-agent control plane 尚未稳定。

Multi-agent 会增加：

```text
state synchronization
memory consistency
message routing
task ownership
```

问题。

---

## 不要优先升级模型

更强模型可能缓解症状，但不会解决：

```text
Plan 不约束 Execution
```

---

## 不要只优化 Summary Prompt

如果 Memory architecture 不改变：

更好的 Summary 依然可能删除 Planner 所需的结构化信息。

---

## 不要继续按文件大小拆 Orchestrator

判断一个逻辑应该拆出的标准应该是：

```text
它是否拥有独立责任和状态边界？
```

而不是：

```text
这个函数是不是太长？
```

---

# 20. v2 的核心设计理念

Darwin v1 更接近：

```text
LLM
 |
Reason
 |
Tool
 |
Observe
 |
Reason
```

Darwin v2 应该变成：

```text
                LLM
                 |
              Decision
                 |
                 v
           Structured Task
                 |
                 v
             Runtime
                 |
                 v
            Capability
                 |
                 v
               Tool
                 |
                 v
              Evidence
                 |
                 v
              Memory
                 |
                 v
                LLM
```

关键区别：

> LLM 不再直接拥有整个系统的控制权。

它提供 intelligence。

Runtime 提供 discipline。

---

# 21. Darwin v2 成功标准

v2 不应该以“代码量减少”作为成功标准。

应该测量以下指标。

## Plan adherence rate

```text
按 Planner 原 Task 意图执行的次数
/
总 Task 数
```

---

## Invalid tool invocation rate

统计：

```text
schema error
invalid argument
missing context
```

目标显著下降。

---

## Recovery rate

前置 Task 失败后：

```text
成功找到 alternative path
```

的比例。

---

## Replan novelty

避免：

```text
失败
->
重新生成几乎同样的计划
```

---

## Duplicate action rate

相同上下文下重复执行相同失败动作的比例。

---

## Explainability

运行结束必须能重建：

```text
为什么生成这个 hypothesis
        ↓
为什么创建这个 Task
        ↓
为什么调用这个 Capability
        ↓
Tool 返回了什么
        ↓
World State 怎么变化
        ↓
为什么下一步这样规划
```

---

# 22. 最终目标

Darwin v2 的方向可以概括成一句话：

> 从“LLM 控制工具”转变为“LLM 控制决策，系统控制执行”。

这同时对应目前四个主要问题：

| 当前问题 | v2 对应机制 |
|---|---|
| Plan 做得好但执行偏离 | Structured Task + Executor |
| Memory compression 导致 Replan 下降 | Plan Memory + Structured Compression |
| Tool 参数错误 | Capability + Validator + Tool Adapter |
| Dependency failure cascade | Evidence-based TaskGraph + Replan |

因此，在真正开始 v2 修改时，最推荐的第一批工作不是进一步拆 Orchestrator，而是：

```text
Trace
  ↓
Task Object
  ↓
Executor consumes Task
  ↓
TaskGraph
  ↓
Plan Memory
```

完成这五步之后，再决定 Capability、Runtime 和 Prompt 应该如何进一步迁移，会比现在直接进行一次大型重构风险低很多。
