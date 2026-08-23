# DKG 拓扑上下文增强计划

## 1. 目标

将 DKG 中已有的节点和边关系提升为正式的 `PipelineState.topology`，通过统一 Cognition Snapshot 向初始计划、任务执行和每轮 replan 提供当前场景拓扑。

首期覆盖通用网络/Web 关系以及现有云/Kubernetes 拓扑，同时保持 Planner、Runtime 和旧调用方接口兼容。

## 2. 当前问题

- DKG 已保存节点、边和 provenance，但原有 `PipelineState` 主要只包含节点事实。
- 原有 Cognition Snapshot 展示服务、端点、漏洞和计划状态，但没有展示节点之间的关系。
- 云攻击路径主要在 analyze 阶段注入，不能保证每轮 replan 都使用最新拓扑。
- Runtime 原先复用传入的固定 state，任务执行后可能无法及时看到新发现的会话、凭证、服务或关系。

## 3. 设计方案

### 3.1 DKG 拓扑快照

- 为 DKG 增加单调递增的 `revision`。
- 增加 `topology_snapshot()`：
  - 支持按锚点节点提取局部子图。
  - 默认最多两跳、48 个节点、96 条边。
  - 对节点和边进行确定性排序。
  - 返回 `revision`、`anchors`、`nodes`、`edges`。
- 增加 `topology_diff(before, after)`：
  - 返回新增、删除和更新的节点。
  - 返回新增和删除的边。
  - 返回前后 revision。
- revision 随节点新增/更新、边新增和 DKG reset 变化，并纳入 DKG JSON 持久化。

### 3.2 类型化世界状态

在 `darwin/data_model.py` 增加：

- `TopologyNode`
- `TopologyEdge`
- `AttackPathSummary`
- `TopologySnapshot`

`PipelineState` 增加 `topology` 字段，并在 `normalize_dkg_state()` 中读取：

- Host、Service、Endpoint、Session、Credential 等通用关系。
- Cloud/Kubernetes 节点和边。
- `cloud_attack_path.compute_attack_paths()` 生成的攻击路径摘要。

旧状态没有 topology 时使用空快照，保持 checkpoint 兼容。

### 3.3 统一 LLM 上下文

在 `darwin/core/belief.py` 增加拓扑渲染区块，并由现有 `_belief_context()` 统一调用。输出包括：

- 当前 revision 和 anchors。
- 局部节点及关键属性。
- 有向关系，例如 `host -[host_has_service]-> service`。
- 节点/边 confidence（存在时）及攻击路径摘要。
- 攻击路径的前置条件、步骤和推荐工具。
- benchmark 场景允许的完整 credential 值。

拓扑输出保持有界，并支持 compact 模式以控制 token 使用。

### 3.4 Planner、执行器和 Replanner

- 初始计划生成 prompt 注入拓扑上下文。
- 每次 plan-review/replan 注入任务前后的拓扑 diff。
- 任务执行 prompt 通过统一 Cognition Snapshot 获得当前局部拓扑。
- 执行任务前记录 topology baseline，任务完成后比较 DKG revision 和拓扑变化。

### 3.5 Runtime 状态刷新

在 `darwin/core/runtime.py` 增加可选 `state_provider`：

- 未提供时保持原有行为。
- 提供时，Runtime 在初始 plan、任务评估和 replan 前刷新 state。
- Orchestrator 注入 `self._get_state`，使 replan 使用最新 DKG 拓扑。

## 4. 代码变动面

- `darwin/dkg.py`：revision、局部拓扑快照、拓扑 diff、持久化。
- `darwin/data_model.py`：拓扑数据类型和 PipelineState 归一化。
- `darwin/core/belief.py`：拓扑和攻击路径渲染。
- `darwin/core/runtime.py`：可选 state provider 和状态刷新。
- `darwin/orchestration/planning.py`：初始 plan 与 plan-review 上下文。
- `darwin/orchestration/execution.py`：Runtime provider 和任务前拓扑基线。
- `docs/darwin/*.md`：模块职责、刷新机制和敏感上下文说明。
- `tests/test_topology_context.py`：拓扑快照、diff、渲染和 Runtime 刷新测试。

## 5. 测试与验收标准

- DKG 局部子图提取、边类型、revision 和 diff 正确。
- 通用及云/Kubernetes 关系能进入 `PipelineState.topology`。
- Cognition Snapshot 能渲染节点、边、攻击路径和完整凭证。
- 任务新增关系后，下一轮 replan prompt 包含拓扑 diff。
- Runtime 通过 state provider 使用刷新后的 state。
- 旧 checkpoint 缺少 topology 时仍可加载。
- 运行：
  - `conda run -n deeplearn python -m pytest -q`
  - `conda run -n deeplearn python -m pytest -m integration -v`
  - `conda run -n deeplearn python -m pytest -m acceptance -v`
  - `conda run -n deeplearn python -m darwin.tools.manifest --out tools_manifest.json --check`
  - `conda run -n deeplearn python -m tools.audit_coverage`
  - `git diff --check`

## 6. 可能副作用与处理

- **Prompt token 增长**：通过局部子图、节点/边上限和 compact 模式控制。
- **状态滞后**：通过 Runtime state provider 和 DKG revision 刷新。
- **推断关系误导规划**：保留 confidence/provenance，限制路径摘要数量。
- **非可信属性污染 prompt**：拓扑属性作为数据区块渲染，不改变系统指令。
- **完整凭证暴露**：benchmark 环境明确允许；仍需将拓扑上下文视为敏感数据。
- **旧 checkpoint 兼容**：缺少 topology 时使用默认空快照。
- **攻击路径重复**：使用稳定 path ID 和数量上限控制重复任务。

## 7. 实施结果

- 全量测试：530 passed。
- Integration 测试：8 passed。
- Acceptance 测试：4 passed。
- 工具 manifest：132 个工具，状态同步。
- Coverage audit：89/89 通过。
- `git diff --check`：通过。

## 8. 已知限制

`MemoryManager` 未增加独立 topology 序列化字段；当前 topology 由 DKG 持久化内容在 `normalize_dkg_state()` 时重新生成。这保持了旧 checkpoint 兼容，也避免重复保存动态图快照。
