# `darwin/data_model.py`

## 模块定位

定义编排器跨阶段共享的领域数据模型，尤其是 `PipelineState` 和任务结果。

## 所在链路

贯穿所有阶段，是 DKG、规划、验证和结果汇总之间的类型化边界。

## 关键入口

- `PipelineState`：阶段快照的主要载体。
- `TopologySnapshot`：PipelineState 中的有界节点/边关系和攻击路径摘要。
- `TaskResult`：对外运行结果。
- `ExploitationPlan`、`VulnerabilityHypothesis`：旧/新规划数据。
- `normalize_dkg_state()`：将动态 DKG 转换为快照。

## 输入/输出概览

输入来自侦察、分析和执行；输出是可序列化的阶段状态和最终结果。

`normalize_dkg_state()` 只把 `dkg.verified_endpoints()`（目标真实响应过的路由）
写入 `PipelineState.endpoints`：派生/假设路由留在图里供审计，但不作为事实进入
规划上下文与运行报告。

`to_prompt_context()` 在渲染上下文最前面额外输出 "## Cluster & Access Facts"
（`_cluster_access_block()`）：K8sCluster（名称/api_url/版本）、Host 节点上的
`k8s_access_summary`（当前 kubectl 身份能做什么）、以及 K8sPod 的名称/命名空间/
phase/镜像/privileged/hostPID。这些是"哪条攻击路径可行"的一等事实，过去只存在
于 Analysis note 里，而渲染窗口只保留最后两条 note，于是 cluster-admin 权限
从未进入任何 prompt。

## 相关模块

`dkg.py`、`core/contracts.py`、`core/task.py`、`orchestrator.py`。

## 阅读建议

先看 `PipelineState` 字段和归一化函数，再看各阶段如何填充它。拓扑通过 DKG revision 刷新，旧 checkpoint 缺少该字段时使用空快照。

## 维护提示

这里的字段是跨阶段契约，变更时同步 schema、checkpoint 和消费方。
