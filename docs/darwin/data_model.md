# `darwin/data_model.py`

## 模块定位

定义编排器跨阶段共享的领域数据模型，尤其是 `PipelineState` 和任务结果。

## 所在链路

贯穿所有阶段，是 DKG、规划、验证和结果汇总之间的类型化边界。

## 关键入口

- `PipelineState`：阶段快照的主要载体。
- `TaskResult`：对外运行结果。
- `ExploitationPlan`、`VulnerabilityHypothesis`：旧/新规划数据。
- `normalize_dkg_state()`：将动态 DKG 转换为快照。

## 输入/输出概览

输入来自侦察、分析和执行；输出是可序列化的阶段状态和最终结果。

## 相关模块

`dkg.py`、`core/contracts.py`、`core/task.py`、`orchestrator.py`。

## 阅读建议

先看 `PipelineState` 字段和归一化函数，再看各阶段如何填充它。

## 维护提示

这里的字段是跨阶段契约，变更时同步 schema、checkpoint 和消费方。

