# `darwin/core/belief.py`

## 模块定位

把 DKG、PipelineState、计划、漏洞和防御信息压缩成供 LLM 阅读的 belief snapshot。

## 所在链路

上下文构建层，连接结构化世界状态与 planner/replanner prompt。

## 关键入口

- `render_belief_snapshot()`：生成完整快照。
- `render_critical_facts()`、`render_new_discoveries()`：生成精简上下文。
- `SnapshotCaps`：控制快照容量。

## 相关模块

`dkg.py`、`data_model.py`、`memory.py`、`orchestrator.py`。

## 阅读建议

先看快照入口和容量限制，再看事实、计划和防御各段的渲染。

## 维护提示

快照标记和压缩格式是 LLM 上下文契约，修改需检查 prompt 消费方。

