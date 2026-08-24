# `darwin/dkg.py`

## 模块定位

基于 NetworkX 的动态知识图谱，保存资产、服务、凭证、会话和漏洞等世界事实及 provenance。

## 所在链路

侦察写入、分析读取、规划和验证跨阶段共享的工作记忆。

## 关键入口

- `DKG`：线程安全的图读写和摘要接口。
- `topology_snapshot()`：按锚点提取有界、确定性排序的局部子图，并返回 revision；边按 `(from, to, type)` 去重（平行边只保留排序中第一条），供 LLM 使用规范关系视图。
- `upsert_edge()`：按 `(from, to, type)` 幂等写入关系，合并 provenance/evidence/confidence/status，并记录变更 journal。
- `topology_context()`：返回全局摘要、局部图、revision 增量和显式 coverage；上下文有界不代表原始图被截断。
- `topology_diff()`：比较任务前后的节点/边变化，供 replan 上下文使用。
- `upsert_attack_path()`：持久化稳定 `path_id` 的 confidence/status/evidence。
- `attack_path_summary()`：门控 + 按 revision 缓存的攻击路径摘要；仅当图中存在云/K8s 相关节点类型时才计算，同 revision 重复调用不重算。
- `NODE_TYPES`、`EDGE_TYPES`：图语义目录。

## 输入/输出概览

输入是工具观察和阶段发现；输出是节点/边、事实 provenance、scope、变更 journal、可供 LLM 使用的局部拓扑快照和摘要。

## 相关模块

`data_model.py`、`core/belief.py`、`cloud_topology.py`、`orchestrator.py`。

## 阅读建议

先读节点/边类型，再看写入、查询、快照和线程安全边界。

## 维护提示

图语义和 provenance 字段是全局约束，新增关系要检查所有查询消费者。
