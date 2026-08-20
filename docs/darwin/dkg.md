# `darwin/dkg.py`

## 模块定位

基于 NetworkX 的动态知识图谱，保存资产、服务、凭证、会话和漏洞等世界事实及 provenance。

## 所在链路

侦察写入、分析读取、规划和验证跨阶段共享的工作记忆。

## 关键入口

- `DKG`：线程安全的图读写和摘要接口。
- `NODE_TYPES`、`EDGE_TYPES`：图语义目录。

## 输入/输出概览

输入是工具观察和阶段发现；输出是节点/边、事实 provenance、快照和摘要。

## 相关模块

`data_model.py`、`core/belief.py`、`cloud_topology.py`、`orchestrator.py`。

## 阅读建议

先读节点/边类型，再看写入、查询、快照和线程安全边界。

## 维护提示

图语义和 provenance 字段是全局约束，新增关系要检查所有查询消费者。

