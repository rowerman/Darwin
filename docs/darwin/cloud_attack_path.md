# `darwin/cloud_attack_path.py`

## 模块定位

基于 DKG 中的云和容器关系推理可行攻击路径，不负责发现资产或执行攻击。

## 所在链路

分析阶段：读取侦察结果，输出供规划器使用的攻击路径报告。

## 关键入口

- `compute_attack_paths()`：汇总各类路径。
- `find_privilege_escalation_paths()`、`find_container_escape_paths()`：专项路径搜索。
- `find_lateral_movement_paths()`、`find_cross_account_paths()`：横向和跨账号推理。
- `find_cloud_data_plane_paths()`：识别 SSRF→IMDS→Credential→CloudResource→Flag 数据面链路。

## 输入/输出概览

输入是 `DKG` 图；输出是 `AttackPathReport` 及 `AttackPath` 列表。数据面路径类别为 `cloud_data_plane`。

## 相关模块

`dkg.py`、`cloud_topology.py`、`core/schemas.py`、`orchestrator.py`。

## 阅读建议

先看路径数据类，再看各搜索函数如何读取节点和边，最后看报告汇总。

## 维护提示

新增节点类型或边语义时，要同时检查 `dkg.py` 和这里的路径规则。
