# `darwin/orchestration/recon.py`

## 模块定位

`ReconCoordinator`：侦察域方法分片，继承 `CoordinatorContext`，通过共享
Orchestrator 上下文读写状态并调用工具端口。

## 关键入口

- `_bootstrap_scan()`：nmap 端口发现 + DKG Host/Service 节点记录。
- `_k8s_cluster_discovery()`：kubectl 集群拓扑发现（静默失败）。
- `_deep_recon()`：HTTP 端点深侦察（目录/已知漏洞/表单）。
- `_detect_defenses()`：DPM 防御检测。
- `_verify_flag()`：DAVE L4 flag 验证与蜜罐拒绝。

## 相关模块

`dkg.py`、`dpm.py`、`dave.py`、`ports.py`。
