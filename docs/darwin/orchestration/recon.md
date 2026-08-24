# `darwin/orchestration/recon.py`

## 模块定位

`ReconCoordinator`：侦察域方法分片，继承 `CoordinatorContext`，通过共享
Orchestrator 上下文读写状态并调用工具端口。

## 关键入口

- `_bootstrap_scan()`：基础 nmap/HTTP 发现、规则环境分类、Host/Service/Endpoint 关系记录。
- `_k8s_cluster_discovery()`：仅在分类为 private cloud/hybrid 后通过 discovery tool port 执行 K8s 只读发现。
- `_deep_recon()`：HTTP 端点深侦察（目录/已知漏洞/表单）。
- `_detect_defenses()`：DPM 防御检测。
- `_verify_flag()`：DAVE L4 flag 验证与蜜罐拒绝。

## 相关模块

`dkg.py`、`dpm.py`、`dave.py`、`ports.py`。
