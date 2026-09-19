# `darwin/reachability.py`

## 模块定位

端点"宿主可达性"的唯一判定入口。侦察阶段会从集群拓扑推导出一些 Endpoint
节点（`relation_analyzer` 写的 ClusterIP Service、云暴露规则），它们只存在于
集群网络内；darwin 宿主没有到 Service CIDR 的路由，任何探测都要付满超时才能
得到"什么都没有"。

## 关键入口

- `is_host_reachable(ep)`：`virtual: True` 或 `discovered_by` 以
  `relation_analyzer` 开头时返回 False。
- `host_reachable_urls(endpoints)`：批量过滤出可探测的 URL 集合。

## 相关模块

`orchestration/recon.py`（CMS 探测、深侦察批处理、标签路径探测、DPM）、
`orchestration/execution.py`（systematic pass）。

## 维护提示

这些端点是**事实**，依旧写入 DKG 并进入 planner 上下文（集群内攻击面必须可见）；
被排除的只是"从宿主直接探测"这一动作。新增派生端点来源时，若其地址只在目标
网络内可路由，应沿用同一标记而不是另加一套判断。
