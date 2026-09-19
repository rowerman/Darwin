# `darwin` 包

DARWIN 的生产运行包。顶层模块负责编排、世界状态、防御感知、验证、经验和知识检索；`orchestration/` 提供按域拆分的阶段协调器，`core/` 提供 v2 控制面，`tools/` 提供工具边界，`utils/` 提供外部服务支持，`prompts/` 保存角色提示词。

## 推荐阅读顺序

`orchestrator.py` → `orchestration/README.md` → `core/runtime.py` → `core/task.py` / `core/executor.py` → `dkg.py` / `data_model.py` → `dpm.py` / `dave.py`。

顶层编排器不直接执行外部命令，工具调用必须经过 `darwin/tools/`、`core/executor.py` 或 `orchestration/ports.py` 注入的端口。

`reachability.py` 是端点"宿主可达性"的唯一判定入口：由集群关系推导出的
ClusterIP/云暴露端点（`virtual: True`）只在集群网络内可路由，侦察、DPM 与
systematic pass 都据此跳过，避免为一个不可达地址付满超时代价。
