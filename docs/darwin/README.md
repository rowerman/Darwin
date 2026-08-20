# `darwin` 包

DARWIN 的生产运行包。顶层模块负责编排、世界状态、防御感知、验证、经验和知识检索；`core/` 提供 v2 控制面，`tools/` 提供工具边界，`utils/` 提供外部服务支持，`prompts/` 保存角色提示词。

## 推荐阅读顺序

`orchestrator.py` → `core/runtime.py` → `core/task.py` / `core/executor.py` → `dkg.py` / `data_model.py` → `dpm.py` / `dave.py`。

顶层编排器不直接执行外部命令，工具调用必须经过 `darwin/tools/` 和 `core/executor.py`。

