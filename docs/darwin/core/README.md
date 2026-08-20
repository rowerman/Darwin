# `darwin.core`

v2 单代理控制面。这里定义 Task、依赖图、调度、执行、评估、重规划、记忆和阶段 schema；`Runtime` 是唯一的主执行路径。

## 推荐阅读顺序

`contracts.py` → `task.py` / `task_graph.py` → `runtime.py` → `scheduler.py` / `executor.py` / `evaluator.py` → `replan.py` / `memory.py`。

所有阶段输出和工具执行都应通过本目录定义的契约进入系统。

