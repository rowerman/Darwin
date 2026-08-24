# `darwin/core/contracts.py`

## 模块定位

定义 v2 控制面的协议、状态枚举和预算/目标等跨组件契约。

## 所在链路

被 TaskGraph、Scheduler、Executor、Evaluator、Memory 和 Runtime 共同依赖。

## 关键入口

- `TaskStatus`、`TaskOutcome`、`ReplanRecommendation`：状态和结果语义；`DependencyType.REQUIRES_ATTACK_PATH` 表示任务依赖 active `path_id`。
- `Budget`、`Objective`：运行约束。
- `Task`、`Planner`、`Scheduler`、`Executor`、`Evaluator`：组件协议。

## 相关模块

`task.py`、`runtime.py`、`evaluator.py`、`executor.py`、`data_model.py`。

## 阅读建议

先读枚举和核心协议，再阅读具体实现类。

## 维护提示

这里是公共契约；状态值或协议签名变更需要同步所有实现和持久化路径。
