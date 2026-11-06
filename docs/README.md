# Darwin 文档导航

本目录只维护稳定的架构边界和阅读入口。源码、schema 和 `tools_manifest.json`
是实现细节的唯一事实来源，不再为每个叶子模块维护镜像文档。

## 阅读入口

1. [架构与包边界](architecture.md)：领域包职责、数据流和兼容策略。
2. [run.py](run.md)：CLI 启动、配置加载和结果摘要。
3. [核心控制面](darwin/core/README.md)：Task、Runtime、Executor 与阶段契约。
4. [编排协调层](darwin/orchestration/README.md)：五个 Coordinator 的共享上下文协议。
5. [工具边界](darwin/tools/README.md)：工具注册、契约和执行入口。

## 文档边界

- 架构、目录或公共 import 路径变化时更新 `architecture.md`。
- 控制面契约变化时更新 `darwin/core/` 下的对应文档。
- 工具契约和注册流程变化时更新 `darwin/tools/README.md`。
- 一次性命令、临时实验结果和自动生成报告不进入版本库；覆盖率报告写入被忽略的 `artifacts/`。

