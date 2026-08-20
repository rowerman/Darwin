# Darwin 模块导航

本目录是 DARWIN 生产源码的导航文档，不是 API 手册。每篇文档回答三个问题：模块负责什么、从哪里开始读源码、它与哪些模块协作。详细行为和接口以源码为准。

## 阅读入口

1. [run.py](run.md)：CLI 启动和配置加载。
2. [darwin/orchestrator.py](darwin/orchestrator.md)：主编排流程。
3. [darwin/core/runtime.py](darwin/core/runtime.md)：`plan → schedule → execute → evaluate → replan` 控制面。
4. [darwin/tools/](darwin/tools/README.md)：工具契约、注册和执行边界。

## 路径映射

源码路径在 `docs/` 下保持相同层级，Python 文件改为 `.md`；目录职责由同目录 `README.md` 概括。例如 `darwin/core/task.py` 对应 `docs/darwin/core/task.md`。

文档覆盖 `darwin/**/*.py`、`run.py`、`tools/*.py` 和 `config/*`。`experiments/`、`tests/`、`knowledge/`、`wordlists/` 及运行时产物不在镜像范围内。

## 文档结构

模块文档通常包含：模块定位、所在链路、主要职责、关键入口、输入/输出概览、相关模块、源码阅读建议和维护提示。实现细节、完整参数表和工具清单请分别查源码、schema 或 `tools_manifest.json`。

