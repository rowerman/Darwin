# `darwin/tools/adapters/acquire_shell.py`

## 模块定位

将获取 shell 的高层 capability 参数适配到对应工具调用。

## 关键入口

- `AcquireShellAdapter`：shell 获取参数适配器。

## 相关模块

`_common.py`、`core/capabilities.py`、`tools/attack_server.py`。

## 阅读建议

从 capability 注册追踪到 adapter，再查看目标工具的 `ToolSpec`。

