# `darwin/tools/adapters/_common.py`

## 模块定位

提供 adapter 基类及通用参数映射辅助函数。

## 关键入口

- `ToolAdapter`：适配器接口。
- `passthrough()`、`http_post_params()`：常用参数转换。

## 相关模块

`acquire_shell.py`、`fetch_url.py`、`test_credentials.py`、`verify_sql_injection.py`、`core/capabilities.py`。

## 维护提示

辅助函数只做参数适配，不应隐藏工具失败或改变结果语义。

