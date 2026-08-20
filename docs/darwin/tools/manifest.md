# `darwin/tools/manifest.py`

## 模块定位

从当前注册表生成、加载和校验提交版 `tools_manifest.json`。

## 关键入口

- `build_manifest()`：收集 gateway specs。
- `verify_manifest()`：比较当前注册表和已提交清单。
- `main()`：manifest CLI。

## 相关模块

`spec.py`、`mcp_gateway.py`、`attack_server.py`、`recon_server.py`。

## 阅读建议

先看收集入口，再看生成文件字段和 `--check` 行为。

## 维护提示

注册工具或参数变化后必须重新生成并检查 manifest。

