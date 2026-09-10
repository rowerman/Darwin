# `darwin/tools/availability.py`

## 模块定位

判断某个工具在本机是否**真的能跑**（其依赖的外部二进制是否存在），
用于把不可用工具排除出规划候选，而不是等调度后以 exit=127 失败。

## 所在链路

规划阶段（工具候选过滤、`_sanitize_plan_tools` 纠错门控）与工具目录渲染。

## 关键入口

- `required_binaries(spec)`：优先取 `ToolSpec.dependencies`；缺失或非法
  （含 `VAR=value`、`{placeholder}`、含空格）时解析 command_template /
  shell_args 的首个可执行 token，跳过 `timeout`/`nice`/`env` 包装与前缀赋值。
- `missing_binaries(spec)` / `is_available(spec)`：PATH 或当前 venv bin 目录命中即可用。
- `filter_available(specs, unavailable)`：批量过滤。
- `clear_cache()`：清空 PATH 查询缓存（测试与环境变化后使用）。

## 约束

- **注册表与 `tools_manifest.json` 不受影响**：可用性只作用于 LLM 暴露面与
  计划校验层，保证 manifest 锁在任何机器上都能重建一致。
- 解释器（`sh`/`python3` 等）与调用时才确定的占位符不参与判定。

## 相关模块

`tools/spec.py`、`tools/contracts.py`、`orchestration/planning.py`。
