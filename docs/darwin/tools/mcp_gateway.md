# `darwin/tools/mcp_gateway.py`

## 模块定位

工具注册和统一调用网关，封装 Python、shell、argv 和 MCP 工具，返回统一 `ToolResult`。

## 所在链路

Executor 与所有外部工具之间的唯一执行边界。

## 关键入口

- `MCPGateway`：注册、查找、调用和工具定义生成。
- `ToolResult`：成功、输出、退出码和解析结果。

`register_shell_argv_tool()` 默认使用无 shell 的 argv 执行；为保持跨平台
契约，显式的 Windows `cmd /c {cmdline}` 模板在 POSIX 环境等价转为
`/bin/sh -c`，并保留原始命令字符串（包含重定向等 shell 语法）。

`register_shell_tool()` 支持可选的 `prepare` 回调：命令首次执行前调用一次，
用于惰性准备运行时前置条件（如 nmap 自定义探针库）。回调异常只记录日志，
不阻断命令执行，保证外部扫描在准备失败时仍可退化运行。

`register_shell_tool()` 还支持可选的 `prepare_params` 回调：在默认值填充之后、
模板格式化之前对参数字典做归一化（解析逻辑字典名、补齐 URL 必需的 `FUZZ`
占位符等）。异常只记录日志，不阻断执行。

shell 模板统一通过 `bash -c` 执行并前置 `set -o pipefail`（无 bash 时回退
`/bin/sh`），使 `cmd | head` 这类管道的退出码反映真实命令结果；
`_pipeline_returncode()` 把“管道读者提前关闭（SIGPIPE=141）但有输出”视为成功。
子进程环境经 `tools/paths.tool_path_env()` 注入，venv 的控制台脚本无需写死路径。

## 相关模块

`core/executor.py`、`tools/spec.py`、`attack_server.py`、`recon_server.py`、`mcp_client.py`。

## 阅读建议

先看 `call()` 和参数归一化，再看不同 executor 的分发和异常包装。

`normalize_params()` 是 `_normalize_params()` 的公开形式，供编排层在
"计划参数是否齐全、能否按计划直接执行"的判断中复用同一套别名/模糊匹配规则，
避免各处重复实现别名逻辑。

## 维护提示

未知工具必须失败；不要让编排器绕过网关直接调用外部命令。

## 参数形状与契约可见性

- **别名**：`contracts._ALIASES` 在服务注册边界写入 `ToolSpec.aliases`，
  规划 LLM 常用的 `body` / `post_data` / `json_body` / `json` /
  `request_body` 都会落到 `data`（仅当该工具声明了 `data` 时生效）。
- **未声明参数即拒绝**：别名与子串纠错之后仍无法归一的键不再被静默丢弃，
  而是返回 `invalid argument: unknown parameter(s) [...] (declared: [...])`
  （`exit_code=2`）并且不调用工具。被丢掉的参数等于丢失的意图：工具会在
  与计划不同的请求上运行，其否定结果会被误读为“假设已被测试且不成立”。
- **修复可见**：值被别名或子串纠错重定向到声明参数的键，会记录在
  `ToolResult.params_repaired`。该列表非空表示调用参数与计划不一致，执行层
  据此把否定结论降级为 inconclusive、不下调假设置信度。
- **`normalize_params()` 仍只归一化**：它是给编排层做“计划能否直接执行”判断的
  预览接口，会过滤并告警未声明键，但不抛错也不拒绝调用。
- **缺必填即拒绝**：分发前检查声明中无 `default` 的参数，缺失时直接返回
  `invalid argument: missing required parameter(s) [...]`，不调用工具。
  Python 工具的声明默认值由 `contracts._sync_python_defaults()` 从函数签名
  同步，因此这条规则不会误伤真正可选的参数。
