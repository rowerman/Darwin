# `darwin/tools/paths.py`

## 模块定位

把外部资源（字典、virtualenv 控制台脚本）的**逻辑名**解析为运行时绝对路径，
让 ToolSpec 的默认值和命令模板保持机器无关。

## 所在链路

工具注册（`recon_server.py` / `attack_server.py`）与 shell 执行
（`mcp_gateway.py`）之间的路径解析层。

## 关键入口

- `project_root()`：仓库根目录。
- `venv_bin_dir()` / `venv_bin(name)`：当前解释器所在 bin 目录与其控制台脚本。
- `resolve_wordlist(name)` / `default_wordlist()`：按
  `项目 wordlists/ → /usr/share/dirb/wordlists → /usr/share/seclists → /usr/share/wordlists`
  顺序解析字典；找不到返回空串，由调用方给出明确错误。
- `tool_path_env()`：给工具子进程的 PATH 前置 venv bin 目录。

## 约束

- **参数 `default` 必须机器无关**：`tools_manifest.json` 是锁文件，
  因此默认值只写逻辑名（如 `raft-large-directories.txt`），绝对路径一律在
  调用时解析；命令模板也只写裸二进制名（如 `netexec`），依赖
  `tool_path_env()` 注入 PATH。

## 相关模块

`tools/recon_server.py`、`tools/attack_server.py`、`tools/mcp_gateway.py`。
