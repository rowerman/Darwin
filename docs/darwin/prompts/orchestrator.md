# `darwin/prompts/orchestrator.py`

## 模块定位

集中保存统一编排、分析、登录、WAF bypass 和探索阶段的角色 prompt。

## 关键入口

- `SYSTEM_PROMPT_ORCHESTRATOR_UNIFIED`：主循环统一角色。
- `SYSTEM_PROMPT_ANALYZE`：漏洞和攻击路径分析。
- `SYSTEM_PROMPT_LOGIN`、`SYSTEM_PROMPT_BYPASS`、`SYSTEM_PROMPT_EXPLORE`：专项阶段角色。

## 相关模块

`orchestrator.py`、`core/schemas.py`、`tools/mcp_gateway.py`。

## 阅读建议

先按常量名称定位调用方，再对照 schema 和工具 registry 查询流程。

## 维护提示

不要在 prompt 中重新维护静态工具目录；工具契约以 registry 和 manifest 为准。

