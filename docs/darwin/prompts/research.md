# `darwin/prompts/research.py`

## 模块定位

定义研究角色，要求只基于证据研究漏洞/服务，不直接执行攻击。

## 关键入口

- `SYSTEM_PROMPT_RESEARCH`：研究范围和 finding 输出约束。

## 相关模块

`search_evidence.py`、`rag.py`、`core/schemas.py`、`orchestrator.py`。

## 阅读建议

先看证据格式，再对照 `ResearchFindingV1` 和 `ServiceResearchFindingV1`。

