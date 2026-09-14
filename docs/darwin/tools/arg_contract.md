# `darwin/tools/arg_contract.py`

## 模块定位

工具**参数名**契约的唯一真源。一次调用有两端：生产端（recon、系统性兜底
探测、fix 循环）把领域意图绑定到工具的声明参数，消费端（`mcp_gateway`）
在分发前把收到的调用投影到同一份声明。两端共用本模块，因此投影后仍无法
映射的键就是真实的契约违规，而不是命名漂移。

## 关键入口

- `PARAM_ALIASES`：`alias -> 优先级有序的规范名` 显式迁移表
  （`content/payload/body/json → data`、`body_format → content_type`、
  `credentials → cookie/password/user` 等）。
- `project_args(declared, args, aliases)`：返回
  `(projected, migrated, dropped, unmappable)`；`migrated` 记录被重定向的键，
  `dropped` 只包含占位符（空值、`<tenant>` 这类未填模板），
  `unmappable` 是携带真实值但该工具无法表达的键。
- `is_placeholder(value)`：占位符判定。刻意收窄——`default` 是真实取值
  （`workspace=default`），HTML 载荷以 `<` 开头，两者都不算占位符。
- `alias_target(alias, declared, aliases)`：按 schema 过滤后的目标名。

## 与旧子串模糊匹配的关系

网关曾有一个"子串模糊匹配"阶段：若某声明参数是提供键的子串且长度比例达标
就迁移。它对 `response_parse` 会把 `content` 迁移到 `content_type`（把原始
响应体写进 content-type 提示）同时仍判定 `data` 缺失而拒绝调用；对真正漂移
的 `param`/`credentials` 又完全无效。该阶段已删除，改由本表显式覆盖。

## 相关模块

`tools/mcp_gateway.py`（消费端投影与拒绝信息）、`tools/contracts.py`
（ToolSpec 与别名表补充）、`orchestration/execution.py`（系统性探测构造）、
`orchestration/recon.py`（bootstrap 调用点）。

## 约束

- 表项必须显式、可读；不得引入子串/编辑距离猜测。
- alias 不能与自身候选项同名；候选项必须能在目标工具 schema 中命中才生效。
- 投影不得因为一个无法表达的键而丢弃其余可表达的调用意图。
