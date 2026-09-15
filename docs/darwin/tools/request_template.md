# `darwin/tools/request_template.py`

## 模块定位

HTTP 利用请求的**唯一形状定义**：动词、Content-Type、body 形态、注入位点和
payload。它解决的是"同一次请求在 plan → tool → fix → evidence 之间被反复重新
猜测"的问题：cloud-29 已经用 JSON POST 证明任意文件读，后续请求却丢掉了
`method`/`body_format` 退化成 GET（405），修复循环在 `http_post` 与
`send_payload` 之间乒乓并逐轮丢参数。

## 关键入口

- `RequestTemplate`：`{url, method, headers, cookies, content_type,
  body_format(none|form|json|raw), body, inject, payload}`；
  `derive()` 从计划参数 + 路由声明构造，`render(payload)` 换注入值，
  `tool_params(tool, declared)` 渲染成某个工具的调用参数（表达不了就返回
  `None`），`to_dict()/from_dict()` 供 `Task.action["request"]` 持久化。
- `InjectSlot`：注入位点（`location` = query/body/header + `name`）。
- `REQUEST_RENDERERS`：每个 HTTP 工具一个渲染函数。覆盖 `send_payload`、
  `http_post`、`http_method_probe`、`curl_get`、`sqlmap_test`、`ssti_inject`、
  `command_injection_test`、`xss_reflection_test`、`ssrf_probe`、`xxe_inject`；
  不在表里的工具走 legacy 参数路径。
- `HTTP_REQUEST_CAPABILITIES`：工具 →（可发送动词, 可承载 body 形态）。
  `tool_can_express()` / `tools_for_request()` 用它做工具选择；
  `contracts.py` 从这里 re-export，避免出现第二份能力表。
- `HTTP_SENDER_TOOLS`：通用 HTTP 发送器集合，`capability_family()` 用它判定
  "修复可以在同族工具间切换"，扫描器类工具仍属于各自能力族。

## 约定

- 路由自己声明的动词优先于工具默认值；写请求带注入参数且未给形态时默认 JSON，
  显式的 `body_format`/`content_type` 仍然优先。
- 渲染不了就是渲染不了：JSON body 不会被悄悄降级成 form，GET-only 工具不会
  被派去发写请求（这正是过去 `ssti_inject` 收到 JSON 计划却发出表单体的原因）。
- `Task.action["request"]` 保存的是该路由的**形状记忆**：同 URL 的后续调用继承
  动词/body 形态/头部，但 URL 与 payload 始终取自本次调用的参数。
