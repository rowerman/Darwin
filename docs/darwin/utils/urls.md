# `darwin/utils/urls.py`

## 模块定位

REST 路由探索的纯函数集：从目标**已经披露**的标识符推导相邻路径，
并解析工具输出里的 body / 状态码。不依赖网关与编排栈，便于单测。

## 关键入口

- `observed_identifiers(text, limit)`：从响应文本中抽取标识符样式的标量；
  优先取 JSON **值**（键名通常不是路径段），不可解析时回退到引号值扫描。
- `response_body(text)`：剥离 curl/urllib 输出的响应头块，只留 body。
- `route_variants(url, identifiers)`：推导“集合路由 → 子路径”候选；
  深度上限（`len(path) <= 4`）、候选上限 `ROUTE_VARIANT_MAX=6`、
  标识符上限 `ROUTE_VARIANT_MAX_IDENTIFIERS=4`。

## 使用方

- `orchestration/execution.py`：写请求 404/405 时的同方法路由变体重试
  （推导出的路径只由观察到的标识符拼成，且候选有界）。
- `orchestration/recon.py`：JSON 集合端点的子路径 OPTIONS 探测。

## 约束

- 只有形如 `^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$` 的 token 能成为路径段，
  横幅、句子、URL 一律不会进入路径。
- 这些函数只做推导；是否发出请求、用什么动词由调用方决定。
