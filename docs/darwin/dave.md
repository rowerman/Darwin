# `darwin/dave.py`

## 模块定位

DAVE 对利用结果进行四级验证：HTTP 响应、浏览器行为、防御完整性和最终影响/flag。

## 所在链路

执行后的验证阶段，决定结果是否是真实成功而非蜜罐或误报。

## 关键入口

- `DAVE`：协调四级验证。
- `VerificationResult`、`LayerResult`：验证结果模型。
- `parse_tool_stdout()`：从工具输出提取结构化证据。
- `ExploitAttempt`：描述待验证的利用尝试。

## 输入/输出概览

输入是利用尝试、目标 URL、HTTP/浏览器证据；输出是分层验证结果和可信 flag。

## 相关模块

`orchestrator.py`、`utils/http_client.py`、`dpm.py`、`core/evaluator.py`。

## 阅读建议

先看验证状态和结果模型，再按 L1、L2、L4 阅读 `DAVE` 的流程。

## 层级说明

- L1（HTTP 响应）：403/406/429 与 body 中的拦截字样只是**弱信号**。
  `verify()` 先做 L4 影响提取，只有在该响应没有产出有效 flag 时才把 L1 的
  拦截判定作为失败返回——云 API 常在 403/AccessDenied 响应体里同时带回
  结果数据，此前的短路会直接丢弃这类 flag。
- L2（浏览器）：XSS/DOM 场景可选。
- L3（防御完整性）已移除：其唯一输入是过滤探针结果，而按任务探测已取消，
  该层不再有数据来源。
- L4（影响确认）：flag 提取与蜜罐拒绝，始终运行。

## 维护提示

flag 正则、蜜罐拒绝和验证层级是安全边界，修改需补对应回归测试。
