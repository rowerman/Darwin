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

先看验证状态和结果模型，再按 L1 到 L4 阅读 `DAVE` 的流程。

## 维护提示

flag 正则、蜜罐拒绝和验证层级是安全边界，修改需补对应回归测试。

