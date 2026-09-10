# `darwin/dpm.py`

## 模块定位

DPM（Defense Perception Module）检测 WAF、cloak、honeypot、trap 及云防御，并给出防御状态和绕过提示。

## 所在链路

**仅侦察期一次**的防御感知，影响规划提示、CTEG scenario profile 与实验指标。

> 每任务自动探测与自动 payload 绕过已移除：它对每个 HTTP 类型任务额外发出
> 2–5 次请求，在整套 benchmark 中从未产生过 flag，唯一的可测效果是把普通
> 的 403/AccessDenied 判成“有 WAF”。防御感知现在只在
> `ReconCoordinator._detect_defenses()` 中执行一次（不调用 LLM）。

## 关键入口

- `DefensePerceptionModule`：规则、签名和 LLM 级联检测。
- `DefenseStateVector`、`FilterProfile`、`WAFMatch`：防御状态模型。
- `detect_cloud_defenses()`：云环境防御探测。

## 输入/输出概览

输入是 HTTP 响应、探测结果和配置指纹；输出是防御分类、置信度、策略和 bypass hints。

## 相关模块

`utils/http_client.py`、`prompts/dpm_classifier.py`、`orchestrator.py`、`dave.py`。

## 阅读建议

先看状态模型，再看级联检测和云防御分支。

## 维护提示

配置指纹、分类阈值和防御类别变化会影响工具计划及 DAVE 判定。
