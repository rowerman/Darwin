# `darwin/prompts/dpm_classifier.py`

## 模块定位

提供 DPM 三级级联中的 LLM 防御分类 prompt。

## 关键入口

- `DPM_CLASSIFIER_PROMPT`：输入响应证据并分类 WAF/防御行为。

## 相关模块

`dpm.py`、`utils/llm.py`、`config/waf_fingerprints.yaml`。

## 阅读建议

结合 `DefensePerceptionModule` 的调用条件阅读，重点关注分类输出如何被消费。

