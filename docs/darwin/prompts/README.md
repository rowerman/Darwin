# `darwin.prompts`

保存不同阶段使用的系统提示词。prompt 负责角色、边界和输出格式提示；结构化输出契约在 `core/schemas.py`，工具发现通过 registry 元工具完成。

## 推荐阅读顺序

先看 `orchestrator.py` 了解阶段，再按 `planner.py`、`evaluator.py`、`research.py`、`memory.py` 和 `dpm_classifier.py` 阅读对应 prompt。

