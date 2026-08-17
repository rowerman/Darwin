# LLM 思维链（Chain-of-Thought）阶段日志 — 功能说明

> 新增功能（2026-08-15），独立于 DARWIN v2 重构交接文档（`refactor_v1.md`）。
> 实现依据：Design v2 模块化方案（已获用户批准）。当前状态：已实现、测试全绿；
> **代码位于 `think-chain` 分支（commit `998fdf0`）**，当前工作区在 `task-status` 分支
> （信念/认知快照功能，commit `82302ae`），**不含本功能**；如需合入请 merge/cherry-pick。

## 1. 背景与目标

原 `PhaseLogger` 只记录各阶段 LLM 产出的"机械结果"（阶段摘要文本）；
LLM 的思维过程（reasoning / chain of thought）在 `LLMSession.generate()` 里被
提取后从未落盘（且下一轮 `_build_messages` 会主动剥除，保持 DeepSeek thinking-mode
连续性）。

目标：记录每个阶段 LLM 调用时"**面对的信息 → 思维过程 → 输出决策 → 工具反馈**"
的完整链路，用于分析 LLM 对当前场景的理解是否准确。

## 2. 设计要点（模块化）

- 新增独立模块 `darwin/utils/thought_logger.py`（`ThoughtLogger`），owns：
  stage 状态机（`set_stage` / `stage` 上下文 / `current_stage`）、事件序号、
  双格式落盘、异常吞掉（只 warning 不阻断主流程）、`enabled=False` 全 no-op
- `LLMSession` 只做观察者挂载（可选 `thought_logger` 参数，鸭子类型，零 import，
  不含任何日志逻辑）
- `orchestrator` 仅声明式接线（约 10 行）：读配置 → 构造 ThoughtLogger → 挂到
  `self.llm` 与 inline `_classifier`，无日志逻辑
- 输出：`log/thought/<run_id>_thoughts.jsonl`（每行一个 JSON 事件，机器可解析）
  + `<run_id>_thoughts.log`（同事件的可读渲染），逐事件 append，崩溃不丢
- 事件类型：
  - `llm_call`：`{stage, model, prompt, system_prompt, reasoning, content, tool_calls}`
  - `tool_result`：`{stage, tool_call_id, result}`（stage 关联最近一次调用的 stage）

## 3. 改动文件

| 文件 | 改动 |
|---|---|
| `darwin/utils/thought_logger.py` | 新增，全部日志逻辑（P0） |
| `darwin/utils/llm.py` | `LLMSession(..., thought_logger=None)` 观察者；`generate(stage=None)` 捕获 reasoning（`reasoning_content` → `reasoning` → None）；`add_tool_result` 记录工具反馈；compress 调用标 `stage="compress"` |
| `darwin/orchestrator.py` | run() 声明式接线 + 14 处调用点 stage 标注（P1.1/P3） |
| `darwin/dpm.py` | 防御分类调用加 `stage="defense_classification"` |
| `README.md` | config 表增加 `log_thoughts \| true`（P4） |
| `tests/test_thought_logger.py` | 新增 8 个单测（P5） |
| `tests/test_llm_thoughts.py` | 新增 7 个单测（monkeypatch litellm，P5） |
| `tests/conftest.py` / `tests/test_smoke_main_loop.py` | FakeLLM.generate 加 `stage=None`（记录格式不变） |

## 4. stage 标签

`task_execution` ×2 / `analyze` / `dkg_augment` / `research` ×4 / `plan` ×2 /
`fix_analysis` / `credential_extraction` / `plan_review` / `flag_search` /
`defense_classification` / `compress`。

未显式标注的调用回退 logger 当前 stage，默认 `main_loop`。

## 5. 配置

`config/darwin.yaml` → `log_thoughts: bool`（默认 `true`；config 文件在仓库外，
代码侧已提供默认值）。关闭后 ThoughtLogger 全 no-op、零 IO。

## 6. 测试与验证

- `pytest tests/test_thought_logger.py tests/test_llm_thoughts.py` → 15 passed
- `pytest tests/ -q` → **379 passed**（364 存量 + 15 新增；实现时验证）
- 关键行为断言：
  - reasoning 字段回退（`reasoning_content` 缺失时用 `reasoning`）
  - tool_calls 解析与事件记录
  - 下一轮 `_build_messages` 仍剥除 reasoning（DeepSeek thinking 连续性不变）
  - 写盘失败/禁用不抛异常、不阻断主流程

## 7. 已知限制

- OpenAI GPT 系列经 litellm 只暴露推理**摘要**（`reasoning_content` = Responses API
  reasoning summary 文本拼接），DeepSeek 为完整思考文本；官方 OpenAI 文档本环境
  403，字段结论基于安装版 litellm 源码 + 官方域名检索摘要
- thought 日志随 prompt 体积增长，暂无保留策略（可关 `log_thoughts` 或后续加截断）
- stage 标签散在调用点（机械、可 grep）；未标注调用回退 `main_loop`

## 8. 下一步（可选）

- 跑一次真实/mock 场景，人工核对 `log/thought/<run_id>_thoughts.log` 各阶段思维链完整性
- 按 stage 汇总/统计的分析工具（JSONL 可直接程序化消费）
- 思维链摘要嵌入现有 phase 日志（v1 设计时评估过的选项，未做）
- GPT 系增加 `reasoning_effort` 请求参数控制思考深度（litellm 已支持该参数映射）
